mod bgp;
use bgp::{parse_bgp_path_attrs, BGPPathAttribute};

#[macro_use]
extern crate num_derive;
extern crate num_traits;
use num_traits::cast::FromPrimitive;

#[macro_use]
extern crate nom;
use nom::{be_u128, be_u16, be_u32, be_u8, IResult};

extern crate flate2;
use flate2::bufread::GzDecoder;
use std::env;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Stdout, Write};
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::result::Result;

#[derive(Debug)]
pub struct MRTHeader {
    timestamp: u32,
    mrt_type: u16,
    mrt_subtype: u16,
    length: u32,
}

#[allow(non_camel_case_types)]
#[derive(Debug, FromPrimitive)]
enum MRTType {
    OSPFv2 = 11,
    TABLE_DUMP = 12,
    TABLE_DUMP_V2 = 13,
    BGP4MP = 16,
    BGP4MP_ET = 17,
    ISIS = 32,
    ISIS_ET = 33,
    OSPFv3 = 48,
    OSPFv3_ET = 49,
}
#[allow(non_camel_case_types)]
#[derive(Debug, FromPrimitive)]
enum TableDumpSubtypes {
    AFI_IPv4 = 1,
    AFI_IPv6 = 2,
}

#[allow(non_camel_case_types)]
#[derive(Debug, FromPrimitive)]
enum TableDumpV2Subtypes {
    PEER_INDEX_TABLE = 1,
    RIB_IPV4_UNICAST = 2,
    RIB_IPV4_MULTICAST = 3,
    RIB_IPV6_UNICAST = 4,
    RIB_IPV6_MULTICAST = 5,
    RIB_GENERIC = 6,
}

named!(pub parse_mrt_table_header<MRTHeader>,
    do_parse!(
        timestamp:   be_u32 >>
        mrt_type:    be_u16 >>
        mrt_subtype: be_u16 >>
        length:      be_u32 >>
        (MRTHeader { timestamp, mrt_type, mrt_subtype, length })
    )
);

impl<'a> fmt::Display for MRTHeader {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match MRTType::from_u16(self.mrt_type) {
            Some(MRTType::TABLE_DUMP) => {
                write!(fmt, "TABLE_DUMP|");
                match TableDumpSubtypes::from_u16(self.mrt_subtype) {
                    Some(TableDumpSubtypes::AFI_IPv4) => {
                        write!(fmt, "AFI_IPv4");
                    }
                    Some(TableDumpSubtypes::AFI_IPv6) => {
                        write!(fmt, "AFI_IPv6");
                    }
                    _ => {
                        write!(fmt, "Unhandled MRT TABLE_DUMP subtype {}", self.mrt_subtype);
                    }
                }
            }
            Some(MRTType::TABLE_DUMP_V2) => {
                write!(fmt, "TABLE_DUMP_V2|");
                match TableDumpV2Subtypes::from_u16(self.mrt_subtype) {
                    Some(TableDumpV2Subtypes::PEER_INDEX_TABLE) => {
                        write!(fmt, "PEER_INDEX_TABLE");
                    }
                    Some(TableDumpV2Subtypes::RIB_IPV4_UNICAST) => {
                        write!(fmt, "RIB_IPV4_UNICAST");
                    }
                    Some(TableDumpV2Subtypes::RIB_IPV4_MULTICAST) => {
                        write!(fmt, "RIB_IPV4_MULTICAST");
                    }
                    Some(TableDumpV2Subtypes::RIB_IPV6_UNICAST) => {
                        write!(fmt, "RIB_IPV6_UNICAST");
                    }
                    Some(TableDumpV2Subtypes::RIB_IPV6_MULTICAST) => {
                        write!(fmt, "RIB_IPV6_MULTICAST");
                    }
                    Some(TableDumpV2Subtypes::RIB_GENERIC) => {
                        write!(fmt, "RIB_GENERIC");
                    }
                    _ => {
                        write!(
                            fmt,
                            "Unhandled MRT TABLE_DUMP_V2 subtype {}",
                            self.mrt_subtype
                        );
                    }
                }
            }
            _ => {
                write!(fmt, "Unhandled MRT Type {}", self.mrt_type);
            }
        }
        write!(fmt, "|{}|", self.timestamp);
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub struct MRTTableDumpIPv4<'a> {
    view_number: u16,
    sequence_number: u16,
    prefix: Ipv4Addr,
    prefix_length: u8,
    status: u8,
    originated_time: u32,
    peer_address: Ipv4Addr,
    peer_asn: u16,
    attr_length: u16,
    as_path: &'a [u8],
}

// Mimic bgpdump output for now
// bgpdump:
// TABLE_DUMP|992216782|B|193.148.15.85|3257|3.0.0.0/8|3257 701 80|IGP|193.148.15.85|0|0||NAG||
// this:
// MRTHeader { timestamp: 992216782, mrt_type: 12, mrt_subtype: 1, length: 44 }
//TABLE_DUMP|992207428|B|193.148.15.85|3257|3.0.0.0/8|16:[40, 01, 01, 00, 40, 02, 08, 02, 03, 0c, b9, 02, bd, 00, 50, 40, 03, 04, c1, 94, 0f, 55]|IGP|193.148.15.85|0|0||NAG||

impl<'a> fmt::Display for MRTTableDumpIPv4<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let prefix = format!("{}/{}", self.prefix, self.prefix_length);
        let path = format!("{:02x}:{:02x?}", self.attr_length, self.as_path);
        let str = [
            "TABLE_DUMP",
            &*self.originated_time.to_string(),
            "B", // this looks hard-wired to B in bgpdump source
            &*self.peer_address.to_string(),
            &*self.peer_asn.to_string(),
            &*prefix,
            &*path,                          // as path
            "IGP",                           // describe_origin
            &*self.peer_address.to_string(), // next hop
            "0",                             // npref
            "0",                             // nmed
            "",                              // community
            "NAG",                           // aggregate
            "",
            "",
        ];
        fmt.write_str(&*str.join("|"));
        Ok(())
    }
}

//        0                   1                   2                   3
//        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |         View Number           |       Sequence Number         |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                        Prefix (variable)                      |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       | Prefix Length |    Status     |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                         Originated Time                       |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                    Peer IP Address (variable)                 |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |           Peer AS             |       Attribute Length        |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                   BGP Attribute... (variable)
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//                         Figure 4: TABLE_DUMP Type

named!(pub parse_mrt_table_dump_ipv4<MRTTableDumpIPv4>,
    do_parse!(
        view_number:     be_u16 >>
        sequence_number: be_u16 >>
        prefix:          be_u32 >>
        prefix_length:   be_u8  >>
        status:          be_u8  >>
        originated_time: be_u32 >>
        peer_address:    be_u32 >>
        peer_asn:        be_u16 >>
        attr_length:     be_u16 >>
        as_path:         take!(attr_length)        >>
    (MRTTableDumpIPv4 {
        view_number,
        sequence_number,
        prefix:          Ipv4Addr::from(prefix),
        prefix_length,
        status,
        originated_time,
        peer_address:    Ipv4Addr::from(peer_address),
        peer_asn,
        attr_length,
        as_path
    })
    )
);

#[derive(Debug)]
pub struct MRTTableDumpIPv6<'a> {
    view_number: u16,
    sequence_number: u16,
    prefix: Ipv6Addr,
    prefix_length: u8,
    status: u8,
    originated_time: u32,
    peer_address: Ipv6Addr,
    peer_asn: u16,
    attr_length: u16,
    as_path: &'a [u8],
}

named!(pub parse_mrt_table_dump_ipv6<MRTTableDumpIPv6>,
    do_parse!(
        view_number:     be_u16 >>
        sequence_number: be_u16 >>
        prefix:          be_u128 >>
        prefix_length:   be_u8  >>
        status:          be_u8  >>
        originated_time: be_u32 >>
        peer_address:    be_u128 >>
        peer_asn:        be_u16 >>
        attr_length:     be_u16 >>
        as_path:         take!(attr_length)        >>
    (MRTTableDumpIPv6 {
        view_number,
        sequence_number,
        prefix:          Ipv6Addr::from(prefix),
        prefix_length,
        status,
        originated_time,
        peer_address:    Ipv6Addr::from(peer_address),
        peer_asn,
        attr_length,
        as_path
    })
    )
);

fn parse_mrt_table_dump<'a>(
    out: &mut BufWriter<Stdout>,
    header: MRTHeader,
    reader: &'a [u8],
) -> ::std::result::Result<&'a [u8], String> {
    match TableDumpSubtypes::from_u16(header.mrt_subtype) {
        Some(TableDumpSubtypes::AFI_IPv4) => {
            let result = parse_mrt_table_dump_ipv4(&reader).unwrap();
            writeln!(out, "{}", result.1);
            return Ok(result.0);
        }
        Some(TableDumpSubtypes::AFI_IPv6) => {
            let result = parse_mrt_table_dump_ipv6(&reader).unwrap();
            writeln!(out, "{:?}", result.1);
            return Ok(result.0);
        }
        _ => {
            writeln!(out, "Unhandled subtype {}", header.mrt_type);
        }
    }
    Err("No match".to_string())
}

//        0                   1                   2                   3
//        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                      Sequence Number = 42                     |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       | Preflen = 32  |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |                 Prefix  =  2001:0DB8::/32                     |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |    Entry Count = 1            |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |    Peer Index =  15           |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |Originated Time = 1300475700 epoch sec (2011-03-18 19:15:00)   |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |   Attribute Length  =  68     |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//       |   BGP Path Attributes =

#[derive(Debug)]
pub struct MRTTableDumpV2PeerIndex<'a> {
    collector_bgp_id: u16,
    view_name_length: u8,
    view_name: &'a [u8],
    peer_count: u8,
    peer_entries: &'a [u8],
}

named!(pub parse_mrt_table_dump_v2_peer_index<MRTTableDumpV2PeerIndex>,
    do_parse!(
        collector_bgp_id: be_u16 >>
        view_name_length: be_u8  >>
        view_name:        take!(view_name_length) >>
        peer_count:       be_u8  >>
        peer_entries:     take!(view_name_length) >>
    (MRTTableDumpV2PeerIndex { collector_bgp_id, view_name_length, view_name, peer_count, peer_entries })
    )
);

// RIB Entries
#[derive(Debug)]
pub struct RibEntry {
    peer_index: u16,
    originated_timestamp: u32,
    attr_length: u16,
    bgp_path_attrs: Vec<BGPPathAttribute>,
}

fn parse_rib_entry(input: &[u8]) -> IResult<&[u8], RibEntry> {
    do_parse!(
        input,
        peer_index: be_u16
            >> originated_timestamp: be_u32
            >> attr_length: be_u16
            >> bgp_path_attrs: call!(parse_bgp_path_attrs, attr_length)
            >> (RibEntry {
                peer_index,
                originated_timestamp,
                attr_length,
                bgp_path_attrs
            })
    )
}

impl fmt::Display for RibEntry {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        for i in &self.bgp_path_attrs {
            write!(fmt, "|{}", i);
        }
        Ok(())
    }
}

named_args!( parse_rib_entries(entry_count: u16)< Vec<RibEntry> >,
    count!( parse_rib_entry, entry_count as usize )
);

#[derive(Debug)]
pub struct MRTTableDumpV2IPv4Unicast<'b> {
    sequence_number: u32,
    prefix_length: u8,
    prefix: &'b [u8],
    entry_count: u16,
    rib_entries: Vec<RibEntry>,
}

fn make_addr(prefix: &[u8]) -> Ipv4Addr {
    let mut prefix_u32: u32 = 0;
    for i in 0..prefix.len() {
        prefix_u32 |= (prefix[i] as u32) << (24 - 8 * i);
    }
    let outputaddr = Ipv4Addr::from(prefix_u32);
    outputaddr
}

impl<'a> fmt::Display for MRTTableDumpV2IPv4Unicast<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let prefix = format!("{}/{}", make_addr(self.prefix), self.prefix_length);

        let line_prefix = format!("{:08x}|{}|", self.sequence_number, String::from(prefix));
        for i in &self.rib_entries {
            write!(fmt, "\n{} {}", line_prefix, i);
        }
        Ok(())
    }
}

fn prefix_octet_count(prefix_length: u8) -> u32 {
    u32::from((prefix_length + 7) / 8)
}

// I had to break out of the macro here because it was grouching about lifetimes.
//named_args!(pub parse_mrt_table_dump_v2_ipv4_unicast<'a>(header: &'a MRTHeader)<MRTTableDumpV2IPv4Unicast>,
//
// This is ugly but the number of bytes for this part of the message is:
// length specific in header - sizeof(sequence_num) - sizeof(prefix_length) - prefix_octet_count - sizeof(entry_count)
//rib_entries:     take!(header.length - (size_of::<u32>() as u32) - (size_of::<u8>() as u32) - prefix_octet_count(prefix_length) - (size_of::<u16>() as u32))  >>
//rib_entries:     parse_rib_entry(input, header.length - (size_of::<u32>() as u32) - (size_of::<u8>() as u32) - prefix_octet_count(prefix_length) - (size_of::<u16>() as u32), entry_count) >>
fn parse_mrt_table_dump_v2_ipv4_unicast<'a>(
    input: &'a [u8],
    header: &MRTHeader,
) -> IResult<&'a [u8], MRTTableDumpV2IPv4Unicast<'a>> {
    do_parse!(
        input,
        sequence_number: be_u32
            >> prefix_length: be_u8
            >> prefix: take!(prefix_octet_count(prefix_length))
            >> entry_count: be_u16
            >> rib_entries: call!(parse_rib_entries, entry_count)
            >> (MRTTableDumpV2IPv4Unicast {
                sequence_number,
                prefix_length,
                prefix,
                entry_count,
                rib_entries
            })
    )
}

#[derive(Debug)]
pub struct MRTTableDumpV2IPv6Unicast<'a> {
    sequence_number: u32,
    prefix_length: u8,
    prefix: &'a [u8],
    entry_count: u16,
    rib_entries: &'a [u8],
}

//named!(pub parse_mrt_table_dump_v2_ipv6_unicast<MRTTableDumpV2IPv6Unicast>,
fn parse_mrt_table_dump_v2_ipv6_unicast<'a>(
    input: &'a [u8],
    header: &MRTHeader,
) -> IResult<&'a [u8], MRTTableDumpV2IPv6Unicast<'a>> {
    do_parse!(
        input,
        sequence_number: be_u32
            >> prefix_length: be_u8
            >> prefix: take!(prefix_octet_count(prefix_length))
            >> entry_count: be_u16
            >> rib_entries:
                take!(
                    header.length
                        - (size_of::<u32>() as u32)
                        - (size_of::<u8>() as u32)
                        - prefix_octet_count(prefix_length)
                        - (size_of::<u16>() as u32)
                )
            >> (MRTTableDumpV2IPv6Unicast {
                sequence_number,
                prefix_length,
                prefix,
                entry_count,
                rib_entries
            })
    )
}

fn parse_mrt_table_dump_v2<'a>(
    out: &mut BufWriter<Stdout>,
    header: MRTHeader,
    reader: &'a [u8],
) -> ::std::result::Result<&'a [u8], String> {
    match TableDumpV2Subtypes::from_u16(header.mrt_subtype) {
        Some(TableDumpV2Subtypes::PEER_INDEX_TABLE) => {
            //let result = parse_mrt_table_dump_v2_peer_index(&reader)
            let header_length = header.length as usize;
            return Ok(&reader[header_length..]);
        }
        Some(TableDumpV2Subtypes::RIB_IPV4_UNICAST) => {
            let result = parse_mrt_table_dump_v2_ipv4_unicast(&reader, &header).unwrap();
            writeln!(out, "{}", result.1);
            return Ok(result.0);
        }
        Some(TableDumpV2Subtypes::RIB_IPV4_MULTICAST) => {
            return Err("TABLE_DUMP_V2 subtype RIB_IPV4_MULTICAST not implemented".to_string());
        }
        Some(TableDumpV2Subtypes::RIB_IPV6_UNICAST) => {
            let result = parse_mrt_table_dump_v2_ipv6_unicast(&reader, &header).unwrap();
            writeln!(out, "{:?}", result.1);
            return Ok(result.0);
        }
        Some(TableDumpV2Subtypes::RIB_IPV6_MULTICAST) => {
            return Err("TABLE_DUMP_V2 subtype RIB_IPV4_MULTICAST not implemented".to_string());
        }
        Some(TableDumpV2Subtypes::RIB_GENERIC) => {
            return Err("TABLE_DUMP_V2 subtype RIB_GENERIC not implemented".to_string());
        }
        _ => {
            writeln!(out, "Unhandled subtype {}", header.mrt_type);
        }
    }
    Err("No match".to_string())
}

fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        return Err("Please provide filename".to_string());
    }

    let filename = &args[1];

    let f = File::open(filename).expect("Cannot open file!");
    let mut f = GzDecoder::new(BufReader::new(f));

    let mut buffer = Vec::new();
    f.read_to_end(&mut buffer).expect("Cannot read file!");
    let mut buffer = buffer.as_slice();

    let a = io::stdout();
    //let mut stdout = a.lock();
    let mut stdout = BufWriter::new(a);

    loop {
        // nom returns IResults which are aliases for Result<(I, O), Err<I, E>>;
        // I: Remaining Input, O: Output, E: Error
        let header = parse_mrt_table_header(&buffer).unwrap();

        let result = header.1;
        writeln!(stdout, "{}", result);

        buffer = header.0;

        match MRTType::from_u16(result.mrt_type) {
            Some(MRTType::TABLE_DUMP) => match parse_mrt_table_dump(&mut stdout, result, buffer) {
                Ok(a) => {
                    buffer = a;
                }
                Err(_err) => {}
            },
            Some(MRTType::TABLE_DUMP_V2) => {
                match parse_mrt_table_dump_v2(&mut stdout, result, buffer) {
                    Ok(a) => {
                        buffer = a;
                    }
                    Err(_err) => {}
                }
            }
            _ => {
                writeln!(stdout, "Unhandled type {}", result.mrt_type);
            }
        }
    }
}
