#[macro_use]
extern crate num_derive;
extern crate num_traits;
use num_traits::cast::FromPrimitive;

#[macro_use]
extern crate nom;
use nom::{be_u128, be_u16, be_u32, be_u8};

extern crate flate2;
use flate2::bufread::GzDecoder;
use std::env;
use std::fmt;
use std::fs::File;
use std::io::{BufReader, Read};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::result::Result;

#[derive(Debug)]
pub struct MRTHeader {
    timestamp: u32,
    mrt_type: u16,
    mrt_subtype: u16,
    length: u32,
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

// currently incomplete
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

#[derive(Debug, FromPrimitive)]
enum TABLE_DUMP_SubTypes {
    AFI_IPv4 = 1,
    AFI_IPv6 = 2,
}

enum TABLE_DUMP_V2_SubTypes {
    PEER_INDEX_TABLE = 1,
    RIB_IPV4_UNICAST = 2,
    RIB_IPV4_MULTICAST = 3,
    RIB_IPV6_UNICAST = 4,
    RIB_IPV6_MULTICAST = 5,
    RIB_GENERIC = 6,
}

fn parse_mrt_table_dump(header: MRTHeader, reader: &[u8]) -> ::std::result::Result<&[u8], String> {
    match TABLE_DUMP_SubTypes::from_u16(header.mrt_subtype) {
        Some(TABLE_DUMP_SubTypes::AFI_IPv4) => {
            let result = parse_mrt_table_dump_ipv4(&reader).unwrap();
            println!("{}", result.1);
            return Ok(result.0);
        }
        Some(TABLE_DUMP_SubTypes::AFI_IPv6) => {
            let result = parse_mrt_table_dump_ipv6(&reader).unwrap();
            println!("{:?}", result.1);
            return Ok(result.0);
        }
        _ => {
            println!("Unhandled subtype {}", header.mrt_type);
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

    loop {
        // nom returns IResults which are aliases for Result<(I, O), Err<I, E>>;
        // I: Remaining Input, O: Output, E: Error
        let header = parse_mrt_table_header(&mut buffer).unwrap();

        let result = header.1;
        println!("{:?}", result);

        buffer = header.0;

        match MRTType::from_u16(result.mrt_type) {
            Some(MRTType::TABLE_DUMP) => {
                match parse_mrt_table_dump(result, buffer) {
                    Ok(a) => {
                        buffer = a;
                    }
                    Err(_err) => {}
                }
            }
            Some(MRTType::TABLE_DUMP_V2) => {
                //println!("TABLE_DUMP_V2: {} {:x} {:x} {} bytes", header.ts, header.mrt_type, header.mrt_subtype, header.length);
            }
            _ => {
                println!("Unhandled type {}", result.mrt_type);
            }
        }
    }
}
