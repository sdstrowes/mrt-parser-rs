extern crate hex;
use nom::{be_u16, be_u8, IResult};
use num_traits::cast::FromPrimitive;
use std::fmt;

// https://www.iana.org/assignments/bgp-parameters/bgp-parameters.txt
#[allow(non_camel_case_types)]
#[derive(Debug, FromPrimitive)]
enum BGPPathAttrTypes {
    // RFC 4271, page 17
    BGP_PATH_ATTR_ORIGIN = 1,
    BGP_PATH_ATTR_ASPATH = 2,
    BGP_PATH_ATTR_NEXTHOP = 3,
    BGP_PATH_ATTR_EXITDISC = 4,
    BGP_PATH_ATTR_LOCALPREF = 5,
    BGP_PATH_ATTR_ATOM_AGG = 6,
    BGP_PATH_ATTR_AGGREGATOR = 7,
    // RFC 1997,
    BGP_PATH_ATTR_COMMUNITY = 8,
    // rfc4760, page 3,
    BGP_PATH_ATTR_MP_REACH_NLRI = 14,
}

#[derive(Debug, PartialEq)]
pub struct BGPPathAttribute {
    pub flags: u8,
    pub code: u8,
    pub len: u16,
    pub data: Vec<u8>,
}

// Each AS path segment is
// represented by a triple <path segment type, path segment
// length, path segment value>.
//
// The path segment type is a 1-octet length field with the
// following values defined:
//
//    Value      Segment Type
//
//    1         AS_SET: unordered set of ASes a route in the
//                 UPDATE message has traversed
//
//    2         AS_SEQUENCE: ordered set of ASes a route in
//                 the UPDATE message has traversed
//
// The path segment length is a 1-octet length field,
// containing the number of ASes (not the number of octets) in
// the path segment value field.
//
// The path segment value field contains one or more AS
// numbers, each encoded as a 2-octet length field.
// Usage of this attribute is defined in 5.1.2.
//
//
//50 BGP_PATH_ATTR_ASPATH [2, 5, 0, 0, 164, 125, 0, 0, 163, 237, 0, 0, 163, 149, 0, 0, 81, 35, 0, 0, 13, 28]
// == 2, (AS Sequence)
//    5, (AS hops)
//    0, 0, 164, 125,
//    0, 0, 163, 237,
//    0, 0, 163, 149,
//    0, 0, 81, 35,
//    0, 0, 13, 28

fn parse_as_path(fmt: &mut fmt::Formatter, buffer: &Vec<u8>) {
    let mut i = 0;
    while i < buffer.len() {
        match buffer[i] {
            1 => {
                write!(fmt, "AS_SET");
                i += 1;
                let asn_count = buffer[i];
                write!(fmt, "[");
                i += 1;
                let mut j = 0;
                while j < asn_count {
                    if j != 0 {
                        write!(fmt, " ");
                    }
                    write!(
                        fmt,
                        "{:02x}{:02x}{:02x}{:02x}",
                        buffer[i],
                        buffer[i + 1],
                        buffer[i + 2],
                        buffer[i + 3]
                    );
                    j += 1;
                    i += 4;
                }
                write!(fmt, "]");
            }
            2 => {
                write!(fmt, "AS_SEQ:");
                i += 1;
                let asn_count = buffer[i];
                i += 1;
                let mut j = 0;
                let mut aspath = String::with_capacity((asn_count * 4 + (asn_count - 1)) as usize);
                while j < asn_count {
                    if j != 0 {
                        write!(fmt, " ");
                    }
                    write!(
                        fmt,
                        "{:02x}{:02x}{:02x}{:02x}",
                        buffer[i],
                        buffer[i + 1],
                        buffer[i + 2],
                        buffer[i + 3]
                    );
                    j += 1;
                    i += 4;
                }
            }
            _ => {
                write!(fmt, "AS_UNKNOWN");
                i += 1;
            }
        }
    }
}
//
//TABLE_DUMP2|1278892800|B|
//
//NEXTHOP? 91.103.24.2|
//42109|
//0.0.0.0/0|
//ASPATH   42109 41965 41877 20771 3356|
//ORIGIN   IGP|
//NEXTHOP? 91.103.24.2|
//0|
//0|
//|
//NAG|
//|

impl fmt::Display for BGPPathAttribute {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        //let flags = format!("{:02x}", self.flags);
        match BGPPathAttrTypes::from_u8(self.code) {
            Some(BGPPathAttrTypes::BGP_PATH_ATTR_ORIGIN) => match self.data[0] {
                0 => {
                    write!(fmt, "IGP");
                }
                1 => {
                    write!(fmt, "EGP");
                }
                2 => {
                    write!(fmt, "INCOMPLETE");
                }
                _ => {
                    write!(fmt, "UNKNOWN_ORIGIN");
                }
            },
            Some(BGPPathAttrTypes::BGP_PATH_ATTR_ASPATH) => {
                write!(fmt, "BGP_PATH_ATTR_ASPATH");
                parse_as_path(fmt, &self.data);
                //        let data  = format!("{:?}", self.data);
            }
            Some(BGPPathAttrTypes::BGP_PATH_ATTR_NEXTHOP) => {
                write!(fmt, "BGP_PATH_ATTR_NEXTHOP");
            }
            Some(BGPPathAttrTypes::BGP_PATH_ATTR_EXITDISC) => {
                write!(fmt, "BGP_PATH_ATTR_EXITDISC");
            }
            Some(BGPPathAttrTypes::BGP_PATH_ATTR_ATOM_AGG) => {
                write!(fmt, "BGP_PATH_ATTR_ATOM_AGG");
            }
            Some(BGPPathAttrTypes::BGP_PATH_ATTR_AGGREGATOR) => {
                write!(fmt, "BGP_PATH_ATTR_AGGREGATOR");
            }
            Some(BGPPathAttrTypes::BGP_PATH_ATTR_COMMUNITY) => {
                write!(fmt, "BGP_PATH_ATTR_COMMUNITY");
            }
            _ => {
                write!(fmt, "Unhandled attr type: {}", self.code);
            }
        }

        Ok(())
    }
}

pub fn read_path_attr_length(input: &[u8], flags: u8) -> IResult<&[u8], u16> {
    if flags & 0x10 == 0x10 {
        be_u16(input)
    } else {
        let tmp = be_u8(input);
        let tmp2 = tmp.unwrap();
        Ok((tmp2.0, tmp2.1 as u16))
    }
}

// logically:
// I have a length to read.
// that byte range may have multiple attributes, each to be parsed

fn parse_bgp_attr_payload(input: &[u8], code: u8, len: u16) -> IResult<&[u8], Vec<u8>> {
    let len = len as usize;
    Ok((&input[len..], input[0..len].to_vec()))
    //    match BGPPathAttrTypes::from_u8(code) {
    //        Some(BGPPathAttrTypes::BGP_PATH_ATTR_ORIGIN) => {
    //            Ok( (&input[len..], vec![&input[0..len]]) );
    //        }
    //        Some(BGPPathAttrTypes::BGP_PATH_ATTR_ASPATH) => {
    //            Ok( (&input[len..], vec![&input[0..len]]) );
    //        }
    //        Some(BGPPathAttrTypes::BGP_PATH_ATTR_NEXTHOP) => {
    //            Ok( (&input[len..], vec![&input[0..len]]) );
    //        }
    //    }
    //    //Err("No matching attr code".to_string());
}

fn parse_bgp_path_attr(input: &[u8], length: usize) -> IResult<&[u8], BGPPathAttribute> {
    do_parse!(
        input,
        flags: be_u8
            >> code: be_u8
            >> len: call!(read_path_attr_length, flags)
            >> data: call!(parse_bgp_attr_payload, code, len)
            >> (BGPPathAttribute {
                flags,
                code,
                len,
                data
            })
    )
}

pub fn parse_bgp_path_attrs(
    mut input: &[u8],
    length: u16,
) -> IResult<&[u8], Vec<BGPPathAttribute>> {
    // pull precisely 'length' bytes out of 'input'
    let length = length as usize;

    let mut total_length = 0;

    let mut res;
    let mut results: Vec<BGPPathAttribute> = Vec::with_capacity(16);

    // this is a bit of a pain, but the protocol doesn't define how many attrs
    // are included, nor does it provide a sentinel; the outer layer defines
    // the number of octets that will be consumed by M attrs. So, loop until
    // that many bytes are consumed.
    while total_length < length {
        res = parse_bgp_path_attr(input, length);
        let tmp = res;
        match tmp {
            Ok(v) => {
                let bytes_read = input.len() - v.0.len();
                total_length += bytes_read;

                results.push(v.1);
                input = v.0;
            }
            Err(e) => panic!("Bad parse on BGP data; {}", e),
        }
    }

    Ok((input, results))
}


#[test]
fn parse_good_test() {
    
//00 01        <-- peer index
//4c 39 56 0a  <-- orig_ts
//00 25        <-- attr length (37)
//  
//4:  40 01 [01] 00
//26: 50 02 [00 16] 02 05 00 00 a4 7d 00  00 a3 ed 00 00 a3 95 00 00 51 23 00 00 0d 1c
//7:  40 03 [04] 5b 67 18 02
//      
    //let buffer = hex::decode("0x00014c39560a0025400101005002001602050000a47d0000a3ed0000a3950000512300000d1c4003045b671802");
    let buffer = hex::decode("400101005002001602050000a47d0000a3ed0000a3950000512300000d1c4003045b671802").unwrap();
    let buffer = buffer.as_slice();
    println!("{:?}", buffer);

    let result = parse_bgp_path_attrs(buffer, 37).unwrap().1;
    
    let mut res = Vec::new();
    res.push(
        BGPPathAttribute{ flags: 0x40, code: 0x01, len: 0x01, data: vec![0x00] } );
    res.push( BGPPathAttribute{ flags: 0x50, code: 0x02, len: 0x16, data: vec![0x02, 0x05, 0x00, 0x00, 0xa4, 0x7d, 0x00, 0x00, 0xa3, 0xed, 0x00, 0x00, 0xa3, 0x95, 0x00, 0x00, 0x51, 0x23, 0x00, 0x00, 0x0d, 0x1c] } );
    res.push( BGPPathAttribute{ flags: 0x40, code: 0x03, len: 0x04, data: vec![0x5b, 0x67, 0x18, 0x02] } );

    //assert_eq!( result, (CompleteByteSlice(b""), res) );
    assert_eq!( result, res );
}

#[test]
fn parse_good_test_long_buffer() {

//00 01        <-- peer index
//4c 39 56 0a  <-- orig_ts
//00 25        <-- attr length (37)
//
//4:  40 01 [01] 00
//26: 50 02 [00 16] 02 05 00 00 a4 7d 00  00 a3 ed 00 00 a3 95 00 00 51 23 00 00 0d 1c
//7:  40 03 [04] 5b 67 18 02
//
    //let buffer = hex::decode("0x00014c39560a0025400101005002001602050000a47d0000a3ed0000a3950000512300000d1c4003045b671802");
    let buffer = hex::decode("400101005002001602050000a47d0000a3ed0000a3950000512300000d1c4003045b6718020000").unwrap();
    let buffer = buffer.as_slice();
    println!("{:?}", buffer);

    let result = parse_bgp_path_attrs(buffer, 37);
    let tmp = result.unwrap();
    println!("{:?} {:?}", buffer, tmp.0);

    let mut res = Vec::new();
    res.push(
        BGPPathAttribute{ flags: 0x40, code: 0x01, len: 0x01, data: vec![0x00] } );
    res.push( BGPPathAttribute{ flags: 0x50, code: 0x02, len: 0x16, data: vec![0x02, 0x05, 0x00, 0x00, 0xa4, 0x7d, 0x00, 0x00, 0xa3, 0xed, 0x00, 0x00, 0xa3, 0x95, 0x00, 0x00, 0x51, 0x23, 0x00, 0x00, 0x0d, 0x1c] } );
    res.push( BGPPathAttribute{ flags: 0x40, code: 0x03, len: 0x04, data: vec![0x5b, 0x67, 0x18, 0x02] } );


    //assert_eq!( result, (CompleteByteSlice(b""), res) );
    assert_eq!( tmp.1, res );
}


