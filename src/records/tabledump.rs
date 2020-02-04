use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Error, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::Header;
use crate::AFI;

use std::convert::TryInto;
fn read_be_u32(input: &mut &[u8]) -> u32 {
    let (int_bytes, rest) = input.split_at(std::mem::size_of::<u32>());
    *input = rest;
    u32::from_be_bytes(int_bytes.try_into().unwrap())
}

/// Represents a RIB entry of a Routing Information Base.
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct TABLE_DUMP {
    /// Identifies the RIB view. Normally set to 0.
    pub view_number: u16,

    /// Sequence number for the RIB entry in the RIB. Will wrap to back to 0.
    pub sequence_number: u16,

    /// The IP address of this RIB entry.
    pub prefix: IpAddr,

    /// The prefix length of this RIB entry.
    pub prefix_length: u8,

    /// Unused and should be set to 1.
    pub status: u8,

    /// Contains the 4-octet time at which this prefix was heard since 1 January 1970 00:00:00 UTC.
    pub originated_time: u32,

    /// IP address of the peer that provided the update for this RIB entry.
    pub peer_address: IpAddr,

    /// ASN of the peer that provided the update for this RIB entry.
    pub peer_as: u16,

    /// The path attributes associated with this route.
    pub attributes: Vec<u8>,
}

#[allow(non_camel_case_types)]
impl TABLE_DUMP {
    ///
    /// # Summary
    /// Used to parse TABLE_DUMP MRT records.
    ///
    /// # Panics
    /// This function does not panic.
    ///
    /// # Errors
    /// Any IO error will be returned while reading from the stream.
    /// If an ill-formatted stream or header is provided behavior will be undefined.
    ///
    /// # Safety
    /// This function does not make use of unsafe code.
    ///
    pub fn parse(header: &Header, stream: &mut Read) -> Result<TABLE_DUMP, Error> {
        let view_number = stream.read_u16::<BigEndian>()?;
        let sequence_number = stream.read_u16::<BigEndian>()?;

        let prefix = match AFI::from(header.sub_type)? {
            AFI::IPV4 => IpAddr::V4(Ipv4Addr::from(stream.read_u32::<BigEndian>()?)),
            AFI::IPV6 => IpAddr::V6(Ipv6Addr::from(stream.read_u128::<BigEndian>()?)),
        };

        let prefix_length = stream.read_u8()?;
        let status = stream.read_u8()?;
        let originated_time = stream.read_u32::<BigEndian>()?;

        let peer_address = match AFI::from(header.sub_type)? {
            AFI::IPV4 => IpAddr::V4(Ipv4Addr::from(stream.read_u32::<BigEndian>()?)),
            AFI::IPV6 => IpAddr::V6(Ipv6Addr::from(stream.read_u128::<BigEndian>()?)),
        };

        let peer_as = stream.read_u16::<BigEndian>()?;
        let attribute_length = stream.read_u16::<BigEndian>()?;
        let mut attributes = vec![0; attribute_length as usize];
        stream.read_exact(&mut attributes)?;

        Ok(TABLE_DUMP {
            view_number,
            sequence_number,
            prefix,
            prefix_length,
            status,
            originated_time,
            peer_address,
            peer_as,
            attributes,
        })
    }
}

/// Used to store Routing Information Base (RIB) entries.
#[derive(Debug)]
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
pub enum TABLE_DUMP_V2 {
    PEER_INDEX_TABLE(PEER_INDEX_TABLE),
    RIB_IPV4_UNICAST(RIB_AFI),
    RIB_IPV4_MULTICAST(RIB_AFI),
    RIB_IPV6_UNICAST(RIB_AFI),
    RIB_IPV6_MULTICAST(RIB_AFI),
    RIB_GENERIC(RIB_GENERIC),
    RIB_IPV4_UNICAST_ADDPATH(RIB_AFI_ADDPATH),
    RIB_IPV4_MULTICAST_ADDPATH(RIB_AFI_ADDPATH),
    RIB_IPV6_UNICAST_ADDPATH(RIB_AFI_ADDPATH),
    RIB_IPV6_MULTICAST_ADDPATH(RIB_AFI_ADDPATH),
    RIB_GENERIC_ADDPATH(RIB_GENERIC_ADDPATH),
}

/// This record provides the BGP ID of the collector, an optional view name,
/// and a list of indexed peers.
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct PEER_INDEX_TABLE {
    /// The identifier of the collector often set to its IPv4 address.
    pub collector_id: u32,

    /// Optional associated view name. Set to the empty string if empty.
    pub view_name: String,

    /// An array of peers from which messages were received.
    pub peer_entries: Vec<PeerEntry>,
}

impl PEER_INDEX_TABLE {
    fn parse(stream: &mut Read) -> Result<PEER_INDEX_TABLE, Error> {
        let collector_id = stream.read_u32::<BigEndian>()?;
        let view_name_length = stream.read_u16::<BigEndian>()?;

        let mut buffer: Vec<u8> = vec![0; view_name_length as usize];
        stream.read_exact(&mut buffer)?;
        let view_name = String::from_utf8_lossy(&buffer).to_string();

        let peer_count = stream.read_u16::<BigEndian>()?;
        let mut peer_entries: Vec<PeerEntry> = Vec::with_capacity(peer_count as usize);
        for _ in 0..peer_count {
            peer_entries.push(PeerEntry::parse(stream)?);
        }

        Ok(PEER_INDEX_TABLE {
            collector_id,
            view_name,
            peer_entries,
        })
    }
}

/// Describes a peer from which BGP messages were received.
#[derive(Debug)]
pub struct PeerEntry {
    /// Special flags in bit 0 and bit 1. Specifying the ASN and IP type.
    pub peer_type: u8,

    /// The BGP identifier of the peer. Often set to its IPv4 address.
    pub peer_bgp_id: u32,

    /// The IP address of the peer.
    pub peer_ip_address: IpAddr,

    /// The ASN of the peer.
    pub peer_as: u32,
}

impl PeerEntry {
    fn parse(stream: &mut Read) -> Result<PeerEntry, Error> {
        let peer_type = stream.read_u8()?;
        let ipv6 = (peer_type & 1) != 0;
        let as_size = (peer_type & 2) != 0;

        let peer_bgp_id = stream.read_u32::<BigEndian>()?;
        let peer_ip_address = if ipv6 {
            IpAddr::V6(Ipv6Addr::from(stream.read_u128::<BigEndian>()?))
        } else {
            IpAddr::V4(Ipv4Addr::from(stream.read_u32::<BigEndian>()?))
        };

        let peer_as = if as_size {
            stream.read_u32::<BigEndian>()?
        } else {
            u32::from(stream.read_u16::<BigEndian>()?)
        };

        Ok(PeerEntry {
            peer_type,
            peer_bgp_id,
            peer_ip_address,
            peer_as,
        })
    }
}

/// RFC4271, https://tools.ietf.org/html/rfc4271#section-5.1
#[derive(Debug, PartialEq)]
#[allow(missing_docs)]
pub enum PathAttribute {
    /// Type Code 1: a well-known mandatory attribute that defines the origin of the path
    /// information
    ORIGIN(Origin),
    ASPATH(AsPath),
    NEXTHOP,
    MULTIEXITDISC,
    LOCALPREF,
    ATOMICAGGREGATE,
    AGGREGATOR,
}

/// ORIGIN (Type Code 1) is a well-known mandatory attribute that defines the origin of the path information.
#[derive(Debug, PartialEq)]
pub enum Origin {
    /// Value: 0 - Network Layer Reachability Information is interior to the originating AS
    IGP,
    /// Value: 1 - Network Layer Reachability Information is learned via the EGP protocol [RFC904]
    EGP,
    /// Value: 2 - Network Layer Reachability Information is learned by some other means
    INCOMPLETE,
}

impl Origin {
    ///  Parse ORIGIN type code values
    pub fn parse(stream: &mut dyn Read) -> Result<Origin, Error> {
        let mut buffer = [0; 1];
        stream.read_exact(&mut buffer)?;

        match buffer[0] {
            0 => return Ok(Origin::IGP),
            1 => return Ok(Origin::EGP),
            2 => return Ok(Origin::INCOMPLETE),
            _ => panic!(
                "Origin type {} dne. TODO: handle error case with invalid origin values",
                buffer[0]
            ),
        }
    }
}

/// AS_PATH (Type Code 2) is a well-known mandatory attribute that is composed of a sequence of AS
/// path path segments. Each AS path segment is represented by a triple <path segment type, path
/// segment length, path segment value>.
#[derive(Debug, PartialEq)]
pub struct AsPath {
    /// Path segment type is a 1-octet length field with the value of AS_SET (1) or AS_SEQUENCE (2)
    segment_type: SegmentType,
    /// Set of ASes a route in the UPDATE message has traversed. Ordering is determined by the
    /// segment_type
    as_path: Vec<u32>,
}

impl AsPath {
    /// Parse AS_PATH type code values
    pub fn parse(stream: &mut dyn Read) -> Result<AsPath, Error> {
        let segment_type = SegmentType::parse(stream)?;

        let mut buffer = [0; 1];
        stream.read_exact(&mut buffer)?;

        let as_path_len = buffer[0];
        let mut as_path: Vec<u32> = Vec::new();

        for _ in 0..as_path_len {
            let mut buffer = [0; 4];
            stream.read_exact(&mut buffer)?;
            let mut asn_bytes = &buffer[..];
            as_path.push(read_be_u32(&mut asn_bytes));
        }

        Ok(AsPath {
            segment_type,
            as_path,
        })
    }
}

/// Path segment type is a 1-octet length field that indicates if the ASes are unordered (AS_SET)
/// or ordered (AS_SEQUENCE).
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
pub enum SegmentType {
    /// Value: 1 - AS_SET: unordered set of ASes a route in the UPDATE message has traversed
    AS_SET,
    /// Value: 2 - AS_SEQUENCE: ordered set of ASes a route in the UPDATE message has traversed
    AS_SEQUENCE,
}

impl SegmentType {
    /// Parse segment type as AS_SET or AS_SEQUENCE
    pub fn parse(stream: &mut dyn Read) -> Result<SegmentType, Error> {
        let mut buffer = [0; 1];
        stream.read_exact(&mut buffer)?;

        match buffer[0] {
            1 => return Ok(SegmentType::AS_SET),
            2 => return Ok(SegmentType::AS_SEQUENCE),
            _ => panic!(
                "Segment type {} dne. TODO: handle error case with invalid segment types",
                buffer[0]
            ),
        }
    }
}

/// From https://tools.ietf.org/html/rfc4271 Section 4.3 UPDATE Message Format
/// Each path attribute is a triple <attribute type, attribute length, attribute value> of
/// variable length.
///
///        0                   1
///        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///        |  Attr. Flags  |Attr. Type Code|
///        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// Attribute Type is a two-octet field that consists of the Attribute Flag octet, followed by
/// the Attribute Type Code octet
impl PathAttribute {
    /// The fourth high-order bit (bit 3) of the Attribute Flags octet is the Extended Length
    /// bit. It defines whether the Attribute Length is one octet (if set to 0) or two octets
    /// (if set to 1).
    ///
    /// The lower-order four bits of the Attribute Flags octet are unused. They MUST be zero
    /// when sent and MUST be ignored when received.
    pub fn parse(
        stream: &mut dyn Read,
        _all_atributes_length: u16,
    ) -> Result<PathAttribute, Error> {
        let mut attribute_buffer: Vec<u8> = vec![0; 2];
        stream.read_exact(&mut attribute_buffer)?;

        let flag = attribute_buffer[0];
        let type_code = attribute_buffer[1];

        // TODO: first, second, and third high-order bit (bits 0, 1, 2)

        // Extended Length bit
        let length_bit = flag & (1 << 4);

        let attribute_length = if length_bit != 0 {
            let mut attribute_buffer: Vec<u8> = vec![0; 2];
            stream.read_exact(&mut attribute_buffer)?;
            let mut attribute_length = &attribute_buffer[..];
            read_be_u32(&mut attribute_length)
        } else {
            let mut attribute_buffer: Vec<u8> = vec![0; 1];
            stream.read_exact(&mut attribute_buffer)?;
            attribute_buffer[0] as u32
        };

        // Lower-order four bits of the Attribute Flags octet
        for i in 1..4 {
            let mask = 1 << i;
            if flag & mask != 0 {
                panic!("handle invalid attribute flag with a lower-order four bit not equal to 0");
            }
        }

        let attribute = match type_code {
            1 => {
                if attribute_length != 1 {
                    panic!("Origin type code must have an attribute length of 1, not {}. TODO: handle error", attribute_length)
                } else {
                    PathAttribute::ORIGIN(Origin::parse(stream)?)
                }
            }
            2 => PathAttribute::ASPATH(AsPath::parse(stream)?),
            3 => PathAttribute::NEXTHOP,
            4 => PathAttribute::MULTIEXITDISC,
            5 => PathAttribute::LOCALPREF,
            6 => PathAttribute::ATOMICAGGREGATE,
            7 => PathAttribute::AGGREGATOR,
            _ => panic!("TODO: Handle all Type Codes"),
        };

        Ok(attribute)
    }
}

/// Represents a route in the Routing Information Base (RIB)
#[derive(Debug)]
pub struct RIBEntry {
    /// The index of the peer inside the PEER_INDEX_TABLE.
    pub peer_index: u16,

    /// The moment that this route was received.
    pub originated_time: u32,

    /// The BGP Path attributes associated with this route.
    pub attributes: Vec<PathAttribute>,
}

impl RIBEntry {
    fn parse(stream: &mut dyn Read) -> Result<RIBEntry, Error> {
        let peer_index = stream.read_u16::<BigEndian>()?;
        let originated_time = stream.read_u32::<BigEndian>()?;
        let attribute_length = stream.read_u16::<BigEndian>()?;

        let mut attribute_bytes: Vec<u8> = vec![0; attribute_length as usize];
        stream.read_exact(&mut attribute_bytes)?;
        PathAttribute::parse(stream, attribute_length)?;

        let origin_attr = PathAttribute::ORIGIN(Origin::IGP);

        let mut attributes: Vec<PathAttribute> = Vec::new();
        attributes.push(origin_attr);

        Ok(RIBEntry {
            peer_index,
            originated_time,
            attributes,
        })
    }
}

/// Represents a collection of routes for a specific IP prefix.
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct RIB_AFI {
    /// A sequence number that identifies the route collection. Wraps back to zero on overflow.
    pub sequence_number: u32,

    /// The prefix length of the prefix.
    pub prefix_length: u8,

    /// The prefix in bytes rounded up to the nearest byte.
    pub prefix: Vec<u8>,

    /// A collection of routes to this prefix.
    pub entries: Vec<RIBEntry>,
}

impl RIB_AFI {
    fn parse(stream: &mut Read) -> Result<RIB_AFI, Error> {
        let sequence_number = stream.read_u32::<BigEndian>()?;

        let prefix_length: u8 = stream.read_u8()?;
        let length: u8 = (prefix_length + 7) / 8;
        let mut prefix: Vec<u8> = vec![0; length as usize];
        stream.read_exact(&mut prefix)?;

        let entry_count = stream.read_u16::<BigEndian>()?;
        let mut entries: Vec<RIBEntry> = Vec::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            entries.push(RIBEntry::parse(stream)?);
        }

        Ok(RIB_AFI {
            sequence_number,
            prefix_length,
            prefix,
            entries,
        })
    }
}

/// Represents a collection of routes for a specific IP prefix.
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct RIB_GENERIC {
    /// A sequence number that identifies the route collection. Wraps back to zero on overflow.
    pub sequence_number: u32,

    /// The Address Family Identifier (AFI) of this RIB entry.
    pub afi: AFI,

    /// The Subsequent Address Family Identifier (SAFI) of this RIB entry.
    pub safi: u8,

    /// The NLRI in bytes.
    pub nlri: Vec<u8>,

    /// A collection of routes to this prefix.
    pub entries: Vec<RIBEntry>,
}

impl RIB_GENERIC {
    fn parse(stream: &mut Read) -> Result<RIB_GENERIC, Error> {
        let sequence_number = stream.read_u32::<BigEndian>()?;
        let afi = AFI::from(stream.read_u16::<BigEndian>()?)?;
        let safi = stream.read_u8()?;

        let length = match afi {
            AFI::IPV4 => {
                match safi {
                    // MPLS-labeled VPN address
                    128 => (stream.read_u8()? + 7) / 8,

                    // Default to 4.
                    _ => 4,
                }
            }
            AFI::IPV6 => 16,
        };

        let mut nlri: Vec<u8> = vec![0; length as usize];
        stream.read_exact(&mut nlri)?;

        let entry_count = stream.read_u16::<BigEndian>()?;
        let mut entries: Vec<RIBEntry> = Vec::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            entries.push(RIBEntry::parse(stream)?);
        }

        Ok(RIB_GENERIC {
            sequence_number,
            afi,
            safi,
            nlri,
            entries,
        })
    }
}

/// Represents a route in the Routing Information Base (RIB) allowing multiple paths.
#[derive(Debug)]
pub struct RIBEntryAddPath {
    /// The index of the peer inside the PEER_INDEX_TABLE.
    pub peer_index: u16,

    /// The moment that this route was received.
    pub originated_time: u32,

    /// Identifies the path together with the address prefix.
    pub path_identifier: u32,

    /// The BGP Path attributes associated with this route.
    pub attributes: Vec<u8>,
}

impl RIBEntryAddPath {
    fn parse(stream: &mut Read) -> Result<RIBEntryAddPath, Error> {
        let peer_index = stream.read_u16::<BigEndian>()?;
        let originated_time = stream.read_u32::<BigEndian>()?;
        let path_identifier = stream.read_u32::<BigEndian>()?;
        let attribute_length = stream.read_u16::<BigEndian>()?;
        let mut attributes: Vec<u8> = vec![0; attribute_length as usize];
        stream.read_exact(&mut attributes)?;

        Ok(RIBEntryAddPath {
            peer_index,
            originated_time,
            path_identifier,
            attributes,
        })
    }
}

/// Represents a collection of routes for a specific IP prefix.
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct RIB_AFI_ADDPATH {
    /// A sequence number that identifies the route collection. Wraps back to zero on overflow.
    pub sequence_number: u32,

    /// The prefix length of the prefix.
    pub prefix_length: u8,

    /// The prefix in bytes rounded up to the nearest byte.
    pub prefix: Vec<u8>,

    /// A collection of routes to this prefix. Might contain multiple paths from a single peer.
    pub entries: Vec<RIBEntryAddPath>,
}

impl RIB_AFI_ADDPATH {
    fn parse(stream: &mut Read) -> Result<RIB_AFI_ADDPATH, Error> {
        let sequence_number = stream.read_u32::<BigEndian>()?;
        let prefix_length: u8 = stream.read_u8()?;
        let length: u8 = (prefix_length + 7) / 8;
        let mut prefix: Vec<u8> = vec![0; length as usize];
        stream.read_exact(&mut prefix)?;

        let entry_count = stream.read_u16::<BigEndian>()?;
        let mut entries: Vec<RIBEntryAddPath> = Vec::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            entries.push(RIBEntryAddPath::parse(stream)?);
        }

        Ok(RIB_AFI_ADDPATH {
            sequence_number,
            prefix_length,
            prefix,
            entries,
        })
    }
}

/// Represents a collection of routes for a specific IP prefix.
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct RIB_GENERIC_ADDPATH {
    /// A sequence number that identifies the route collection. Wraps back to zero on overflow.
    pub sequence_number: u32,

    /// The Address Family Identifier (AFI) of this RIB entry.
    pub afi: AFI,

    /// The Subsequent Address Family Identifier (SAFI) of this RIB entry.
    pub safi: u8,

    /// The NLRI in bytes.
    pub nlri: Vec<u8>,

    /// A collection of routes to this prefix.
    pub entries: Vec<RIBEntryAddPath>,
}

impl RIB_GENERIC_ADDPATH {
    fn parse(stream: &mut Read) -> Result<RIB_GENERIC_ADDPATH, Error> {
        let sequence_number = stream.read_u32::<BigEndian>()?;
        let afi = AFI::from(stream.read_u16::<BigEndian>()?)?;
        let safi = stream.read_u8()?;

        let length = match afi {
            AFI::IPV4 => {
                match safi {
                    // MPLS-labeled VPN address
                    128 => (stream.read_u8()? + 7) / 8,

                    // Default to 4.
                    _ => 4,
                }
            }
            AFI::IPV6 => 16,
        };

        let mut nlri: Vec<u8> = vec![0; length as usize];
        stream.read_exact(&mut nlri)?;

        let entry_count = stream.read_u16::<BigEndian>()?;
        let mut entries: Vec<RIBEntryAddPath> = Vec::with_capacity(entry_count as usize);
        for _ in 0..entry_count {
            entries.push(RIBEntryAddPath::parse(stream)?);
        }

        Ok(RIB_GENERIC_ADDPATH {
            sequence_number,
            afi,
            safi,
            nlri,
            entries,
        })
    }
}

#[allow(non_camel_case_types)]
impl TABLE_DUMP_V2 {
    ///
    /// # Summary
    /// Used to parse TABLE_DUMP_V2 MRT records.
    ///
    /// # Panics
    /// This function does not panic.
    ///
    /// # Errors
    /// Any IO error will be returned while reading from the stream.
    /// If an ill-formatted stream or header is provided behavior will be undefined.
    ///
    /// # Safety
    /// This function does not make use of unsafe code.
    ///
    pub fn parse(header: &Header, stream: &mut Read) -> Result<TABLE_DUMP_V2, Error> {
        match header.sub_type {
            1 => Ok(TABLE_DUMP_V2::PEER_INDEX_TABLE(PEER_INDEX_TABLE::parse(
                stream,
            )?)),
            2 => Ok(TABLE_DUMP_V2::RIB_IPV4_UNICAST(RIB_AFI::parse(stream)?)),
            3 => Ok(TABLE_DUMP_V2::RIB_IPV4_MULTICAST(RIB_AFI::parse(stream)?)),
            4 => Ok(TABLE_DUMP_V2::RIB_IPV6_UNICAST(RIB_AFI::parse(stream)?)),
            5 => Ok(TABLE_DUMP_V2::RIB_IPV6_MULTICAST(RIB_AFI::parse(stream)?)),
            6 => Ok(TABLE_DUMP_V2::RIB_GENERIC(RIB_GENERIC::parse(stream)?)),
            8 => Ok(TABLE_DUMP_V2::RIB_IPV4_UNICAST_ADDPATH(
                RIB_AFI_ADDPATH::parse(stream)?,
            )),
            9 => Ok(TABLE_DUMP_V2::RIB_IPV4_MULTICAST_ADDPATH(
                RIB_AFI_ADDPATH::parse(stream)?,
            )),
            10 => Ok(TABLE_DUMP_V2::RIB_IPV6_UNICAST_ADDPATH(
                RIB_AFI_ADDPATH::parse(stream)?,
            )),
            11 => Ok(TABLE_DUMP_V2::RIB_IPV6_MULTICAST_ADDPATH(
                RIB_AFI_ADDPATH::parse(stream)?,
            )),
            12 => Ok(TABLE_DUMP_V2::RIB_GENERIC_ADDPATH(
                RIB_GENERIC_ADDPATH::parse(stream)?,
            )),
            _ => {
                let msg = format!(
                    "{} is not a valid sub-type of Tabledump v2",
                    header.sub_type
                );
                Err(std::io::Error::new(std::io::ErrorKind::Other, msg))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parse_origin_igp() -> Result<(), Error> {
        let mut rdr = Cursor::new(vec![64, 1, 1, 0]);
        let have = PathAttribute::parse(&mut rdr, 4u16)?;
        let want = PathAttribute::ORIGIN(Origin::IGP);

        assert_eq!(have, want);
        Ok(())
    }

    #[test]
    fn parse_origin_egp() -> Result<(), Error> {
        let mut rdr = Cursor::new(vec![64, 1, 1, 1]);
        let have = PathAttribute::parse(&mut rdr, 4u16)?;
        let want = PathAttribute::ORIGIN(Origin::EGP);

        assert_eq!(have, want);
        Ok(())
    }

    #[test]
    fn parse_origin_incomplete() -> Result<(), Error> {
        let mut rdr = Cursor::new(vec![64, 1, 1, 2]);
        let have = PathAttribute::parse(&mut rdr, 4u16)?;
        let want = PathAttribute::ORIGIN(Origin::INCOMPLETE);

        assert_eq!(have, want);
        Ok(())
    }

    #[test]
    fn parse_aspath_unordered() -> Result<(), Error> {
        let mut rdr = Cursor::new(vec![64, 2, 10, 1, 2, 0, 0, 165, 233, 0, 0, 5, 19]);
        let have = PathAttribute::parse(&mut rdr, 13u16)?;
        let as_path_values = AsPath {
            segment_type: SegmentType::AS_SET,
            as_path: vec![42473, 1299],
        };
        let want = PathAttribute::ASPATH(as_path_values);

        assert_eq!(have, want);
        Ok(())
    }

    #[test]
    fn parse_aspath_ordered() -> Result<(), Error> {
        let mut rdr = Cursor::new(vec![64, 2, 10, 2, 2, 0, 0, 165, 233, 0, 0, 5, 19]);
        let have = PathAttribute::parse(&mut rdr, 13u16)?;
        let as_path_values = AsPath {
            segment_type: SegmentType::AS_SEQUENCE,
            as_path: vec![42473, 1299],
        };
        let want = PathAttribute::ASPATH(as_path_values);

        assert_eq!(have, want);
        Ok(())
    }

    #[test]
    fn parse_segment_type_unordered() -> Result<(), Error> {
        let mut rdr = Cursor::new(vec![1]);
        let have = SegmentType::parse(&mut rdr)?;
        let want = SegmentType::AS_SET;
        assert_eq!(have, want);
        Ok(())
    }

    #[test]
    fn parse_segment_type_ordered() -> Result<(), Error> {
        let mut rdr = Cursor::new(vec![2]);
        let have = SegmentType::parse(&mut rdr)?;
        let want = SegmentType::AS_SEQUENCE;
        assert_eq!(have, want);
        Ok(())
    }
}
