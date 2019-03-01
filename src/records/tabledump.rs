use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Error, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::Header;
use crate::AFI;

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

/// Represents a route in the Routing Information Base (RIB)
#[derive(Debug)]
pub struct RIBEntry {
    /// The index of the peer inside the PEER_INDEX_TABLE.
    pub peer_index: u16,

    /// The moment that this route was received.
    pub originated_time: u32,

    /// The BGP Path attributes associated with this route.
    pub attributes: Vec<u8>,
}

impl RIBEntry {
    fn parse(stream: &mut Read) -> Result<RIBEntry, Error> {
        let peer_index = stream.read_u16::<BigEndian>()?;
        let originated_time = stream.read_u32::<BigEndian>()?;
        let attribute_length = stream.read_u16::<BigEndian>()?;

        let mut attributes: Vec<u8> = vec![0; attribute_length as usize];
        stream.read_exact(&mut attributes)?;

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
            8 => Ok(TABLE_DUMP_V2::RIB_IPV4_UNICAST_ADDPATH (RIB_AFI_ADDPATH::parse(stream)?)),
            9 => Ok(TABLE_DUMP_V2::RIB_IPV4_MULTICAST_ADDPATH (RIB_AFI_ADDPATH::parse(stream)?)),
            10 => Ok(TABLE_DUMP_V2::RIB_IPV6_UNICAST_ADDPATH (RIB_AFI_ADDPATH::parse(stream)?)),
            11 => Ok(TABLE_DUMP_V2::RIB_IPV6_MULTICAST_ADDPATH (RIB_AFI_ADDPATH::parse(stream)?)),
            12 => Ok(TABLE_DUMP_V2::RIB_GENERIC_ADDPATH (RIB_GENERIC_ADDPATH::parse(stream)?)),
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
