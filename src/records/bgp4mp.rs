use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Error, ErrorKind, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::Header;
use crate::AFI;

///
/// The BGP4MP enum represents all possible subtypes of the BGP4MP record type.
///
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum BGP4MP {
    /// Represents a state change of the BGP collector using 16 bit ASN.
    STATE_CHANGE(STATE_CHANGE),

    /// Represents UPDATE, OPEN, NOTIFICATION and KEEPALIVE messages supporting 16 bit ASN.
    MESSAGE(MESSAGE),

    /// Used to encode BGP RIB entries in older MRT files but is now superseded by TABLE_DUMP_V2.
    ENTRY(ENTRY),

    /// Represents a state change of the BGP collector using 32 bit ASN.
    SNAPSHOT(SNAPSHOT),

    /// Represents UPDATE, OPEN, NOTIFICATION and KEEPALIVE messages supporting 32 bit ASN.
    MESSAGE_AS4(MESSAGE_AS4),

    /// Represents a state change of the BGP collector using 32 bit ASN.
    STATE_CHANGE_AS4(STATE_CHANGE_AS4),

    /// A locally generated UPDATE, OPEN, NOTIFICATION and KEEPALIVE messages supporting 16 bit ASN.
    MESSAGE_LOCAL(MESSAGE),

    /// A locally generated UPDATE, OPEN, NOTIFICATION and KEEPALIVE messages supporting 32 bit ASN.
    MESSAGE_AS4_LOCAL(MESSAGE_AS4),

    /// Added by (RFC8050)[https://tools.ietf.org/html/rfc8050] to enable advertisement of multiple paths as defined in (RFC7911)[https://tools.ietf.org/html/rfc7911].
    /// This type signifies that 16-bit ASN are used and that the message is not locally generated.
    MESSAGE_ADDPATH(MESSAGE),

    /// Added by (RFC8050)[https://tools.ietf.org/html/rfc8050] to enable advertisement of multiple paths as defined in (RFC7911)[https://tools.ietf.org/html/rfc7911].
    /// This type signifies that 32bit ASN are used and that the message is not locally generated.
    MESSAGE_AS4_ADDPATH(MESSAGE_AS4),

    /// Added by (RFC8050)[https://tools.ietf.org/html/rfc8050] to enable advertisement of multiple paths as defined in (RFC7911)[https://tools.ietf.org/html/rfc7911].
    /// This type signifies that 16-bit ASN are used and that the message is locally generated.
    MESSAGE_LOCAL_ADDPATH(MESSAGE),

    /// Added by (RFC8050)[https://tools.ietf.org/html/rfc8050] to enable advertisement of multiple paths as defined in (RFC7911)[https://tools.ietf.org/html/rfc7911].
    /// This type signifies that 32-bit ASN are used and that the message is locally generated.
    MESSAGE_AS4_LOCAL_ADDPATH(MESSAGE_AS4),
}

///
/// Represents a state change in the BGP Finite State Machine (FSM).
/// More information can found in [RFC4271](https://tools.ietf.org/html/rfc4271#section-8).
///
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct STATE_CHANGE {
    /// The peer ASN from which the BGP message has been received.
    pub peer_as: u16,

    /// The ASN of the AS that received this BGP message.
    pub local_as: u16,

    /// The interface identifier to which this message applies.
    pub interface: u16,

    /// The peer IP address address from which the BGP message has been received.
    pub peer_address: IpAddr,

    /// The IP address of the AS that received this BGP message.
    pub local_address: IpAddr,

    /// The old state of the BGP collector.
    pub old_state: u16,

    /// The new state of the BGP collector.
    pub new_state: u16,
}

impl STATE_CHANGE {
    fn parse(stream: &mut Read) -> Result<STATE_CHANGE, Error> {
        let peer_as = stream.read_u16::<BigEndian>()?;
        let local_as = stream.read_u16::<BigEndian>()?;
        let interface = stream.read_u16::<BigEndian>()?;
        let afi = stream.read_u16::<BigEndian>()?;
        let peer_address = match AFI::from(afi)? {
            AFI::IPV4 => IpAddr::V4(Ipv4Addr::from(stream.read_u32::<BigEndian>()?)),
            AFI::IPV6 => IpAddr::V6(Ipv6Addr::from(stream.read_u128::<BigEndian>()?)),
        };
        let local_address = match AFI::from(afi)? {
            AFI::IPV4 => IpAddr::V4(Ipv4Addr::from(stream.read_u32::<BigEndian>()?)),
            AFI::IPV6 => IpAddr::V6(Ipv6Addr::from(stream.read_u128::<BigEndian>()?)),
        };
        let old_state = stream.read_u16::<BigEndian>()?;
        let new_state = stream.read_u16::<BigEndian>()?;

        Ok(STATE_CHANGE {
            peer_as,
            local_as,
            interface,
            peer_address,
            local_address,
            old_state,
            new_state,
        })
    }
}

/// Represents a BGP message (UPDATE, OPEN, NOTIFICATION and KEEPALIVE) using 16bit ASN.
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct MESSAGE {
    /// The peer ASN from which the BGP message has been received.
    pub peer_as: u16,

    /// The ASN of the AS that received this BGP message.
    pub local_as: u16,

    /// The interface identifier to which this message applies.
    pub interface: u16,

    /// The peer IP address address from which the BGP message has been received.
    pub peer_address: IpAddr,

    /// The IP address of the AS that received this BGP message.
    pub local_address: IpAddr,

    /// The message that has been received.
    pub message: Vec<u8>,
}

impl MESSAGE {
    fn parse(header: &Header, stream: &mut Read) -> Result<MESSAGE, Error> {
        let peer_as = stream.read_u16::<BigEndian>()?;
        let local_as = stream.read_u16::<BigEndian>()?;
        let interface = stream.read_u16::<BigEndian>()?;
        let afi = stream.read_u16::<BigEndian>()?;
        let peer_address = match AFI::from(afi)? {
            AFI::IPV4 => IpAddr::V4(Ipv4Addr::from(stream.read_u32::<BigEndian>()?)),
            AFI::IPV6 => IpAddr::V6(Ipv6Addr::from(stream.read_u128::<BigEndian>()?)),
        };
        let local_address = match AFI::from(afi)? {
            AFI::IPV4 => IpAddr::V4(Ipv4Addr::from(stream.read_u32::<BigEndian>()?)),
            AFI::IPV6 => IpAddr::V6(Ipv6Addr::from(stream.read_u128::<BigEndian>()?)),
        };

        let length = header.length - (8 + 2 * AFI::from(afi)?.size());
        let mut message = vec![0; length as usize];
        stream.read_exact(&mut message)?;

        Ok(MESSAGE {
            peer_as,
            local_as,
            interface,
            peer_address,
            local_address,
            message,
        })
    }
}

/// Represents a BGP message (UPDATE, OPEN, NOTIFICATION and KEEPALIVE) using 32bit ASN.
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct MESSAGE_AS4 {
    /// The peer ASN from which the BGP message has been received.
    pub peer_as: u32,

    /// The ASN of the AS that received this BGP message.
    pub local_as: u32,

    /// The interface identifier to which this message applies.
    pub interface: u16,

    /// The peer IP address address from which the BGP message has been received.
    pub peer_address: IpAddr,

    /// The IP address of the AS that received this BGP message.
    pub local_address: IpAddr,

    /// The message that has been received.
    pub message: Vec<u8>,
}

impl MESSAGE_AS4 {
    fn parse(header: &Header, stream: &mut Read) -> Result<MESSAGE_AS4, Error> {
        let peer_as = stream.read_u32::<BigEndian>()?;
        let local_as = stream.read_u32::<BigEndian>()?;
        let interface = stream.read_u16::<BigEndian>()?;
        let afi = stream.read_u16::<BigEndian>()?;
        let peer_address = match AFI::from(afi)? {
            AFI::IPV4 => IpAddr::V4(Ipv4Addr::from(stream.read_u32::<BigEndian>()?)),
            AFI::IPV6 => IpAddr::V6(Ipv6Addr::from(stream.read_u128::<BigEndian>()?)),
        };
        let local_address = match AFI::from(afi)? {
            AFI::IPV4 => IpAddr::V4(Ipv4Addr::from(stream.read_u32::<BigEndian>()?)),
            AFI::IPV6 => IpAddr::V6(Ipv6Addr::from(stream.read_u128::<BigEndian>()?)),
        };

        let length = header.length - (12 + 2 * AFI::from(afi)?.size());
        let mut message = vec![0; length as usize];
        stream.read_exact(&mut message)?;

        Ok(MESSAGE_AS4 {
            peer_as,
            local_as,
            interface,
            peer_address,
            local_address,
            message,
        })
    }
}

///
/// Represents a state change in the BGP Finite State Machine (FSM).
///
/// 1 Idle
/// 2 Connect
/// 3 Active
/// 4 OpenSent
/// 5 OpenConfirm
/// 6 Established
/// More information can found in [RFC4271](https://tools.ietf.org/html/rfc4271#section-8).
///
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct STATE_CHANGE_AS4 {
    /// The peer ASN from which the BGP message has been received.
    pub peer_as: u32,

    /// The ASN of the AS that received this BGP message.
    pub local_as: u32,

    /// The interface identifier to which this message applies.
    pub interface: u16,

    /// The peer IP address address from which the BGP message has been received.
    pub peer_address: IpAddr,

    /// The IP address of the AS that received this BGP message.
    pub local_address: IpAddr,

    /// The old state of the BGP collector.
    pub old_state: u16,

    /// The new state of the BGP collector.
    pub new_state: u16,
}

impl STATE_CHANGE_AS4 {
    fn parse(stream: &mut Read) -> Result<STATE_CHANGE_AS4, Error> {
        let peer_as = stream.read_u32::<BigEndian>()?;
        let local_as = stream.read_u32::<BigEndian>()?;
        let interface = stream.read_u16::<BigEndian>()?;
        let afi = stream.read_u16::<BigEndian>()?;
        let peer_address = match AFI::from(afi)? {
            AFI::IPV4 => IpAddr::V4(Ipv4Addr::from(stream.read_u32::<BigEndian>()?)),
            AFI::IPV6 => IpAddr::V6(Ipv6Addr::from(stream.read_u128::<BigEndian>()?)),
        };
        let local_address = match AFI::from(afi)? {
            AFI::IPV4 => IpAddr::V4(Ipv4Addr::from(stream.read_u32::<BigEndian>()?)),
            AFI::IPV6 => IpAddr::V6(Ipv6Addr::from(stream.read_u128::<BigEndian>()?)),
        };
        let old_state = stream.read_u16::<BigEndian>()?;
        let new_state = stream.read_u16::<BigEndian>()?;

        Ok(STATE_CHANGE_AS4 {
            peer_as,
            local_as,
            interface,
            peer_address,
            local_address,
            old_state,
            new_state,
        })
    }
}

/// Deprecated: Used to record BGP4MP messages in a file.
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct SNAPSHOT {
    /// The associated view number.
    pub view_number: u16,

    /// The NULL-terminated filename of the file where ENTRY records are recorded.
    pub filename: Vec<u8>,
}

impl SNAPSHOT {
    fn parse(stream: &mut Read) -> Result<SNAPSHOT, Error> {
        let view_number = stream.read_u16::<BigEndian>()?;
        let mut filename = Vec::new();

        let mut buffer = stream.read_u8()?;
        while buffer != b'\0' {
            filename.push(buffer);
            buffer = stream.read_u8()?;
        }

        Ok(SNAPSHOT {
            view_number,
            filename,
        })
    }
}

/// Used to record RIB table entries but has not seen wide support.
/// More information can found in [RFC6396](https://tools.ietf.org/html/rfc6396#appendix-B.2.6).
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct ENTRY {
    /// The peer ASN from which the BGP message has been received.
    pub peer_as: u16,

    /// The ASN of the AS that received this BGP message.
    pub local_as: u16,

    /// The interface identifier to which this message applies.
    pub interface: u16,

    /// The peer IP address address from which the BGP message has been received.
    pub peer_address: IpAddr,

    /// The IP address of the AS that received this BGP message.
    pub local_address: IpAddr,

    /// The associated view number.
    pub view_number: u16,

    /// Status bits.
    pub status: u16,

    /// The last time that this route has been changed.
    pub time_last_change: u32,

    /// Represents the address of the next hop of this route.
    pub next_hop: IpAddr,

    /// The Address Family Identifier (AFI) of the NLRI.
    pub afi: u16,

    /// The Subsequent Address Family Identifier (SAFI) of the NLRI.
    pub safi: u8,

    /// The prefix length of the prefix.
    pub prefix_length: u8,

    /// The prefix in bytes rounded up to the nearest byte.
    pub prefix: Vec<u8>,

    /// The BGP Path attributes associated with this route.
    pub attributes: Vec<u8>,
}

impl ENTRY {
    fn parse(stream: &mut Read) -> Result<ENTRY, Error> {
        let peer_as = stream.read_u16::<BigEndian>()?;
        let local_as = stream.read_u16::<BigEndian>()?;
        let interface = stream.read_u16::<BigEndian>()?;

        let afi = stream.read_u16::<BigEndian>()?;
        let peer_address = match AFI::from(afi)? {
            AFI::IPV4 => IpAddr::V4(Ipv4Addr::from(stream.read_u32::<BigEndian>()?)),
            AFI::IPV6 => IpAddr::V6(Ipv6Addr::from(stream.read_u128::<BigEndian>()?)),
        };
        let local_address = match AFI::from(afi)? {
            AFI::IPV4 => IpAddr::V4(Ipv4Addr::from(stream.read_u32::<BigEndian>()?)),
            AFI::IPV6 => IpAddr::V6(Ipv6Addr::from(stream.read_u128::<BigEndian>()?)),
        };

        let view_number = stream.read_u16::<BigEndian>()?;
        let status = stream.read_u16::<BigEndian>()?;
        let time_last_change = stream.read_u32::<BigEndian>()?;

        // Read the AFI and SAFI belonging to the prefix.
        let afi = stream.read_u16::<BigEndian>()?;
        let safi = stream.read_u8()?;

        // Read the next hop.
        let next_hop_length = stream.read_u8()?;
        let next_hop = match next_hop_length {
            4 => IpAddr::V4(Ipv4Addr::from(stream.read_u32::<BigEndian>()?)),
            16 => IpAddr::V6(Ipv6Addr::from(stream.read_u128::<BigEndian>()?)),
            x => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("Unknown NEXT_HOP length in BGP4MP::ENTRY: {}", x),
                ));
            }
        };

        // Read the prefix.
        let prefix_length: u8 = stream.read_u8()?;
        let length: u8 = (prefix_length + 7) / 8;
        let mut prefix: Vec<u8> = vec![0; prefix_length as usize];
        stream.read_exact(&mut prefix)?;

        // Read the attributes
        let attribute_length = stream.read_u16::<BigEndian>()?;
        let mut attributes = vec![0; attribute_length as usize];
        stream.read_exact(&mut attributes)?;

        Ok(ENTRY {
            peer_as,
            local_as,
            interface,
            peer_address,
            local_address,
            view_number,
            status,
            time_last_change,
            next_hop,
            afi,
            safi,
            prefix_length,
            prefix,
            attributes,
        })
    }
}

impl BGP4MP {
    ///
    /// # Summary
    /// Used to parse sub-types of the BGP4MP MRT record type.
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
    pub(crate) fn parse(header: &Header, stream: &mut Read) -> Result<BGP4MP, Error> {
        debug_assert!(
            header.record_type == 16 || header.record_type == 17,
            "Invalid record type in MRTHeader, expected BGP4MP record type."
        );

        match header.sub_type {
            0 => Ok(BGP4MP::STATE_CHANGE(STATE_CHANGE::parse(stream)?)),
            1 => Ok(BGP4MP::MESSAGE(MESSAGE::parse(header, stream)?)),
            2 => Ok(BGP4MP::ENTRY(ENTRY::parse(stream)?)),
            3 => Ok(BGP4MP::SNAPSHOT(SNAPSHOT::parse(stream)?)),
            4 => Ok(BGP4MP::MESSAGE_AS4(MESSAGE_AS4::parse(header, stream)?)),
            5 => Ok(BGP4MP::STATE_CHANGE_AS4(STATE_CHANGE_AS4::parse(stream)?)),
            6 => Ok(BGP4MP::MESSAGE_LOCAL(MESSAGE::parse(header, stream)?)),
            7 => Ok(BGP4MP::MESSAGE_AS4_LOCAL(MESSAGE_AS4::parse(
                header, stream,
            )?)),
            8 => Ok(BGP4MP::MESSAGE_ADDPATH(MESSAGE::parse(header, stream)?)),
            9 => Ok(BGP4MP::MESSAGE_AS4_ADDPATH(MESSAGE_AS4::parse(
                header, stream,
            )?)),
            10 => Ok(BGP4MP::MESSAGE_LOCAL_ADDPATH(MESSAGE::parse(
                header, stream,
            )?)),
            11 => Ok(BGP4MP::MESSAGE_AS4_LOCAL_ADDPATH(MESSAGE_AS4::parse(
                header, stream,
            )?)),
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                "Unknown MRT record subtype found in MRTHeader",
            )),
        }
    }
}
