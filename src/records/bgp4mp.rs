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
    ENTRY,

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
            2 => unimplemented!("BGP4MP::ENTRY sub-type is not yet implemented."),
            3 => Ok(BGP4MP::SNAPSHOT(SNAPSHOT::parse(stream)?)),
            4 => Ok(BGP4MP::MESSAGE_AS4(MESSAGE_AS4::parse(
                header, stream,
            )?)),
            5 => Ok(BGP4MP::STATE_CHANGE_AS4(STATE_CHANGE_AS4::parse(
                stream,
            )?)),
            6 => Ok(BGP4MP::MESSAGE_LOCAL(MESSAGE::parse(
                header, stream,
            )?)),
            7 => Ok(BGP4MP::MESSAGE_AS4_LOCAL(MESSAGE_AS4::parse(
                header, stream,
            )?)),
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                "Unknown MRT record subtype found in MRTHeader",
            )),
        }
    }
}
