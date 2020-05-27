use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Error, ErrorKind, Read};
use std::net::Ipv6Addr;

use crate::Header;

/// The BGPPLUS enum represents all possible subtypes of the BGPPLUS record type.
#[derive(Debug)]
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
pub enum BGP4PLUS {
    NULL,
    UPDATE(MESSAGE),
    PREF_UPDATE,
    STATE_CHANGE(STATE_CHANGE),
    SYNC(SYNC),
    OPEN(MESSAGE),
    NOTIFY(MESSAGE),
    KEEPALIVE(MESSAGE),
}

/// Used for the deprecated BGP message type.
impl BGP4PLUS {
    pub(crate) fn parse(header: &Header, stream: impl Read) -> Result<BGP4PLUS, Error> {
        match header.sub_type {
            0 => Ok(BGP4PLUS::NULL),
            1 => Ok(BGP4PLUS::UPDATE(MESSAGE::parse(header, stream)?)),
            2 => Ok(BGP4PLUS::PREF_UPDATE),
            3 => Ok(BGP4PLUS::STATE_CHANGE(STATE_CHANGE::parse(stream)?)),
            4 => Ok(BGP4PLUS::SYNC(SYNC::parse(stream)?)),
            5 => Ok(BGP4PLUS::OPEN(MESSAGE::parse(header, stream)?)),
            6 => Ok(BGP4PLUS::NOTIFY(MESSAGE::parse(header, stream)?)),
            7 => Ok(BGP4PLUS::KEEPALIVE(MESSAGE::parse(header, stream)?)),
            _ => Err(Error::new(
                ErrorKind::Other,
                "Unknown MRT record subtype found in MRTHeader",
            )),
        }
    }
}

/// Represents the BGP_UPDATE, BGP_OPEN, BGP_NOTIFY and BGP_KEEPALIVE subtypes of IPv6 peers.
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct MESSAGE {
    /// The peer ASN from which the BGP message has been received.
    pub peer_as: u16,

    /// The peer IPv6 address from which the BGP message has been received.
    pub peer_ip: Ipv6Addr,

    /// The ASN of the AS that received this BGP message.
    pub local_as: u16,

    /// The IPv6 of the AS that received this BGP message.
    pub local_ip: Ipv6Addr,

    /// The message that has been received.
    pub message: Vec<u8>,
}

impl MESSAGE {
    fn parse(header: &Header, mut stream: impl Read) -> Result<MESSAGE, Error> {
        let peer_as = stream.read_u16::<BigEndian>()?;
        let peer_ip = Ipv6Addr::from(stream.read_u128::<BigEndian>()?);
        let local_as = stream.read_u16::<BigEndian>()?;
        let local_ip = Ipv6Addr::from(stream.read_u128::<BigEndian>()?);

        let length = header.length - 12;
        let mut message = vec![0; length as usize];
        stream.read_exact(&mut message)?;

        Ok(MESSAGE {
            peer_as,
            peer_ip,
            local_as,
            local_ip,
            message,
        })
    }
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

    /// The peer IPv6 address from which the BGP message has been received.
    pub peer_ip: Ipv6Addr,

    /// The old state of the BGP collector.
    pub old_state: u16,

    /// The new state of the BGP collector.
    pub new_state: u16,
}

impl STATE_CHANGE {
    fn parse(mut stream: impl Read) -> Result<STATE_CHANGE, Error> {
        Ok(STATE_CHANGE {
            peer_as: stream.read_u16::<BigEndian>()?,
            peer_ip: Ipv6Addr::from(stream.read_u128::<BigEndian>()?),
            old_state: stream.read_u16::<BigEndian>()?,
            new_state: stream.read_u16::<BigEndian>()?,
        })
    }
}

/// Deprecated: Used to record RIB entries in a file.
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct SYNC {
    /// The view number of this Routing Information Base.
    pub view_number: u16,

    /// The filename of the BGP RIB entries. NULL-terminated.
    pub filename: Vec<u8>,
}

impl SYNC {
    fn parse(mut stream: impl Read) -> Result<SYNC, Error> {
        let view_number = stream.read_u16::<BigEndian>()?;
        let mut filename = Vec::new();

        let mut buffer = stream.read_u8()?;
        while buffer != b'\0' {
            filename.push(buffer);
            buffer = stream.read_u8()?;
        }

        Ok(SYNC {
            view_number,
            filename,
        })
    }
}
