use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Error, ErrorKind, Read};
use std::net::Ipv4Addr;

use crate::Header;

/// The BGP enum represents all possible subtypes of the BGP record type.
#[derive(Debug)]
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
pub enum BGP {
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
impl BGP {
    pub(crate) fn parse(header: &Header, stream: &mut Read) -> Result<BGP, Error> {
        match header.sub_type {
            0 => Ok(BGP::NULL),
            1 => Ok(BGP::UPDATE(MESSAGE::parse(header, stream)?)),
            2 => Ok(BGP::PREF_UPDATE),
            3 => Ok(BGP::STATE_CHANGE(STATE_CHANGE::parse(stream)?)),
            4 => Ok(BGP::SYNC(SYNC::parse(stream)?)),
            5 => Ok(BGP::OPEN(MESSAGE::parse(header, stream)?)),
            6 => Ok(BGP::NOTIFY(MESSAGE::parse(header, stream)?)),
            7 => Ok(BGP::KEEPALIVE(MESSAGE::parse(header, stream)?)),
            _ => Err(Error::new(
                ErrorKind::Other,
                "Unknown record subtype found in MRT header",
            )),
        }
    }
}

/// Represents the UPDATE, OPEN, NOTIFY and KEEPALIVE messages.
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct MESSAGE {
    /// The peer ASN from which the BGP message has been received.
    pub peer_as: u16,

    /// The peer IPv4 address from which the BGP message has been received.
    pub peer_ip: Ipv4Addr,

    /// The ASN of the AS that received this BGP message.
    pub local_as: u16,

    /// The IPv4 of the AS that received this BGP message.
    pub local_ip: Ipv4Addr,

    /// The message that has been received.
    pub message: Vec<u8>,
}

impl MESSAGE {
    fn parse(header: &Header, stream: &mut Read) -> Result<MESSAGE, Error> {
        let peer_as = stream.read_u16::<BigEndian>()?;
        let peer_ip = Ipv4Addr::from(stream.read_u32::<BigEndian>()?);
        let local_as = stream.read_u16::<BigEndian>()?;
        let local_ip = Ipv4Addr::from(stream.read_u32::<BigEndian>()?);

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

    /// The peer IPv4 address from which the BGP message has been received.
    pub peer_ip: Ipv4Addr,

    /// The old state of the BGP collector.
    pub old_state: u16,

    /// The new state of the BGP collector.
    pub new_state: u16,
}

impl STATE_CHANGE {
    fn parse(stream: &mut Read) -> Result<STATE_CHANGE, Error> {
        Ok(STATE_CHANGE {
            peer_as: stream.read_u16::<BigEndian>()?,
            peer_ip: Ipv4Addr::from(stream.read_u32::<BigEndian>()?),
            old_state: stream.read_u16::<BigEndian>()?,
            new_state: stream.read_u16::<BigEndian>()?,
        })
    }
}

/// Deprecated: Used to record RIB entries in a file.
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct SYNC {
    /// The associated view number.
    pub view_number: u16,

    /// The NULL-terminated filename of the file where RIB entries are recorded.
    pub filename: Vec<u8>,
}

impl SYNC {
    fn parse(stream: &mut Read) -> Result<SYNC, Error> {
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