use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Error, ErrorKind, Read};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::MRTHeader;

///
/// 1. Summary
///
#[allow(non_camel_case_types)]
pub enum BGP {
    BGP_NULL,
    BGP_UPDATE(BGP_MESSAGE),
    BGP_PREF_UPDATE,
    BGP_STATE_CHANGE(BGP_STATE_CHANGE),
    BGP_SYNC(BGP_SYNC),
    BGP_OPEN(BGP_MESSAGE),
    BGP_NOTIFY(BGP_MESSAGE),
    BGP_KEEPALIVE(BGP_MESSAGE),
}

/// Used for the deprecated BGP message type.
impl BGP {
    pub fn parse(header: MRTHeader, stream: &mut Read) -> Result<BGP, Error> {
        match header.sub_type {
            0 => Ok(BGP::BGP_NULL),
            1 => Ok(BGP::BGP_UPDATE(BGP_MESSAGE::parse(header, stream)?)),
            2 => Ok(BGP::BGP_PREF_UPDATE),
            3 => Ok(BGP::BGP_STATE_CHANGE(BGP_STATE_CHANGE::parse(stream)?)),
            4 => Ok(BGP::BGP_SYNC(BGP_SYNC::parse(stream)?)),
            5 => Ok(BGP::BGP_OPEN(BGP_MESSAGE::parse(header, stream)?)),
            6 => Ok(BGP::BGP_NOTIFY(BGP_MESSAGE::parse(header, stream)?)),
            7 => Ok(BGP::BGP_KEEPALIVE(BGP_MESSAGE::parse(header, stream)?)),
            _ => Err(Error::new(
                ErrorKind::Other,
                "Unknown MRT record subtype found in MRTHeader",
            )),
        }
    }
}

// Represents the BGP_UPDATE, BGP_OPEN, BGP_NOTIFY and BGP_KEEPALIVE subtypes.
#[allow(non_camel_case_types)]
pub struct BGP_MESSAGE {
    pub peer_as: u16,
    pub peer_ip: Ipv4Addr,
    pub local_as: u16,
    pub local_ip: Ipv4Addr,
    pub message: Vec<u8>,
}

impl BGP_MESSAGE {
    pub fn parse(header: MRTHeader, stream: &mut Read) -> Result<BGP_MESSAGE, Error> {
        let peer_as = stream.read_u16::<BigEndian>()?;
        let peer_ip = Ipv4Addr::from(stream.read_u32::<BigEndian>()?);
        let local_as = stream.read_u16::<BigEndian>()?;
        let local_ip = Ipv4Addr::from(stream.read_u32::<BigEndian>()?);

        let length = header.length - 12;
        let mut message = vec![0; length as usize];
        stream.read_exact(&mut message)?;

        Ok(BGP_MESSAGE {
            peer_as,
            peer_ip,
            local_as,
            local_ip,
            message,
        })
    }
}

#[allow(non_camel_case_types)]
pub struct BGP_STATE_CHANGE {
    pub peer_as: u16,
    pub peer_ip: Ipv4Addr,
    pub old_state: u16,
    pub new_state: u16,
}

impl BGP_STATE_CHANGE {
    pub fn parse(stream: &mut Read) -> Result<BGP_STATE_CHANGE, Error> {
        Ok(BGP_STATE_CHANGE {
            peer_as: stream.read_u16::<BigEndian>()?,
            peer_ip: Ipv4Addr::from(stream.read_u32::<BigEndian>()?),
            old_state: stream.read_u16::<BigEndian>()?,
            new_state: stream.read_u16::<BigEndian>()?,
        })
    }
}

#[allow(non_camel_case_types)]
pub struct BGP_SYNC {
    pub view_number: u16,
    pub filename: Vec<u8>,
}

impl BGP_SYNC {
    pub fn parse(stream: &mut Read) -> Result<BGP_SYNC, Error> {
        let view_number = stream.read_u16::<BigEndian>()?;
        let mut filename = Vec::new();

        let mut buffer = stream.read_u8()?;
        while buffer != b'\0' {
            filename.push(buffer);
            buffer = stream.read_u8()?;
        }

        Ok(BGP_SYNC {
            view_number,
            filename,
        })
    }
}

#[allow(non_camel_case_types)]
pub enum BGP4PLUS {
    BGP4PLUS_NULL,
    BGP4PLUS_UPDATE(BGP4PLUS_MESSAGE),
    BGP4PLUS_PREF_UPDATE,
    BGP4PLUS_STATE_CHANGE(BGP4PLUS_STATE_CHANGE),
    BGP4PLUS_SYNC(BGP4PLUS_SYNC),
    BGP4PLUS_OPEN(BGP4PLUS_MESSAGE),
    BGP4PLUS_NOTIFY(BGP4PLUS_MESSAGE),
    BGP4PLUS_KEEPALIVE(BGP4PLUS_MESSAGE),
}

// ----------------------------------
// BGPPLUS Types

/// Used for the deprecated BGP message type.
impl BGP4PLUS {
    pub fn parse(header: MRTHeader, stream: &mut Read) -> Result<BGP4PLUS, Error> {
        match header.sub_type {
            0 => Ok(BGP4PLUS::BGP4PLUS_NULL),
            1 => Ok(BGP4PLUS::BGP4PLUS_UPDATE(BGP4PLUS_MESSAGE::parse(
                header, stream,
            )?)),
            2 => Ok(BGP4PLUS::BGP4PLUS_PREF_UPDATE),
            3 => Ok(BGP4PLUS::BGP4PLUS_STATE_CHANGE(
                BGP4PLUS_STATE_CHANGE::parse(stream)?,
            )),
            4 => Ok(BGP4PLUS::BGP4PLUS_SYNC(BGP4PLUS_SYNC::parse(stream)?)),
            5 => Ok(BGP4PLUS::BGP4PLUS_OPEN(BGP4PLUS_MESSAGE::parse(
                header, stream,
            )?)),
            6 => Ok(BGP4PLUS::BGP4PLUS_NOTIFY(BGP4PLUS_MESSAGE::parse(
                header, stream,
            )?)),
            7 => Ok(BGP4PLUS::BGP4PLUS_KEEPALIVE(BGP4PLUS_MESSAGE::parse(
                header, stream,
            )?)),
            _ => Err(Error::new(
                ErrorKind::Other,
                "Unknown MRT record subtype found in MRTHeader",
            )),
        }
    }
}

// Represents the BGP_UPDATE, BGP_OPEN, BGP_NOTIFY and BGP_KEEPALIVE subtypes.
#[allow(non_camel_case_types)]
pub struct BGP4PLUS_MESSAGE {
    pub peer_as: u16,
    pub peer_ip: Ipv6Addr,
    pub local_as: u16,
    pub local_ip: Ipv6Addr,
    pub message: Vec<u8>,
}

impl BGP4PLUS_MESSAGE {
    pub fn parse(header: MRTHeader, stream: &mut Read) -> Result<BGP4PLUS_MESSAGE, Error> {
        let peer_as = stream.read_u16::<BigEndian>()?;
        let peer_ip = Ipv6Addr::from(stream.read_u128::<BigEndian>()?);
        let local_as = stream.read_u16::<BigEndian>()?;
        let local_ip = Ipv6Addr::from(stream.read_u128::<BigEndian>()?);

        let length = header.length - 12;
        let mut message = vec![0; length as usize];
        stream.read_exact(&mut message)?;

        Ok(BGP4PLUS_MESSAGE {
            peer_as,
            peer_ip,
            local_as,
            local_ip,
            message,
        })
    }
}

#[allow(non_camel_case_types)]
pub struct BGP4PLUS_STATE_CHANGE {
    pub peer_as: u16,
    pub peer_ip: Ipv6Addr,
    pub old_state: u16,
    pub new_state: u16,
}

impl BGP4PLUS_STATE_CHANGE {
    pub fn parse(stream: &mut Read) -> Result<BGP4PLUS_STATE_CHANGE, Error> {
        Ok(BGP4PLUS_STATE_CHANGE {
            peer_as: stream.read_u16::<BigEndian>()?,
            peer_ip: Ipv6Addr::from(stream.read_u128::<BigEndian>()?),
            old_state: stream.read_u16::<BigEndian>()?,
            new_state: stream.read_u16::<BigEndian>()?,
        })
    }
}

#[allow(non_camel_case_types)]
pub struct BGP4PLUS_SYNC {
    pub view_number: u16,
    pub filename: Vec<u8>,
}

impl BGP4PLUS_SYNC {
    pub fn parse(stream: &mut Read) -> Result<BGP4PLUS_SYNC, Error> {
        let view_number = stream.read_u16::<BigEndian>()?;
        let mut filename = Vec::new();

        let mut buffer = stream.read_u8()?;
        while buffer != b'\0' {
            filename.push(buffer);
            buffer = stream.read_u8()?;
        }

        Ok(BGP4PLUS_SYNC {
            view_number,
            filename,
        })
    }
}
