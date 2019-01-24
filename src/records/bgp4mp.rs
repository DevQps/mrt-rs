use byteorder::{BigEndian, ReadBytesExt};
use std::fmt;
use std::io::{Error, ErrorKind, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::MRTHeader;
use crate::AFI;

///
/// The BGP4MP enum represents all possible subtypes of the BGP4MP record type.
///
#[allow(non_camel_case_types)]
pub enum BGP4MP {

    /// Represents a state change of the BGP collector using 16 bit ASN.
    STATE_CHANGE(BGP4MP_STATE_CHANGE),

    /// Represents UPDATE, OPEN, NOTIFICATION and KEEPALIVE messages supporting 16 bit ASN.
    MESSAGE(BGP4MP_MESSAGE),

    /// Used to encode BGP RIB entries in older MRT files but is now superseded by TABLE_DUMP_V2.
    ENTRY,

    /// Represents a state change of the BGP collector using 32 bit ASN.
    SNAPSHOT(BGP4MP_SNAPSHOT),

    /// Represents UPDATE, OPEN, NOTIFICATION and KEEPALIVE messages supporting 32 bit ASN.
    MESSAGE_AS4(BGP4MP_MESSAGE_AS4),

    /// Represents a state change of the BGP collector using 32 bit ASN.
    STATE_CHANGE_AS4(BGP4MP_STATE_CHANGE_AS4),

    /// A locally generated UPDATE, OPEN, NOTIFICATION and KEEPALIVE messages supporting 16 bit ASN.
    MESSAGE_LOCAL(BGP4MP_MESSAGE),

    /// A locally generated UPDATE, OPEN, NOTIFICATION and KEEPALIVE messages supporting 32 bit ASN.
    MESSAGE_AS4_LOCAL(BGP4MP_MESSAGE_AS4),
}

///
/// # Summary
/// BGP4MP Message which is received when the BGP collector changes states.
///
/// 1 Idle
/// 2 Connect
/// 3 Active
/// 4 OpenSent
/// 5 OpenConfirm
/// 6 Established
///
#[allow(non_camel_case_types)]
pub struct BGP4MP_STATE_CHANGE {
    pub peer_as: u16,
    pub local_as: u16,
    pub interface: u16,
    pub peer_address: IpAddr,
    pub local_address: IpAddr,
    pub old_state: u16,
    pub new_state: u16,
}

impl BGP4MP_STATE_CHANGE {

    fn parse(stream: &mut Read) -> Result<BGP4MP_STATE_CHANGE, Error> {
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

        Ok(BGP4MP_STATE_CHANGE {
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

#[allow(non_camel_case_types)]
pub struct BGP4MP_MESSAGE {
    pub peer_as: u16,
    pub local_as: u16,
    pub interface: u16,
    pub peer_address: IpAddr,
    pub local_address: IpAddr,
    pub message: Vec<u8>,
}

impl BGP4MP_MESSAGE {
    pub fn parse(header: MRTHeader, stream: &mut Read) -> Result<BGP4MP_MESSAGE, Error> {
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

        Ok(BGP4MP_MESSAGE {
            peer_as,
            local_as,
            interface,
            peer_address,
            local_address,
            message,
        })
    }
}

impl fmt::Display for BGP4MP_MESSAGE {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "(Peer AS: {}, Local AS: {}, Interface: {}, Peer IP Address: {}, Local IP Address: {}, Size: {})",
               self.peer_as,
               self.local_as,
               self.interface,
               self.peer_address,
               self.local_address,
               self.message.len())
    }
}

#[allow(non_camel_case_types)]
pub struct BGP4MP_MESSAGE_AS4 {
    pub peer_as: u32,
    pub local_as: u32,
    pub interface: u16,
    pub peer_address: IpAddr,
    pub local_address: IpAddr,
    pub message: Vec<u8>,
}

impl fmt::Display for BGP4MP_MESSAGE_AS4 {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "(Peer AS: {}, Local AS: {}, Interface: {}, Peer IP Address: {}, Local IP Address: {}, Size: {})",
               self.peer_as,
               self.local_as,
               self.interface,
               self.peer_address,
               self.local_address,
               self.message.len())
    }
}

impl BGP4MP_MESSAGE_AS4 {
    pub fn parse(header: MRTHeader, stream: &mut Read) -> Result<BGP4MP_MESSAGE_AS4, Error> {
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

        Ok(BGP4MP_MESSAGE_AS4 {
            peer_as,
            local_as,
            interface,
            peer_address,
            local_address,
            message,
        })
    }
}

#[allow(non_camel_case_types)]
pub struct BGP4MP_STATE_CHANGE_AS4 {
    pub peer_as: u32,
    pub local_as: u32,
    pub interface: u16,
    pub peer_address: IpAddr,
    pub local_address: IpAddr,
    pub old_state: u16,
    pub new_state: u16,
}

impl BGP4MP_STATE_CHANGE_AS4 {
    pub fn parse(stream: &mut Read) -> Result<BGP4MP_STATE_CHANGE_AS4, Error> {
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

        Ok(BGP4MP_STATE_CHANGE_AS4 {
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

#[allow(non_camel_case_types)]
pub struct BGP4MP_SNAPSHOT {
    pub view_number: u16,
    pub filename: Vec<u8>,
}

impl BGP4MP_SNAPSHOT {
    pub fn parse(stream: &mut Read) -> Result<BGP4MP_SNAPSHOT, Error> {
        let view_number = stream.read_u16::<BigEndian>()?;
        let mut filename = Vec::new();

        let mut buffer = stream.read_u8()?;
        while buffer != b'\0' {
            filename.push(buffer);
            buffer = stream.read_u8()?;
        }

        Ok(BGP4MP_SNAPSHOT {
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
    pub fn parse(header: MRTHeader, stream: &mut Read) -> Result<BGP4MP, Error> {

        debug_assert!(header.record_type == 16 || header.record_type == 17,
                      "Invalid record type in MRTHeader, expected BGP4MP record type.");

        match header.sub_type {
            0 => Ok(BGP4MP::STATE_CHANGE(BGP4MP_STATE_CHANGE::parse(stream)?)),
            1 => Ok(BGP4MP::MESSAGE(BGP4MP_MESSAGE::parse(header, stream)?)),
            2 => unimplemented!("BGP4MP::BGP4MP_ENTRY sub-type is not yet implemented."),
            3 => Ok(BGP4MP::SNAPSHOT(BGP4MP_SNAPSHOT::parse(stream)?)),
            4 => Ok(BGP4MP::MESSAGE_AS4(BGP4MP_MESSAGE_AS4::parse(
                header, stream,
            )?)),
            5 => Ok(BGP4MP::STATE_CHANGE_AS4(BGP4MP_STATE_CHANGE_AS4::parse(
                stream,
            )?)),
            6 => Ok(BGP4MP::MESSAGE_LOCAL(BGP4MP_MESSAGE::parse(
                header, stream,
            )?)),
            7 => Ok(BGP4MP::MESSAGE_AS4_LOCAL(BGP4MP_MESSAGE_AS4::parse(
                header, stream,
            )?)),
            _ => Err(Error::new(
                ErrorKind::InvalidData,
                "Unknown MRT record subtype found in MRTHeader",
            )),
        }
    }
}