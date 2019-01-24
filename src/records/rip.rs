use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Error, Read};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::MRTHeader;
use crate::AFI;

/// The RIP struct represents the data contained in an MRT record type of RIP.
#[derive(Debug)]
pub struct RIP {
    /// The IPv4 address of the router from which this message was received.
    pub remote: Ipv4Addr,

    /// The IPv4 address of the interface at which this message was received.
    pub local: Ipv4Addr,

    /// The message that has been received.
    pub message: Vec<u8>,
}

impl RIP {
    ///
    /// # Summary
    /// Used to parse RIP MRT records.
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
    pub fn parse(header: MRTHeader, stream: &mut Read) -> Result<RIP, Error> {
        // The fixed size of the header consisting of two IPv4 addresses.
        let length = (header.length - 2 * AFI::IPV4.size()) as usize;
        let mut record = RIP {
            remote: Ipv4Addr::from(stream.read_u32::<BigEndian>()?),
            local: Ipv4Addr::from(stream.read_u32::<BigEndian>()?),
            message: vec![0; length as usize],
        };

        // Fill the entire buffer.
        stream.read_exact(&mut record.message)?;
        Ok(record)
    }
}

/// The RIP struct represents the data contained in an MRT record type of RIP.
#[derive(Debug)]
pub struct RIPNG {
    /// The IPv6 address of the router from which this message was received.
    pub remote: Ipv6Addr,

    /// The IPv6 address of the interface at which this message was received.
    pub local: Ipv6Addr,

    /// The message that has been received.
    pub message: Vec<u8>,
}

impl RIPNG {
    ///
    /// # Summary
    /// Used to parse RIPNG MRT records.
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
    pub fn parse(header: MRTHeader, stream: &mut Read) -> Result<RIPNG, Error> {
        // The fixed size of the header consisting of two IPv4 addresses.
        let length = (header.length - 2 * AFI::IPV6.size()) as usize;
        let mut record = RIPNG {
            remote: Ipv6Addr::from(stream.read_u128::<BigEndian>()?),
            local: Ipv6Addr::from(stream.read_u128::<BigEndian>()?),
            message: vec![0; length as usize],
        };

        // Fill the entire buffer.
        stream.read_exact(&mut record.message)?;
        Ok(record)
    }
}
