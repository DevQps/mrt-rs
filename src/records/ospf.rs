use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Error, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::Header;
use crate::AFI;

/// The OSPFv2 struct represents the data contained in an MRT record type of OSPFv2.
#[derive(Debug)]
pub struct OSPFv2 {
    /// The IPv4 address from which this message was received.
    pub remote: Ipv4Addr,

    /// The IPv4 address of the interface on which this message was received.
    pub local: Ipv4Addr,

    /// The binary OSPFv2 message.
    pub message: Vec<u8>,
}

impl OSPFv2 {
    ///
    /// # Summary
    /// Used to parse OSPFv2 MRT records.
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
    pub fn parse(header: &Header, stream: &mut Read) -> Result<OSPFv2, Error> {
        // The fixed size of the header consisting of two IPv4 addresses.
        let length = (header.length - 2 * AFI::IPV4.size()) as usize;
        let mut record = OSPFv2 {
            remote: Ipv4Addr::from(stream.read_u32::<BigEndian>()?),
            local: Ipv4Addr::from(stream.read_u32::<BigEndian>()?),
            message: vec![0; length as usize],
        };

        // Fill the entire buffer.
        stream.read_exact(&mut record.message)?;
        Ok(record)
    }
}

/// The OSPFv3 struct represents the data contained in an MRT record type of OSPFv3 and OSPFv3_ET.
#[derive(Debug)]
pub struct OSPFv3 {
    /// The IP address of the router from which this message was received.
    pub remote: IpAddr,

    /// The IP address of the interface at which this message was received.
    pub local: IpAddr,

    /// The message that has been received.
    pub message: Vec<u8>,
}

impl OSPFv3 {
    ///
    /// # Summary
    /// Used to parse OSPFv3 MRT records.
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
    pub fn parse(header: &Header, stream: &mut Read) -> Result<OSPFv3, Error> {
        let mut record = match AFI::from(stream.read_u16::<BigEndian>()?)? {
            AFI::IPV4 => {
                let length = (header.length - 2 * AFI::IPV4.size()) as usize;
                OSPFv3 {
                    remote: IpAddr::V4(Ipv4Addr::from(stream.read_u32::<BigEndian>()?)),
                    local: IpAddr::V4(Ipv4Addr::from(stream.read_u32::<BigEndian>()?)),
                    message: vec![0; length as usize],
                }
            }
            AFI::IPV6 => {
                let length: usize = (header.length - 2 * AFI::IPV6.size()) as usize;
                OSPFv3 {
                    remote: IpAddr::V6(Ipv6Addr::from(stream.read_u128::<BigEndian>()?)),
                    local: IpAddr::V6(Ipv6Addr::from(stream.read_u128::<BigEndian>()?)),
                    message: vec![0; length as usize],
                }
            }
        };

        // Fill the entire buffer.
        stream.read_exact(&mut record.message)?;
        Ok(record)
    }
}
