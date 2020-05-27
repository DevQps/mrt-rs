#![deny(missing_docs)]

//! The `mrt-rs` crate provides functionality to parse an MRT-formatted streams.
//!
//! # Examples
//!
//! ## Reading a MRT file containing BPG messages
//! ```
//! use std::fs::File;
//! use mrt_rs::Record;
//! use mrt_rs::bgp4mp::BGP4MP;
//!
//! // Open an MRT-formatted file.
//! let mut file = File::open("res/bird-mrtdump_bgp").unwrap();
//!
//! // Keep reading (Header, Record) tuples till the end of the file has been reached.
//! while let Some((header, record)) = mrt_rs::read(&mut file).unwrap() {
//!     match record {
//!         Record::BGP4MP(x) => match x {
//!             BGP4MP::MESSAGE(y) => println!("{:?}", y),
//!             BGP4MP::MESSAGE_AS4(y) => println!("{:?}", y),
//!             _ => continue,
//!         },
//!         _ => continue,
//!     }
//! }
//! ```

use byteorder::{BigEndian, ReadBytesExt};
use std::io::{Error, ErrorKind, Read};

/// Contains the implementation of all MRT record types.
pub mod records {

    /// Contains all BGP subtypes.
    pub mod bgp;

    /// Contains all BGP4PLUS subtypes.
    pub mod bgp4plus;

    /// Contains all BGP4MP subtypes.
    pub mod bgp4mp;

    /// Contains all ISIS subtypes.
    pub mod isis;

    /// Contains all OSPF subtypes such as OSPFv2 and OSPFv3.
    pub mod ospf;

    /// Contains all RIP subtypes.
    pub mod rip;

    /// Contains all TABLE_DUMP subtypes such as TABLE_DUMP and TABLE_DUMP_V2.
    pub mod tabledump;
}

// Re-exports to allow users more convenient access.
pub use records::bgp;
pub use records::bgp4mp;
pub use records::bgp4plus;
pub use records::isis;
pub use records::ospf;
pub use records::rip;
pub use records::tabledump;

/// Represents an Address Family Idenfitier. Currently only IPv4 and IPv6 are supported.
#[derive(Debug)]
#[repr(u16)]
pub enum AFI {
    /// Internet Protocol version 4 (32 bits)
    IPV4 = 1,
    /// Internet Protocol version 6 (128 bits)
    IPV6 = 2,
}

impl AFI {
    fn from(value: u16) -> Result<AFI, Error> {
        match value {
            1 => Ok(AFI::IPV4),
            2 => Ok(AFI::IPV6),
            _ => {
                let msg = format!(
                    "Number {} does not represent a valid address family.",
                    value
                );
                Err(std::io::Error::new(std::io::ErrorKind::Other, msg))
            }
        }
    }

    /// Returns the size in bytes of the an instance of this address family type.
    pub fn size(&self) -> u32 {
        match self {
            AFI::IPV4 => 4,
            AFI::IPV6 => 16,
        }
    }
}

/// Represents the MRT header accompanying every MRT record.
#[derive(Debug)]
pub struct Header {
    /// The time at which this message was generated. Represented in UNIX time.
    pub timestamp: u32,

    /// Microsecond resolution of the time on which this message was generated. Zero if not present.
    pub extended: u32,

    /// The main type of the MRT record.
    pub record_type: u16,

    /// The sub-type of the MRT record.
    pub sub_type: u16,

    /// The length in bytes of the MRT record excluding the MRT header.
    pub length: u32,
}

/// Represents a single MRT record.
#[derive(Debug)]
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
pub enum Record {
    NULL,
    START,
    DIE,
    I_AM_DEAD,
    PEER_DOWN,
    BGP(records::bgp::BGP),
    RIP(records::rip::RIP),
    IDRP,
    RIPNG(records::rip::RIPNG),
    BGP4PLUS(records::bgp4plus::BGP4PLUS),
    BGP4PLUS_01(records::bgp4plus::BGP4PLUS),
    OSPFv2(records::ospf::OSPFv2),
    TABLE_DUMP(records::tabledump::TABLE_DUMP),
    TABLE_DUMP_V2(records::tabledump::TABLE_DUMP_V2),
    BGP4MP(records::bgp4mp::BGP4MP),
    BGP4MP_ET(records::bgp4mp::BGP4MP),
    ISIS(Vec<u8>),
    ISIS_ET(Vec<u8>),
    OSPFv3(records::ospf::OSPFv3),
    OSPFv3_ET(records::ospf::OSPFv3),
}

///
/// Reads the next MRT record in the stream.
///
/// # Panics
/// This function does not panic.
///
/// # Errors
/// Any IO error will be returned while reading from the stream.
/// If an ill-formatted stream provided behavior will be undefined.
///
/// # Safety
/// This function does not make use of unsafe code.
///
pub fn read(mut stream: &mut impl Read) -> Result<Option<(Header, Record)>, Error> {
    let result = stream.read_u32::<BigEndian>();

    // Check if an EOF has occurred at the beginning of the stream and return None
    // if this is the case.
    let timestamp = match result {
        Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
        Ok(x) => x,
    };

    // Parse the MRTHeader
    let mut header = Header {
        timestamp,
        extended: 0,
        record_type: stream.read_u16::<BigEndian>()?,
        sub_type: stream.read_u16::<BigEndian>()?,
        length: stream.read_u32::<BigEndian>()?,
    };

    match header.record_type {
        0 => Ok(Some((header, Record::NULL))),
        1 => Ok(Some((header, Record::START))),
        2 => Ok(Some((header, Record::DIE))),
        3 => Ok(Some((header, Record::I_AM_DEAD))),
        4 => Ok(Some((header, Record::PEER_DOWN))),
        5 => {
            let record = records::bgp::BGP::parse(&header, &mut stream)?;
            Ok(Some((header, Record::BGP(record))))
        }
        6 => {
            let record = records::rip::RIP::parse(&header, &mut stream)?;
            Ok(Some((header, Record::RIP(record))))
        }
        7 => Ok(Some((header, Record::IDRP))),
        8 => {
            let record = records::rip::RIPNG::parse(&header, &mut stream)?;
            Ok(Some((header, Record::RIPNG(record))))
        }
        9 => {
            let record = records::bgp4plus::BGP4PLUS::parse(&header, &mut stream)?;
            Ok(Some((header, Record::BGP4PLUS(record))))
        }
        10 => {
            let record = records::bgp4plus::BGP4PLUS::parse(&header, &mut stream)?;
            Ok(Some((header, Record::BGP4PLUS_01(record))))
        }
        11 => {
            let record = records::ospf::OSPFv2::parse(&header, &mut stream)?;
            Ok(Some((header, Record::OSPFv2(record))))
        }
        12 => {
            let record = records::tabledump::TABLE_DUMP::parse(&header, &mut stream)?;
            Ok(Some((header, Record::TABLE_DUMP(record))))
        }
        13 => {
            let record = records::tabledump::TABLE_DUMP_V2::parse(&header, &mut stream)?;
            Ok(Some((header, Record::TABLE_DUMP_V2(record))))
        }
        16 => {
            let record = records::bgp4mp::BGP4MP::parse(&header, &mut stream)?;
            Ok(Some((header, Record::BGP4MP(record))))
        }
        17 => {
            header.extended = stream.read_u32::<BigEndian>()?;
            let record = records::bgp4mp::BGP4MP::parse(&header, &mut stream)?;
            Ok(Some((header, Record::BGP4MP_ET(record))))
        }
        32 => {
            let record = records::isis::parse(&header, &mut stream)?;
            Ok(Some((header, Record::ISIS(record))))
        }
        33 => {
            header.extended = stream.read_u32::<BigEndian>()?;
            let record = records::isis::parse(&header, &mut stream)?;
            Ok(Some((header, Record::ISIS_ET(record))))
        }
        48 => {
            let record = records::ospf::OSPFv3::parse(&header, &mut stream)?;
            Ok(Some((header, Record::OSPFv3(record))))
        }
        49 => {
            header.extended = stream.read_u32::<BigEndian>()?;
            let record = records::ospf::OSPFv3::parse(&header, &mut stream)?;
            Ok(Some((header, Record::OSPFv3_ET(record))))
        }
        x => Err(Error::new(
            ErrorKind::Other,
            format!("Unknown record type found in MRT header: {}", x),
        )),
    }
}
