#![deny(missing_docs)]

//! The `mrt-rs` crate provides functionality to parse an MRT-formatted streams.
//!
//! # Examples
//!
//! ## Reading a MRT file containing BPG messages
//! ```
//! use std::fs::File;
//! use std::io::Cursor;
//! use std::io::Read;
//! use mrt_rs::MRTReader;
//! use mrt_rs::MRTRecord;
//! use mrt_rs::BGP4MP;
//! use libflate::gzip::Decoder;
//!
//! fn main() {
//!     // Open an MRT-formatted file.
//!     let file = File::open("res/updates.20190101.0000.gz").unwrap();
//!
//!     // Decode the GZIP stream
//!     let mut decoder = Decoder::new(file).unwrap();
//!
//!     // Read the entire contents of the File in a buffer.
//!     let mut buffer: Vec<u8> = vec![];
//!     decoder.read_to_end(&mut buffer).unwrap();
//!     let length = buffer.len() as u64;
//!
//!     // Create a new MRTReader with a Cursor such that we can keep track of the position.
//!     let mut reader = MRTReader {
//!         stream: Cursor::new(buffer),
//!     };
//!
//!     // Keep reading entries till the end of the file has been reached.
//!     while reader.stream.position() < length {
//!         let result = reader.read();
//!         match &result.unwrap() {
//!             MRTRecord::BGP4MP(x) => match x {
//!                 BGP4MP::MESSAGE(y) => println!("{:?}", y),
//!                 BGP4MP::MESSAGE_AS4(y) => println!("{:?}", y),
//!                 _ => continue,
//!             },
//!             _ => continue,
//!         }
//!     }
//! }
//! ```

use byteorder::{BigEndian, ReadBytesExt};
use std::fmt;
use std::io::{Error, ErrorKind, Read};

// Structure the internal module hierarchy
mod records {
    pub mod bgp;
    pub mod bgp4mp;
    pub mod isis;
    pub mod ospf;
    pub mod rip;
    pub mod tabledump;
}

// Re-export symbols such that they are easily accessible.
pub use records::bgp::{
    BGP, BGP4PLUS, BGP4PLUS_MESSAGE, BGP4PLUS_STATE_CHANGE, BGP4PLUS_SYNC, BGP_MESSAGE,
    BGP_STATE_CHANGE, BGP_SYNC,
};
pub use records::bgp4mp::{
    BGP4MP, BGP4MP_MESSAGE, BGP4MP_MESSAGE_AS4, BGP4MP_SNAPSHOT, BGP4MP_STATE_CHANGE,
    BGP4MP_STATE_CHANGE_AS4,
};
pub use records::ospf::{OSPFv2, OSPFv3};
pub use records::rip::{RIP, RIPNG};
pub use records::tabledump::{
    PeerEntry, RIBEntry, PEER_INDEX_TABLE, RIB_AFI, TABLE_DUMP, TABLE_DUMP_V2,
};

/// Represents an Address Family Idenfitier. Currently only IPv4 and IPv6 are supported.
#[derive(Debug)]
#[repr(u16)]
enum AFI {
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

    pub fn size(&self) -> u32 {
        match self {
            AFI::IPV4 => 4,
            AFI::IPV6 => 16,
        }
    }
}

/// The MRTReader can read MRT records from an MRT-formatted stream.
pub struct MRTReader<T>
where
    T: Read,
{
    /// The stream from which MRT records will be read.
    pub stream: T,
}

/// Represents the MRT header accompanying every MRT record.
#[derive(Debug)]
pub struct MRTHeader {
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

impl fmt::Display for MRTHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "(Timestamp: {}, Type: {}, Subtype: {}, Length: {})",
            self.timestamp, self.record_type, self.sub_type, self.length
        )
    }
}

/// Represents a single MRT record.
#[derive(Debug)]
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
pub enum MRTRecord {
    NULL,
    START,
    DIE,
    I_AM_DEAD,
    PEER_DOWN,
    BGP(records::bgp::BGP),
    RIP(records::rip::RIP),
    IDRP,
    RIPNG(records::rip::RIPNG),
    BGP4PLUS(records::bgp::BGP4PLUS),
    BGP4PLUS_01(records::bgp::BGP4PLUS),
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

impl<T> MRTReader<T>
where
    T: Read,
{
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
    pub fn read(&mut self) -> Result<MRTRecord, Error> {
        // Parse the MRTHeader
        let mut header = MRTHeader {
            timestamp: self.stream.read_u32::<BigEndian>()?,
            extended: 0,
            record_type: self.stream.read_u16::<BigEndian>()?,
            sub_type: self.stream.read_u16::<BigEndian>()?,
            length: self.stream.read_u32::<BigEndian>()?,
        };

        match header.record_type {
            0 => Ok(MRTRecord::NULL),
            1 => Ok(MRTRecord::START),
            2 => Ok(MRTRecord::DIE),
            3 => Ok(MRTRecord::I_AM_DEAD),
            4 => Ok(MRTRecord::PEER_DOWN),
            5 => Ok(MRTRecord::BGP(records::bgp::BGP::parse(
                header,
                &mut self.stream,
            )?)),
            6 => Ok(MRTRecord::RIP(records::rip::RIP::parse(
                header,
                &mut self.stream,
            )?)),
            7 => Ok(MRTRecord::IDRP),
            8 => Ok(MRTRecord::RIPNG(records::rip::RIPNG::parse(
                header,
                &mut self.stream,
            )?)),
            9 => Ok(MRTRecord::BGP4PLUS(records::bgp::BGP4PLUS::parse(
                header,
                &mut self.stream,
            )?)),
            10 => Ok(MRTRecord::BGP4PLUS_01(records::bgp::BGP4PLUS::parse(
                header,
                &mut self.stream,
            )?)),
            11 => Ok(MRTRecord::OSPFv2(records::ospf::OSPFv2::parse(
                header,
                &mut self.stream,
            )?)),
            12 => Ok(MRTRecord::TABLE_DUMP(
                records::tabledump::TABLE_DUMP::parse(header, &mut self.stream)?,
            )),
            13 => Ok(MRTRecord::TABLE_DUMP_V2(
                records::tabledump::TABLE_DUMP_V2::parse(header, &mut self.stream)?,
            )),
            16 => Ok(MRTRecord::BGP4MP(records::bgp4mp::BGP4MP::parse(
                header,
                &mut self.stream,
            )?)),
            17 => {
                header.extended = self.stream.read_u32::<BigEndian>()?;
                Ok(MRTRecord::BGP4MP_ET(records::bgp4mp::BGP4MP::parse(
                    header,
                    &mut self.stream,
                )?))
            }
            32 => Ok(MRTRecord::ISIS(records::isis::parse(
                header,
                &mut self.stream,
            )?)),
            33 => {
                header.extended = self.stream.read_u32::<BigEndian>()?;
                Ok(MRTRecord::ISIS_ET(records::isis::parse(
                    header,
                    &mut self.stream,
                )?))
            }
            48 => Ok(MRTRecord::OSPFv3(records::ospf::OSPFv3::parse(
                header,
                &mut self.stream,
            )?)),
            49 => {
                header.extended = self.stream.read_u32::<BigEndian>()?;
                Ok(MRTRecord::OSPFv3_ET(records::ospf::OSPFv3::parse(
                    header,
                    &mut self.stream,
                )?))
            }
            _ => Err(Error::new(
                ErrorKind::Other,
                "Unknown MRT record type found in MRTHeader",
            )),
        }
    }
}
