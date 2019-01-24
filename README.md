# Multi-Threaded Routing Toolkit in Rust (mrt-rs)
[![Build Status](https://travis-ci.com/DevQps/mrt-rs.svg?branch=master)](https://travis-ci.com/DevQps/mrt-rs) [![codecov](https://codecov.io/gh/DevQps/mrt-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/DevQps/mrt-rs)

A library for parsing Multi-Threaded Routing Toolkit (MRT) formatted streams in Rust.

## Example
In this example we read an gzip MRT archive from a file and parse it. Note that the MRTReader works with any object that implements the [Read](https://doc.rust-lang.org/std/io/trait.Read.html) trait.
```
use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use mrt_rs::MRTReader;
use mrt_rs::MRTRecord;
use libflate::gzip::Decoder;

fn main() {
     // Open an gzip archive that contains a MRT-formatted file.
     let file = File::open("res/updates.20190101.0000.gz").unwrap();

     // Decode the GZIP stream
     let mut decoder = Decoder::new(file).unwrap();

     // Read the entire contents of the File in a buffer.
     let mut buffer: Vec<u8> = vec![];
     decoder.read_to_end(&mut buffer).unwrap();
     let length = buffer.len() as u64;

     // Create a new MRTReader with a Cursor such that we can keep track of the position.
     let mut reader = MRTReader {
         stream: Cursor::new(buffer),
     };

    // Keep reading entries till the end of the file has been reached.
     // _ can be replaced with the MRT type contained in your MRT file.
     while reader.stream.position() < length {
        let result = reader.read();
       match &result.unwrap() {
            MRTRecord::BGP4MP(_x) => continue,
        }
    }
}
```

## Supported types
All MRT record types (including deprecated ones) that are mentioned in [RFC6396](https://tools.ietf.org/html/rfc6396) are supported except for RIB_GENERIC (sub-type of TABLE_DUMP_V2) and the BGP4MP_ENTRY (sub-type of BGP4MP). It should be noted however that only BGP4MP and TABLE_DUMP_V2 messages currently contain tests. This is due to the fact that I do not have MRT-formatted streams for other protocols.

**Supported MRT types:**
- NULL
- START,
- DIE,
- I_AM_DEAD,
- PEER_DOWN,
- BGP
- RIP
- IDRP,
- RIPNG
- BGP4PLUS
- BGP4PLUS_01
- OSPFv2
- TABLE_DUMP
- **[Tested]** TABLE_DUMP_V2     
- **[Tested]** BGP4MP            
- **[Tested]** BGP4MP_ET         
- ISIS
- ISIS_ET
- OSPFv3
- OSPFv3_ET

## Help required
Do you have MRT files for MRT types that are currently not tested? Please let me know so I can add new tests for these types as well.
Any bug reports or requests for additional features are always welcome and can be submitted at the [Issue Tracker](https://github.com/DevQps/mrt-rs).