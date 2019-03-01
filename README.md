# Multi-Threaded Routing Toolkit in Rust (mrt-rs)
[![Build Status](https://travis-ci.com/DevQps/mrt-rs.svg?branch=master)](https://travis-ci.com/DevQps/mrt-rs) [![codecov](https://codecov.io/gh/DevQps/mrt-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/DevQps/mrt-rs)

A library for parsing Multi-Threaded Routing Toolkit (MRT) formatted streams in Rust.

## Examples & Documentation
If not using Rust 2018 edition:
```
extern mrt_rs;
extern libflate;
```

Reading a MRT file containing BPG messages:
```
use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use std::io::BufReader;
use mrt_rs::{Reader, Record};
use mrt_rs::bgp4mp::BGP4MP;
use libflate::gzip::Decoder;

fn main() {
    // Open an MRT-formatted file.
    let file = File::open("res/updates.20190101.0000.gz").unwrap();

    // Decode the GZIP stream using BufReader for better performance.
    let mut decoder = Decoder::new(BufReader::new(file)).unwrap();

    // Create a new Reader with a Cursor such that we can keep track of the position.
    let mut reader = Reader { stream: decoder };

    // Keep reading (Header, Record) tuples till the end of the file has been reached.
    while let Ok(Some((_, record))) = reader.read() {
        match record {
            Record::BGP4MP(x) => match x {
                BGP4MP::MESSAGE(y) => println!("{:?}", y),
                BGP4MP::MESSAGE_AS4(y) => println!("{:?}", y),
                _ => continue,
            },
            _ => continue,
        }
    }
}
```
For full documentation look [here](https://docs.rs/mrt-rs/).
If one seeks to ultimately parse BGP messages [bgp-rs](https://github.com/DevQps/bgp-rs) can be used to do so.
Examples on how [bgp-rs](https://github.com/DevQps/bgp-rs) and [mrt-rs](https://github.com/DevQps/mrt-rs) interact are provided [here](https://docs.rs/bgp-rs).


## Full support
All MRT record types, including deprecated types, that are mentioned in [RFC6396](https://tools.ietf.org/html/rfc6396) and [RFC8050](https://tools.ietf.org/html/rfc8050) are supported.
It should be noted that not all code is tested. This is due to the fact that I do not have MRT-formatted streams for other protocols.

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
- **[Tested]** TABLE_DUMP
- **[Tested]** TABLE_DUMP_V2
  - Including [RFC8050](https://tools.ietf.org/html/rfc8050) sub-types.
- **[Tested]** BGP4MP
  - Including [RFC8050](https://tools.ietf.org/html/rfc8050) sub-types.
- **[Tested]** BGP4MP_ET
  - Including [RFC8050](https://tools.ietf.org/html/rfc8050) sub-types.
- ISIS
- ISIS_ET
- OSPFv3
- OSPFv3_ET

## Help needed!
*Do you have MRT files for MRT types that are currently not tested?* Please let me know so I can add new tests for these types as well.
Any bug reports or requests for additional features are always welcome and can be submitted at the [Issue Tracker](https://github.com/DevQps/mrt-rs).
