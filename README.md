# Multi-Threaded Routing Toolkit in Rust (mrt-rs)
[![Build Status](https://travis-ci.com/DevQps/mrt-rs.svg?branch=master)](https://travis-ci.com/DevQps/mrt-rs) [![codecov](https://codecov.io/gh/DevQps/mrt-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/DevQps/mrt-rs)

A library for parsing Multi-Threaded Routing Toolkit (MRT) formatted streams in Rust.

## Examples & Documentation
For examples and documentation look [here](https://docs.rs/mrt-rs/).
If one seeks to ultimately parse BGP messages, mrt-rs can be used together with [bgp-rs](https://github.com/DevQps/bgp-rs).
Examples on how these two libraries work together are provided there.

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
- **[Tested]** TABLE_DUMP_V2 (including RFC8050 changes)
- **[Tested]** BGP4MP (including RFC8050 changes)
- **[Tested]** BGP4MP_ET         
- ISIS
- ISIS_ET
- OSPFv3
- OSPFv3_ET

## Help needed!
*Do you have MRT files for MRT types that are currently not tested?* Please let me know so I can add new tests for these types as well.
Any bug reports or requests for additional features are always welcome and can be submitted at the [Issue Tracker](https://github.com/DevQps/mrt-rs).
