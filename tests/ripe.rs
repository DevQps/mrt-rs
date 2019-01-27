use libflate::gzip::Decoder;
use mrt_rs::MRTReader;
use mrt_rs::MRTRecord;
use mrt_rs::BGP4MP;
use mrt_rs::TABLE_DUMP_V2;
use std::fs::File;
use std::io::Read;
use std::io::BufReader;

// Tests if it is able to parse a stream of BGP4MP messages.
#[test]
fn parse_updates() {
    // Download an update message.
    let file = File::open("res/updates.20190101.0000.gz").unwrap();

    // Decode the GZIP stream.
    let mut decoder = Decoder::new(BufReader::new(file)).unwrap();

    // Create a new MRTReader with a Cursor such that we can keep track of the position.
    let mut reader = MRTReader {stream: decoder};

    while let Ok(Some(record)) = reader.read() {
        match record {
            _ => continue,
        }
    }
}

// Tests if it is able to parse a stream of TABLE_DUMP_V2 messages.
#[test]
fn parse_rib() {
    // Download an update message.
    let file = File::open("res/bview.20100101.0759.gz").unwrap();

    // Decode the GZIP stream.
    let mut decoder = Decoder::new(BufReader::new(file)).unwrap();

    // Create a new MRTReader
    let mut reader = MRTReader { stream: decoder };

    while let Ok(Some(record)) = reader.read() {
        match record {
            _ => continue,
        }
    }
}
