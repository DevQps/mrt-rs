use libflate::gzip::Decoder;
use std::fs::File;
use std::io::BufReader;

// Tests if it is able to parse a stream of BGP4MP messages.
#[test]
fn parse_updates() {
    // Download an update message.
    let file = File::open("res/updates.20190101.0000.gz").unwrap();

    // Decode the GZIP stream.
    let decoder = Decoder::new(BufReader::new(file)).unwrap();

    // Create a new MRTReader with a Cursor such that we can keep track of the position.
    let mut reader = mrt_rs::Reader { stream: decoder };

    // Read a (Header, Record) tuple.
    while let Ok(Some((_, record))) = reader.read() {
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
    let decoder = Decoder::new(BufReader::new(file)).unwrap();

    // Create a new MRTReader.
    let mut reader = mrt_rs::Reader { stream: decoder };

    // Read a (Header, Record) tuple.
    while let Ok(Some((_, record))) = reader.read() {
        match record {
            _ => continue,
        }
    }
}
