use libflate::gzip::Decoder;
use mrt_rs::MRTReader;
use mrt_rs::MRTRecord;
use mrt_rs::BGP4MP;
use std::fs::File;
use std::io::Cursor;
use std::io::Read;

// Tests if it is able to parse a stream of BGP4MP messages.
#[test]
fn parse_updates() {
    // Download an update message
    let file = File::open("res/updates.20190101.0000.gz").unwrap();

    // Decode the GZIP stream
    let mut decoder = Decoder::new(file).unwrap();

    // Parse the contents
    parse(&mut decoder)
}

// Tests if it is able to parse a stream of TABLE_DUMP_V2 messages.
#[test]
fn parse_rib() {
    // Download an update message
    let file = File::open("res/bview.20100101.0759.gz").unwrap();

    // Decode the GZIP stream
    let mut decoder = Decoder::new(file).unwrap();

    // Parse the contents
    parse(&mut decoder)
}

fn parse(readable: &mut Read) {
    // Read the entire contents of the File in a buffer.
    let mut buffer: Vec<u8> = vec![];
    readable.read_to_end(&mut buffer).unwrap();
    let length = buffer.len() as u64;

    // Create a new MRTReader with a Cursor such that we can keep track of the position.
    let mut reader = MRTReader {
        stream: Cursor::new(buffer),
    };

    // Keep reading entries till
    while reader.stream.position() < length {
        let result = reader.read();
        match &result.unwrap() {
            MRTRecord::BGP4MP(x) => match x {
                BGP4MP::MESSAGE(y) => println!("{:?}", y),
                BGP4MP::MESSAGE_AS4(y) => println!("{:?}", y),
                _ => continue,
            },
            _ => continue,
        }
    }
}
