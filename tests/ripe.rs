use libflate::gzip::Decoder;
use std::fs;
use std::fs::File;
use std::io::BufReader;

// Tests if it is able to parse a stream of BGP4MP messages.
#[test]
fn test_samples() {
    for entry in fs::read_dir("res/").unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let file = File::open(path.to_str().unwrap()).unwrap();
            println!("Parsing: {:?}", file);

            // Create a new MRTReader with a Cursor such that we can keep track of the position.
            let mut reader = mrt_rs::Reader { stream: file };

            // Read a (Header, Record) tuple.
            while let Some((_, record)) = reader.read().unwrap() {
                println!("{:?}", record);
                match record {
                    _ => continue,
                }
            }
        }
    }
}