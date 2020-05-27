use std::fs;
use std::fs::File;

// Tests if it is able to parse a stream of BGP4MP messages.
#[test]
fn test_samples() {
    for entry in fs::read_dir("res/").unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let mut file = File::open(path.to_str().unwrap()).unwrap();
            println!("\nParsing: {:?}", file);

            // Read a (Header, Record) tuple.
            while let Some((_, record)) = mrt_rs::read(&mut file).unwrap() {
                println!("{:?}", record);
            }
        }
    }
}
