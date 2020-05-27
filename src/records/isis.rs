use std::io::{Error, Read};

use crate::Header;

///
/// # Summary
/// Used to parse ISIS MRT records.
///
/// # Panics
/// This function does not panic.
///
/// # Errors
/// Any IO error will be returned while reading from the stream.
/// If an ill-formatted stream or header is provided behavior will be undefined.
///
/// # Safety
/// This function does not make use of unsafe code.
///
pub fn parse(header: &Header, mut stream: impl Read) -> Result<Vec<u8>, Error> {
    // The fixed size of the header consisting of two IPv4 addresses.
    let mut message = vec![0; header.length as usize];
    stream.read_exact(&mut message)?;
    Ok(message)
}
