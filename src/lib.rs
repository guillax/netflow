//! This is the documentation for `netflow`
//!
//! # Examples

// https://netflow.caligare.com/netflow_v1.htm
// http://www.ciscopress.com/articles/article.asp?p=2812391&seqNum=3

#[derive(Debug, PartialEq)]
pub enum Error {
    NotEnoughData { expected: usize, actual: usize },
    InvalidVersion { expected: Vec<u16>, actual: u16 },
}

mod endianness;
mod utils;
pub mod v5;
// pub mod v9;

#[derive(PartialEq)]
pub enum Version {
    V5 = 5,
    V9 = 9,
}

use crate::endianness::Endianness;

pub fn peek_version<'a>(data: &'a [u8]) -> Result<Version, Error> {
    if data.len() < std::mem::size_of::<u16>() {
        return Err(Error::NotEnoughData {
            expected: std::mem::size_of::<u16>(),
            actual: data.len(),
        });
    }

    let version: u16 = utils::read_unaligned_unchecked(data);

    match version {
        v5::Header::VERSION_NETWORK_ORDER => Ok(Version::V5),
        // v9::HEADER_VERSION_NETWORK_ORDER => Ok(Version::V9),
        _ => Err(Error::InvalidVersion {
            expected: vec![v5::Header::VERSION],
            actual: convert!(version),
        }),
    }
}

/// Say hello from netflow crate
///
/// # Arguments
///
/// * `identifier` - A 6 byte vec that provides some arbitrary identification.
///
/// # Remarks
///
/// This is a convenience function that converts the `identifier` `vec` into
/// a 6 byte array. Where possible, prefer the array and use `new`.
///
/// # Examples
///
/// None yet
///
/// # Panics
///
/// Never
///
/// # Errors
///
/// None
///
/// # Safety
///
/// Don't even care
///
/// # Garbage
///
/// Done
///
/// *Note*: This also assumes the `flaker` is being created on a little endian
/// CPU.
pub fn greetings() -> String {
    String::from("Hello from netflow-0.1.0")
}
