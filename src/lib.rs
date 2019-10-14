//! This is the documentation for `netflow`
//!
//! # Examples

// https://netflow.caligare.com/netflow_v1.htm
// http://www.ciscopress.com/articles/article.asp?p=2812391&seqNum=3

extern crate byteorder;

type Error = &'static str;

pub const ERROR_NOT_ENOUGH_DATA: Error = "Not enough data";
pub const ERROR_INVALID_VERSION: Error = "Invalid Netflow export format version number";

pub mod v5;
pub mod v9;

pub enum Version {
    V5 = 5,
    V9 = 9,
}

pub fn peek_version<'a>(data: &'a [u8]) -> Result<Version, Error> {
    if data.len() < std::mem::size_of::<u16>() {
        return Err(ERROR_NOT_ENOUGH_DATA);
    }

    let version: u16 = unsafe {
        let mut version: u16 = 0;
        std::ptr::copy_nonoverlapping(
            data.as_ptr(),
            &mut version as *mut u16 as *mut u8,
            std::mem::size_of::<u16>(),
        );
        version
    };

    match version {
        v5::HEADER_VERSION_NETWORK_ORDER => Ok(Version::V5),
        v9::HEADER_VERSION_NETWORK_ORDER => Ok(Version::V9),
        _ => Err(ERROR_INVALID_VERSION),
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

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
