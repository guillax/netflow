//! This is the documentation for `netflow`
//!
//! # Examples

extern crate byteorder;

pub mod v5;

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
