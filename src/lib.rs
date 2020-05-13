/// This is the documentation for `netflow`
// http://www.ciscopress.com/articles/article.asp?p=2812391&seqNum=3
mod endianness;
mod utils;

#[cfg(feature = "ipfix")]
pub mod ipfix;
#[cfg(feature = "netflow-v5")]
pub mod v5;
#[cfg(feature = "netflow-v7")]
pub mod v7;
#[cfg(feature = "netflow-v9")]
pub mod v9;

#[derive(Debug, PartialEq)]
pub enum Error {
    NotEnoughData { expected: usize, actual: usize },
    InvalidVersion { expected: Vec<u16>, actual: u16 },
}

#[derive(PartialEq)]
pub enum Version {
    V5 = 5,
    V7 = 7,
    V9 = 9,
    Ipfix = 10,
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
        #[cfg(feature = "netflow-v5")]
        v5::Header::VERSION_NETWORK_ORDER => Ok(Version::V5),
        #[cfg(feature = "netflow-v7")]
        v7::Header::VERSION_NETWORK_ORDER => Ok(Version::V7),
        #[cfg(feature = "netflow-v9")]
        v9::HEADER_VERSION_NETWORK_ORDER => Ok(Version::V9),
        #[cfg(feature = "ipfix")]
        ipfix::Header::VERSION_NETWORK_ORDER => Ok(Version::Ipfix),
        _ => Err(Error::InvalidVersion {
            expected: vec![
                #[cfg(feature = "netflow-v5")]
                v5::Header::VERSION,
                #[cfg(feature = "netflow-v7")]
                v7::Header::VERSION,
                #[cfg(feature = "netflow-v9")]
                v9::Header::VERSION,
                #[cfg(feature = "ipfix")]
                ipfix::Header::VERSION,
            ],
            actual: convert!(version),
        }),
    }
}
