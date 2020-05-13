use std::fmt;

use crate::convert;
use crate::endianness::Endianness;
use crate::utils::read_unaligned_unchecked;
use crate::Error;

/// Netflow v7 header struct
#[derive(Copy, Clone, PartialEq)]
#[repr(C)]
pub struct Header {
    /// NetFlow export format version number
    pub version: u16,
    /// Number of flows that are exported in this packet (1-30)
    pub count: u16,
    /// Current time in milliseconds since the export device started
    pub sys_uptime_msecs: u32,
    /// Current time in seconds since 0000 Coordinated Universal Time 1970
    pub unix_secs: u32,
    /// Residual nanoseconds since 0000 Coordinated Universal Time 1970
    pub unix_nsecs: u32,
    /// Sequence counter of total flows seen
    pub sequence_number: u32,
    reserved: u32,
}

impl Header {
    pub const LEN: usize = std::mem::size_of::<Self>();
    pub const VERSION: u16 = 7;
    pub const VERSION_NETWORK_ORDER: u16 = Self::VERSION.to_be();

    /// Parse a netflow v7 packet header
    pub fn from_bytes<'a>(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::LEN {
            return Err(Error::NotEnoughData {
                expected: Self::LEN,
                actual: data.len(),
            });
        }

        let version_be = read_unaligned_unchecked::<u16>(data);
        if version_be != Self::VERSION_NETWORK_ORDER {
            return Err(Error::InvalidVersion {
                expected: vec![Self::VERSION],
                actual: convert!(version_be),
            });
        }

        Ok(Self {
            version: Self::VERSION,
            count: convert!(read_unaligned_unchecked::<u16>(&data[2..4])),
            sys_uptime_msecs: convert!(read_unaligned_unchecked::<u32>(&data[4..8])),
            unix_secs: convert!(read_unaligned_unchecked::<u32>(&data[8..12])),
            unix_nsecs: convert!(read_unaligned_unchecked::<u32>(&data[12..16])),
            sequence_number: convert!(read_unaligned_unchecked::<u32>(&data[16..20])),
            reserved: 0, // read_unaligned_unchecked::<u32>(&data[20..23])
        })
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field("version", &self.version)
            .field("count", &self.count)
            .field("sys_uptime_msecs", &self.sys_uptime_msecs)
            .field("unix_secs", &self.unix_secs)
            .field("unix_nsecs", &self.unix_nsecs)
            .field("sequence_number", &self.sequence_number)
            .finish()
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_data::get_flow_packet_header;
    use super::Header;
    use crate::Error;

    #[test]
    fn header_parse_should_succeed_with_valid_data() {
        assert!(Header::from_bytes(get_flow_packet_header()).is_ok());
    }

    #[test]
    fn header_parse_should_fail_with_not_enough_data() {
        assert_eq!(
            Header::from_bytes(&get_flow_packet_header()[..Header::LEN - 1]),
            Err(Error::NotEnoughData {
                expected: Header::LEN,
                actual: Header::LEN - 1
            })
        );
    }

    #[test]
    fn header_parse_should_fail_with_invalid_version() {
        let data = {
            let mut data: Vec<u8> = get_flow_packet_header().to_vec();
            data[1] = 1;
            data
        };

        let res = Header::from_bytes(&data);

        assert!(res.is_err());
        assert_eq!(
            res,
            Err(Error::InvalidVersion {
                expected: vec!(7),
                actual: 1
            })
        );
    }

    #[test]
    fn header_accessors_expose_fields() {
        let header = Header::from_bytes(get_flow_packet_header()).unwrap();

        assert_eq!(header.version, 7);
        assert_eq!(header.count, 0x1d);
        assert_eq!(header.sys_uptime_msecs, 51469784);
        assert_eq!(header.unix_secs, 1544476581);
        assert_eq!(header.unix_nsecs, 0);
        assert_eq!(header.sequence_number, 873873830);
    }

    #[test]
    fn header_implements_debug() {
        println!(
            "{:?}",
            Header::from_bytes(get_flow_packet_header()).unwrap()
        );
    }

    #[test]
    fn header_implements_display() {
        println!("{}", Header::from_bytes(get_flow_packet_header()).unwrap());
    }
}
