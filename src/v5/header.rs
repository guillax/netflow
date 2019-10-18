use std::fmt;

use super::{Error, ERROR_INVALID_VERSION, ERROR_NOT_ENOUGH_DATA};

use super::super::utils::read_unaligned;
use crate::convert;
use crate::endianness::Endianness;

#[derive(Copy, Clone, PartialEq)]
pub struct Header {
    sys_uptime_msecs: u32,
    unix_secs: u32,
    unix_nsecs: u32,
    sequence_number: u32,
    engine_type: u8,
    engine_id: u8,
    sampling: u16,
    count: u16,
}

impl Header {
    pub const LEN: usize = 24;
    pub const VERSION: u16 = 5;
    pub const VERSION_NETWORK_ORDER: u16 = Self::VERSION.to_be();

    /// Parse a netflow v5 packet header
    pub fn parse<'a>(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::LEN {
            return Err(ERROR_NOT_ENOUGH_DATA);
        }

        if read_unaligned::<u16>(data) != Self::VERSION_NETWORK_ORDER {
            return Err(ERROR_INVALID_VERSION);
        }

        Ok(Self {
            count: convert!(read_unaligned::<u16>(&data[2..4])),
            sys_uptime_msecs: convert!(read_unaligned::<u32>(&data[4..8])),
            unix_secs: convert!(read_unaligned::<u32>(&data[8..12])),
            unix_nsecs: convert!(read_unaligned::<u32>(&data[12..16])),
            sequence_number: convert!(read_unaligned::<u32>(&data[16..20])),
            engine_type: data[20],
            engine_id: data[21],
            sampling: convert!(read_unaligned::<u16>(&data[22..24])),
        })
    }

    /// NetFlow export format version number
    pub fn version(&self) -> u16 {
        Self::VERSION
    }

    /// Number of flows that are exported in this packet (1-30)
    pub fn count(&self) -> u16 {
        self.count
    }

    /// Current time in milliseconds since the export device started
    pub fn sys_uptime_msecs(&self) -> u32 {
        self.sys_uptime_msecs
    }

    /// Current time in seconds since 0000 Coordinated Universal Time 1970
    pub fn unix_secs(&self) -> u32 {
        self.unix_secs
    }

    /// Residual nanoseconds since 0000 Coordinated Universal Time 1970
    pub fn unix_nsecs(&self) -> u32 {
        self.unix_nsecs
    }

    /// Sequence counter of total flows seen
    pub fn sequence_number(&self) -> u32 {
        self.sequence_number
    }

    /// Type of flow-switching engine
    pub fn engine_type(&self) -> u8 {
        self.engine_type
    }

    /// Slot number of the flow-switching engine
    pub fn engine_id(&self) -> u8 {
        self.engine_id
    }

    /// First two bits hold the sampling mode; remaining 14 bits hold value of sampling interval
    pub fn sampling(&self) -> u16 {
        self.sampling
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Header {{ version: {}, count: {}, sys_uptime_msecs: {}, unix_secs: {}, unix_nsecs: {}, sequence_number: {}, engine_type: {}, engine_id: {}, sampling: {} }}",
        self.version(), self.count(), self.sys_uptime_msecs(), self.unix_secs(), self.unix_nsecs(), self.sequence_number(), self.engine_type(), self.engine_id(), self.sampling())
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    pub use super::super::tests::{get_flow_packet_header, get_flow_packet_records, FLOW_PACKET_1};
    use super::*;

    #[test]
    fn header_parse_should_succeed_with_valid_data() {
        assert!(Header::parse(get_flow_packet_header()).is_ok());
    }

    #[test]
    fn header_parse_should_fail_with_not_enough_data() {
        assert_eq!(
            Header::parse(&get_flow_packet_header()[..Header::LEN - 1]),
            Err(ERROR_NOT_ENOUGH_DATA)
        );
    }

    #[test]
    fn header_parse_should_fail_with_invalid_version() {
        let data = {
            let mut data: Vec<u8> = get_flow_packet_header().to_vec();
            data[1] = 1;
            data
        };

        let res = Header::parse(&data);

        assert!(res.is_err());
        assert_eq!(res, Err(ERROR_INVALID_VERSION));
    }

    #[test]
    fn header_accessors_expose_fields() {
        let header = Header::parse(get_flow_packet_header()).unwrap();

        assert_eq!(header.version(), 5);
        assert_eq!(header.count(), 0x1d);
        assert_eq!(header.sys_uptime_msecs(), 51469784);
        assert_eq!(header.unix_secs(), 1544476581);
        assert_eq!(header.unix_nsecs(), 0);
        assert_eq!(header.sequence_number(), 873873830);
        assert_eq!(header.engine_type(), 0);
        assert_eq!(header.engine_id(), 0);
        assert_eq!(header.sampling(), 1000);
    }

    #[test]
    fn header_implements_debug() {
        println!("{:?}", Header::parse(get_flow_packet_header()).unwrap());
    }
}
