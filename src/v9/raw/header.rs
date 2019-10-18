use super::{Error, ERROR_INVALID_VERSION, ERROR_NOT_ENOUGH_DATA};

/// A Netflow v9 header helper struct
#[derive(PartialEq)]
pub struct Header<'a> {
    pub(crate) data: &'a [u8],
}

impl<'a> Header<'a> {
    pub const LEN: usize = 20;
    pub const VERSION: u16 = 9;
    pub const VERSION_NETWORK_ORDER: u16 = Self::VERSION.to_be();

    pub fn new(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::LEN {
            return Err(ERROR_NOT_ENOUGH_DATA);
        }
        let version: u16 = unsafe {
            let mut version: u16 = 0;
            std::ptr::copy_nonoverlapping(data.as_ptr(), &mut version as *mut u16 as *mut u8, 2);
            version
        };
        if version != Self::VERSION_NETWORK_ORDER {
            return Err(ERROR_INVALID_VERSION);
        }

        Ok(Self { data: data })
    }

    /// NetFlow export format version number
    pub fn version(&self) -> u16 {
        Self::VERSION
    }

    /// Number of flows that are exported in this packet (1-30)
    pub fn count(&self) -> u16 {
        NetworkEndian::read_u16(&(self.data[2..4]))
    }

    /// Current time in milliseconds since the export device started
    pub fn sys_uptime_msecs(&self) -> u32 {
        NetworkEndian::read_u32(&(self.data[4..8]))
    }

    /// Current time in seconds since 0000 Coordinated Universal Time 1970
    pub fn unix_secs(&self) -> u32 {
        NetworkEndian::read_u32(&(self.data[8..12]))
    }

    /// Sequence counter of total flows seen
    pub fn sequence_number(&self) -> u32 {
        NetworkEndian::read_u32(&(self.data[12..16]))
    }

    ///
    pub fn source_id(&self) -> u32 {
        NetworkEndian::read_u32(&(self.data[16..20]))
    }
}

impl<'a> std::fmt::Debug for Header<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Header {{ version: {}, count: {}, sys_uptime_msecs: {}, unix_secs: {}, sequence_number: {}, source_id: {} }}",
        self.version(), self.count(), self.sys_uptime_msecs(), self.unix_secs(), self.sequence_number(), self.source_id())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::get_flow_packet_header;
    use super::*;
    #[test]
    fn header_new_should_succeed_with_valid_data() {
        assert!(Header::new(get_flow_packet_header()).is_ok());
    }

    #[test]
    fn header_new_should_fail_with_not_enough_data() {
        assert_eq!(
            Header::new(&get_flow_packet_header()[..Header::LEN - 1]),
            Err(ERROR_NOT_ENOUGH_DATA)
        );
    }

    #[test]
    fn header_new_should_fail_with_invalid_version() {
        let data = {
            let mut data: Vec<u8> = get_flow_packet_header().to_vec();
            data[1] = 1;
            data
        };

        let res = Header::new(&data);

        assert!(res.is_err());
        assert_eq!(res, Err(ERROR_INVALID_VERSION));
    }

    #[test]
    fn header_accessors_expose_fields() {
        let header = Header::new(get_flow_packet_header()).unwrap();

        assert_eq!(header.version(), 9);
        assert_eq!(header.count(), 0x15);
        assert_eq!(header.sys_uptime_msecs(), 3462915953);
        assert_eq!(header.unix_secs(), 1571059124);
        assert_eq!(header.sequence_number(), 3228052148);
        assert_eq!(header.source_id(), 2081);
    }

    #[test]
    fn header_implements_debug() {
        println!("{:?}", Header::new(get_flow_packet_header()).unwrap());
    }
}
