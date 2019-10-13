use super::{Error, ERROR_INVALID_VERSION, ERROR_NOT_ENOUGH_DATA};
use byteorder::{ByteOrder, NetworkEndian};

/// A Netflow v5 header helper struct
#[derive(PartialEq)]
pub struct Header<'a> {
  pub(crate) data: &'a [u8],
}

impl<'a> std::fmt::Debug for Header<'a> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "Header {{ version: {}, count: {}, sys_uptime_msecs: {}, unix_secs: {}, unix_nsecs: {}, sequence_number: {}, engine_type: {}, engine_id: {}, sampling: {} }}",
        self.version(), self.count(), self.sys_uptime_msecs(), self.unix_secs(), self.unix_nsecs(), self.sequence_number(), self.engine_type(), self.engine_id(), self.sampling())
  }
}

impl<'a> Header<'a> {
  pub const LEN: usize = 24;
  pub const VERSION: u16 = 5;
  pub const VERSION_NETWORK_ORDER: u16 = Self::VERSION.to_be();

  pub fn new(data: &'a [u8]) -> Result<Header<'a>, Error> {
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

    Ok(Header { data: data })
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

  /// Residual nanoseconds since 0000 Coordinated Universal Time 1970
  pub fn unix_nsecs(&self) -> u32 {
    NetworkEndian::read_u32(&(self.data[12..16]))
  }

  /// Sequence counter of total flows seen
  pub fn sequence_number(&self) -> u32 {
    NetworkEndian::read_u32(&(self.data[16..20]))
  }

  /// Type of flow-switching engine
  pub fn engine_type(&self) -> u8 {
    self.data[20]
  }

  /// Slot number of the flow-switching engine
  pub fn engine_id(&self) -> u8 {
    self.data[21]
  }

  /// First two bits hold the sampling mode; remaining 14 bits hold value of sampling interval
  pub fn sampling(&self) -> u16 {
    NetworkEndian::read_u16(&(self.data[22..24]))
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
    println!("{:?}", Header::new(get_flow_packet_header()).unwrap());
  }
}
