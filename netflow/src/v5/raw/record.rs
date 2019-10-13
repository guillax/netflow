use super::{Error, ERROR_NOT_ENOUGH_DATA};
use byteorder::{ByteOrder, NetworkEndian};

/// A Netflow v5 record helper struct
#[derive(PartialEq)]
pub struct Record<'a> {
  pub(crate) data: &'a [u8],
}

impl<'a> std::fmt::Debug for Record<'a> {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "Record {{ source_addr: {}, destination_addr: {}, next_hop: {}, input: {}, output: {}, packets: {}, bytes: {}, first_packet_sys_uptime: {}, last_packet_sys_uptime: {}, source_port: {}, destination_port: {}, tcp_flags: {}, protocol: {}, type_of_service: {}, source_as: {}, destination_as: {}, source_mask: {}, destination_mask: {} }}",
        self.source_addr(), self.destination_addr(), self.next_hop(), self.input(), self.output(), self.packets(), self.bytes(), self.first_packet_sys_uptime(), self.last_packet_sys_uptime(), self.source_port(), self.destination_port(), self.tcp_flags(), self.protocol(), self.type_of_service(), self.source_as(), self.destination_as(), self.source_mask(), self.destination_mask())
  }
}

impl<'a> Record<'a> {
  pub const LEN: usize = 48;
  pub fn new(data: &'a [u8]) -> Result<Record<'a>, Error> {
    if data.len() < Self::LEN {
      return Err(ERROR_NOT_ENOUGH_DATA);
    }

    Ok(Record { data: data })
  }

  /// Source IP address
  pub fn source_addr(&self) -> std::net::IpAddr {
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(
      self.data[0],
      self.data[1],
      self.data[2],
      self.data[3],
    ))
  }

  /// Destination IP address
  pub fn destination_addr(&self) -> std::net::IpAddr {
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(
      self.data[4],
      self.data[5],
      self.data[6],
      self.data[7],
    ))
  }

  /// IP address of next hop router
  pub fn next_hop(&self) -> std::net::IpAddr {
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(
      self.data[8],
      self.data[9],
      self.data[10],
      self.data[11],
    ))
  }

  /// SNMP index of input interface
  pub fn input(&self) -> u16 {
    NetworkEndian::read_u16(&(self.data[12..14]))
  }

  /// SNMP index of output interface
  pub fn output(&self) -> u16 {
    NetworkEndian::read_u16(&(self.data[14..16]))
  }

  /// Packets in the flow
  pub fn packets(&self) -> u32 {
    NetworkEndian::read_u32(&(self.data[16..20]))
  }

  /// Total number of Layer 3 bytes in the packets of the flow
  pub fn bytes(&self) -> u32 {
    NetworkEndian::read_u32(&(self.data[20..24]))
  }

  /// SysUptime at start of flow
  pub fn first_packet_sys_uptime(&self) -> u32 {
    NetworkEndian::read_u32(&(self.data[24..28]))
  }

  /// SysUptime at the time the last packet of the flow was received
  pub fn last_packet_sys_uptime(&self) -> u32 {
    NetworkEndian::read_u32(&(self.data[28..32]))
  }

  /// TCP or UDP source port number or equivalient
  pub fn source_port(&self) -> u16 {
    NetworkEndian::read_u16(&(self.data[32..34]))
  }

  /// TCP or UDP destination port number or equivalient
  pub fn destination_port(&self) -> u16 {
    NetworkEndian::read_u16(&(self.data[34..36]))
  }

  /// Cumulative OR of TCP flags
  pub fn tcp_flags(&self) -> u8 {
    self.data[37]
  }

  /// IP protocol type (for example, TCP = 6, UDP = 17, ...)
  pub fn protocol(&self) -> u8 {
    self.data[38]
  }

  /// IP type of service (ToS)
  pub fn type_of_service(&self) -> u8 {
    self.data[39]
  }

  /// Autonomous system number of the source, either origin or peer
  pub fn source_as(&self) -> u16 {
    NetworkEndian::read_u16(&(self.data[40..42]))
  }

  /// Autonomous system number of the destination, either origin or peer
  pub fn destination_as(&self) -> u16 {
    NetworkEndian::read_u16(&(self.data[42..44]))
  }

  /// Source address prefix mask bits
  pub fn source_mask(&self) -> u8 {
    self.data[44]
  }

  /// Destination address prefix mask bits
  pub fn destination_mask(&self) -> u8 {
    self.data[45]
  }
}

#[cfg(test)]
mod tests {
  use super::super::tests::get_flow_packet_records;
  use super::*;

  #[test]
  fn record_new_should_succeed_with_valid_data() {
    assert!(Record::new(get_flow_packet_records()).is_ok());
  }

  #[test]
  fn record_new_should_fail_with_not_enough_data() {
    assert_eq!(
      Record::new(&get_flow_packet_records()[..Record::LEN - 1]),
      Err(ERROR_NOT_ENOUGH_DATA)
    );
  }

  #[test]
  fn record_accessors_expose_fields() {
    let record = Record::new(get_flow_packet_records()).unwrap();

    assert_eq!(
      record.source_addr(),
      std::net::Ipv4Addr::new(125, 238, 46, 48)
    );
    assert_eq!(
      record.destination_addr(),
      std::net::Ipv4Addr::new(114, 23, 236, 96)
    );
    assert_eq!(record.next_hop(), std::net::Ipv4Addr::new(114, 23, 3, 231));
    assert_eq!(record.input(), 791);
    assert_eq!(record.output(), 817);
    assert_eq!(record.packets(), 4);
    assert_eq!(record.bytes(), 1708);
    assert_eq!(record.first_packet_sys_uptime(), 51402145);
    assert_eq!(record.last_packet_sys_uptime(), 51433264);
    assert_eq!(record.source_port(), 49233);
    assert_eq!(record.destination_port(), 443);
    assert_eq!(record.tcp_flags(), 0x10);
    assert_eq!(record.protocol(), 6);
    assert_eq!(record.type_of_service(), 0x0);
    assert_eq!(record.source_as(), 4771);
    assert_eq!(record.destination_as(), 56030);
    assert_eq!(record.source_mask(), 20);
    assert_eq!(record.destination_mask(), 22);
  }

  #[test]
  fn record_implements_debug() {
    println!("{:?}", Record::new(get_flow_packet_records()).unwrap());
  }
}
