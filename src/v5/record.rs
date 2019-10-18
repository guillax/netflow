use std::fmt;
use std::net::Ipv4Addr;

use super::super::utils::read_unaligned;
use super::{Error, ERROR_NOT_ENOUGH_DATA};
use crate::convert;
use crate::endianness::Endianness;

/// A Netflow v5 record struct
#[derive(Copy, Clone, PartialEq)]
pub struct Record {
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    next_hop: Ipv4Addr,
    in_iface: u16,
    out_iface: u16,
    packets: u32,
    bytes: u32,
    first_sys_uptime: u32,
    last_sys_uptime: u32,
    src_port: u16,
    dst_port: u16,
    src_as: u16,
    dst_as: u16,
    tcp_flags: u8,
    proto: u8,
    tos: u8,
    src_mask: u8,
    dst_mask: u8,
}

impl Record {
    pub const LEN: usize = 48;

    /// Parse a netflow v5 packet record
    pub fn parse<'a>(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::LEN {
            return Err(ERROR_NOT_ENOUGH_DATA);
        }

        Ok(Self {
            src_addr: Ipv4Addr::new(data[0], data[1], data[2], data[3]),
            dst_addr: Ipv4Addr::new(data[4], data[5], data[6], data[7]),
            next_hop: Ipv4Addr::new(data[8], data[9], data[10], data[11]),
            in_iface: convert!(read_unaligned::<u16>(&data[12..14])),
            out_iface: convert!(read_unaligned::<u16>(&data[14..16])),
            packets: convert!(read_unaligned::<u32>(&data[16..20])),
            bytes: convert!(read_unaligned::<u32>(&data[20..24])),
            first_sys_uptime: convert!(read_unaligned::<u32>(&data[24..28])),
            last_sys_uptime: convert!(read_unaligned::<u32>(&data[28..32])),
            src_port: convert!(read_unaligned::<u16>(&data[32..34])),
            dst_port: convert!(read_unaligned::<u16>(&data[34..36])),
            // padding: u8,
            tcp_flags: data[37],
            proto: data[38],
            tos: data[39],
            src_as: convert!(read_unaligned::<u16>(&data[40..42])),
            dst_as: convert!(read_unaligned::<u16>(&data[42..44])),
            src_mask: data[44],
            dst_mask: data[45],
            // padding: u16,
        })
    }
    /// Source IP address
    pub fn source_addr(&self) -> Ipv4Addr {
        self.src_addr
    }

    /// Destination IP address
    pub fn destination_addr(&self) -> Ipv4Addr {
        self.dst_addr
    }

    /// IP address of next hop router
    pub fn next_hop(&self) -> Ipv4Addr {
        self.next_hop
    }

    /// SNMP index of input interface
    pub fn input_iface(&self) -> u16 {
        self.in_iface
    }

    /// SNMP index of output interface
    pub fn output_iface(&self) -> u16 {
        self.out_iface
    }

    /// Packets in the flow
    pub fn packets(&self) -> u32 {
        self.packets
    }

    /// Total number of Layer 3 bytes in the packets of the flow
    pub fn bytes(&self) -> u32 {
        self.bytes
    }

    /// SysUptime at start of flow
    pub fn first_packet_sys_uptime(&self) -> u32 {
        self.first_sys_uptime
    }

    /// SysUptime at the time the last packet of the flow was received
    pub fn last_packet_sys_uptime(&self) -> u32 {
        self.last_sys_uptime
    }

    /// TCP or UDP source port number or equivalient
    pub fn source_port(&self) -> u16 {
        self.src_port
    }

    /// TCP or UDP destination port number or equivalient
    pub fn destination_port(&self) -> u16 {
        self.dst_port
    }

    /// Cumulative OR of TCP flags
    pub fn tcp_flags(&self) -> u8 {
        self.tcp_flags
    }

    /// IP protocol type (for example, TCP = 6, UDP = 17, ...)
    pub fn protocol(&self) -> u8 {
        self.proto
    }

    /// IP type of service (ToS)
    pub fn type_of_service(&self) -> u8 {
        self.tos
    }

    /// Autonomous system number of the source, either origin or peer
    pub fn source_as(&self) -> u16 {
        self.src_as
    }

    /// Autonomous system number of the destination, either origin or peer
    pub fn destination_as(&self) -> u16 {
        self.dst_as
    }

    /// Source address prefix mask bits
    pub fn source_mask(&self) -> u8 {
        self.src_mask
    }

    /// Destination address prefix mask bits
    pub fn destination_mask(&self) -> u8 {
        self.dst_mask
    }
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Record {{ source_addr: {}, destination_addr: {}, next_hop: {}, input_iface: {}, output_iface: {}, packets: {}, bytes: {}, first_packet_sys_uptime: {}, last_packet_sys_uptime: {}, source_port: {}, destination_port: {}, tcp_flags: {}, protocol: {}, type_of_service: {}, source_as: {}, destination_as: {}, source_mask: {}, destination_mask: {} }}",
        self.source_addr(), self.destination_addr(), self.next_hop(), self.input_iface(), self.output_iface(), self.packets(), self.bytes(), self.first_packet_sys_uptime(), self.last_packet_sys_uptime(), self.source_port(), self.destination_port(), self.tcp_flags(), self.protocol(), self.type_of_service(), self.source_as(), self.destination_as(), self.source_mask(), self.destination_mask())
    }
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::get_flow_packet_records;
    use super::*;

    #[test]
    fn record_parse_should_succeed_with_valid_data() {
        assert!(Record::parse(get_flow_packet_records()).is_ok());
    }

    #[test]
    fn record_parse_should_fail_with_not_enough_data() {
        assert_eq!(
            Record::parse(&get_flow_packet_records()[..Record::LEN - 1]),
            Err(ERROR_NOT_ENOUGH_DATA)
        );
    }

    #[test]
    fn record_accessors_expose_fields() {
        let record = Record::parse(get_flow_packet_records()).unwrap();

        assert_eq!(
            record.source_addr(),
            std::net::Ipv4Addr::new(125, 238, 46, 48)
        );
        assert_eq!(
            record.destination_addr(),
            std::net::Ipv4Addr::new(114, 23, 236, 96)
        );
        assert_eq!(record.next_hop(), std::net::Ipv4Addr::new(114, 23, 3, 231));
        assert_eq!(record.input_iface(), 791);
        assert_eq!(record.output_iface(), 817);
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
        println!("{:?}", Record::parse(get_flow_packet_records()).unwrap());
    }
}
