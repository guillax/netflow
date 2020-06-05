use std::fmt;
use std::net::Ipv4Addr;

use crate::convert;
use crate::endianness::Endianness;
use crate::utils::read_unaligned_unchecked;
use crate::Error;

/// Netflow v7 record struct
#[derive(Copy, Clone, PartialEq)]
#[repr(C)]
pub struct Record {
    /// Source IP address
    pub source_addr: Ipv4Addr,
    /// Destination IP address
    pub destination_addr: Ipv4Addr,
    /// IP address of next hop router
    pub next_hop: Ipv4Addr,
    /// SNMP index of input interface
    pub input_iface: u16,
    /// SNMP index of output interface
    pub output_iface: u16,
    /// Packets in the flow
    pub packets: u32,
    /// Total number of Layer 3 bytes in the packets of the flow
    pub bytes: u32,
    /// System uptime at start of flow
    pub first_sys_uptime: u32,
    /// System uptime at the time the last packet of the flow was received
    pub last_sys_uptime: u32,
    /// TCP or UDP source port number or equivalient
    pub source_port: u16,
    /// TCP or UDP destination port number or equivalient
    pub destination_port: u16,
    padding_0: u8,
    /// Cumulative OR of TCP flags
    pub tcp_flags: u8,
    /// IP protocol type (for example, TCP = 6, UDP = 17, ...)
    pub proto: u8,
    /// IP type of service (ToS)
    pub tos: u8,
    /// Autonomous system number of the source, either origin or peer
    pub source_as: u16,
    /// Autonomous system number of the destination, either origin or peer
    pub destination_as: u16,
    /// Source address prefix mask bits
    pub source_mask: u8,
    /// Destination address prefix mask bits
    pub destination_mask: u8,
    /// Flags indicating, among other things, what flows are invalid
    pub flags: u16,
    /// IP address of the router that is bypassed by the Catalyst 5000 series switch.
    pub source_router: Ipv4Addr,
}

impl Record {
    pub const LEN: usize = std::mem::size_of::<Self>();

    /// Parse a netflow v7 packet record
    pub fn from_bytes<'a>(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::LEN {
            return Err(Error::NotEnoughData {
                expected: Self::LEN,
                actual: data.len(),
            });
        }

        Ok(Self {
            source_addr: Ipv4Addr::new(data[0], data[1], data[2], data[3]),
            destination_addr: Ipv4Addr::new(data[4], data[5], data[6], data[7]),
            next_hop: Ipv4Addr::new(data[8], data[9], data[10], data[11]),
            input_iface: convert!(read_unaligned_unchecked::<u16>(&data[12..14])),
            output_iface: convert!(read_unaligned_unchecked::<u16>(&data[14..16])),
            packets: convert!(read_unaligned_unchecked::<u32>(&data[16..20])),
            bytes: convert!(read_unaligned_unchecked::<u32>(&data[20..24])),
            first_sys_uptime: convert!(read_unaligned_unchecked::<u32>(&data[24..28])),
            last_sys_uptime: convert!(read_unaligned_unchecked::<u32>(&data[28..32])),
            source_port: convert!(read_unaligned_unchecked::<u16>(&data[32..34])),
            destination_port: convert!(read_unaligned_unchecked::<u16>(&data[34..36])),
            padding_0: 0, // read_unaligned_unchecked::<u8>(&data[36])
            tcp_flags: data[37],
            proto: data[38],
            tos: data[39],
            source_as: convert!(read_unaligned_unchecked::<u16>(&data[40..42])),
            destination_as: convert!(read_unaligned_unchecked::<u16>(&data[42..44])),
            source_mask: data[44],
            destination_mask: data[45],
            flags: convert!(read_unaligned_unchecked::<u16>(&data[46..48])),
            source_router: Ipv4Addr::new(data[48], data[49], data[50], data[51]),
        })
    }
}

impl fmt::Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("source_addr", &self.source_addr)
            .field("destination_addr", &self.destination_addr)
            .field("next_hop", &self.next_hop)
            .field("input_iface", &self.input_iface)
            .field("output_iface", &self.output_iface)
            .field("packets", &self.packets)
            .field("bytes", &self.bytes)
            .field("first_sys_uptime", &self.first_sys_uptime)
            .field("last_sys_uptime", &self.last_sys_uptime)
            .field("source_port", &self.source_port)
            .field("destination_port", &self.destination_port)
            .field("tcp_flags", &self.tcp_flags)
            .field("proto", &self.proto)
            .field("tos", &self.tos)
            .field("source_as", &self.source_as)
            .field("destination_as", &self.destination_as)
            .field("source_mask", &self.source_mask)
            .field("destination_mask", &self.destination_mask)
            .field("flags", &self.flags)
            .field("source_router", &self.source_router)
            .finish()
    }
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_data::get_flow_packet_records;
    use super::Record;
    use crate::Error;

    #[test]
    fn record_parse_should_succeed_with_valid_data() {
        assert!(Record::from_bytes(get_flow_packet_records()).is_ok());
    }

    #[test]
    fn record_parse_should_fail_with_not_enough_data() {
        assert_eq!(
            Record::from_bytes(&get_flow_packet_records()[..Record::LEN - 1]),
            Err(Error::NotEnoughData {
                expected: Record::LEN,
                actual: Record::LEN - 1
            })
        );
    }

    #[test]
    fn record_accessors_expose_fields() {
        let record = Record::from_bytes(get_flow_packet_records()).unwrap();

        assert_eq!(
            record.source_addr,
            std::net::Ipv4Addr::new(125, 238, 46, 48)
        );
        assert_eq!(
            record.destination_addr,
            std::net::Ipv4Addr::new(114, 23, 236, 96)
        );
        assert_eq!(record.next_hop, std::net::Ipv4Addr::new(114, 23, 3, 231));
        assert_eq!(record.input_iface, 791);
        assert_eq!(record.output_iface, 817);
        assert_eq!(record.packets, 4);
        assert_eq!(record.bytes, 1708);
        assert_eq!(record.first_sys_uptime, 51402145);
        assert_eq!(record.last_sys_uptime, 51433264);
        assert_eq!(record.source_port, 49233);
        assert_eq!(record.destination_port, 443);
        assert_eq!(record.tcp_flags, 0x10);
        assert_eq!(record.proto, 6);
        assert_eq!(record.tos, 0x0);
        assert_eq!(record.source_as, 4771);
        assert_eq!(record.destination_as, 56030);
        assert_eq!(record.source_mask, 20);
        assert_eq!(record.destination_mask, 22);
        assert_eq!(record.flags, 0);
        assert_eq!(
            record.source_router,
            std::net::Ipv4Addr::new(125, 238, 46, 48)
        );
    }

    #[test]
    fn record_implements_debug() {
        println!(
            "{:?}",
            Record::from_bytes(get_flow_packet_records()).unwrap()
        );
    }

    #[test]
    fn record_implements_display() {
        println!("{}", Record::from_bytes(get_flow_packet_records()).unwrap());
    }
}
