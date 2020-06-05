use std::fmt;

use crate::convert;
use crate::endianness::Endianness;
use crate::utils::read_unaligned_unchecked;
use crate::Error;

use super::{DataFlowSet, FlowSet, FlowSetHeader, Header, OptionFlowSet, TemplateFlowSet};

/// Netflow v9 header struct
#[derive(Clone, PartialEq)]
pub struct Packet {
    pub header: Header,
    pub flowsets: Vec<FlowSet>,
}

impl Packet {
    /// Parse an entire netflow v9 packet
    pub fn from_bytes<'a>(data: &'a [u8]) -> Result<Self, Error> {
        let header = Header::from_bytes(data)?;

        if data.len() < Header::LEN + header.count as usize * FlowSetHeader::LEN {
            return Err(Error::NotEnoughData {
                expected: Header::LEN + header.count as usize * FlowSetHeader::LEN,
                actual: data.len(),
            });
        }

        let mut flowsets: Vec<FlowSet> = Vec::with_capacity(header.count as usize);
        let mut start = Header::LEN;
        for _ in 0..header.count as usize {
            let flowset_header = FlowSetHeader::from_bytes(&data[start..])?;

            let flowset = if flowset_header.id == 1 {
                FlowSet::Option(OptionFlowSet::from_bytes(
                    &data[start..start + flowset_header.length as usize],
                )?)
            } else if flowset_header.id < 256 {
                FlowSet::Template(TemplateFlowSet::from_bytes(
                    &data[start..start + flowset_header.length as usize],
                )?)
            } else {
                FlowSet::Data(DataFlowSet::from_bytes(
                    &data[start..start + flowset_header.length as usize],
                )?)
            };

            flowsets.push(flowset);

            start += flowset_header.length as usize;
        }

        Ok(Self {
            header: header,
            flowsets: flowsets,
        })
    }
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packet")
            .field("header", &self.header)
            .field("flowsets", &self.flowsets)
            .finish()
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_data::FLOW_PACKET_1;
    use super::Packet;

    #[test]
    fn packet_parse_should_succeed_with_valid_data() {
        let result = Packet::from_bytes(&FLOW_PACKET_1);
        println!("{:?}", result);
        assert!(result.is_ok());
    }

    #[test]
    fn packet_implements_debug() {
        println!("{:?}", Packet::from_bytes(&FLOW_PACKET_1).unwrap());
    }

    #[test]
    fn packet_implements_display() {
        println!("{}", Packet::from_bytes(&FLOW_PACKET_1).unwrap());
    }
}
