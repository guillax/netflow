use std::fmt;

use super::{Header, Record};
use crate::Error;

#[derive(PartialEq)]
pub struct FlowSet {
    /// Flow set's header
    pub header: Header,
    /// Flow set's records
    pub records: Vec<Record>,
}

impl FlowSet {
    /// Parse an entire netflow v5 packet
    pub fn from_bytes<'a>(data: &'a [u8]) -> Result<Self, Error> {
        let header = Header::from_bytes(data)?;

        if data.len() < Header::LEN + header.count as usize * Record::LEN {
            return Err(Error::NotEnoughData {
                expected: Header::LEN + header.count as usize * Record::LEN,
                actual: data.len(),
            });
        }

        let mut records: Vec<Record> = Vec::with_capacity(header.count as usize);
        for r in 0..header.count as usize {
            let start = Header::LEN + Record::LEN * r;
            let end = Header::LEN + Record::LEN * (r + 1);
            records.push(Record::from_bytes(&data[start..end])?)
        }

        Ok(Self {
            header: header,
            records: records,
        })
    }
}

impl fmt::Display for FlowSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlowSet")
            .field("header", &self.header)
            .field("records", &self.records)
            .finish()
    }
}

impl fmt::Debug for FlowSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_data::FLOW_PACKET_1;
    use super::FlowSet;

    #[test]
    fn using_set_iterator() {
        let set = FlowSet::from_bytes(&FLOW_PACKET_1).unwrap();

        println!("{:?}", set.header);

        for record in set.records {
            println!("{:?}", record);
        }
    }

    #[test]
    fn flow_set_implements_debug() {
        let set = FlowSet::from_bytes(&FLOW_PACKET_1).unwrap();

        println!("{:?}", set);
    }

    #[test]
    fn flow_set_implements_display() {
        let set = FlowSet::from_bytes(&FLOW_PACKET_1).unwrap();

        println!("{}", set);
    }
}
