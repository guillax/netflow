use std::fmt;

use super::{Error, Header, Record, ERROR_NOT_ENOUGH_DATA};

#[derive(PartialEq)]
pub struct FlowSet {
    header: Header,
    records: Vec<Record>,
}

impl FlowSet {
    /// Parse an entire netflow v5 packet
    pub fn parse<'a>(data: &'a [u8]) -> Result<Self, Error> {
        let header = Header::parse(data)?;

        if data.len() < Header::LEN + header.count() as usize * Record::LEN {
            return Err(ERROR_NOT_ENOUGH_DATA);
        }

        let mut records: Vec<Record> = Vec::with_capacity(header.count() as usize);
        for r in 0..header.count() as usize {
            let start = Header::LEN + Record::LEN * r;
            let end = Header::LEN + Record::LEN * (r + 1);
            records.push(Record::parse(&data[start..end])?)
        }

        Ok(Self {
            header: header,
            records: records,
        })
    }

    /// Flow set's header
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Flow set's records
    pub fn records(&self) -> &Vec<Record> {
        &self.records
    }
}

impl fmt::Display for FlowSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FlowSet {{ header: ")?;
        fmt::Display::fmt(&self.header, f)?;
        write!(f, ", records: ")?;
        f.debug_list().entries(self.records.iter()).finish()?;
        write!(f, " }}")
    }
}

impl fmt::Debug for FlowSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::FLOW_PACKET_1;
    use super::*;

    #[test]
    fn using_set_iterator() {
        let set = FlowSet::parse(&FLOW_PACKET_1).unwrap();

        println!("{:?}", set.header());

        for record in set.records() {
            println!("{:?}", record);
        }
    }

    #[test]
    fn flow_set_implements_debug() {
        let set = FlowSet::parse(&FLOW_PACKET_1).unwrap();

        println!("{:?}", set);
    }
}
