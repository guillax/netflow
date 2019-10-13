use super::{Error, ERROR_NOT_ENOUGH_DATA};

use super::{Header, RecordIterator};

#[derive(PartialEq)]
pub struct FlowSet<'a> {
  pub(crate) data: &'a [u8],
}

impl<'a> FlowSet<'a> {
  pub fn new(data: &'a [u8]) -> Result<FlowSet<'a>, Error> {
    if data.len() < Header::LEN {
      return Err(ERROR_NOT_ENOUGH_DATA);
    }

    Ok(FlowSet { data: data })
  }

  pub fn header(&'a self) -> Header<'a> {
    Header { data: self.data }
  }

  pub fn records(&'a self) -> RecordIterator {
    RecordIterator {
      set: self,
      pos: 0,
      count: self.header().count() as usize,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::super::tests::FLOW_PACKET_1;
  use super::*;

  #[test]
  fn using_set_iterator() {
    let set = FlowSet::new(&FLOW_PACKET_1).unwrap();

    println!("{:?}", set.header());
    for record in set.records() {
      println!("{:?}", record);
    }
  }
}
