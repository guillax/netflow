use super::{FlowSet, Header, Record};

pub struct RecordIterator<'a> {
  pub(crate) set: &'a FlowSet<'a>,
  pub(crate) pos: usize,
  pub(crate) count: usize,
}

impl<'a> Iterator for RecordIterator<'a> {
  type Item = Record<'a>;

  fn next(&mut self) -> Option<Record<'a>> {
    if self.pos == self.count {
      return None;
    }

    let start = Header::LEN + self.pos * Record::LEN;
    let ref data = self.set.data[start..start + Record::LEN];
    self.pos += 1;
    Some(Record { data: data })
  }

  fn size_hint(&self) -> (usize, Option<usize>) {
    let remainder = self.count - self.pos;
    (remainder, Some(remainder))
  }
}
