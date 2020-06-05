use std::fmt;

use crate::convert;
use crate::endianness::Endianness;
use crate::utils::read_unaligned_unchecked;

use crate::Error;

#[derive(Clone, Debug, PartialEq)]
#[repr(C)]
pub struct FlowSetHeader {
    pub id: u16,
    pub length: u16,
}

impl FlowSetHeader {
    pub const LEN: usize = std::mem::size_of::<Self>();

    pub fn from_bytes<'a>(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::LEN {
            return Err(Error::NotEnoughData {
                expected: Self::LEN,
                actual: data.len(),
            });
        }

        Ok(Self {
            id: convert!(read_unaligned_unchecked::<u16>(&data[0..2])),
            length: convert!(read_unaligned_unchecked::<u16>(&data[2..4])),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum FlowSet {
    Data(DataFlowSet),
    Option(OptionFlowSet),
    Template(TemplateFlowSet),
}

#[derive(Clone, Debug, PartialEq)]
pub struct TemplateFlowSet {
    id: u16, // Always 0
    length: u16,
    records: Vec<TemplateRecord>,
}

impl TemplateFlowSet {
    pub const MIN_LEN: usize = 2 * std::mem::size_of::<u16>();

    pub fn from_bytes<'a>(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::MIN_LEN {
            return Err(Error::NotEnoughData {
                expected: Self::MIN_LEN,
                actual: data.len(),
            });
        }

        Ok(Self {
            id: convert!(read_unaligned_unchecked::<u16>(&data[0..2])),
            length: convert!(read_unaligned_unchecked::<u16>(&data[2..4])),
            records: Vec::new(),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct OptionFlowSet {
    id: u16, // Always 1
    length: u16,
    template_id: u16, // > 255
    option_scope_length: u16,
    option_length: u16,
    records: Vec<TemplateRecord>,
}

impl OptionFlowSet {
    pub const MIN_LEN: usize = 5 * std::mem::size_of::<u16>();

    pub fn from_bytes<'a>(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::MIN_LEN {
            return Err(Error::NotEnoughData {
                expected: Self::MIN_LEN,
                actual: data.len(),
            });
        }

        Ok(Self {
            id: convert!(read_unaligned_unchecked::<u16>(&data[0..2])),
            length: convert!(read_unaligned_unchecked::<u16>(&data[2..4])),
            template_id: convert!(read_unaligned_unchecked::<u16>(&data[4..6])),
            option_scope_length: convert!(read_unaligned_unchecked::<u16>(&data[6..8])),
            option_length: convert!(read_unaligned_unchecked::<u16>(&data[8..10])),
            records: Vec::new(),
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DataFlowSet {}

impl DataFlowSet {
    pub const MIN_LEN: usize = 2 * std::mem::size_of::<u16>();

    pub fn from_bytes<'a>(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::MIN_LEN {
            return Err(Error::NotEnoughData {
                expected: Self::MIN_LEN,
                actual: data.len(),
            });
        }

        Ok(Self {})
    }
}

/*
#[derive(PartialEq)]
pub struct Header {
    id: u16,
    length: u16,
}

#[derive(PartialEq)]
pub struct FlowSet<T> {
    header: Header,
    records: Vec<T>,
}

pub type TemplateFlowSet = FlowSet<TemplateRecord>;
pub type OptionFlowSet = FlowSet<OptionRecord>;
pub type DataFlowSet = FlowSet<DataRecord>;
*/

#[derive(Clone, Debug, PartialEq)]
pub struct TemplateRecord {
    id: u16,
    count: u16,
    fields: Vec<FieldDefinition>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DataRecord {}

#[derive(Clone, Debug, PartialEq)]
pub struct OptionRecord {}

#[derive(Clone, Debug, PartialEq)]
pub struct FieldDefinition {
    typ: u16,
    length: u16,
}
