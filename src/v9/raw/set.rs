use super::{Error, SetHeader, ERROR_INVALID_FLOWSET_ID};
use byteorder::{ByteOrder, NetworkEndian};

#[derive(PartialEq, Debug)]
pub enum Set<'a> {
    Data(DataFlowSet<'a>),
    Template(TemplateFlowSet<'a>),
    Options(OptionsTemplate<'a>),
}

#[derive(PartialEq)]
pub struct DataFlowSet<'a> {
    data: &'a [u8],
}

impl<'a> DataFlowSet<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, Error> {
        let header = SetHeader::new(data)?;

        if header.flowset_id() <= 255 {
            return Err(ERROR_INVALID_FLOWSET_ID);
        }

        Ok(Self { data: data })
    }
}

impl<'a> std::fmt::Debug for DataFlowSet<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DataFlowSet {{ header: ")?;
        SetHeader::new(self.data).unwrap().fmt(f)?;
        write!(f, " }}")
    }
}

#[derive(PartialEq)]
pub struct TemplateFlowSet<'a> {
    data: &'a [u8],
}

impl<'a> TemplateFlowSet<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, Error> {
        let header = SetHeader::new(data)?;

        if header.flowset_id() != 0 {
            return Err(ERROR_INVALID_FLOWSET_ID);
        }

        Ok(Self { data: data })
    }
}

impl<'a> std::fmt::Debug for TemplateFlowSet<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TemplateFlowSet {{ header: ")?;
        SetHeader::new(self.data).unwrap().fmt(f)?;
        write!(f, " }}")
    }
}

#[derive(PartialEq)]
pub struct OptionsTemplate<'a> {
    data: &'a [u8],
}

impl<'a> OptionsTemplate<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, Error> {
        let header = SetHeader::new(data)?;

        if header.flowset_id() != 1 {
            return Err(ERROR_INVALID_FLOWSET_ID);
        }

        Ok(Self { data: data })
    }
}

impl<'a> std::fmt::Debug for OptionsTemplate<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OptionsTemplate {{ header: ")?;
        SetHeader::new(self.data).unwrap().fmt(f)?;
        write!(f, " }}")
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::get_flow_packet_sets;
    use super::super::ERROR_NOT_ENOUGH_DATA;
    use super::*;

    #[test]
    fn data_flow_set_new_should_succeed_with_valid_data() {
        assert!(DataFlowSet::new(get_flow_packet_sets()).is_ok());
    }

    #[test]
    fn data_flow_set_new_should_fail_with_not_enough_data() {
        assert_eq!(
            DataFlowSet::new(&get_flow_packet_sets()[..SetHeader::LEN - 1]),
            Err(ERROR_NOT_ENOUGH_DATA)
        );
    }

    /*
    #[test]
    fn data_flow_set_accessors_expose_fields() {
        let header = DataFlowSet::new(get_flow_packet_sets()).unwrap();

        assert_eq!(header.flowset_id(), 324);
        assert_eq!(header.length(), 1372);
    }
    */

    #[test]
    fn data_flow_set_implements_debug() {
        println!("{:?}", DataFlowSet::new(get_flow_packet_sets()).unwrap());
    }
}
