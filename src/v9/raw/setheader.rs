use super::{Error, ERROR_NOT_ENOUGH_DATA};
use byteorder::{ByteOrder, NetworkEndian};

#[derive(PartialEq)]
pub struct SetHeader<'a> {
    pub(crate) data: &'a [u8],
}

impl<'a> SetHeader<'a> {
    pub const LEN: usize = 4;

    pub fn new(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::LEN {
            return Err(ERROR_NOT_ENOUGH_DATA);
        }

        Ok(SetHeader { data: data })
    }

    pub fn flowset_id(&self) -> u16 {
        NetworkEndian::read_u16(&(self.data[0..2]))
    }

    pub fn length(&self) -> u16 {
        NetworkEndian::read_u16(&(self.data[2..4]))
    }
}

impl<'a> std::fmt::Debug for SetHeader<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SetHeader {{ flowset_id: {}, length: {} }}",
            self.flowset_id(),
            self.length()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::get_flow_packet_sets;
    use super::*;

    #[test]
    fn set_header_new_should_succeed_with_valid_data() {
        assert!(SetHeader::new(get_flow_packet_sets()).is_ok());
    }

    #[test]
    fn set_header_new_should_fail_with_not_enough_data() {
        assert_eq!(
            SetHeader::new(&get_flow_packet_sets()[..SetHeader::LEN - 1]),
            Err(ERROR_NOT_ENOUGH_DATA)
        );
    }

    #[test]
    fn set_header_accessors_expose_fields() {
        let header = SetHeader::new(get_flow_packet_sets()).unwrap();

        assert_eq!(header.flowset_id(), 324);
        assert_eq!(header.length(), 1372);
    }

    #[test]
    fn set_header_implements_debug() {
        println!("{:?}", SetHeader::new(get_flow_packet_sets()).unwrap());
    }
}
