pub trait Endianness {
    const REPR: u16;
}

pub struct BigEndian {}
pub struct LittleEndian {}

pub type NativeEndian = LittleEndian;
pub type NetworkEndian = BigEndian;

impl Endianness for BigEndian {
    const REPR: u16 = 0x0001;
}

impl Endianness for LittleEndian {
    const REPR: u16 = 0x0100;
}

#[macro_export]
macro_rules! convert {
    ($value: expr) => {
        convert!(
            $crate::endianness::NetworkEndian,
            $crate::endianness::NativeEndian,
            $value
        )
    };
    ($data_type: ty, $result_type: ty, $value: expr) => {
        if <$data_type>::REPR == <$result_type>::REPR {
            $value
        } else {
            $value.swap_bytes()
        }
    };
}
