use super::{Endianness, Error, NetworkEndian, ERROR_INVALID_VERSION, ERROR_NOT_ENOUGH_DATA};

// todo: use read_unaligned https://doc.rust-lang.org/std/ptr/fn.read_unaligned.html#examples

pub struct Header<'a, E: Endianness> {
    data: &'a [u8],
    phantom: std::marker::PhantomData<E>,
}

macro_rules! convert_u16 {
    ($data_type: ty, $result_type: ty, $value: expr) => {
        if <$data_type>::REPR == <$result_type>::REPR {
            $value
        } else {
            $value.swap_bytes()
        }
    };
}

impl<'a, E: Endianness> Header<'a, E> {
    pub const LEN: usize = 24;
    pub const VERSION: u16 = 5;
    pub const VERSION_NETWORK_ORDER: u16 = Self::VERSION.to_be();

    pub fn new(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::LEN {
            return Err(ERROR_NOT_ENOUGH_DATA);
        }

        let version: u16 = unsafe {
            let mut version: u16 = 0;
            std::ptr::copy_nonoverlapping(data.as_ptr(), &mut version as *mut u16 as *mut u8, 2);
            version
        };

        if version != Self::VERSION_NETWORK_ORDER {
            return Err(ERROR_INVALID_VERSION);
        }

        Ok(Self {
            data: data,
            phantom: std::marker::PhantomData,
        })
    }

    pub fn version(&self) -> u16 {
        unsafe {
            let mut version: u16 = 0;
            std::ptr::copy_nonoverlapping(
                self.data.as_ptr(),
                &mut version as *mut u16 as *mut u8,
                std::mem::size_of::<u16>(),
            );
            convert_u16!(NetworkEndian, E, version)
        }
    }
}

pub struct FlowSet<'a, E: Endianness> {
    data: &'a [u8],
    phantom: std::marker::PhantomData<E>,
}

impl<'a, E: Endianness> FlowSet<'a, E> {
    pub fn new(data: &'a [u8]) -> Result<Self, Error> {
        let header = Header::<E>::new(data);

        Ok(Self {
            data: data,
            phantom: std::marker::PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    pub use super::super::tests::{get_flow_packet_header, get_flow_packet_records, FLOW_PACKET_1};
}
