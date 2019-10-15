extern crate netflow;

use netflow::{NativeEndian, NetworkEndian};

pub trait ENDIANNESS {
    fn to_u16(x: u16) -> u16;
}

pub enum NULL {}
pub struct B<TO: ENDIANNESS = NULL> {
    __hidden__: TO,
}
pub struct L<TO: ENDIANNESS = NULL> {
    __hidden__: TO,
}

impl ENDIANNESS for NULL {
    fn to_u16(_: u16) -> u16 {
        unimplemented!()
    }
}

impl ENDIANNESS for B<L> {
    fn to_u16(x: u16) -> u16 {
        x.swap_bytes()
    }
}

impl ENDIANNESS for B<B> {
    fn to_u16(x: u16) -> u16 {
        x
    }
}

impl ENDIANNESS for L<B> {
    fn to_u16(x: u16) -> u16 {
        x.swap_bytes()
    }
}

impl ENDIANNESS for L<L> {
    fn to_u16(x: u16) -> u16 {
        x
    }
}

impl ENDIANNESS for L {
    fn to_u16(_: u16) -> u16 {
        unimplemented!()
    }
}

impl ENDIANNESS for B {
    fn to_u16(_: u16) -> u16 {
        unimplemented!()
    }
}

fn toto(received_packet: &[u8]) {
    println!("{}", u16::from_be_bytes(received_packet));
}

fn main() {
    let received_packet: [u8; 2] = [0x00, 0x05];

    let version = netflow::peek_version(&received_packet).expect("Failed to peek netflow version");

    if version != netflow::Version::V5 {
        panic!("Unexpected netflow version");
    }

    println!("{}", Native::ConvertFrom::<Network>::_u16(1));

    println!("{}", B::<L>::to_u16(1));
    println!("{}", L::<B>::to_u16(1));
    println!("{}", B::<B>::to_u16(1));
    println!("{}", L::<L>::to_u16(1));

    toto(&received_packet);
    /*
    let flowset = netflow::v5::FlowSet::new::<NetworkEndian>(&received_packet)
        .expect("Failed to instantiate FlowSet");
    print!("{:?}", flowset);

    let flowset = netflow::v5::FlowSet::new::<NativeEndian>(&received_packet)
        .expect("Failed to instantiate FlowSet");
    print!("{:?}", flowset);
    */
}
