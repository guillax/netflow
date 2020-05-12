extern crate netflow;

fn main() {
    let received_packet: [u8; 2] = [0x00, 0x05];

    let version = netflow::peek_version(&received_packet).expect("Failed to peek netflow version");

    if version != netflow::Version::V5 {
        panic!("Unexpected netflow version");
    }

    let flowset =
        netflow::v5::FlowSet::from_bytes(&received_packet).expect("Failed to instantiate FlowSet");
    print!("{:?}", flowset);
}
