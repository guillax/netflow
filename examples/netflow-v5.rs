extern crate netflow;

fn main() {
    let received_packet: [u8; 2] = [0x00, 0x05];

    match netflow::peek_version(&received_packet).expect("Failed to peek version") {
        netflow::Version::V5 => {
            println!("Found v5!");
            match netflow::v5::raw::FlowSet::new(&received_packet) {
                Ok(_) => print!("Success"),
                Err(e) => println!("Failed with error: {}", e),
            }
        }
        netflow::Version::V9 => println!("Found v9!"),
    }
}
