use super::{Error, ERROR_INVALID_VERSION, ERROR_NOT_ENOUGH_DATA};

mod header;

pub use header::PacketHeader;

#[cfg(test)]
mod tests {
    pub use super::super::tests::{get_flow_packet_header, get_flow_packet_records, FLOW_PACKET_1};
}
