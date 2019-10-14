use byteorder::{NetworkEndian, ReadBytesExt};
use std::io::Cursor;

use super::{Error, ERROR_INVALID_VERSION, ERROR_NOT_ENOUGH_DATA};

/// Based on https://www.ibm.com/support/knowledgecenter/SSCVHB_1.3.1/collector/cnpi_netflow_v5.html

#[derive(Debug)]
#[repr(C)]
pub struct PacketHeader {
    /// NetFlow export format version number
    pub version: u16,
    /// Number of flows that are exported in this packet (1-30)
    pub count: u16,
    /// Current time in milliseconds since the export device started
    pub sys_uptime_msecs: u32,
    /// Current time in seconds since 0000 Coordinated Universal Time 1970
    pub unix_secs: u32,
    /// Residual nanoseconds since 0000 Coordinated Universal Time 1970
    pub unix_nsecs: u32,
    /// Sequence counter of total flows seen
    pub sequence_number: u32,
    /// Type of flow-switching engine
    pub engine_type: u8,
    /// Slot number of the flow-switching engine
    pub engine_id: u8,
    /// First two bits hold the sampling mode; remaining 14 bits hold value of sampling interval
    pub sampling: u16,
}

impl PacketHeader {
    pub fn parse(data: &[u8]) -> Result<(PacketHeader, &[u8]), Error> {
        if data.len() < std::mem::size_of::<PacketHeader>() {
            return Err(ERROR_NOT_ENOUGH_DATA);
        }

        let mut reader = Cursor::new(data);

        Ok((
            PacketHeader {
                version: reader
                    .read_u16::<NetworkEndian>()
                    .map_err(|_| ERROR_NOT_ENOUGH_DATA)?,
                count: reader
                    .read_u16::<NetworkEndian>()
                    .map_err(|_| ERROR_NOT_ENOUGH_DATA)?,
                sys_uptime_msecs: reader
                    .read_u32::<NetworkEndian>()
                    .map_err(|_| ERROR_NOT_ENOUGH_DATA)?,
                unix_secs: reader
                    .read_u32::<NetworkEndian>()
                    .map_err(|_| ERROR_NOT_ENOUGH_DATA)?,
                unix_nsecs: reader
                    .read_u32::<NetworkEndian>()
                    .map_err(|_| ERROR_NOT_ENOUGH_DATA)?,
                sequence_number: reader
                    .read_u32::<NetworkEndian>()
                    .map_err(|_| ERROR_NOT_ENOUGH_DATA)?,
                engine_type: reader.read_u8().map_err(|_| ERROR_NOT_ENOUGH_DATA)?,
                engine_id: reader.read_u8().map_err(|_| ERROR_NOT_ENOUGH_DATA)?,
                sampling: reader
                    .read_u16::<NetworkEndian>()
                    .map_err(|_| ERROR_NOT_ENOUGH_DATA)?,
            },
            &data[std::mem::size_of::<PacketHeader>()..],
        ))
    }
}

#[cfg(test)]
mod test {
    use super::super::tests::{get_flow_packet_header, get_flow_packet_records, FLOW_PACKET_1};
    use super::*;

    #[test]
    fn packet_header_parsing_short() {
        let data = &FLOW_PACKET_1[..std::mem::size_of::<PacketHeader>() - 1];

        let res = PacketHeader::parse(data);
        assert!(res.is_err());
    }

    #[test]
    fn packet_header_parsing() {
        let (header, _rest) = PacketHeader::parse(&FLOW_PACKET_1).unwrap();

        println!("Version: {:?}", header.version);
        println!("Count: {:?}", header.count);
        println!("Uptime: {:?}", header.sys_uptime_msecs);
        println!("Unix (s): {:?}", header.unix_secs);
        println!("Unix (ns): {:?}", header.unix_nsecs);
        println!("Sequence: {:?}", header.sequence_number);
        println!("Engine type: {:?}", header.engine_type);
        println!("Engine id: {:?}", header.engine_id);
        println!("Sampling: {:?}", header.sampling);

        assert_eq!(header.version, 5);
        assert_eq!(header.count, 0x1d);
        assert_eq!(header.sys_uptime_msecs, 51469784);
        assert_eq!(header.unix_secs, 1544476581);
        assert_eq!(header.unix_nsecs, 0);
        assert_eq!(header.sequence_number, 873873830);
        assert_eq!(header.engine_type, 0);
        assert_eq!(header.engine_id, 0);
        assert_eq!(header.sampling, 1000);
    }
}
