// TCG Eventlog for Conventional BIOS
// Spec: https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf

use crate::enums::EVENTLOG_TYPES;
use anyhow::*;
use byteorder::{LittleEndian, ReadBytesExt};
use core::fmt;
use std::convert::TryFrom;

const SHA1_DIGEST_SIZE: usize = 20;

#[derive(Clone)]
pub struct BiosEventlog {
    pub log: Vec<BiosEventlogEntry>,
}

impl fmt::Display for BiosEventlog {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut parsed_el = String::default();
        for event_entry in self.log.clone() {
            parsed_el = format!(
                "{}\nEvent Entry:\n\tPCR: {}\n\tEvent Type: {}\n\tDigest: {}\n\tEvent Data: {}\n",
                parsed_el,
                event_entry.pcr_index,
                event_entry.event_type,
                hex::encode(event_entry.digest.clone()),
                String::from_utf8(event_entry.event_data.clone())
                    .unwrap_or_else(|_| hex::encode(event_entry.event_data.clone())),
            );
        }

        write!(f, "{parsed_el}")
    }
}

#[derive(Clone)]
pub struct BiosEventlogEntry {
    pub pcr_index: u32,
    pub event_type: String,
    pub digest: Vec<u8>,
    pub event_data: Vec<u8>,
}

impl TryFrom<Vec<u8>> for BiosEventlog {
    type Error = anyhow::Error;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        let mut index = 0;
        let mut event_log: Vec<BiosEventlogEntry> = Vec::new();

        while index < data.len() as usize {
            let stop_flag = (&data[index..(index + 8)]).read_u64::<LittleEndian>()?;
            let pcr_index = (&data[index..(index + 4)]).read_u32::<LittleEndian>()?;
            index += 4;

            let event_type_num = (&data[index..(index + 4)]).read_u32::<LittleEndian>()?;
            index += 4;
            let event_type = match EVENTLOG_TYPES.get(&event_type_num) {
                Some(type_name) => type_name.to_string(),
                None => format!("UNKOWN_TYPE: {:x}", &event_type_num),
            };

            if stop_flag == 0xFFFFFFFFFFFFFFFF || stop_flag == 0x0000000000000000 {
                break;
            }

            let digest = data[index..(index + SHA1_DIGEST_SIZE)].to_vec();
            index += SHA1_DIGEST_SIZE;

            let event_data_size = (&data[index..(index + 4)]).read_u32::<LittleEndian>()? as usize;
            index += 4;
            let event_data = data[index..(index + event_data_size)].to_vec();
            index += event_data_size;

            let eventlog_entry = BiosEventlogEntry {
                pcr_index,
                event_type,
                digest,
                event_data,
            };

            event_log.push(eventlog_entry)
        }

        Ok(BiosEventlog { log: event_log })
    }
}
