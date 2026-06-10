use anyhow::{anyhow, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use core::fmt;
use enums::{EVENTLOG_TYPES, TCG_ALGORITHMS};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::convert::TryFrom;

const RTMR_LENGTH_BY_BYTES: usize = 32;

mod bios_eventlog;
mod enums;

pub use bios_eventlog::BiosEventlog;
pub mod read;

#[derive(Clone)]
pub struct Eventlog {
    pub log: Vec<EventlogEntry>,
}

impl fmt::Display for Eventlog {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut parsed_el = String::default();
        for event_entry in self.log.clone() {
            parsed_el = format!(
                "{}\nEvent Entry:\nPCR(CC Event Log MR): {}\n\tEvent Type id: 0x{:08X}\n\tEvent Type: {}\n\tDigest Algorithm: {}\n\tDigest: {}\n\tEvent Desc: {}\n",
                parsed_el,
                event_entry.target_measurement_registry,
                event_entry.event_type_id,
                event_entry.event_type,
                event_entry.digests[0].algorithm,
                hex::encode(event_entry.digests[0].digest.clone()),
                String::from_utf8(event_entry.event_desc.clone())
                    .unwrap_or_else(|_| hex::encode(event_entry.event_desc.clone())),
            );
        }

        write!(f, "{parsed_el}")
    }
}

#[derive(Clone)]
pub struct EventlogEntry {
    pub target_measurement_registry: u32,
    pub event_type_id: u32,
    pub event_type: String,
    pub digests: Vec<ElDigest>,
    pub event_desc: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ElDigest {
    pub algorithm: String,
    pub digest: Vec<u8>,
}

impl Eventlog {
    pub fn replay_measurement_registry(&self) -> HashMap<u32, Vec<u8>> {
        // result dictionary for classifying event logs by rtmr index
        // the key is a integer, which represents rtmr index
        // the value is a list of event log entries whose rtmr index is equal to its related key
        let mut event_logs_by_mr_index: HashMap<u32, Vec<EventlogEntry>> = HashMap::new();

        let mut result: HashMap<u32, Vec<u8>> = HashMap::new();

        for log_entry in self.log.iter() {
            match event_logs_by_mr_index.get_mut(&log_entry.target_measurement_registry) {
                Some(logs) => logs.push(log_entry.clone()),
                None => {
                    event_logs_by_mr_index.insert(
                        log_entry.target_measurement_registry,
                        vec![log_entry.clone()],
                    );
                }
            }
        }

        for (mr_index, log_set) in event_logs_by_mr_index.iter() {
            let mut mr_value = [0; RTMR_LENGTH_BY_BYTES];

            for log in log_set.iter() {
                let digest = &log.digests[0].digest;
                let mut sha_algo = Sha256::new();
                sha_algo.update(mr_value);
                sha_algo.update(digest.as_slice());
                mr_value.copy_from_slice(sha_algo.finalize().as_slice());
            }
            result.insert(*mr_index, mr_value.to_vec());
        }

        result
    }
}

impl TryFrom<Vec<u8>> for Eventlog {
    type Error = anyhow::Error;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        let mut index = 0;
        let mut event_log: Vec<EventlogEntry> = Vec::new();
        let mut digest_size_map: HashMap<u16, u16> = HashMap::new();

        while index < data.len() {
            let stop_flag = (&data[index..(index + 8)]).read_u64::<LittleEndian>()?;
            let target_measurement_registry =
                (&data[index..(index + 4)]).read_u32::<LittleEndian>()?;
            index += 4;

            let event_type_num = (&data[index..(index + 4)]).read_u32::<LittleEndian>()?;
            index += 4;
            let event_type = match EVENTLOG_TYPES.get(&event_type_num) {
                Some(type_name) => type_name.to_string(),
                None => format!("UNKNOWN_TYPE: {:x}", &event_type_num),
            };

            let event_type_id = event_type_num;
            if event_type == "EV_NO_ACTION" {
                index += 48;
                let algo_number = (&data[index..(index + 4)]).read_u32::<LittleEndian>()?;
                index += 4;
                for _ in 0..algo_number {
                    digest_size_map.insert(
                        (&data[index..(index + 2)]).read_u16::<LittleEndian>()?,
                        (&data[(index + 2)..(index + 4)]).read_u16::<LittleEndian>()?,
                    );
                    index += 4;
                }
                let vendor_size = data[index];
                index += vendor_size as usize + 1;
                continue;
            }

            if stop_flag == 0xFFFFFFFFFFFFFFFF || stop_flag == 0x0000000000000000 {
                break;
            }

            let digest_count = (&data[index..(index + 4)]).read_u32::<LittleEndian>()?;
            index += 4;
            let mut digests: Vec<ElDigest> = Vec::new();
            for _ in 0..digest_count {
                let digest_algo_num = (&data[index..(index + 2)]).read_u16::<LittleEndian>()?;
                index += 2;
                let algorithm = match TCG_ALGORITHMS.get(&digest_algo_num) {
                    Some(digest_algo_name) => digest_algo_name.to_string(),
                    None => format!("UNKNOWN_ALGORITHM: {:x}", &digest_algo_num),
                };
                let digest_size = digest_size_map
                    .get(&digest_algo_num)
                    .ok_or(anyhow!(
                        "Internal Error: get digest size failed when parse eventlog entry, digest_algo_num: {:?}", &digest_algo_num
                    ))?
                    .to_owned() as usize;
                let digest = data[index..(index + digest_size)].to_vec();
                index += digest_size;
                digests.push(ElDigest { algorithm, digest });
            }

            let event_desc_size = (&data[index..(index + 4)]).read_u32::<LittleEndian>()? as usize;
            index += 4;
            let event_desc = data[index..(index + event_desc_size)].to_vec();
            index += event_desc_size;

            let eventlog_entry = EventlogEntry {
                target_measurement_registry,
                event_type_id,
                event_type,
                digests,
                event_desc,
            };

            event_log.push(eventlog_entry)
        }

        Ok(Eventlog { log: event_log })
    }
}
