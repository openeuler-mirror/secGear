/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
*/

use super::CVM_REM_ARR_SIZE;
use crate::ima::file_reader;
use anyhow::{anyhow, bail, Result};
use attestation_types::UefiLog;
use eventlog_rs::{self, Eventlog};
use hex;
use log;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;

#[cfg(not(feature = "no_as"))]
const UEFI_REFERENCE_FILE: &str =
    "/etc/attestation/attestation-service/verifier/virtcca/uefi/digest_list_file";

// attestation agent local uefi reference
#[cfg(feature = "no_as")]
const UEFI_REFERENCE_FILE: &str =
    "/etc/attestation/attestation-agent/local_verifier/virtcca/uefi/digest_list_file";

#[derive(Debug)]
pub struct FirmwareState {
    pub grub_image_count: u8,
    pub grub_image_list: Vec<String>,
    pub state_hash: HashMap<String, String>,
}

#[derive(Debug, Default)]
pub struct UefiVerify {}

impl UefiVerify {
    pub fn compare_rtmr_with_uefi_log(
        _replayed_rtmr: &HashMap<u32, Vec<u8>>,
        uefi_log_hash: &[Vec<u8>; CVM_REM_ARR_SIZE],
    ) -> bool {
        for i in 1..CVM_REM_ARR_SIZE as u32 {
            let index = i as usize - 1;

            // 获取 RTMR 值
            let Some(rtmr_value) = _replayed_rtmr.get(&i) else {
                log::error!("RTMR[{}] not found in hashmap", i);
                return false;
            };

            // 检查长度是否为 SHA256 (32 bytes)
            if rtmr_value.len() != 32 {
                log::error!("RTMR[{}] hash length invalid: {}", i, rtmr_value.len());
                return false;
            }

            if uefi_log_hash[index].len() != 32 {
                log::error!(
                    "UEFI_LOG_HASH[{}] hash length invalid: {}",
                    i,
                    uefi_log_hash[index].len()
                );
                return false;
            }

            // 如果哈希不匹配，记录详细信息
            if rtmr_value != &uefi_log_hash[index] {
                log::error!("RTMR[{}] and UEFI_LOG_HASH[{}] do not match.", i, index);
                log::debug!("RTMR[{}] = {}", i, hex::encode(rtmr_value));
                log::debug!(
                    "UEFI_LOG_HASH[{}] = {}",
                    index,
                    hex::encode(&uefi_log_hash[index])
                );
                return false;
            }

            log::debug!("RTMR[{}] = {}", i, hex::encode(rtmr_value));
            log::debug!(
                "UEFI_LOG_HASH[{}] = {}",
                index,
                hex::encode(&uefi_log_hash[index])
            );
        }

        log::info!("All RTMR values match UEFI log hashes.");
        true
    }

    pub fn firmware_log_state(event_log: &Eventlog) -> FirmwareState {
        let grub_event_type: &str = "EV_EFI_BOOT_SERVICES_APPLICATION";
        let exclude_event_descs: &[&str] = &["grub_cmd:"];
        let event_descs: HashMap<_, _> = HashMap::from([
            ("grub_cfg", "grub.cfg"),
            ("kernel", "/vmlinuz-"),
            ("initramfs", "/initramfs-"),
        ]);

        let mut state = FirmwareState {
            grub_image_count: 0,
            grub_image_list: vec![],
            state_hash: HashMap::new(),
        };

        //based event_type get grub image info
        for event_entry in event_log.log.iter() {
            if event_entry.event_type == grub_event_type {
                let Some(digest) = event_entry
                    .digests
                    .first()
                    .filter(|digest| !digest.digest.is_empty())
                else {
                    log::warn!("Skipping UEFI GRUB image event without digest");
                    continue;
                };
                state.grub_image_count += 1;
                state.grub_image_list.push(hex::encode(&digest.digest));
            } else {
                let event_desc = match std::str::from_utf8(&event_entry.event_desc) {
                    Ok(s) => s,
                    Err(_) => continue,
                };

                if exclude_event_descs.iter().any(|&s| event_desc.contains(s)) {
                    continue;
                }

                for (&key, &pattern) in event_descs.iter() {
                    if state.state_hash.contains_key(key) {
                        continue;
                    }

                    if event_desc.contains(pattern) {
                        let Some(digest) = event_entry
                            .digests
                            .first()
                            .filter(|digest| !digest.digest.is_empty())
                        else {
                            log::warn!("Skipping UEFI event '{key}' without digest");
                            continue;
                        };
                        state
                            .state_hash
                            .insert(key.to_string(), hex::encode(&digest.digest));
                    }
                }

                if state.state_hash.len() == event_descs.len() {
                    break;
                }
            }
        }

        state
    }

    fn validate_event_log_digests(event_log: &Eventlog) -> Result<()> {
        for (index, event_entry) in event_log.log.iter().enumerate() {
            match event_entry.digests.first() {
                Some(digest) if !digest.digest.is_empty() => {}
                Some(_) => bail!("UEFI event log entry {index} has an empty digest"),
                None => bail!("UEFI event log entry {index} has no digest"),
            }
        }

        Ok(())
    }

    pub fn check_uefi_references(
        firmware_state: &FirmwareState,
        uefi_refs: &HashSet<String>,
    ) -> serde_json::Value {
        let mut uefi_detail: Map<String, Value> = Map::new();

        for (index, image) in firmware_state.grub_image_list.iter().enumerate() {
            let exists = uefi_refs.contains(image);
            let key = format!("Image[{}]", index);
            uefi_detail.insert(key, Value::Bool(exists));
            if !exists {
                log::debug!(
                    "GRUB Image[{}] ('{}') not found in UEFI reference set.",
                    index,
                    image
                );
            }
        }

        for (key, value) in firmware_state.state_hash.iter() {
            let exists = uefi_refs.contains(value);
            uefi_detail.insert(key.clone(), Value::Bool(exists));
            if !exists {
                log::debug!("'{}' : '{}' not found in UEFI reference set.", key, value);
            }
        }
        let js_uefi_detail: Value = uefi_detail.into();
        log::debug!("uefi event verify detail result: {:?}", js_uefi_detail);
        log::info!("uefi event verify Finished");
        js_uefi_detail
    }

    pub fn uefi_verify(
        &self,
        uefi_log: UefiLog,
        uefi_log_hash: [Vec<u8>; CVM_REM_ARR_SIZE],
    ) -> Result<Value> {
        if uefi_log.ccel_data.is_empty() {
            return Ok(json!({}));
        }

        let event_log = eventlog_rs::Eventlog::try_from(uefi_log.ccel_data)
            .map_err(|err| anyhow!("failed to parse UEFI event log: {err}"))?;
        UefiVerify::validate_event_log_digests(&event_log)?;
        let _replayed_rtmr = event_log.replay_measurement_registry();

        if !UefiVerify::compare_rtmr_with_uefi_log(&_replayed_rtmr, &uefi_log_hash) {
            log::error!("uefi log hash verify failed");
            bail!("uefi log hash verify failed");
        }

        let uefi_refs = file_reader(UEFI_REFERENCE_FILE)?;
        log::debug!("uefi reference file: {:?}", uefi_refs);

        let firmware_state: FirmwareState = UefiVerify::firmware_log_state(&event_log);
        log::debug!("firmware state: {:?}", firmware_state);

        Ok(UefiVerify::check_uefi_references(
            &firmware_state,
            &uefi_refs,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eventlog_rs::{ElDigest, EventlogEntry};

    fn event_entry(event_type: &str, digests: Vec<ElDigest>, event_desc: &[u8]) -> EventlogEntry {
        EventlogEntry {
            target_measurement_registry: 1,
            event_type_id: 0x80000003,
            event_type: event_type.to_string(),
            digests,
            event_desc: event_desc.to_vec(),
        }
    }

    fn ccel_data_with_empty_digest_entry() -> Vec<u8> {
        let mut ccel_data = Vec::new();
        ccel_data.extend_from_slice(&1u32.to_le_bytes());
        ccel_data.extend_from_slice(&4u32.to_le_bytes());
        ccel_data.extend_from_slice(&0u32.to_le_bytes());
        ccel_data.extend_from_slice(&0u32.to_le_bytes());
        ccel_data
    }

    #[test]
    fn event_log_digest_validation_rejects_entries_without_digests() {
        let event_log = Eventlog {
            log: vec![event_entry("EV_EFI_BOOT_SERVICES_APPLICATION", vec![], b"")],
        };

        assert!(UefiVerify::validate_event_log_digests(&event_log).is_err());
    }

    #[test]
    fn event_log_digest_validation_rejects_empty_digest_bytes() {
        let event_log = Eventlog {
            log: vec![event_entry(
                "EV_EFI_BOOT_SERVICES_APPLICATION",
                vec![ElDigest {
                    algorithm: "TPM_ALG_SHA256".to_string(),
                    digest: vec![],
                }],
                b"",
            )],
        };

        assert!(UefiVerify::validate_event_log_digests(&event_log).is_err());
    }

    #[test]
    fn firmware_log_state_ignores_entries_without_digests() {
        let event_log = Eventlog {
            log: vec![
                event_entry("EV_EFI_BOOT_SERVICES_APPLICATION", vec![], b""),
                event_entry("EV_SEPARATOR", vec![], b"/vmlinuz-test"),
            ],
        };

        let state = UefiVerify::firmware_log_state(&event_log);

        assert_eq!(state.grub_image_count, 0);
        assert!(state.grub_image_list.is_empty());
        assert!(state.state_hash.is_empty());
    }

    #[test]
    fn uefi_verify_rejects_entries_without_digests_before_replay() {
        let verifier = UefiVerify::default();
        let uefi_log = UefiLog {
            ccel_table: vec![],
            ccel_data: ccel_data_with_empty_digest_entry(),
        };
        let uefi_log_hash = std::array::from_fn(|_| vec![0; 32]);

        let result = std::panic::catch_unwind(|| verifier.uefi_verify(uefi_log, uefi_log_hash));

        assert!(result.is_ok(), "uefi_verify should return Err, not panic");
        assert!(result.unwrap().is_err());
    }
}
