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
use anyhow::{bail, Result};
use eventlog_rs::{self, Eventlog};
use hex;
use log;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;

#[cfg(not(feature = "no_as"))]
const EVENT_REFERENCE_FILE: &str =
    "/etc/attestation/attestation-service/verifier/virtcca/event/digest_list_file";

// attestation agent local event reference
#[cfg(feature = "no_as")]
const EVENT_REFERENCE_FILE: &str =
    "/etc/attestation/attestation-agent/local_verifier/virtcca/event/digest_list_file";

#[derive(Debug)]
pub struct FirmwareState {
    pub grub_image_count: u8,
    pub grub_image_list: Vec<String>,
    pub state_hash: HashMap<String, String>,
}

#[derive(Debug, Default)]
pub struct EventVerify {}

impl EventVerify {
    pub fn compare_rtmr_with_event_log(
        _replayed_rtmr: &HashMap<u32, Vec<u8>>,
        event_log_hash: &[Vec<u8>; CVM_REM_ARR_SIZE],
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

            if event_log_hash[index].len() != 32 {
                log::error!(
                    "EVENT_LOG_HASH[{}] hash length invalid: {}",
                    i,
                    event_log_hash[index].len()
                );
                return false;
            }

            // 如果哈希不匹配，记录详细信息
            if rtmr_value != &event_log_hash[index] {
                log::error!("RTMR[{}] and EVENT_LOG_HASH[{}] do not match.", i, index);
                log::debug!("RTMR[{}] = {}", i, hex::encode(rtmr_value));
                log::debug!(
                    "EVENT_LOG_HASH[{}] = {}",
                    index,
                    hex::encode(&event_log_hash[index])
                );
                return false;
            }

            log::debug!("RTMR[{}] = {}", i, hex::encode(rtmr_value));
            log::debug!(
                "EVENT_LOG_HASH[{}] = {}",
                index,
                hex::encode(&event_log_hash[index])
            );
        }

        log::info!("All RTMR values match EVENT log hashes.");
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
                state.grub_image_count += 1;
                state
                    .grub_image_list
                    .push(hex::encode(event_entry.digests[0].digest.clone()));
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
                        state.state_hash.insert(
                            key.to_string(),
                            hex::encode(event_entry.digests[0].digest.clone()),
                        );
                    }
                }

                if state.state_hash.len() == event_descs.len() {
                    break;
                }
            }
        }

        state
    }

    pub fn check_event_references(
        firmware_state: &FirmwareState,
        event_refs: &HashSet<String>,
    ) -> serde_json::Value {
        let mut event_detail: Map<String, Value> = Map::new();

        for (index, image) in firmware_state.grub_image_list.iter().enumerate() {
            let exists = event_refs.contains(image);
            let key = format!("Image[{}]", index);
            event_detail.insert(key, Value::Bool(exists));
            if !exists {
                log::debug!(
                    "GRUB Image[{}] ('{}') not found in EVENT reference set.",
                    index,
                    image
                );
            }
        }

        for (key, value) in firmware_state.state_hash.iter() {
            let exists = event_refs.contains(value);
            event_detail.insert(key.clone(), Value::Bool(exists));
            if !exists {
                log::debug!("'{}' : '{}' not found in EVENT reference set.", key, value);
            }
        }
        let js_event_detail: Value = event_detail.into();
        log::debug!("event event verify detail result: {:?}", js_event_detail);
        log::info!("event event verify Finished");
        js_event_detail
    }

    pub fn event_verify(
        event_log: Vec<u8>,
        event_log_hash: [Vec<u8>; CVM_REM_ARR_SIZE],
    ) -> Result<Value> {
        if event_log.is_empty() {
            return Ok(json!({}));
        }

        let event_parsed = eventlog_rs::Eventlog::try_from(event_log).unwrap();
        let _replayed_rtmr = event_parsed.replay_measurement_registry();

        if !EventVerify::compare_rtmr_with_event_log(&_replayed_rtmr, &event_log_hash) {
            log::error!("event log hash verify failed");
            bail!("event log hash verify failed");
        }

        let event_refs = file_reader(EVENT_REFERENCE_FILE)?;
        log::debug!("event reference file: {:?}", event_refs);

        let firmware_state: FirmwareState = EventVerify::firmware_log_state(&event_parsed);
        log::debug!("firmware state: {:?}", firmware_state);

        Ok(EventVerify::check_event_references(
            &firmware_state,
            &event_refs,
        ))
    }
}
