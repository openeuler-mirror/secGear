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

use super::{file_reader, ImaVerifier};
use anyhow::{bail, Result};
use fallible_iterator::FallibleIterator;
use ima_measurements::{Event, EventData, Parser};
use serde_json::{json, Map, Value};

#[cfg(not(feature = "no_as"))]
const IMA_REFERENCE_FILE: &str =
    "/etc/attestation/attestation-service/verifier/virtcca/ima/digest_list_file";

// attestation agent local ima reference
#[cfg(feature = "no_as")]
const IMA_REFERENCE_FILE: &str =
    "/etc/attestation/attestation-agent/local_verifier/virtcca/ima/digest_list_file";

const CVM_REM_ARR_SIZE: usize = 4;

/// VirtCCA specific IMA verifier implementation
#[derive(Debug, Default)]
pub struct VirtCCAImaVerify {}

impl ImaVerifier for VirtCCAImaVerify {
    fn ima_verify(&self, ima_log: &[u8], cvm_rem: &[Vec<u8>]) -> Result<Value> {
        if ima_log.is_empty() {
            return Ok(json!({}));
        }

        let mut parser = Parser::new(ima_log);
        let mut events: Vec<Event> = Vec::new();
        while let Some(event) = parser.next()? {
            events.push(event);
        }

        if events.len() < 2 {
            bail!("No IMA measurement records for files found.");
        }
        
        let pcr_index = events[1].pcr_index;
        if pcr_index < 1 || pcr_index > CVM_REM_ARR_SIZE as u32 {
            bail!("Invalid pcr_index for IMA");
        }
        
        let ima_index = (pcr_index - 1) as usize;
        let pcr_values = parser.pcr_values();
        let pcr_value = pcr_values.get(&pcr_index).expect("PCR not measured");
        let string_pcr_sha256 = hex::encode(pcr_value.sha256);
        let string_ima_log_hash = hex::encode(cvm_rem[ima_index].clone());
        
        log::debug!(
            "pcr_index: {}, string_pcr_sha256: {}, string_ima_log_hash: {}",
            pcr_index, 
            string_pcr_sha256, 
            string_ima_log_hash
        );

        if string_pcr_sha256 != string_ima_log_hash {
            log::error!(
                "ima log verify failed string_pcr_sha256 {}, string_ima_log_hash {}",
                string_pcr_sha256,
                string_ima_log_hash
            );
            bail!("IMA log hash verification failed. Please check the log and reference data, and verify if PCR has been extended to PCR4.");
        }

        let ima_refs = file_reader(IMA_REFERENCE_FILE)?;

        let mut ima_detail = Map::new();
        // parser each file digest in ima log, and compare with reference base value
        for event in events {
            let (name, file_digest) = match event.data {
                EventData::ImaNg { digest, name } => (name, digest.digest),
                _ => bail!("Invalid event {:?}", event),
            };
            if name == "boot_aggregate".to_string() {
                continue;
            }
            let hex_str_digest = hex::encode(file_digest);
            if ima_refs.contains(&hex_str_digest) {
                ima_detail.insert(name, Value::Bool(true));
            } else {
                log::error!(
                    "there is no refernce base value of file digest {:?}",
                    hex_str_digest
                );
                ima_detail.insert(name, Value::Bool(false));
            }
        }
        
        let js_ima_detail: Value = ima_detail.into();
        log::debug!("ima verify detail result: {:?}", js_ima_detail);

        Ok(js_ima_detail)
    }
} 