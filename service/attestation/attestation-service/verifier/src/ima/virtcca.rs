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

use super::{file_reader, verify_ima_events, ImaVerifier};
use anyhow::{anyhow, bail, Result};
use fallible_iterator::FallibleIterator;
use ima_measurements::{Event, Parser};
use serde_json::{json, Value};

#[cfg(not(feature = "no_as"))]
const IMA_REFERENCE_FILE: &str =
    "/etc/attestation/attestation-service/verifier/virtcca/ima/digest_list_file";
#[cfg(not(feature = "no_as"))]
const IMA_BASE_DIR: &str = "/etc/attestation/attestation-service/verifier/virtcca/ima";

// attestation agent local ima reference
#[cfg(feature = "no_as")]
const IMA_REFERENCE_FILE: &str =
    "/etc/attestation/attestation-agent/local_verifier/virtcca/ima/digest_list_file";
#[cfg(feature = "no_as")]
const IMA_BASE_DIR: &str = "/etc/attestation/attestation-agent/local_verifier/virtcca/ima";

const DIGEST_LIST_FILE_NAME: &str = "digest_list_file";
const CVM_REM_ARR_SIZE: usize = 4;
const MIN_IMA_EVENTS: usize = 2;
const RIM_HEX_LEN_SHA256: usize = 64;
const RIM_HEX_LEN_SHA384: usize = 96;
const RIM_HEX_LEN_SHA512: usize = 128;

/// VirtCCA specific IMA verifier implementation
#[derive(Debug, Default)]
pub struct VirtCCAImaVerify {}

impl ImaVerifier for VirtCCAImaVerify {
    fn ima_verify(
        &self,
        ima_log: &[u8],
        cvm_rem: &[Vec<u8>],
        app_id: Option<&str>,
    ) -> Result<Value> {
        if ima_log.is_empty() {
            return Ok(json!({}));
        }

        // Parse IMA events
        let mut parser = Parser::new(ima_log);
        let mut events: Vec<Event> = Vec::new();
        while let Some(event) = parser.next()? {
            events.push(event);
        }

        if events.len() < MIN_IMA_EVENTS {
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
                "ima log verify failed app_id={:?} string_pcr_sha256 {} string_ima_log_hash {}",
                app_id,
                string_pcr_sha256,
                string_ima_log_hash
            );
            bail!("IMA log hash verification failed. Please check the log and reference data, and verify if PCR has been extended to PCR4.");
        }

        let ref_path = Self::get_ima_reference_file_path(app_id);
        let ima_refs: std::collections::HashSet<String> = file_reader(&ref_path)
            .map_err(|err| anyhow!("Failed to read {}: {}", ref_path, err))?
            .into_iter()
            .collect();
        log::debug!(
            "ima reference loaded for app_id {:?} from {} entries={}",
            app_id,
            ref_path,
            ima_refs.len()
        );

        // Use the common function to verify IMA events
        verify_ima_events(&events, &ima_refs)
    }
}

impl VirtCCAImaVerify {
    fn get_ima_reference_file_path(app_id: Option<&str>) -> String {
        if let Some(app_id) = app_id {
            if !Self::is_valid_rim_hex(app_id) {
                log::warn!(
                    "invalid rim app_id {}, fallback to default reference",
                    app_id
                );
                return IMA_REFERENCE_FILE.to_string();
            }
            let app_path = format!("{}/{}/{}", IMA_BASE_DIR, app_id, DIGEST_LIST_FILE_NAME);
            if std::path::Path::new(&app_path).exists() {
                return app_path;
            }
            log::warn!(
                "app specific ima reference not found, app_id={}, path={}, fallback default",
                app_id,
                app_path
            );
        }
        IMA_REFERENCE_FILE.to_string()
    }

    fn is_valid_rim_hex(s: &str) -> bool {
        matches!(
            s.len(),
            RIM_HEX_LEN_SHA256 | RIM_HEX_LEN_SHA384 | RIM_HEX_LEN_SHA512
        ) && s.chars().all(|c| c.is_ascii_hexdigit())
    }
}
