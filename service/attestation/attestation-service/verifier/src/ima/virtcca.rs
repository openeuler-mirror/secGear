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

use super::{CommonImaVerifier, HashVerifier, ImaVerifier};
use anyhow::{bail, Result};
use ima_measurements::{Event, Parser};
use serde_json::Value;

#[cfg(not(feature = "no_as"))]
const IMA_REFERENCE_FILE: &str =
    "/etc/attestation/attestation-service/verifier/virtcca/ima/digest_list_file";

// attestation agent local ima reference
#[cfg(feature = "no_as")]
const IMA_REFERENCE_FILE: &str =
    "/etc/attestation/attestation-agent/local_verifier/virtcca/ima/digest_list_file";

const CVM_REM_ARR_SIZE: usize = 4;

/// VirtCCA specific hash verifier implementation
#[derive(Debug, Default)]
pub struct VirtCCAHashVerifier {
    cvm_rem: Vec<Vec<u8>>,
}

impl VirtCCAHashVerifier {
    pub fn new(cvm_rem: Vec<Vec<u8>>) -> Self {
        Self { cvm_rem }
    }
}

impl HashVerifier for VirtCCAHashVerifier {
    fn verify_hash(&self, _ima_log: &[u8], events: &[Event]) -> Result<()> {
        let pcr_index = events[1].pcr_index;
        if pcr_index < 1 || pcr_index > CVM_REM_ARR_SIZE as u32 {
            bail!("Invalid pcr_index for IMA");
        }
        
        let ima_index = (pcr_index - 1) as usize;
        if ima_index >= self.cvm_rem.len() {
            bail!("ima_index {} out of bounds for cvm_rem array of size {}", ima_index, self.cvm_rem.len());
        }
        
        let parser = Parser::new(_ima_log);
        let pcr_values = parser.pcr_values();
        let pcr_value = pcr_values.get(&pcr_index).expect("PCR not measured");
        let string_pcr_sha256 = hex::encode(pcr_value.sha256);
        let string_ima_log_hash = hex::encode(self.cvm_rem[ima_index].clone());
        
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

        Ok(())
    }
}

/// VirtCCA specific IMA verifier implementation
#[derive(Debug, Default)]
pub struct VirtCCAImaVerify {}

impl ImaVerifier for VirtCCAImaVerify {
    fn ima_verify(&self, ima_log: &[u8], cvm_rem: &[Vec<u8>]) -> Result<Value> {
        let common_verifier = CommonImaVerifier::new(IMA_REFERENCE_FILE.to_string());
        let hash_verifier = VirtCCAHashVerifier::new(cvm_rem.to_vec());
        
        common_verifier.verify_ima(ima_log, &hash_verifier)
    }
} 