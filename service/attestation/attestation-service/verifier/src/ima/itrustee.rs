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
use ima_measurements::Event;
use openssl::sha::sha256;
use serde_json::Value;

#[cfg(not(feature = "no_as"))]
const IMA_REFERENCE_FILE: &str =
    "/etc/attestation/attestation-service/verifier/itrustee/ima/digest_list_file";

// attestation agent local ima reference
#[cfg(feature = "no_as")]
const IMA_REFERENCE_FILE: &str =
    "/etc/attestation/attestation-agent/local_verifier/itrustee/ima/digest_list_file";

/// iTrustee specific hash verifier implementation
#[derive(Debug, Default)]
pub struct ItrusteeHashVerifier {
    ima_log_hash: Vec<Vec<u8>>,
}

impl ItrusteeHashVerifier {
    pub fn new(ima_log_hash: Vec<Vec<u8>>) -> Self {
        Self { ima_log_hash }
    }
}

impl HashVerifier for ItrusteeHashVerifier {
    fn verify_hash(&self, ima_log: &[u8], _events: &[Event]) -> Result<()> {
        // Verify that ima_log_hash array is not empty before accessing
        if self.ima_log_hash.is_empty() {
            bail!("ima_log_hash array is empty");
        }

        // Calculate the sha256sum of the ima log and compare with the expected hash
        let ima_log_hashsum = sha256(ima_log);
        if ima_log_hashsum.to_vec() != self.ima_log_hash[0] {
            log::error!("ima log hash verification failed, sha256sum not match. \
                        ima_log_hashsum: {:?}, ima_log_hash: {:?}", ima_log_hashsum, self.ima_log_hash[0]);
            bail!("ima log hash verification failed, sha256sum not match. \
                        ima_log_hashsum: {:?}, ima_log_hash: {:?}", ima_log_hashsum, self.ima_log_hash[0]);
        }

        Ok(())
    }
}

/// iTrustee specific IMA verifier implementation
#[derive(Debug, Default)]
pub struct ItrusteeImaVerify {}

impl ImaVerifier for ItrusteeImaVerify {
    fn ima_verify(&self, ima_log: &[u8], ima_log_hash: &[Vec<u8>]) -> Result<Value> {
        let common_verifier = CommonImaVerifier::new(IMA_REFERENCE_FILE.to_string());
        let hash_verifier = ItrusteeHashVerifier::new(ima_log_hash.to_vec());
        
        common_verifier.verify_ima(ima_log, &hash_verifier)
    }
} 