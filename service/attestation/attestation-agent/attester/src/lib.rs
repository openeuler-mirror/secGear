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

//! attester
//!
//! This crate provides unified APIs to get TEE evidence.

use anyhow::*;
use async_trait::async_trait;
use log;

#[cfg(feature = "itrustee-attester")]
mod itrustee;

#[cfg(feature = "virtcca-attester")]
pub mod virtcca;

#[derive(Debug, Clone)]
pub struct EvidenceRequest {
    pub uuid: String,
    pub challenge: Vec<u8>,
    pub ima: Option<bool>,
}

#[async_trait]
pub trait AttesterAPIs {
    /// Call tee plugin to get the hardware evidence.
    /// Automatically detect the TEE type of the current running environment.
    async fn tee_get_evidence(&self, user_data: EvidenceRequest) -> Result<Vec<u8>>;
}

#[derive(Default)]
pub struct Attester {}

const MAX_CHALLENGE_LEN: usize = 64;

#[async_trait]
impl AttesterAPIs for Attester {
    async fn tee_get_evidence(&self, _user_data: EvidenceRequest) -> Result<Vec<u8>> {
        let len = _user_data.challenge.len();
        if len <= 0 || len > MAX_CHALLENGE_LEN {
            log::error!(
                "challenge len is error, expecting 0 < len <= {}, got {}",
                MAX_CHALLENGE_LEN,
                len
            );
            bail!(
                "challenge len is error, expecting 0 < len <= {}, got {}",
                MAX_CHALLENGE_LEN,
                len
            );
        }
        #[cfg(feature = "itrustee-attester")]
        if itrustee::detect_platform() {
            let evidence = itrustee::ItrusteeAttester::default()
                .tee_get_evidence(_user_data)
                .await?;
            let aa_evidence = attestation_types::Evidence {
                tee: attestation_types::TeeType::Itrustee,
                evidence: evidence,
            };
            let evidence = serde_json::to_vec(&aa_evidence)?;

            return Ok(evidence);
        }
        #[cfg(feature = "virtcca-attester")]
        if virtcca::detect_platform() {
            let evidence = virtcca::VirtccaAttester::default()
                .tee_get_evidence(_user_data)
                .await?;
            let aa_evidence = attestation_types::Evidence {
                tee: attestation_types::TeeType::Virtcca,
                evidence: evidence,
            };
            let evidence = serde_json::to_vec(&aa_evidence)?;
            return Ok(evidence);
        }
        bail!("unknown tee platform");
    }
}
