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

//! Unified tee verifier
//!
//! This crate provides unified APIs to verify TEE evidence.

use anyhow::*;
use async_trait::async_trait;
use serde_json;

use attestation_types::{Evidence, TeeType};

#[cfg(feature = "itrustee-verifier")]
pub mod itrustee;

#[cfg(feature = "virtcca-verifier")]
pub mod virtcca;

#[cfg(feature = "rustcca-verifier")]
pub mod rustcca;

pub type TeeClaim = serde_json::Value;

#[derive(Debug, Default)]
pub struct Verifier {}

#[async_trait]
pub trait VerifierAPIs {
    async fn verify_evidence(&self, user_data: &[u8], evidence: &[u8]) -> Result<TeeClaim>;
}

#[async_trait]
impl VerifierAPIs for Verifier {
    async fn verify_evidence(&self, user_data: &[u8], evidence: &[u8]) -> Result<TeeClaim> {

        let aa_evidence: Evidence = serde_json::from_slice(evidence)?;
        let tee_type = aa_evidence.tee;
        let evidence = aa_evidence.evidence.as_bytes();
        match tee_type {
            #[cfg(feature = "itrustee-verifier")]
            TeeType::Itrustee => {
                itrustee::ItrusteeVerifier::default()
                    .evaluate(user_data, evidence)
                    .await
            }
            #[cfg(feature = "virtcca-verifier")]
            TeeType::Virtcca => {
                virtcca::VirtCCAVerifier::default()
                    .evaluate(user_data, evidence)
                    .await
            }
            #[cfg(feature = "rustcca-verifier")]
            TeeType::Rustcca => {
                rustcca::RustCCAVerifier::default()
                    .evaluate(user_data, evidence)
                    .await
            }
            _ => bail!("unsupported tee type:{:?}", tee_type),
        }
    }
}

#[cfg(feature = "no_as")]
pub fn virtcca_parse_evidence(evidence: &[u8]) -> Result<TeeClaim> {
    let aa_evidence: Evidence = serde_json::from_slice(evidence)?;
    let evidence = aa_evidence.evidence.as_bytes();

    return virtcca::Evidence::parse_evidence(evidence);
}
