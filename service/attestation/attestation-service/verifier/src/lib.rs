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
use serde_json;
use async_trait::async_trait;

use attester::{Evidence, TeeType};

#[cfg(feature = "itrustee-verifier")]
mod itrustee;

#[cfg(feature = "virtcca-verifier")]
mod virtcca;

#[derive(Debug, Default)]
pub struct Verifier {}

#[async_trait]
pub trait VerifierAPIs {
    async fn verify_evidence(&self, user_data: &[u8], evidence: &[u8]) -> Result<()>;
}

#[async_trait]
impl VerifierAPIs for Verifier {
    async fn verify_evidence(&self, user_data: &[u8], evidence: &[u8]) -> Result<()> {
        let aa_evidence: Evidence = serde_json::from_slice(evidence)?;
        let tee_type = aa_evidence.tee;
        let evidence = aa_evidence.evidence.as_bytes();
        match tee_type {
            #[cfg(feature = "itrustee-verifier")]
            TeeType::Itrustee => itrustee::ItrusteeVerifier::default().evaluate(user_data, evidence).await,
            #[cfg(feature = "virtcca-verifier")]
            TeeType::Virtcca => virtcca::VirtCCAVerifier::default().evaluate(user_data, evidence).await,
            _ => bail!("unsupported tee type:{:?}", tee_type),
        }
    }
}