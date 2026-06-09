// Copyright (c) 2023-2024 Arm Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
use super::tsm_report::*;
use crate::EvidenceRequest;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default)]
pub struct CcaAttester {}

const CCA_CHALLENGE_SIZE: usize = 64;

pub fn detect_platform() -> bool {
    #[cfg(target_arch = "aarch64")]
    return TsmReportPath::new(TsmReportProvider::Cca).is_ok();
    #[cfg(not(target_arch = "aarch64"))]
    return false;
}

#[derive(Serialize, Deserialize)]
struct CcaEvidence {
    /// CCA token
    token: Vec<u8>,
}

impl CcaAttester {
    pub async fn tee_get_evidence(&self, user_data: EvidenceRequest) -> Result<String> {
        let mut challenge = base64_url::decode(&user_data.challenge)?;

        if challenge.len() > CCA_CHALLENGE_SIZE {
            bail!("CCA Attester: Challenge size must be {CCA_CHALLENGE_SIZE} bytes or less.");
        }

        // 将 challenge 填充到固定大小
        challenge.resize(CCA_CHALLENGE_SIZE, 0);

        // 获取 TSM 报告
        let tsm = TsmReportPath::new(TsmReportProvider::Cca)?;
        let token = tsm.attestation_report(TsmReportData::Cca(challenge))?;

        // 构造 CCA 证据
        let evidence = CcaEvidence { token };

        // 序列化为 JSON 字符串
        let ev =
            serde_json::to_string(&evidence).context("Serialization of CCA evidence failed")?;

        // 将 JSON 字符串进行 base64_url 编码
        let ev_str = base64_url::encode(&ev);

        Ok(ev_str)
    }
}
