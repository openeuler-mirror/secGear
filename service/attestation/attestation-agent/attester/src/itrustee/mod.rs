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

//! itrustee tee plugin
//!
//! Call the hardware sdk or driver to get the specific evidence

use anyhow::*;
use attestation_types::ItrusteeEvidence;
use base64_url;
use log;
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use std::fs;

use crate::ima;
use crate::EvidenceRequest;

mod itrustee;

#[derive(Debug, Default)]
pub struct ItrusteeAttester {}

impl ItrusteeAttester {
    pub async fn tee_get_evidence(&self, user_data: EvidenceRequest) -> Result<String> {
        let ret = itrustee_provision();
        if ret.is_err() {
            log::error!("itrustee attester provision failed");
            bail!("itrustee attester provision failed");
        }

        itrustee_get_evidence(user_data)
    }
}

pub fn detect_platform() -> bool {
    fs::read_to_string("/proc/modules")
        .map(|content| content.lines().any(|line| line.starts_with("tzdriver")))
        .unwrap_or(false)
}

#[derive(Serialize, Deserialize)]
struct ReportInputPayload {
    version: String,
    nonce: String,
    uuid: String,
    hash_alg: String,
    with_tcb: bool,
    request_key: bool,
}

#[derive(Serialize, Deserialize)]
struct ItrusteeInput {
    handler: String,
    payload: ReportInputPayload,
}

const MAX_CHALLENGE_LEN: usize = 64;
const MAX_CHALLENGE_LEN_IMA: usize = 32;
fn itrustee_get_evidence(user_data: EvidenceRequest) -> Result<String> {
    let challenge = base64_url::decode(&user_data.challenge)?;
    let len = challenge.len();
    let with_ima = match user_data.ima {
        Some(ima) => ima,
        None => false,
    };
    // If IMA is enabled, the challenge length is 32 bytes, otherwise it is 64 bytes
    // As we need 32 bytes to pass IMA log hash to the TEE.
    let max_challenge_len = if with_ima {
        MAX_CHALLENGE_LEN_IMA
    } else {
        MAX_CHALLENGE_LEN
    };
    if len <= 0 || len > max_challenge_len {
        log::error!(
            "challenge length is wrong, expecting 0 < len <= {}, got {}",
            max_challenge_len,
            len
        );
        bail!(
            "challenge length is wrong, expecting 0 < len <= {}, got {}",
            max_challenge_len,
            len
        );
    }

    let ima_log = if with_ima {
        ima::read_ima_log_if_requested(with_ima)?
    } else {
        None
    };

    let nonce = if with_ima {
        if ima_log.is_none() {
            log::error!("ima log is empty");
            bail!("ima log is empty");
        }

        // Calculate SHA256 hash of IMA log
        let mut hasher = Sha256::new();
        hasher.update(ima_log.as_ref().unwrap());
        let ima_log_hash = hasher.finalize();

        // Combine challenge and IMA log hash
        let mut combined = challenge.clone();
        combined.extend_from_slice(&ima_log_hash);
        base64_url::encode(&combined)
    } else {
        String::from_utf8(user_data.challenge)?
    };

    let payload = ReportInputPayload {
        nonce: nonce,
        uuid: user_data.uuid,
        with_tcb: false,
        request_key: true,
        version: String::from("TEE.RA.1.0"),
        hash_alg: String::from("HS256"),
    };

    let itrustee_input = ItrusteeInput {
        handler: String::from("report-input"),
        payload: payload,
    };
    let mut buf = serde_json::to_string(&itrustee_input)?;
    let mut input = itrustee::ra_buffer_data {
        size: buf.len() as ::std::os::raw::c_uint,
        buf: buf.as_mut_ptr() as *mut ::std::os::raw::c_uchar,
    };

    let mut report = Vec::new();
    report.resize(0x3000, b'\0');
    let mut output = itrustee::ra_buffer_data {
        size: report.len() as ::std::os::raw::c_uint,
        buf: report.as_mut_ptr() as *mut ::std::os::raw::c_uchar,
    };

    unsafe {
        let ret = itrustee::RemoteAttest(&mut input, &mut output);
        if ret != 0 {
            log::error!("itrustee get report failed, ret:{}", ret);
            bail!("itrustee get report failed, ret:{}", ret);
        }
        let out_len: usize = output.size.try_into()?;
        report.set_len(out_len);
    }
    let str_report = String::from_utf8(report)?;
    let final_report = ItrusteeEvidence {
        report: str_report,
        ima_log: ima_log,
    };

    let final_report_str = serde_json::to_string(&final_report)?;
    Ok(final_report_str)
}

fn itrustee_provision() -> Result<()> {
    let json = r#"{"handler":"provisioning-input","payload":{"version":"TEE.RA.1.0","scenario":"sce_no_as","hash_alg":"HS256"}}"#;

    let provision_input: serde_json::Value = serde_json::from_str(json)?;
    let mut provision_input = provision_input.to_string();

    let mut input = itrustee::ra_buffer_data {
        size: provision_input.len() as ::std::os::raw::c_uint,
        buf: provision_input.as_mut_ptr() as *mut ::std::os::raw::c_uchar,
    };

    let mut report = Vec::new();
    report.resize(0x3000, b'\0');

    let mut output = itrustee::ra_buffer_data {
        size: report.len() as ::std::os::raw::c_uint,
        buf: report.as_mut_ptr() as *mut ::std::os::raw::c_uchar,
    };
    unsafe {
        let ret = itrustee::RemoteAttest(&mut input, &mut output);
        if ret != 0 {
            log::error!("itrustee provision failed, ret:{}", ret);
            bail!("itrustee provision failed, ret:{}", ret);
        }
    }
    Ok(())
}
