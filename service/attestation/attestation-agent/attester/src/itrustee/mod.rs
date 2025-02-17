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
use base64_url;
use log;
use serde::{Deserialize, Serialize};
use serde_json;
use std::path::Path;

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
    Path::new("/usr/bin/tee").exists()
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
fn itrustee_get_evidence(user_data: EvidenceRequest) -> Result<String> {
    let challenge = base64_url::decode(&user_data.challenge)?;
    let len = challenge.len();
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
    let payload = ReportInputPayload {
        nonce: String::from_utf8(user_data.challenge)?,
        uuid: user_data.uuid,
        with_tcb: false,
        request_key: true,
        version: String::from("TEE.RA.1.0"),
        hash_alg: String::from("HS256"),
    };

    let itrustee_input: ItrusteeInput = ItrusteeInput {
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

    Ok(str_report)
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
