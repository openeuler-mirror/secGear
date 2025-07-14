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

//! itrustee verifier plugin

use super::*;
use log;
use serde_json::json;
use std::ops::Add;
use std::path::Path;
use crate::ima::ImaVerifier;
use attestation_types::ItrusteeEvidence;

mod itrustee;

const ITRUSTEE_REF_VALUE_DIR: &str =
    "/etc/attestation/attestation-service/verifier/itrustee";
const MAX_CHALLENGE_LEN: usize = 64;

#[derive(Debug, Default)]
pub struct ItrusteeVerifier {}

impl ItrusteeVerifier {
    pub async fn evaluate(&self, user_data: &[u8], evidence: &[u8]) -> Result<TeeClaim> {
        return evaluate_wrapper(user_data, evidence);
    }
}

fn evaluate_wrapper(user_data: &[u8], evidence: &[u8]) -> Result<TeeClaim> {
    let challenge = base64_url::decode(user_data)?;
    let evidence: ItrusteeEvidence = serde_json::from_slice(evidence)?;
    
    log::debug!("{}", serde_json::to_string_pretty(&evidence).unwrap());
    
    let report = evidence.report;
    let js_evidence: serde_json::Value = serde_json::from_str(&report)?;
    let with_ima = match evidence.ima_log {
        Some(_) => true,
        None => false,
    };
    let ima_log = match evidence.ima_log {
        Some(ima_log) => ima_log,
        None => vec![],
    };
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

    let mut ima = serde_json::Value::Null;
    let mut in_data = challenge.to_vec();
    if with_ima {
        let report_nonce = js_evidence["payload"]["nonce"].as_str().unwrap();
        let nonce_all = base64_url::decode(&report_nonce)?;
        if nonce_all.len() != MAX_CHALLENGE_LEN {
            log::error!("IMA verification: nonce length is not 64 bytes, got {}", nonce_all.len());
            bail!("IMA verification: nonce length is not 64 bytes, got {}", nonce_all.len());
        }
        let nonce_expected = &nonce_all[..32]; // 前32字节是challenge
        let ima_log_hash = &nonce_all[32..];   // 后32字节是ima_log_hash
        if nonce_expected != challenge {
            log::error!("IMA verification: nonce and challenge mismatch");
            bail!("IMA verification: nonce and challenge mismatch");
        }
        ima = crate::ima::itrustee::ItrusteeImaVerify::default()
            .ima_verify(&ima_log, &[ima_log_hash.to_vec()])?;
        in_data = nonce_all.to_vec();
    }

    // let mut in_data = challenge.to_vec();
    let mut in_evidence = report.as_bytes().to_vec();
    let mut data_buf: itrustee::buffer_data = itrustee::buffer_data {
        size: in_evidence.len() as ::std::os::raw::c_uint,
        buf: in_evidence.as_mut_ptr() as *mut ::std::os::raw::c_uchar,
    };
    let mut nonce = itrustee::buffer_data {
        size: in_data.len() as ::std::os::raw::c_uint,
        buf: in_data.as_mut_ptr() as *mut ::std::os::raw::c_uchar,
    };
  
    // 1: verify ta_img; 2: verfiy ta_mem; 3: verify ta_img and ta_mem hash;
    let policy: std::os::raw::c_int = 1;

    let uuid;
    if let Some(v) = js_evidence.get("payload")
                                      .and_then(|v|v.get("uuid"))
                                      .and_then(|v|v.as_str()) {
        uuid = v;
    } else {
        log::error!("Parse TA uuid from evidence failed.");
        bail!("Parse TA uuid from evidence failed.");
    }
    let ref_file = ITRUSTEE_REF_VALUE_DIR.to_string() + "/itrustee_" + uuid;
    if !Path::new(&ref_file).exists() {
        log::error!(
            "itrustee verify report {} not exists",
            ref_file
        );
        bail!(
            "itrustee verify report {} not exists",
            ref_file
        );
    }
    
    let mut file = ref_file.add("\0");
    let basevalue = file.as_mut_ptr() as *mut ::std::os::raw::c_char;
    unsafe {
        let ret = itrustee::tee_verify_report(&mut data_buf, &mut nonce, policy, basevalue);
        if ret != 0 {
            log::error!("itrustee verify report failed ret:{}", ret);
            bail!("itrustee verify report failed ret:{}", ret);
        }
    }

    let payload = json!({
        "itrustee.nonce": js_evidence["payload"]["nonce"].clone(),
        "itrustee.hash_alg": js_evidence["payload"]["hash_alg"].clone(),
        "itrustee.key": js_evidence["payload"]["key"].clone(),
        "itrustee.ta_img": js_evidence["payload"]["ta_img"].clone(),
        "itrustee.ta_mem": js_evidence["payload"]["ta_mem"].clone(),
        "itrustee.uuid": js_evidence["payload"]["uuid"].clone(),
        "itrustee.version": js_evidence["payload"]["version"].clone(),
    });

    let claim = json!({
        "tee": "itrustee",
        "payload" : payload,
        "ima" : ima,
    });

    log::debug!("claim: {}", serde_json::to_string_pretty(&claim).unwrap());

    Ok(claim as TeeClaim)
}