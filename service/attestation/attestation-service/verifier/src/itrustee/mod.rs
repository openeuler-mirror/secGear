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
use std::path::Path;
use std::ops::Add;

mod itrustee;

const ITRUSTEE_REF_VALUE_FILE: &str = "/etc/attestation/attestation-service/verifier/itrustee/basevalue.txt";

#[derive(Debug, Default)]
pub struct ItrusteeVerifier {}

impl ItrusteeVerifier {
    pub async fn evaluate(&self, user_data: &[u8], evidence: &[u8]) -> Result<TeeClaim> {
        return evalute_wrapper(user_data, evidence);
    }
}

fn evalute_wrapper(user_data: &[u8], evidence: &[u8]) -> Result<TeeClaim> {
    let mut in_data = user_data.to_vec();
    let mut in_evidence = evidence.to_vec();
    let mut data_buf: itrustee::buffer_data = itrustee::buffer_data {
        size: in_evidence.len() as ::std::os::raw::c_uint,
        buf: in_evidence.as_mut_ptr() as *mut ::std::os::raw::c_uchar,
    };
    let mut nonce = itrustee::buffer_data {
        size: in_data.len() as ::std::os::raw::c_uint,
        buf: in_data.as_mut_ptr() as *mut ::std::os::raw::c_uchar,
    };
    log::info!("input nonce:{:?}", nonce);
    let policy: std::os::raw::c_int = 1;
    if !Path::new(ITRUSTEE_REF_VALUE_FILE).exists() {
        log::error!("itrustee verify report {} not exists", ITRUSTEE_REF_VALUE_FILE);
        bail!("itrustee verify report {} not exists", ITRUSTEE_REF_VALUE_FILE);
    }
    let ref_file = String::from(ITRUSTEE_REF_VALUE_FILE);
    let mut file = ref_file.add("\0");
    let basevalue = file.as_mut_ptr() as *mut ::std::os::raw::c_char;
    unsafe {
        let ret = itrustee::tee_verify_report(&mut data_buf, &mut nonce, policy, basevalue);
        if ret != 0 {
            log::error!("itrustee verify report failed ret:{}", ret);
            bail!("itrustee verify report failed ret:{}", ret);
        }
    }
    let js_evidence: serde_json::Value = serde_json::from_slice(evidence)?;
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
    });
    Ok(claim as TeeClaim)
}
