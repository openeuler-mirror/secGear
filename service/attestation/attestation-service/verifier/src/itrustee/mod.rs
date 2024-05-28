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
use std::path::Path;

mod itrustee;

const ITRUSTEE_REF_VALUE_FILE: &str = "/etc/attestation/itrustee/basevalue.txt";

#[derive(Debug, Default)]
pub struct ItrusteeVerifier {}

impl ItrusteeVerifier {
    pub async fn evaluate(&self, user_data: &[u8], evidence: &[u8]) -> Result<()> {
        return evalute_wrapper(user_data, evidence);
    }
}

fn evalute_wrapper(user_data: &[u8], evidence: &[u8]) -> Result<()> {
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
    let policy: std::os::raw::c_int = 1;
    if !Path::new(ITRUSTEE_REF_VALUE_FILE).exists() {
        log::error!("itrustee verify report {} not exists", ITRUSTEE_REF_VALUE_FILE);
        bail!("itrustee verify report {} not exists", ITRUSTEE_REF_VALUE_FILE);
    }
    let mut ref_file = String::from(ITRUSTEE_REF_VALUE_FILE);
    let basevalue = ref_file.as_mut_ptr() as *mut ::std::os::raw::c_char;
    unsafe {
        let ret = itrustee::tee_verify_report(&mut data_buf, &mut nonce, policy, basevalue);
        if ret != 0 {
            log::error!("itrustee verify report failed ret:{}", ret);
            bail!("itrustee verify report failed ret:{}", ret);
        }
    }
    Ok(())
}
