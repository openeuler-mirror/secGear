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

//! virtcca tee plugin
//!
//! Call the hardware sdk or driver to get the specific evidence

use anyhow::{bail, Result};
use attestation_types::VirtccaEvidence;
use log;
use std::path::Path;

use self::virtcca::{get_attestation_token, get_dev_cert, tsi_new_ctx};
use crate::virtcca::virtcca::tsi_free_ctx;
use crate::EvidenceRequest;

mod virtcca;

#[derive(Debug, Default)]
pub struct VirtccaAttester {}

impl VirtccaAttester {
    pub async fn tee_get_evidence(&self, user_data: EvidenceRequest) -> Result<String> {
        let evidence = virtcca_get_token(user_data)?;
        let evidence = serde_json::to_string(&evidence)?;
        Ok(evidence)
    }
}

pub fn detect_platform() -> bool {
    Path::new("/dev/tsi").exists()
}

const MAX_CHALLENGE_LEN: usize = 64;
fn virtcca_get_token(user_data: EvidenceRequest) -> Result<VirtccaEvidence> {
    let mut challenge = base64_url::decode(&user_data.challenge)?;
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
    unsafe {
        let ctx = tsi_new_ctx();
        let p_challenge = challenge.as_mut_ptr() as *mut ::std::os::raw::c_uchar;
        let challenge_len = challenge.len() as usize;
        let mut token = Vec::new();
        token.resize(4096, b'\0');
        let p_token = token.as_mut_ptr() as *mut ::std::os::raw::c_uchar;
        let mut token_len = token.len();
        let p_token_len = &mut token_len as *mut usize;
        let ret = get_attestation_token(ctx, p_challenge, challenge_len, p_token, p_token_len);
        if ret != 0 {
            log::error!("virtcca get attestation token failed {}", ret);
            bail!("virtcca get attestation token failed {}", ret);
        }
        token.set_len(token_len);

        let mut dev_cert = Vec::new();
        dev_cert.resize(4096, b'\0');
        let p_dev_cert = dev_cert.as_mut_ptr() as *mut ::std::os::raw::c_uchar;
        let mut dev_cert_len = dev_cert.len();
        let p_dev_cert_len = &mut dev_cert_len as *mut usize;
        let ret = get_dev_cert(ctx, p_dev_cert, p_dev_cert_len);
        if ret != 0 {
            log::error!("get dev cert failed {}", ret);
            bail!("get dev cert failed {}", ret);
        }
        dev_cert.set_len(dev_cert_len);

        let with_ima = match user_data.ima {
            Some(ima) => ima,
            None => false,
        };
        let ima_log = match with_ima {
            true => {
                Some(std::fs::read("/sys/kernel/security/ima/binary_runtime_measurements").unwrap())
            }
            false => None,
        };

        let evidence = VirtccaEvidence {
            evidence: token,
            dev_cert: dev_cert,
            ima_log: ima_log,
        };
        let _ = tsi_free_ctx(ctx);
        Ok(evidence)
    }
}
