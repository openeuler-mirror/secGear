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

use anyhow::{anyhow, bail, Result};
use attestation_types::{UefiLog, VirtccaEvidence};
use log;
#[cfg(feature = "virtcca-attester")]
use rand::RngCore;
use std::path::Path;

use self::virtcca::{get_attestation_token, get_dev_cert, tsi_new_ctx};
use crate::ima;
use crate::virtcca::virtcca::tsi_free_ctx;
use crate::EvidenceRequest;

mod virtcca;

const CCEL_TABLE_PATH: &str = "/sys/firmware/acpi/tables/CCEL";
const CCEL_DATA_PATH: &str = "/sys/firmware/acpi/tables/data/CCEL";

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
    let mutex = TSI_MUTEX.get_or_init(|| std::sync::Mutex::new(()));
    let _lock = mutex
        .lock()
        .map_err(|e| anyhow!("TSI mutex poisoned: {}", e))?;
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

        // Use the new IMA module to read IMA log
        let ima_log = ima::read_ima_log_if_requested(with_ima)?;

        let ccel_table = std::fs::read(CCEL_TABLE_PATH).ok();
        let ccel_data = std::fs::read(CCEL_DATA_PATH).ok();
        let uefi_log = match (ccel_table, ccel_data) {
            (Some(table), Some(data)) => {
                log::info!("read ccel table and data success");
                Some(UefiLog {
                    ccel_table: table,
                    ccel_data: data,
                })
            }
            _ => {
                log::warn!("read ccel table or data failed");
                None
            }
        };

        let evidence = VirtccaEvidence {
            evidence: token,
            dev_cert: dev_cert,
            ima_log: ima_log,
            uefi_log: uefi_log,
        };

        let _ = tsi_free_ctx(ctx);
        Ok(evidence)
    }
}

static TSI_MUTEX: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

#[cfg(feature = "virtcca-attester")]
struct TsiContext(*mut virtcca::tsi_ctx);

#[cfg(feature = "virtcca-attester")]
impl Drop for TsiContext {
    fn drop(&mut self) {
        unsafe {
            let _ = tsi_free_ctx(self.0);
        }
    }
}

#[cfg(feature = "virtcca-attester")]
pub fn tee_get_token_only(challenge: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if challenge.len() != 32 {
        bail!(
            "challenge must be exactly 32 bytes, got {}",
            challenge.len()
        );
    }
    if !detect_platform() {
        bail!("Not on virtCCA platform, /dev/tsi not found");
    }
    let mutex = TSI_MUTEX.get_or_init(|| std::sync::Mutex::new(()));
    let _lock = mutex
        .lock()
        .map_err(|e| anyhow!("TSI mutex poisoned: {}", e))?;
    let mut challenge = challenge.to_vec();
    unsafe {
        let ctx = tsi_new_ctx();
        if ctx.is_null() {
            bail!("Failed to create TSI context");
        }
        let ctx = TsiContext(ctx);
        let mut token = Vec::new();
        token.resize(4096, b'\0');
        let token_capacity = token.len();
        let mut token_len = token.len();
        let ret = get_attestation_token(
            ctx.0,
            challenge.as_mut_ptr(),
            challenge.len(),
            token.as_mut_ptr(),
            &mut token_len,
        );
        if ret != 0 {
            bail!("TSI get_attestation_token failed: {}", ret);
        }
        if token_len > token_capacity {
            bail!(
                "TSI get_attestation_token output length {} exceeds buffer {}",
                token_len,
                token_capacity
            );
        }
        token.set_len(token_len);
        let mut dev_cert = Vec::new();
        dev_cert.resize(4096, b'\0');
        let dev_cert_capacity = dev_cert.len();
        let mut dev_cert_len = dev_cert.len();
        let ret = get_dev_cert(ctx.0, dev_cert.as_mut_ptr(), &mut dev_cert_len);
        if ret != 0 {
            bail!("get_dev_cert failed: {}", ret);
        }
        if dev_cert_len > dev_cert_capacity {
            bail!(
                "get_dev_cert output length {} exceeds buffer {}",
                dev_cert_len,
                dev_cert_capacity
            );
        }
        dev_cert.set_len(dev_cert_len);
        Ok((token, dev_cert))
    }
}

#[cfg(feature = "virtcca-attester")]
const CVM_LABEL: u64 = 44241; // must match verifier/src/virtcca/mod.rs
#[cfg(feature = "virtcca-attester")]
const CVM_RIM_LABEL: u64 = 44238; // must match verifier/src/virtcca/mod.rs
#[cfg(feature = "virtcca-attester")]
const CBOR_TAG: u64 = 399; // must match verifier/src/virtcca/mod.rs

#[cfg(feature = "virtcca-attester")]
fn extract_rim_from_cbor(cbor_data: &[u8]) -> Result<Vec<u8>> {
    use ciborium::de::from_reader;
    use ciborium::value::Value;

    let value: Value =
        from_reader(cbor_data).map_err(|e| anyhow!("Failed to parse CBOR: {}", e))?;

    let token_bytes = match &value {
        Value::Tag(tag, inner) if *tag == CBOR_TAG => match inner.as_ref() {
            Value::Map(entries) => entries
                .iter()
                .find_map(|(k, v)| {
                    if let Value::Integer(label) = k {
                        if i128::from(*label) == CVM_LABEL as i128 {
                            return Some(v.clone());
                        }
                    }
                    None
                })
                .ok_or_else(|| anyhow!("Key {} not found in CBOR map", CVM_LABEL))?,
            _ => bail!("Expected Map inside tag {}", CBOR_TAG),
        },
        _ => bail!("Expected CBOR tag {}", CBOR_TAG),
    };

    let cose_payload = match &token_bytes {
        Value::Bytes(b) => {
            let mut cose_envelop = cose::message::CoseMessage::new_sign();
            cose_envelop.bytes = b.clone();
            cose_envelop
                .init_decoder(None)
                .map_err(|e| anyhow!("Failed to parse COSE_Sign1: {:?}", e))?;
            cose_envelop.payload
        }
        _ => bail!("Expected bytes for COSE_Sign1"),
    };

    let payload_bytes: Vec<u8> = from_reader(cose_payload.as_slice())
        .map_err(|e| anyhow!("Failed to parse CvmToken payload bytes: {}", e))?;
    let payload: Value = from_reader(payload_bytes.as_slice())
        .map_err(|e| anyhow!("Failed to parse CvmToken payload: {}", e))?;

    match &payload {
        Value::Map(entries) => entries
            .iter()
            .find_map(|(k, v)| {
                if let Value::Integer(label) = k {
                    if i128::from(*label) == CVM_RIM_LABEL as i128 {
                        if let Value::Bytes(rim) = v {
                            return Some(rim.clone());
                        }
                    }
                }
                None
            })
            .ok_or_else(|| anyhow!("RIM field (label {}) not found", CVM_RIM_LABEL)),
        _ => bail!("Expected Map in CvmToken payload"),
    }
}

#[cfg(feature = "virtcca-attester")]
pub fn discover_rim() -> Result<String> {
    if !detect_platform() {
        bail!("Not on virtCCA platform, /dev/tsi not found");
    }
    let mut challenge = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    let (token, _) = tee_get_token_only(&challenge)?;
    let rim = extract_rim_from_cbor(&token)?;
    Ok(hex::encode(&rim))
}

#[cfg(all(test, feature = "virtcca-attester"))]
mod tests {
    use super::*;

    const TEST_VIRTCCA_TOKEN: &[u8] =
        include_bytes!("../../../../attestation-service/verifier/test_data/virtcca.cbor");

    #[test]
    fn extract_rim_from_cbor_matches_verifier_fixture() {
        let rim = extract_rim_from_cbor(TEST_VIRTCCA_TOKEN).unwrap();

        assert_eq!(rim.len(), 64);
    }
}
