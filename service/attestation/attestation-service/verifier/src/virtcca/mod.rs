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

//! virtcca verifier plugin
use super::TeeClaim;

use anyhow::{Result, bail, anyhow};
use cose::keys::CoseKey;
use cose::message::CoseMessage;
use ciborium;
use ciborium::Value;
use openssl::rsa;
use openssl::pkey::Public;
use openssl::x509;
use openssl::pkey::PKey;
use log;
use serde_json::json;

pub use attestation_types::VirtccaEvidence;
pub mod ima;

#[cfg(not(feature = "no_as"))]
const VIRTCCA_ROOT_CERT: &str = "/etc/attestation/attestation-service/verifier/virtcca/Huawei Equipment Root CA.pem";
#[cfg(not(feature = "no_as"))]
const VIRTCCA_SUB_CERT: &str = "/etc/attestation/attestation-service/verifier/virtcca/Huawei IT Product CA.pem";

// attestation agent local reference 
#[cfg(feature = "no_as")]
const VIRTCCA_REF_VALUE_FILE: &str = "/etc/attestation/attestation-agent/local_verifier/virtcca/ref_value.json";
#[cfg(feature = "no_as")]
const VIRTCCA_ROOT_CERT: &str = "/etc/attestation/attestation-agent/local_verifier/virtcca/Huawei Equipment Root CA.pem";
#[cfg(feature = "no_as")]
const VIRTCCA_SUB_CERT: &str = "/etc/attestation/attestation-agent/local_verifier/virtcca/Huawei IT Product CA.pem";

#[derive(Debug, Default)]
pub struct VirtCCAVerifier {}

impl VirtCCAVerifier {
    pub async fn evaluate(&self, user_data: &[u8], evidence: &[u8]) -> Result<TeeClaim> {
        return Evidence::verify(user_data, evidence);
    }
}

const CBOR_TAG: u64 = 399;
const CVM_LABEL: i128 = 44241;

const CVM_CHALLENGE_LABEL: i128 = 10;
const CVM_RPV_LABEL: i128 = 44235;
const CVM_RIM_LABEL: i128 = 44238;
const CVM_REM_LABEL: i128 = 44239;
const CVM_HASH_ALG_LABEL: i128 = 44236;
const CVM_PUB_KEY_LABEL: i128 = 44237;
const CVM_PUB_KEY_HASH_ALG_LABEL: i128 = 44240;

const CVM_CHALLENGE_SIZE: usize = 64;
const CVM_RPV_SIZE: usize = 64;
const CVM_REM_ARR_SIZE: usize = 4;
const CVM_PUB_KEY_SIZE: usize = 550;

#[derive(Debug)]
pub struct CvmToken {
    pub challenge: [u8; CVM_CHALLENGE_SIZE],        //    10 => bytes .size 64
    pub rpv: [u8; CVM_RPV_SIZE],                    // 44235 => bytes .size 64
    pub rim: Vec<u8>,                               // 44238 => bytes .size {32,48,64}
    pub rem: [Vec<u8>; CVM_REM_ARR_SIZE],           // 44239 => [ 4*4 bytes .size {32,48,64} ]
    pub hash_alg: String,                           // 44236 => text
    pub pub_key: [u8; CVM_PUB_KEY_SIZE],            // 44237 => bytes .size 550
    pub pub_key_hash_alg: String,                   // 44240 => text
}

pub struct Evidence {
    /// COSE Sign1 envelope for cvm_token
    pub cvm_envelop: CoseMessage,
    /// Decoded cvm token
    pub cvm_token: CvmToken,
}

impl Evidence {
    pub fn new() -> Self {
        Self {
            cvm_envelop: CoseMessage::new_sign(),
            cvm_token: CvmToken::new(),
        }
    }
    pub fn verify(user_data: &[u8], evidence: &[u8]) -> Result<TeeClaim> {
        let virtcca_ev: VirtccaEvidence = serde_json::from_slice(evidence)?;
        let evidence = virtcca_ev.evidence;
        let dev_cert = virtcca_ev.dev_cert;
        let mut evidence = Evidence::decode(evidence)?;

        // verify platform token
        evidence.verify_platform_token(&dev_cert)?;

        // verify cvm token
        evidence.verify_cvm_token(user_data)?;

        // verify ima
        let ima_log = match virtcca_ev.ima_log {
            Some(ima_log) => ima_log,
            _ => {log::info!("no ima log"); vec![]},
        };
        let ima: serde_json::Value = ima::ImaVerify::default()
            .ima_verify(&ima_log, evidence.cvm_token.rem[0].clone())?;

        // todo parsed TeeClaim
        evidence.parse_claim_from_evidence(ima)
    }
    fn parse_claim_from_evidence(&self, ima: serde_json::Value) -> Result<TeeClaim> {
        let payload = json!({
            "vcca.cvm.challenge": hex::encode(self.cvm_token.challenge.clone()),
            "vcca.cvm.rpv": hex::encode(self.cvm_token.rpv.clone()),
            "vcca.cvm.rim": hex::encode(self.cvm_token.rim.clone()),
            "vcca.cvm.rem.0": hex::encode(self.cvm_token.rem[0].clone()),
            "vcca.cvm.rem.1": hex::encode(self.cvm_token.rem[1].clone()),
            "vcca.cvm.rem.2": hex::encode(self.cvm_token.rem[2].clone()),
            "vcca.cvm.rem.3": hex::encode(self.cvm_token.rem[3].clone()),
            "vcca.platform": "",
        });
        let claim = json!({
            "tee": "vcca",
            "payload" : payload,
            "ima": ima,
        });
        Ok(claim as TeeClaim)
    }
    fn verify_platform_token(&mut self, dev_cert: &[u8]) -> Result<()> {
        // todo verify platform COSE_Sign1 by dev_cert, virtCCA report has no platform token now

        // verify dev_cet by cert chain
        Evidence::verify_dev_cert_chain(dev_cert)?;

        Ok(())
    }
    // todo verify cert chain, now only verify signature
    fn verify_dev_cert_chain(dev_cert: &[u8]) -> Result<()> {
        let dev_cert = x509::X509::from_der(dev_cert)?;
        let sub_cert_file = std::fs::read(VIRTCCA_SUB_CERT)?;
        let sub_cert = x509::X509::from_pem(&sub_cert_file)?;
        let root_cert_file = std::fs::read(VIRTCCA_ROOT_CERT)?;
        let root_cert = x509::X509::from_pem(&root_cert_file)?;

        // verify dev_cert by sub_cert
        let ret = dev_cert.verify(&(sub_cert.public_key()? as PKey<Public>))?;
        if !ret {
            log::error!("verify dev cert by sub cert failed");
            bail!("verify dev cert by sub cert failed");
        }
        // verify sub_cert by root_cert
        let ret = sub_cert.verify(&(root_cert.public_key()? as PKey<Public>))?;
        if !ret {
            log::error!("verify sub cert by root cert failed");
            bail!("verify sub cert by root cert failed");
        }
        // verify self signed root_cert
        let ret = root_cert.verify(&(root_cert.public_key()? as PKey<Public>))?;
        if !ret {
            log::error!("verify self signed root cert failed");
            bail!("verify self signed root cert failed");
        }
        Ok(())
    }
    fn verify_cvm_token(&mut self, challenge: &[u8]) -> Result<()> {
        // verify challenge
        let len = challenge.len();
        let token_challenge = &self.cvm_token.challenge[0..len];
        if challenge != token_challenge {
            log::error!("verify cvm token challenge error, cvm_token challenge {:?}, input challenge {:?}", 
                token_challenge, challenge);
            bail!("verify cvm token challenge error, cvm_token challenge {:?}, input challenge {:?}", 
                token_challenge, challenge);
        }

        // todo verify cvm pubkey by platform.challenge, virtCCA report has no platform token now

        // verify COSE_Sign1 signature begin
        let raw_pub_key = self.cvm_token.pub_key;
        let mut cose_key: CoseKey = Evidence::from_raw_pub_key(&raw_pub_key)?;
        cose_key.key_ops(vec![cose::keys::KEY_OPS_VERIFY]);
        match self.cvm_envelop.header.alg {
            Some(alg) => cose_key.alg(alg),
            None => bail!("cose sign verify alg is none"),
        }
        self.cvm_envelop.key(&cose_key).map_err(|err| anyhow!("set cose_key to COSE_Sign1 envelop failed: {err:?}"))?;
        self.cvm_envelop.decode(None, None).map_err(|err| anyhow!("verify COSE_Sign1 signature failed:{err:?}"))?;
        // verify COSE_Sign1 signature end

        // verfiy cvm token with reference value
        #[cfg(feature = "no_as")]
        self.compare_with_ref()?;

        Ok(())
    }
    #[cfg(feature = "no_as")]
    fn compare_with_ref(&mut self) -> Result<()> {
        let ref_file = std::fs::read(VIRTCCA_REF_VALUE_FILE)?;
        let js_ref = serde_json::from_slice(&ref_file)?;
        match js_ref {
            serde_json::Value::Object(obj) => {
                for (k, v) in obj {
                    if k == "rim" {
                        let rim_ref = match v {
                            serde_json::Value::String(rim) => rim,
                            _ => bail!("tim ref expecting String"),
                        };
                        let rim = hex::encode(self.cvm_token.rim.clone());
                        if rim_ref != rim {
                            log::error!("expecting rim: {}, got: {}", rim_ref, rim);
                            bail!("expecting rim: {}, got: {}", rim_ref, rim);
                        }
                    }
                }
            }
            _ => bail!("invalid json ref value"),
        }

        Ok(())
    }
    fn from_raw_pub_key(raw_pub_key: &[u8]) -> Result<CoseKey> {
        let pub_key: rsa::Rsa<Public> = rsa::Rsa::public_key_from_der(raw_pub_key)?;
        let mut cose_key = CoseKey::new();
        cose_key.kty(cose::keys::RSA);
        cose_key.e(pub_key.e().to_vec());
        cose_key.n(pub_key.n().to_vec());

        Ok(cose_key)
    }
    pub fn decode(raw_evidence: Vec<u8>) -> Result<Evidence> {
        let mut evidence: Evidence = Evidence::new();

        // decode CBOR evidence to ciborium Value
        let val: Value = ciborium::de::from_reader(raw_evidence.as_slice())?;
        log::debug!("[debug] decode CBOR virtcca token to ciborium Value:{:?}", val);
        if let Value::Tag(t, m) = val {
            if t != CBOR_TAG {
                log::error!("input evidence error, expecting tag {}, got {}", CBOR_TAG, t);
                bail!("input evidence error, expecting tag {}, got {}", CBOR_TAG, t);
            }
            if let Value::Map(contents) = *m {
                for (k, v) in contents.iter() {
                    if let Value::Integer(i) = k {
                        match (*i).into() {
                            CVM_LABEL => evidence.set_cvm_token(v)?,
                            err => bail!("unknown label {}", err),
                        }
                    } else {
                        bail!("expecting integer key");
                    }
                }
            } else {
                bail!("expecting map type");
            }
        } else {
            bail!("expecting tag type");
        }

        let ret = evidence.cvm_envelop.init_decoder(None);
        match ret {
            Ok(_) => log::info!("decode COSE success"),
            Err(e) => {
                log::error!("decode COSE failed, {:?}", e);
                bail!("decode COSE failed");
            },
        }

        // decode cvm CBOR payload
        evidence.cvm_token = CvmToken::decode(&evidence.cvm_envelop.payload)?;
        Ok(evidence)
    }
    fn set_cvm_token(&mut self, v: &Value) -> Result<()> {
        let tmp = v.as_bytes();
        if tmp.is_none() {
            log::error!("cvm token is none");
            bail!("cvm token is none");
        }
        self.cvm_envelop.bytes = tmp.unwrap().clone();
        Ok(())
    }
}

impl CvmToken {
    pub fn new() -> Self {
        Self {
            challenge: [0; CVM_CHALLENGE_SIZE],
            rpv: [0; CVM_RPV_SIZE],
            rim: vec![0, 64],
            rem: Default::default(),
            hash_alg: String::from(""),
            pub_key: [0; CVM_PUB_KEY_SIZE],
            pub_key_hash_alg: String::from(""),
        }
    }
    pub fn decode(raw_payload: &Vec<u8>) -> Result<CvmToken> {
        let payload: Vec<u8> = ciborium::de::from_reader(raw_payload.as_slice())?;
        log::debug!("After decode CBOR payload, payload {:?}", payload);
        let payload: Value = ciborium::de::from_reader(payload.as_slice())?;
        log::debug!("After decode CBOR payload agin, payload {:?}", payload);
        let mut cvm_token: CvmToken = CvmToken::new();
        if let Value::Map(contents) = payload {
            for (k, v) in contents.iter() {
                if let Value::Integer(i) = k {
                    match (*i).into() {
                        CVM_CHALLENGE_LABEL => cvm_token.set_challenge(v)?,
                        CVM_RPV_LABEL => cvm_token.set_rpv(v)?,
                        CVM_RIM_LABEL => cvm_token.set_rim(v)?,
                        CVM_REM_LABEL => cvm_token.set_rem(v)?,
                        CVM_HASH_ALG_LABEL => cvm_token.set_hash_alg(v)?,
                        CVM_PUB_KEY_LABEL => cvm_token.set_pub_key(v)?,
                        CVM_PUB_KEY_HASH_ALG_LABEL => cvm_token.set_pub_key_hash_alg(v)?,
                        err => bail!("cvm payload unkown label {}", err),
                    }
                } else {
                    bail!("cvm payload expecting integer key");
                }
            }
        } else {
            bail!("expecting cvm payload map type");
        }
        log::debug!("cvm_token decode from raw payload, {:?}", cvm_token);
        Ok(cvm_token)
    }
    fn set_challenge(&mut self, v: &Value) -> Result<()> {
        let tmp = v.as_bytes();
        if tmp.is_none() {
            bail!("cvm token challenge is none");
        }
        let tmp = tmp.unwrap().clone();
        if tmp.len() != CVM_CHALLENGE_SIZE {
            bail!("cvm token challenge expecting {} bytes, got {}", CVM_CHALLENGE_SIZE,tmp.len());
        }
        self.challenge[..].clone_from_slice(&tmp);
        Ok(())
    }
    fn set_rpv(&mut self, v: &Value) -> Result<()> {
        let tmp = v.as_bytes();
        if tmp.is_none() {
            bail!("cvm token rpv is none");
        }
        let tmp = tmp.unwrap().clone();
        if tmp.len() != CVM_RPV_SIZE {
            bail!("cvm token rpv expecting {} bytes, got {}", CVM_RPV_SIZE, tmp.len());
        }
        self.rpv[..].clone_from_slice(&tmp);
        Ok(())
    }
    fn get_measurement(v: &Value, who: &str) -> Result<Vec<u8>> {
        let tmp = v.as_bytes();
        if tmp.is_none() {
            bail!("cvm token {} is none", who);
        }
        let tmp = tmp.unwrap().clone();
        if !matches!(tmp.len(), 32 | 48 | 64) {
            bail!("cvm token {} expecting 32, 48 or 64 bytes, got {}", who, tmp.len());
        }
        Ok(tmp)
    }
    fn set_rim(&mut self, v: &Value) -> Result<()> {
        self.rim = Self::get_measurement(v, "rim")?;
        Ok(())
    }
    fn set_rem(&mut self, v: &Value) -> Result<()> {
        let tmp = v.as_array();
        if tmp.is_none() {
            bail!("cvm token rem is none");
        }
        let tmp = tmp.unwrap().clone();
        if tmp.len() != 4 {
            bail!("cvm token rem expecting size {}, got {}", CVM_REM_ARR_SIZE, tmp.len());
        }

        for (i, val) in tmp.iter().enumerate() {
            self.rem[i] = Self::get_measurement(val, "rem[{i}]")?;
        }
        Ok(())
    }
    fn get_hash_alg(v: &Value, who: &str) -> Result<String> {
        let alg = v.as_text();
        if alg.is_none() {
            bail!("{} hash alg must be str", who);
        }
        Ok(alg.unwrap().to_string())
    }
    fn set_hash_alg(&mut self, v: &Value) -> Result<()> {
        self.hash_alg = Self::get_hash_alg(v, "cvm token")?;
        Ok(())
    }
    fn set_pub_key(&mut self, v: &Value) -> Result<()> {
        let tmp = v.as_bytes();
        if tmp.is_none() {
            bail!("cvm token pub key is none");
        }
        let tmp = tmp.unwrap().clone();
        if tmp.len() != CVM_PUB_KEY_SIZE {
            bail!("cvm token pub key len expecting {}, got {}", CVM_PUB_KEY_SIZE, tmp.len());
        }
        self.pub_key[..].clone_from_slice(&tmp);
        Ok(())
    }
    fn set_pub_key_hash_alg(&mut self, v: &Value) -> Result<()> {
        self.pub_key_hash_alg = Self::get_hash_alg(v, "pub key")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    const TEST_VIRTCCA_TOKEN: &[u8; 2862] = include_bytes!("../../test_data/virtcca.cbor");
    #[test]
    fn decode_token() {
        let token = hex::decode(TEST_VIRTCCA_TOKEN).unwrap();
        let dev_cert = std::fs::read("./test_data/virtcca_aik_cert.der").unwrap();
        let challenge = Vec::new();
        let virtcca_ev = VirtccaEvidence {
            evidence: token.to_vec(),
            dev_cert: dev_cert,
            ima_log: None,
        };
        let virtcca_ev = serde_json::to_vec(&virtcca_ev).unwrap();
        let r = Evidence::verify(&challenge, &virtcca_ev);
        match r {
            Ok(claim) => println!("verify success {:?}", claim),
            Err(e) => assert!(false, "verify failed {:?}", e),
        }
    }
}
