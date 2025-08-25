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
pub mod ccatoken;
pub mod event_log;
use attestation_types::VirtccaEvidence;
use ccatoken::{CvmToken, Decode, PlatformToken};
use event_log::EventVerify;

use super::TeeClaim;
use crate::ima::{virtcca::VirtCCAImaVerify, ImaVerifier};
use anyhow::{anyhow, bail, Ok, Result};
use ciborium::{de, Value};
use cose::{
    keys::{CoseKey, EC2, KEY_OPS_VERIFY, RSA},
    message::CoseMessage,
};
use log;
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    hash::{hash, MessageDigest},
    nid::Nid,
    pkey::{Id, PKey, Public},
    x509::X509,
};
use serde_json::json;

#[cfg(not(feature = "no_as"))]
const RSA_ROOT_CERT: &str =
    "/etc/attestation/attestation-service/verifier/virtcca/Huawei Equipment Root CA.pem";
#[cfg(not(feature = "no_as"))]
const RSA_SUB_CERT: &str =
    "/etc/attestation/attestation-service/verifier/virtcca/Huawei IT Product CA.pem";
const ECCP_ROOT_CERT: &str =
    "/etc/attestation/attestation-service/verifier/virtcca/eccp521_root_cert.pem";
#[cfg(not(feature = "no_as"))]
const ECCP_SUB_CERT: &str =
    "/etc/attestation/attestation-service/verifier/virtcca/eccp521_sub_cert.pem";

// attestation agent local reference
#[cfg(feature = "no_as")]
const VIRTCCA_REF_VALUE_FILE: &str =
    "/etc/attestation/attestation-agent/local_verifier/virtcca/ref_value.json";
#[cfg(feature = "no_as")]
const RSA_ROOT_CERT: &str =
    "/etc/attestation/attestation-agent/local_verifier/virtcca/Huawei Equipment Root CA.pem";
#[cfg(feature = "no_as")]
const RSA_SUB_CERT: &str =
    "/etc/attestation/attestation-agent/local_verifier/virtcca/Huawei IT Product CA.pem";
#[cfg(feature = "no_as")]
const ECCP_ROOT_CERT: &str =
    "/etc/attestation/attestation-agent/local_verifier/virtcca/eccp521_root_cert.pem";
#[cfg(feature = "no_as")]
const ECCP_SUB_CERT: &str =
    "/etc/attestation/attestation-agent/local_verifier/virtcca/eccp521_sub_cert.pem";

const MAX_CHALLENGE_LEN: usize = 64;
const CBOR_TAG: u64 = 399;
const CVM_LABEL: i128 = 44241;
const PLATFORM_LABEL: i128 = 44234;

#[derive(Debug, Default)]
pub struct VirtCCAVerifier {}

impl VirtCCAVerifier {
    pub async fn evaluate(&self, user_data: &[u8], evidence: &[u8]) -> Result<TeeClaim> {
        let challenge = base64_url::decode(user_data)?;
        let len = challenge.len();
        if len == 0 || len > MAX_CHALLENGE_LEN {
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
        Evidence::verify(&challenge.to_vec(), evidence)
    }
}

pub struct Evidence {
    // COSE Sign1 envelope for cvm_token
    pub cvm_envelop: CoseMessage,
    // Decoded cvm token
    pub cvm_token: CvmToken,
    pub platform_envelop: CoseMessage,
    pub platform_token: PlatformToken,
    pub is_platform: bool,
}

impl Default for Evidence {
    fn default() -> Self {
        Self::new()
    }
}

impl Evidence {
    pub fn new() -> Self {
        Self {
            cvm_envelop: CoseMessage::new_sign(),
            cvm_token: CvmToken::new(),
            platform_envelop: CoseMessage::new_sign(),
            platform_token: PlatformToken::new(),
            is_platform: false,
        }
    }
    pub fn verify(user_data: &[u8], evidence: &[u8]) -> Result<TeeClaim> {
        let virtcca_ev: VirtccaEvidence = serde_json::from_slice(evidence)?;
        let evidence = virtcca_ev.evidence;
        let mut evidence = Evidence::decode(evidence)?;

        let dev_cert = if evidence.is_platform {
            X509::from_pem(&virtcca_ev.dev_cert)?
        } else {
            X509::from_der(&virtcca_ev.dev_cert)?
        };

        // verify platform token
        evidence.verify_platform_token(&dev_cert)?;

        // verify cvm token
        evidence.verify_cvm_token(user_data)?;

        // verify ima
        let ima_log = match virtcca_ev.ima_log {
            Some(ima_log) => {
                log::info!("get ima log");
                ima_log
            }
            None => {
                log::info!("no ima log");
                vec![]
            }
        };

        let ima: serde_json::Value =
            VirtCCAImaVerify::default().ima_verify(&ima_log, &evidence.cvm_token.rem)?;

        // verify event
        let event_log = match virtcca_ev.event_log {
            Some(log) => {
                log::info!("get event log");
                log
            }
            None => {
                log::info!("no event log");
                vec![]
            }
        };

        let event: serde_json::Value =
            EventVerify::event_verify(event_log, evidence.cvm_token.rem.clone())?;

        evidence.parse_claim_from_evidence(ima, event)
    }
    pub fn parse_evidence(evidence: &[u8]) -> Result<TeeClaim> {
        let virtcca_ev: VirtccaEvidence = serde_json::from_slice(evidence)?;
        let evidence = virtcca_ev.evidence;
        let evidence = Evidence::decode(evidence)?;

        let ima = json!("");
        let event = json!("");
        // parsed TeeClaim
        let claim = evidence.parse_claim_from_evidence(ima, event).unwrap();
        Ok(claim["payload"].clone() as TeeClaim)
    }

    fn parse_claim_from_evidence(
        &self,
        ima: serde_json::Value,
        event: serde_json::Value,
    ) -> Result<TeeClaim> {
        let payload = json!({
            "vcca.cvm.challenge": hex::encode(self.cvm_token.challenge),
            "vcca.cvm.rpv": hex::encode(self.cvm_token.rpv),
            "vcca.cvm.rim": hex::encode(self.cvm_token.rim.clone()),
            "vcca.cvm.rem.0": hex::encode(self.cvm_token.rem[0].clone()),
            "vcca.cvm.rem.1": hex::encode(self.cvm_token.rem[1].clone()),
            "vcca.cvm.rem.2": hex::encode(self.cvm_token.rem[2].clone()),
            "vcca.cvm.rem.3": hex::encode(self.cvm_token.rem[3].clone()),
            "vcca.is_platform": self.is_platform.clone(),
            "vcca.platform.measure_value": self.platform_token.sw_components.clone(),
        });
        let claim = json!({
            "tee": "vcca",
            "payload" : payload,
            "ima": ima,
            "event": event,
        });
        Ok(claim)
    }

    pub fn pkey_to_cosekey(pkey: &PKey<Public>) -> Result<CoseKey> {
        let mut cose_key = CoseKey::new();
        match pkey.id() {
            Id::RSA => {
                let rsa = pkey.rsa()?;
                cose_key.kty(RSA);
                cose_key.n(rsa.n().to_vec());
                cose_key.e(rsa.e().to_vec());
            }
            Id::EC => {
                let ec_key = pkey.ec_key()?;
                cose_key.kty(EC2);
                let group = ec_key.group();
                match group.curve_name() {
                    Some(openssl::nid::Nid::SECP521R1) => cose_key.crv(cose::keys::P_521),
                    Some(nid) => bail!("Unsupported EC curve: {:?}", nid),
                    None => bail!("EC key has no associated curve name"),
                }

                let public_key = ec_key.public_key();
                let mut ctx = BigNumContext::new()?;
                let encoded_point =
                    public_key.to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;
                if !encoded_point.is_empty() && encoded_point[0] == 0x04 {
                    let coordinate_len = (encoded_point.len() - 1) / 2;
                    let x = encoded_point[1..1 + coordinate_len].to_vec();
                    let y = encoded_point[1 + coordinate_len..].to_vec();
                    cose_key.x(x);
                    cose_key.y(y);
                } else {
                    bail!("Unsupported EC point format");
                }
            }
            _ => bail!("Unsupported key type"),
        }

        Ok(cose_key)
    }

    pub fn verify_cose_sign1(envelop: &mut CoseMessage, pkey: &PKey<Public>) -> Result<()> {
        let mut cose_key: CoseKey = Evidence::pkey_to_cosekey(pkey)?;
        cose_key.key_ops(vec![KEY_OPS_VERIFY]);
        match envelop.header.alg {
            Some(alg) => cose_key.alg(alg),
            None => bail!("cose sign verify alg is none"),
        }
        envelop
            .key(&cose_key)
            .map_err(|err| anyhow!("set cose_key to COSE_Sign1 envelop failed: {err:?}"))?;
        envelop
            .decode(None, None)
            .map_err(|err| anyhow!("verify COSE_Sign1 signature failed:{err:?}"))?;

        Ok(())
    }

    fn verify_platform_token(&mut self, dev_cert: &X509) -> Result<()> {
        // verify dev_cet by cert chain
        log::info!("verify dev_cert by cert chain");
        Evidence::verify_dev_cert_chain(dev_cert)?;

        // verify platform token cose_sign1
        if self.is_platform {
            log::info!("verify platform COSE_Sign1 by dev_cert");
            let pkey = dev_cert.public_key()?;
            Evidence::verify_cose_sign1(&mut self.platform_envelop, &pkey)?;
        }

        Ok(())
    }

    //get cert path by cert_type
    fn detect_cert_path(dev_cert: &X509) -> Result<(&'static str, &'static str)> {
        let pubkey = dev_cert.public_key()?;
        match pubkey.id() {
            Id::RSA => Ok((RSA_ROOT_CERT, RSA_SUB_CERT)),
            Id::EC => Ok((ECCP_ROOT_CERT, ECCP_SUB_CERT)),
            _ => Err(anyhow!("unsupported cert type")),
        }
    }

    fn verify_dev_cert_chain(dev_cert: &X509) -> Result<()> {
        let (root_cert_path, sub_cert_path) = Evidence::detect_cert_path(dev_cert)?;
        let sub_cert_file = std::fs::read(sub_cert_path)?;
        let sub_cert = X509::from_pem(&sub_cert_file)?;
        let root_cert_file = std::fs::read(root_cert_path)?;
        let root_cert = X509::from_pem(&root_cert_file)?;

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

    pub fn verfiy_cvm_challenge(&self, challenge: &[u8], raw_pub_key: &[u8]) -> Result<()> {
        let digest = match self.cvm_token.pub_key_hash_alg.as_str() {
            "sha-256" => MessageDigest::sha256(),
            "sha-384" => MessageDigest::sha384(),
            "sha-512" => MessageDigest::sha512(),
            _ => bail!("unsupported algorithm for pubkey verification"),
        };

        // Calculate the hash value of the CVM public key
        let calculated_challenge = hash(digest, raw_pub_key)?;

        // Compare value with the platform challenge value
        if calculated_challenge.as_ref() != challenge {
            log::error!(
                "verify cvm pubkey by platform challenge failed, expected: {:?}, got: {:?}",
                challenge,
                calculated_challenge
            );
            bail!("verify cvm pubkey by platform challenge failed");
        }

        Ok(())
    }

    pub fn raw_ec_public_key_to_pkey(&self) -> Result<PKey<Public>> {
        let raw_key = &self.cvm_token.pub_key;
        // Check if it's in uncompressed format (the first byte should be 0x04)
        if raw_key.is_empty() || raw_key[0] != 0x04 {
            bail!("Invalid uncompressed EC public key format");
        }
        let group = EcGroup::from_curve_name(Nid::SECP521R1)?;
        let mut ctx = BigNumContext::new()?;
        let point = openssl::ec::EcPoint::from_bytes(&group, raw_key, &mut ctx)?;
        let ec_key = EcKey::from_public_key(&group, &point)?;

        Ok(PKey::from_ec_key(ec_key)?)
    }
    fn verify_cvm_token(&mut self, challenge: &[u8]) -> Result<()> {
        // verify challenge
        let len = challenge.len();
        let token_challenge = &self.cvm_token.challenge[0..len];
        if challenge != token_challenge {
            log::error!(
                "verify cvm token challenge error, cvm_token challenge {:?}, input challenge {:?}",
                token_challenge,
                challenge
            );
            bail!(
                "verify cvm token challenge error, cvm_token challenge {:?}, input challenge {:?}",
                token_challenge,
                challenge
            );
        }

        if self.is_platform {
            self.verfiy_cvm_challenge(&self.platform_token.challenge, &self.cvm_token.pub_key)?;
            log::info!("verify cvm pubkey by platform challenge success");
        }

        let pkey = PKey::public_key_from_der(&self.cvm_token.pub_key)
            .or_else(|_| self.raw_ec_public_key_to_pkey())?;

        Evidence::verify_cose_sign1(&mut self.cvm_envelop, &pkey)?;

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

    fn cose_decode(envelop: &mut CoseMessage) -> Result<()> {
        envelop.init_decoder(None).map_err(|e| {
            log::error!("decode COSE failed, {:?}", e);
            anyhow::anyhow!("decode COSE failed")
        })?;
        log::debug!("decode COSE success");
        Ok(())
    }

    pub fn decode(raw_evidence: Vec<u8>) -> Result<Evidence> {
        let mut evidence: Evidence = Evidence::new();

        // decode CBOR evidence to ciborium Value
        let val: Value = de::from_reader(raw_evidence.as_slice())?;
        log::debug!(
            "[debug] decode CBOR virtcca token to ciborium Value:{:?}",
            val
        );
        if let Value::Tag(t, m) = val {
            if t != CBOR_TAG {
                log::error!(
                    "input evidence error, expecting tag {}, got {}",
                    CBOR_TAG,
                    t
                );
                bail!(
                    "input evidence error, expecting tag {}, got {}",
                    CBOR_TAG,
                    t
                );
            }
            if let Value::Map(contents) = *m {
                for (k, v) in contents.iter() {
                    if let Value::Integer(i) = k {
                        match (*i).into() {
                            CVM_LABEL => evidence.set_cvm_token(v)?,
                            PLATFORM_LABEL => {
                                evidence.is_platform = true;
                                evidence.set_platform_token(v)?
                            }
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

        Evidence::cose_decode(&mut evidence.cvm_envelop)?;
        evidence.cvm_token = CvmToken::decode(&evidence.cvm_envelop.payload)?;

        if evidence.is_platform {
            Evidence::cose_decode(&mut evidence.platform_envelop)?;
            evidence.platform_token = PlatformToken::decode(&evidence.platform_envelop.payload)?;
        }

        Ok(evidence)
    }
    fn set_cvm_token(&mut self, v: &Value) -> Result<()> {
        self.cvm_envelop.bytes = Decode::get_vec(v, "cvm_token", vec![])?;
        Ok(())
    }

    fn set_platform_token(&mut self, v: &Value) -> Result<()> {
        self.platform_envelop.bytes = Decode::get_vec(v, "platform_token", vec![])?;
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
            dev_cert,
            ima_log: None,
            event_log: None,
        };
        let virtcca_ev = serde_json::to_vec(&virtcca_ev).unwrap();
        let r = Evidence::verify(&challenge, &virtcca_ev);
        match r {
            Ok(claim) => println!("verify success {:?}", claim),
            Err(e) => assert!(false, "verify failed {:?}", e),
        }
    }
}
