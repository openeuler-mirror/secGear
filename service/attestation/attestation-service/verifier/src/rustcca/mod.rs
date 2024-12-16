// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

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

//! rust-cca verifier plugin
use super::TeeClaim;
use ear::claim::*;
use serde_json::json;
use anyhow::{Result, bail};
extern crate ccatoken;
use ccatoken::token;
use ccatoken::store::{
    PlatformRefValue, RealmRefValue, Cpak, MemoRefValueStore, MemoTrustAnchorStore, RefValues,
    SwComponent,
};

use serde_json::value::RawValue;
use std::error::Error;


const TEST_CPAK: &str = include_str!("../../test_data/cpak.json");

#[derive(Debug, Default)]
pub struct RustCCAVerifier {}

impl RustCCAVerifier {
    pub fn evaluate(&self, user_data: &[u8], evidence: &[u8]) -> Result<TeeClaim> {
        return evalute_wrapper(user_data, evidence);
    }
}


//参数是challenge 和report
// 1. execute golden to get tas, rvs
// 2. execute verify   
fn evalute_wrapper(user_data: &[u8], evidence: &[u8]) -> Result<TeeClaim> {

    	let mut in_evidence =
        token::Evidence::decode(&evidence.to_vec()).unwrap_or_else(|_| panic!("decode evidence"));
        
    	let cpak = map_str_to_cpak(&in_evidence.platform_claims, &TEST_CPAK).unwrap_or_else(|_| panic!("map cpak"));
    	let _ = in_evidence.verify_with_cpak(cpak).unwrap_or_else(|_| panic!("verify cpak"));
    
    	let (platform_tvec, realm_tvec) = in_evidence.get_trust_vectors();
    	if platform_tvec.instance_identity != TRUSTWORTHY_INSTANCE {
            bail!("platform is not trustworthy");
    	}
    	if realm_tvec.instance_identity != TRUSTWORTHY_INSTANCE {
            bail!("realm is not trustworthy");
    	}
    
    	let rv = map_evidence_to_refval(&in_evidence).unwrap_or_else(|_| panic!("map refval"));
    	let ta = map_evidence_to_trustanchor(&in_evidence.platform_claims, &TEST_CPAK).unwrap_or_else(|_| panic!("map trustanchor"));
    
    
    	let mut rvs: MemoRefValueStore = Default::default();
    	rvs.load_json(&rv).unwrap_or_else(|_| panic!("load rvs"));
    	let mut tas: MemoTrustAnchorStore = Default::default();
    	tas.load_json(&ta).unwrap_or_else(|_| panic!("load tas"));
    	let _ = in_evidence.verify(&tas);
        
        //verify challenge
        let _ = verify_realm_challenge(user_data, &in_evidence.realm_claims);
        
        let payload = json!({
            "platform trust vector":  serde_json::to_string_pretty(&platform_tvec).unwrap(),
            "realm trust vector" : serde_json::to_string_pretty(&realm_tvec).unwrap(),
            "realm" : {
            	"challenge" : hex::encode(in_evidence.realm_claims.challenge.clone()),
            	"perso" : hex::encode(in_evidence.realm_claims.perso.clone()),
            	"hash_alg" : hex::encode(in_evidence.realm_claims.hash_alg.clone()),
            	"rak" : hex::encode(in_evidence.realm_claims.rak.clone())
            }
        });
        
        let claim = json!({
            "tee_type": "ccatoken",
            "payload" : payload,
        });
    	Ok(claim as TeeClaim)
}



fn verify_realm_challenge(challenge: &[u8], realm_token: &token::Realm) -> Result<()>{
	let len = challenge.len();
        let token_challenge = &realm_token.challenge[0..len];
        
        if challenge != token_challenge {
            log::error!("verify cvm token challenge error, cvm_token challenge {:?}, input challenge {:?}", 
                token_challenge, challenge);
            bail!("verify cvm token challenge error, cvm_token challenge {:?}, input challenge {:?}", 
                token_challenge, challenge);
        }
        
        Ok(())
}
fn map_str_to_cpak(p: &token::Platform, cpak_str: &str) -> Result<Cpak, Box<dyn Error>> {
    let raw_pkey = RawValue::from_string(cpak_str.to_string())?;

    let mut v = Cpak {
        raw_pkey,
        inst_id: p.inst_id,
        impl_id: p.impl_id,
        ..Default::default()
    };
    v.parse_pkey()?;
    Ok(v)
}

fn map_evidence_to_refval(e: &token::Evidence) -> Result<String, Box<dyn Error>> {
    let prv = map_evidence_to_platform_refval(&e.platform_claims)?;
    let rrv = map_evidence_to_realm_refval(&e.realm_claims)?;

    let rvs: RefValues = RefValues {
        platform: Some(vec![prv]),
        realm: Some(vec![rrv]),
    };

    let j = serde_json::to_string_pretty(&rvs)?;

    Ok(j)
}

fn map_evidence_to_platform_refval(
    p: &token::Platform,
) -> Result<PlatformRefValue, Box<dyn Error>> {
    let mut v = PlatformRefValue {
        impl_id: p.impl_id,
        config: p.config.clone(),
        ..Default::default()
    };

    for other in &p.sw_components {
        let swc = SwComponent {
            mval: other.mval.clone(),
            signer_id: other.signer_id.clone(),
            version: other.version.clone(),
            mtyp: other.mtyp.clone(),
        };

        v.sw_components.push(swc)
    }

    Ok(v)
}

fn map_evidence_to_realm_refval(p: &token::Realm) -> Result<RealmRefValue, Box<dyn Error>> {
    let mut v = RealmRefValue {
        perso: p.perso.to_vec(),
        rim: p.rim.clone(),
        rak_hash_alg: p.rak_hash_alg.clone(),
        ..Default::default()
    };

    for (i, other) in p.rem.iter().enumerate() {
        v.rem[i].value.clone_from(other);
    }

    Ok(v)
}

fn map_evidence_to_trustanchor(p: &token::Platform, cpak: &str) -> Result<String, Box<dyn Error>> {
    let raw_pkey = RawValue::from_string(cpak.to_string())?;

    let v = Cpak {
        raw_pkey,
        inst_id: p.inst_id,
        impl_id: p.impl_id,
        ..Default::default() // pkey is not serialised
    };

    let j = serde_json::to_string_pretty(&vec![v])?;

    Ok(j)
}
#[cfg(test)]
mod tests {
    use super::*;
    use ear::claim::TRUSTWORTHY_INSTANCE;


    const TEST_CCA_TOKEN: &[u8; 1222] = include_bytes!("../../test_data/cca-token-01.cbor");
    //const TEST_CCA_TOKEN: &[u8; 1125] = include_bytes!("../../test_data/cca-token-02.cbor");
    const TEST_CPAK: &str = include_str!("../../test_data/cpak.json");


    #[test]
    fn cca_test() -> Result<(), Box<dyn Error>>{


    	let mut evidence =
        token::Evidence::decode(&TEST_CCA_TOKEN.to_vec()).expect("decoding TEST_CCA_TOKEN");
 	
 	let j = TEST_CPAK;
    	let cpak = map_str_to_cpak(&evidence.platform_claims, &j)?;
        let _ = evidence.verify_with_cpak(cpak)?;

        
        
        let (platform_tvec, realm_tvec) = evidence.get_trust_vectors();
        if platform_tvec.instance_identity != TRUSTWORTHY_INSTANCE {
            return Err("platform is not trustworthy".into());
        }
        if realm_tvec.instance_identity != TRUSTWORTHY_INSTANCE {
            return Err("realm is not trustworthy".into());
        }
	
        let rv = map_evidence_to_refval(&evidence)?;
        let ta = map_evidence_to_trustanchor(&evidence.platform_claims, &j)?;

	let mut rvs: MemoRefValueStore = Default::default();
	rvs.load_json(&rv)?;
	let mut tas: MemoTrustAnchorStore = Default::default();
	tas.load_json(&ta)?;
        let _ = evidence.verify(&tas);
        
        
        let (platform_tvec, realm_tvec) = evidence.get_trust_vectors();
        let payload = json!({
            "platform trust vector":  serde_json::to_string_pretty(&platform_tvec).unwrap(),
            "realm trust vector" : serde_json::to_string_pretty(&realm_tvec).unwrap(),
            "realm" : {
            	"challenge" : hex::encode(evidence.realm_claims.challenge.clone()),
            	"perso" : hex::encode(evidence.realm_claims.perso.clone()),
            	"hash_alg" : hex::encode(evidence.realm_claims.hash_alg.clone()),
            	"rak" : hex::encode(evidence.realm_claims.rak.clone())
            }
        });
        
        let claim = json!({
            "tee_type": "ccatoken",
            "payload" : payload,
        });
        println!("verify success {:?}", claim);
        Ok(())  
    }
    
}

