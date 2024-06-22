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

//! This is a test bin, test get evidence and verify
//! on kunpeng platform, libqca has white ta lists, need copy target/debug/attestation-agent to /vendor/bin/

use rand::{self, RngCore};
use tokio;
use env_logger;

const TEST_THREAD_NUM: i64 = 1; // multi thread num
const DEFAULT_AACONFIG_FILE: &str = "/etc/attestation/attestation-agent/attestation-agent.conf";

//mod agent;
use attestation_agent::agent::*;

#[tokio::main]
async fn main() {
    env_logger::init();
    let mut handles = Vec::with_capacity(TEST_THREAD_NUM as usize);
    for i in 0..TEST_THREAD_NUM {
        let t = tokio::spawn(async move {attestation_proc(i).await;});
        handles.push(t);
    }

    for handle in handles {
        let _ = tokio::join!(handle);
    }
    println!("main stop");
}

async fn attestation_proc(i: i64) {
    println!("attestation_proc {} start", i);
    let aa: AttestationAgent = AttestationAgent::new(Some(DEFAULT_AACONFIG_FILE)).unwrap();

    let mut nonce: [u8; 16] = [0; 16];
    rand::thread_rng().fill_bytes(&mut nonce);

    // Step1: construct input param
    let user_data: attester::EvidenceRequest = attester::EvidenceRequest {
        uuid: String::from("f68fd704-6eb1-4d14-b218-722850eb3ef0"),
        challenge: nonce.to_vec(),
    };

    // Step2: get tee evidence
    let evidence = aa.get_evidence(user_data.clone()).await;
    match evidence {
        Ok(evidence) => {
            println!("get evidence success");
            // Step3: verify evidence
            let ret = aa.verify_evidence(&nonce, &evidence).await;
            match ret {
                Ok(_) => println!("verify evidence success"),
                Err(e) =>println!("verify evidence failed {:?}", e),
            }
        },
        Err(e) => println!("get evidence failed: {}", e),
    }

    let token = aa.get_token(user_data).await;
    match token {
        Ok(token) => {
            let ret = aa.verify_token(token).await;
            match ret {
                Ok(_) => println!("verify token success"),
                Err(e) =>println!("verify token failed {:?}", e),
            }
        },
        Err(e) => println!("get token failed {}", e),
    }

    println!("attestation_proc {} end", i);
}