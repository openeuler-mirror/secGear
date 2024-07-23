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
use serde_json::json;
use reqwest;
use base64_url;

const TEST_THREAD_NUM: i64 = 1; // multi thread num

#[tokio::main]
async fn main() {
    env_logger::init();
    let mut handles = Vec::with_capacity(TEST_THREAD_NUM as usize);
    for i in 0..TEST_THREAD_NUM {
        let t = tokio::spawn(async move {aa_proc(i).await;});
        handles.push(t);
    }

    for handle in handles {
        let _ = tokio::join!(handle);
    }
    println!("main stop");
}

async fn aa_proc(i: i64) {
    println!("attestation_proc {} start", i);
    
    // get evidence
    let mut nonce: [u8; 16] = [0; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let request_body = json!({
        "challenge": base64_url::encode(&nonce),
        "uuid": String::from("f68fd704-6eb1-4d14-b218-722850eb3ef0"),
    });

    let client = reqwest::Client::new();
    let attest_endpoint = "http://127.0.0.1:8081/evidence";
    let res = client
        .get(attest_endpoint)
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    match res.status() {
        reqwest::StatusCode::OK => {
            let respone = res.text().await.unwrap();
            println!("get evidence success, AA Response: {:?}", respone);
        }
        status => {
            println!("get evidence Failed, AA Response: {:?}", status);
        }
    }

    println!("attestation_proc {} end", i);
}