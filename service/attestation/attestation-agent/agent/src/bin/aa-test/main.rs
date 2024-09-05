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
use tokio;
use env_logger;
use serde_json::json;
use reqwest;

const TEST_THREAD_NUM: i64 = 1; // multi thread num
const AA_ADDR: &str = "http://127.0.0.1:8081";

#[tokio::main]
async fn main() {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let mut handles = Vec::with_capacity(TEST_THREAD_NUM as usize);
    for i in 0..TEST_THREAD_NUM {
        let t = tokio::spawn(async move {aa_proc(i).await;});
        handles.push(t);
    }

    for handle in handles {
        let _ = tokio::join!(handle);
    }
    log::info!("main stop");
}

async fn aa_proc(i: i64) {
    log::info!("attestation_proc thread {} start", i);

    // get challenge
    log::info!("thread {} case1 get challenge", i);
    let client = reqwest::Client::new();
    let challenge_endpoint = format!("{AA_ADDR}/challenge");
    let res = client
        .get(challenge_endpoint)
        .header("Content-Type", "application/json")
        .header("content-length", 0)
        //.json(&request_body)
        .send()
        .await
        .unwrap();

    let challenge = match res.status() {
        reqwest::StatusCode::OK => {
            let respone = res.text().await.unwrap();
            log::info!("thread {} case1 get challenge success response: {:?}", i, respone);
            respone
        }
        status => {
            log::error!("thread {} case1 get challenge failed response: {:?}", i, status);
            return;
        }
    };

    // get evidence
    let request_body = json!({
        "challenge": challenge,
        "uuid": String::from("f68fd704-6eb1-4d14-b218-722850eb3ef0"),
    });
    log::info!("thread {} case2 get evidence, request body: {}", i, request_body);
    let attest_endpoint = format!("{AA_ADDR}/evidence");
    let client = reqwest::Client::new();
    let res = client
        .get(attest_endpoint.clone())
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    let evidence = match res.status() {
        reqwest::StatusCode::OK => {
            let respone = res.text().await.unwrap();
            log::info!("thread {} case2 get evidence success", i);
            log::debug!("thread {} response: {:?}", i, respone);
            respone
        }
        status => {
            log::error!("thread {} case2 get evidence failed response: {:?}", i, status);
            return;
        }
    };
    // case3 verify evidence with no challenge
    // verify evidence with challenge
    let request_body = json!({
        "challenge": challenge,
        "evidence": evidence,
    });
    log::info!("thread {} case4 verify evidence with challenge", i);
    let client = reqwest::Client::new();
    let res = client
        .post(attest_endpoint)
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .unwrap();

    match res.status() {
        reqwest::StatusCode::OK => {
            let respone = res.text().await.unwrap();
            log::info!("thread {} case4 verify evidence success response: {:?}", i, respone);
        }
        status => {
            log::error!("thread {} case4 verify evidence failed response: {:?}", i, status);
        }
    }

    #[cfg(not(feature = "no_as"))]
    {
        // get token
        let token_endpoint = format!("{AA_ADDR}/token");
        let request_body = json!({
            "challenge": challenge,
            "uuid": String::from("f68fd704-6eb1-4d14-b218-722850eb3ef0"),
        });
        log::info!("thread {} case5 get token, request body: {}", i, request_body);
        let client = reqwest::Client::new();
        let res = client
            .get(token_endpoint.clone())
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .unwrap();

        let token = match res.status() {
            reqwest::StatusCode::OK => {
                let respone = res.text().await.unwrap();
                log::info!("thread {} case5 get token success", i);
                log::debug!("thread {} response: {:?}", i, respone);
                respone
            }
            status => {
                log::error!("thread {} case5 get token failed status: {:?} response: {:?}", i, status, res.text().await.unwrap());
                return;
            }
        };

        // verify token
        let request_body = json!({
            "token": token,
        });

        log::info!("thread {} case6 verify token", i);
        let client = reqwest::Client::new();
        let res = client
            .post(token_endpoint)
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .unwrap();

        match res.status() {
            reqwest::StatusCode::OK => {
                let respone = res.text().await.unwrap();
                log::info!("thread {} case6 verify token success response: {:?}", i, respone);
            }
            status => {
                log::error!("thread {} case6 verify token failed response: {:?}", i, status);
            }
        }
    }
    

    log::info!("attestation_proc thread {} end", i);
}