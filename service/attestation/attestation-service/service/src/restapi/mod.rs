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
pub mod resource;

use crate::result::{AsError, Result};
use crate::session::Session;
use crate::AttestationService;
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use attestation_types::SESSION_TIMEOUT_MIN;
use log;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

const DEFAULT_POLICY_DIR: &str = "/etc/attestation/attestation-service/policy";
#[derive(Deserialize, Serialize, Debug)]
pub struct ChallengeRequest {
    pub user_data: Vec<u8>,
}

#[get("/challenge")]
pub async fn get_challenge(
    request: Option<web::Json<ChallengeRequest>>,
    service: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    log::debug!("challenge request");
    let user_data: Option<Vec<u8>>;

    if request.is_some() {
        user_data = Some(request.unwrap().0.user_data);
        if user_data.clone().unwrap().len() > 32 {
            return Err(AsError::ParameterInvalid(String::from(
                "user data length should not exceed 32",
            )));
        }
        log::debug!("user data is {:?}", user_data.clone().unwrap());
    } else {
        log::debug!("user data is None");
        user_data = Option::None;
    }

    let map = service.read().await.get_sessions();
    let challenge = service.read().await.generate_challenge(user_data).await;
    let new_session = Session::new(challenge, SESSION_TIMEOUT_MIN);

    let response = HttpResponse::Ok()
        .cookie(new_session.cookie())
        .json(new_session.challenge.clone());
    map.insert(new_session);

    Ok(response)
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AttestationRequest {
    challenge: String,
    evidence: String,
    policy_id: Option<Vec<String>>,
}

#[post("/attestation")]
pub async fn attestation(
    http_req: HttpRequest,
    request: web::Json<AttestationRequest>,
    service: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    log::debug!("attestation request is coming");
    let map = service.read().await.get_sessions();
    let request = request.0;
    let challenge = request.challenge;
    let mut cookie_exist = false;
    let mut cookie = actix_web::cookie::Cookie::new("init", "init");
    if !http_req.headers().contains_key("as-challenge") {
        log::info!("attestation request lacks 'as-challenge' header field.");
    } else {
        log::info!("sessions map len:{}", map.session_map.len());
        cookie = http_req
            .cookie("oeas-session-id")
            .ok_or(AsError::CookieMissing)?;
        cookie_exist = true;
        let session = map
            .session_map
            .get_async(cookie.value())
            .await
            .ok_or(AsError::SessionNotFound)?;
        if session.is_expired() {
            return Err(AsError::SessionExpired);
        }
        if challenge != session.challenge {
            log::error!(
                "request challenge:{} does not match session challenge:{}",
                challenge,
                session.challenge
            );
            return Err(AsError::ChallengeInvalid);
        }
    }

    // The challenge in evidence is base64 encoded.
    let nonce = challenge.as_bytes();
    let evidence = base64_url::decode(&request.evidence)?;
    let ids = request.policy_id;
    let token = service
        .read()
        .await
        .evaluate(&nonce, &evidence, &ids)
        .await?;

    if cookie_exist {
        Ok(HttpResponse::Ok().cookie(cookie).body(token))
    } else {
        Ok(HttpResponse::Ok().body(token))
    }

}

#[derive(Deserialize, Serialize, Debug)]
pub struct ReferenceRequest {
    refs: String,
}

#[post("/reference")]
pub async fn reference(
    request: web::Json<ReferenceRequest>,
    service: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    let request = request.0;
    log::debug!("reference request: {:?}", request);
    service
        .read()
        .await
        .register_reference(&request.refs)
        .await?;
    Ok(HttpResponse::Ok().body("set reference success"))
}

#[derive(Deserialize, Serialize, Debug)]
pub struct PolicyRequest {
    tee: String,
    id: String,
    policy: String,
}

#[post("/policy")]
pub async fn set_policy(
    request: web::Json<PolicyRequest>,
    service: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    let request = request.0;
    log::debug!("set policy request: {:?}", request);
    let policy_id = request.id.clone();
    let policy = request.policy.clone();
    let dir: String = String::from(DEFAULT_POLICY_DIR);
    service
        .read()
        .await
        .set_policy(&policy_id, &policy, &dir)
        .await?;
    Ok(HttpResponse::Ok().body("set policy success"))
}

#[derive(Deserialize, Serialize, Debug)]
pub struct PolicyGetRequest {
    policy_id: String,
}

#[get("/policy")]
pub async fn get_policy(
    request: web::Json<PolicyGetRequest>,
    service: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    let request = request.0;
    log::debug!("get policy request: {:?}", request);
    let id = request.policy_id.clone();
    let dir: String = String::from(DEFAULT_POLICY_DIR);
    let ret = service
        .read()
        .await
        .get_policy(&dir, &id.to_string())
        .await?;
    Ok(HttpResponse::Ok().body(ret))
}
