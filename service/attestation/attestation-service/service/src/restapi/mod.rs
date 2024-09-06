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
use attestation_service::AttestationService;
use attestation_service::result::{Result, Error};

use actix_web::{ post, get, web, HttpResponse, HttpRequest};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use log;
use base64_url;
use attestation_types::SESSION_TIMEOUT_MIN;
use crate::session::{Session, SessionMap};

const DEFAULT_POLICY_DIR: &str = "/etc/attestation/attestation-service/policy";
#[derive(Deserialize, Serialize, Debug)]
pub struct ChallengeRequest {}

#[get("/challenge")]
pub async fn get_challenge(
    map: web::Data<SessionMap>,
    service: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    log::debug!("challenge request");

    let challenge = service.read().await.generate_challenge().await;
    let session = Session::new(challenge, SESSION_TIMEOUT_MIN);
    let response = HttpResponse::Ok()
        .cookie(session.cookie())
        .json(session.challenge.clone());
    map.insert(session);

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
    map: web::Data<SessionMap>,
    request: web::Json<AttestationRequest>,
    service: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    log::debug!("attestation request is coming");
    let request = request.0;
    let challenge = request.challenge;

    if http_req.headers().contains_key("as-challenge") {
        log::info!("sessions map len:{}", map.session_map.len());
        let cookie = http_req.cookie("oeas-session-id").ok_or(Error::CookieMissing)?;
        let session = map
            .session_map
            .get_async(cookie.value())
            .await
            .ok_or(Error::SessionNotFound)?;
        if session.is_expired() {
            return Err(Error::SessionExpired);
        }
        if challenge != session.challenge {
            log::error!("request challenge:{} does not match session challenge:{}", challenge, session.challenge);
            return Err(Error::ChallengeInvalid);
        }
    }

    let nonce = base64_url::decode(&challenge).expect("base64 decode nonce");
    let evidence = base64_url::decode(&request.evidence).expect("base64 decode evidence");
    let ids = request.policy_id;
    let token = service.read().await.evaluate(&nonce, &evidence, &ids).await?;

    Ok(HttpResponse::Ok().body(token))
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ReferenceRequest {
    refs: String
}

#[post("/reference")]
pub async fn reference(
    request: web::Json<ReferenceRequest>,
    service: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    let request = request.0;
    log::debug!("reference request: {:?}", request);
    match service.read().await.register_reference(&request.refs).await {
        Ok(_) => Ok(HttpResponse::Ok().body("set reference success")),
        Err(_err) => Ok(HttpResponse::Ok().body("set reference fail")),
    }
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
    let dir:String = String::from(DEFAULT_POLICY_DIR);
    match service.read().await.set_policy(&policy_id, &policy, &dir).await {
        Ok(_) => Ok(HttpResponse::Ok().body("set policy success")),
        Err(err) => {
            log::debug!("set policy error: {:?}", err);
            Ok(HttpResponse::Ok().body("set policy fail"))
        }
    }
}

#[get("/policy")]
pub async fn get_policy(
    request: HttpRequest,
    service: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    log::debug!("get policy request: {:?}", request);
    let dir:String = String::from(DEFAULT_POLICY_DIR);
    match service.read().await.get_policy(&dir).await {
        Ok(ret) => Ok(HttpResponse::Ok().body(ret)),
        Err(_err) => Ok(HttpResponse::Ok().body("get policy fail")),
    }
}
