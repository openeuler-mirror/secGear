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
use crate::result::{self, AsError, Result};
use crate::session::Session;
use crate::AttestationService;
use actix_web::http::header::Header;
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use anyhow::Context;
use attestation_types::SESSION_TIMEOUT_MIN;
use base64_url;
use log;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::sync::Arc;
use token_signer::verify;
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
            return Err(Error::ParameterInvalid(String::from(
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

    if http_req.headers().contains_key("as-challenge") {
        log::warn!("attestation request lacks 'as-challenge' header field.");
    }

    log::info!("sessions map len:{}", map.session_map.len());
    let cookie = http_req
        .cookie("oeas-session-id")
        .ok_or(AsError::CookieMissing)?;
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

    // The challenge in evidence is base64 encoded.
    let nonce = challenge.as_bytes();
    let evidence = base64_url::decode(&request.evidence)?;
    let ids = request.policy_id;
    let token = service
        .read()
        .await
        .evaluate(&nonce, &evidence, &ids)
        .await?;

    Ok(HttpResponse::Ok().body(token))
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

#[derive(Deserialize, Serialize, Debug)]
struct ResourcePath {
    repository: String,
    r#type: String,
    tag: String,
}

impl Display for ResourcePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.repository, self.r#type, self.tag)
    }
}

#[get("/resource/{repository}/{type}/{tag}")]
pub async fn get_resource(
    req: HttpRequest,
    agent: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    let sessions = agent.read().await.get_sessions();

    // If the corresponding session of the token exists, get the token inside the session.
    // Otherwise, get the token from the http header.
    let token = match {
        if let Some(cookie) = req.cookie("oeas-session-id") {
            sessions
                .session_map
                .get_async(cookie.value())
                .await
                .map(|session| session.get_token())
                .flatten()
                .map(|t| {
                    log::debug!("Get token from session {}", cookie.value());
                    t
                })
        } else {
            None
        }
    } {
        Some(token) => token,
        None => {
            let bearer = Authorization::<Bearer>::parse(&req)
                .context("failed to parse bearer token")?
                .into_scheme();
            log::debug!("Get token from headers");
            bearer.token().to_string()
        }
    };

    let claim = verify(&token).context("illegal token")?;

    let p = ResourcePath {
        repository: req.match_info().get("repository").unwrap().to_owned(),
        r#type: req.match_info().get("type").unwrap().to_owned(),
        tag: req.match_info().get("tag").unwrap().to_owned(),
    };

    let resource_path = format!("{}", p);
    let claim = serde_json::to_string(&claim)?;

    log::debug!("Resource path: {}", resource_path);
    log::debug!("Receive claim: {}", claim);

    match agent
        .read()
        .await
        .resource_evaluate(&resource_path, &claim)
        .await
    {
        Ok(r) => {
            if r {
                log::debug!("Resource evaluate success.");
                let content = agent.read().await.get_resource(&resource_path).await?;

                Ok(HttpResponse::Ok().body(content))
            } else {
                log::debug!("Resource evaluate fail.");
                Ok(HttpResponse::BadRequest().body("resource evaluation failed"))
            }
        }
        Err(e) => {
            log::debug!("{}", e);
            Err(result::AsError::ResourcePolicy(
                resource::error::ResourceError::LoadPolicy(e),
            ))
        }
    }
}
