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
use crate::result::Result;
use crate::{AgentError, AttestationAgent, AttestationAgentAPIs, TokenRequest};
use actix_web::{get, post, web, HttpResponse};
use attester::EvidenceRequest;
use log;
use resource::resource::ResourceLocation;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Deserialize, Serialize, Debug)]
struct GetChallengeRequest {
    pub user_data: Vec<u8>,
}

#[get("/challenge")]
pub async fn get_challenge(
    request: Option<web::Json<GetChallengeRequest>>,
    agent: web::Data<Arc<RwLock<AttestationAgent>>>,
) -> Result<HttpResponse> {
    log::debug!("get challenge request");
    let user_data: Option<Vec<u8>>;
    if request.is_some() {
        user_data = Some(request.unwrap().0.user_data);
        if user_data.clone().unwrap().len() > 32 {
            return Err(crate::result::Error::Agent {
                source: AgentError::ChallengeError(String::from(
                    "user data length should not exceed 32",
                )),
            });
        }
        log::debug!("user data is {:?}", user_data.clone().unwrap());
    } else {
        log::debug!("user data is None");
        user_data = Option::None;
    }
    let challenge = agent
        .read()
        .await
        .get_challenge(user_data)
        .await
        .map_err(|err| AgentError::ChallengeError(err.to_string()))?;

    Ok(HttpResponse::Ok().body(challenge))
}

#[derive(Deserialize, Serialize, Debug)]
struct GetEvidenceRequest {
    challenge: String,
    uuid: String,
    ima: Option<bool>,
}

#[get("/evidence")]
pub async fn get_evidence(
    request: web::Json<GetEvidenceRequest>,
    agent: web::Data<Arc<RwLock<AttestationAgent>>>,
) -> Result<HttpResponse> {
    let request = request.0;
    log::debug!("get evidence request: {:?}", request);
    let challenge = request.challenge;
    let uuid = request.uuid;
    let ima = request.ima;
    let input = EvidenceRequest {
        uuid: uuid,
        challenge: challenge.into_bytes(),
        ima: ima,
    };
    let evidence = agent
        .read()
        .await
        .get_evidence(input)
        .await
        .map_err(|err| AgentError::GetEvidenceError(err.to_string()))?;

    Ok(HttpResponse::Ok().body(evidence))
}

#[derive(Deserialize, Serialize, Debug)]
struct VerifyEvidenceRequest {
    challenge: String,
    evidence: String,
    policy_id: Option<Vec<String>>,
}
#[post("/evidence")]
pub async fn verify_evidence(
    request: web::Json<VerifyEvidenceRequest>,
    agent: web::Data<Arc<RwLock<AttestationAgent>>>,
) -> Result<HttpResponse> {
    let request = request.0;
    log::debug!("verify evidence request: {:?}", request);
    let challenge = request.challenge;
    let evidence = request.evidence;
    let policy_id = request.policy_id;

    let claim = agent
        .read()
        .await
        .verify_evidence(&challenge.into_bytes(), evidence.as_bytes(), policy_id)
        .await
        .map_err(|err| AgentError::VerifyEvidenceError(err.to_string()))?;
    let string_claim = serde_json::to_string(&claim)?;

    Ok(HttpResponse::Ok().body(string_claim))
}

#[derive(Deserialize, Serialize, Debug)]
struct GetTokenRequest {
    challenge: String,
    uuid: String,
    ima: Option<bool>,
    policy_id: Option<Vec<String>>,
}

#[get("/token")]
pub async fn get_token(
    request: web::Json<GetTokenRequest>,
    agent: web::Data<Arc<RwLock<AttestationAgent>>>,
) -> Result<HttpResponse> {
    let request = request.0;
    log::debug!("get token request: {:?}", request);
    let challenge = request.challenge;
    let uuid = request.uuid;
    let ima = request.ima;
    let policy_id = request.policy_id;
    let ev = EvidenceRequest {
        uuid: uuid,
        challenge: challenge.into_bytes(),
        ima: ima,
    };
    let input = TokenRequest {
        ev_req: ev,
        policy_id: policy_id,
    };

    let token = agent
        .read()
        .await
        .get_token(input)
        .await
        .map_err(|err| AgentError::GetTokenError(err.to_string()))?;

    Ok(HttpResponse::Ok().body(token))
}

#[derive(Deserialize, Serialize, Debug)]
struct VerifyTokenRequest {
    token: String,
}
#[post("/token")]
pub async fn verify_token(
    request: web::Json<VerifyTokenRequest>,
    agent: web::Data<Arc<RwLock<AttestationAgent>>>,
) -> Result<HttpResponse> {
    let request = request.0;
    log::debug!("verify token request: {:?}", request);

    let claim = agent
        .read()
        .await
        .verify_token(request.token)
        .await
        .map_err(|err| AgentError::VerifyTokenError(err.to_string()))?;
    let string_claim = serde_json::to_string(&claim)
        .map_err(|err| AgentError::VerifyTokenError(err.to_string()))?;

    Ok(HttpResponse::Ok().body(string_claim))
}

#[derive(Deserialize, Serialize, Debug)]
struct Location {
    repository: String,
    r#type: String,
    tag: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct GetResourceRequest {
    uuid: String,
    challenge: Option<String>,
    ima: Option<bool>,
    policy_id: Option<Vec<String>>,
    resource: ResourceLocation,
}

#[get("/resource/storage")]
pub async fn get_resource(
    request: web::Json<GetResourceRequest>,
    agent: web::Data<Arc<RwLock<AttestationAgent>>>,
) -> Result<HttpResponse> {
    let agent = agent.read().await;

    // If user provides the challenge number, use the challenge to find session.
    let challenge = match request.challenge.as_ref() {
        Some(c) => c.clone(),
        None => agent
            .get_challenge(None)
            .await
            .map_err(|err| AgentError::ChallengeError(err.to_string()))?,
    };

    // base64 encoded challenge
    let ev_req = EvidenceRequest {
        uuid: request.uuid.clone(),
        challenge: challenge.clone().into_bytes(),
        ima: request.ima,
    };

    let token_req = TokenRequest {
        ev_req,
        policy_id: request.policy_id.clone(),
    };

    #[cfg(feature = "no_as")]
    {
        bail!("Resource can only be got from attestation server.");
    }

    let token = agent.get_token(token_req).await?;

    let restful = format!("{}/resource/storage", agent.config.svr_url,);

    let resource = agent
        .get_resource(&challenge, &restful, request.resource.clone(), &token)
        .await
        .map_err(|err| AgentError::GetTokenError(err.to_string()))?;

    Ok(HttpResponse::Ok().body(resource))
}
