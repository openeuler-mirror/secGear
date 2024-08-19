use attestation_agent::{AttestationAgent, AttestationAgentAPIs};
use attestation_agent::result::Result;

use actix_web::{ post, get, web, HttpResponse};
use attester::EvidenceRequest;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use log;
use base64_url;

#[derive(Deserialize, Serialize, Debug)]
struct GetChallengeRequest {}

#[get("/challenge")]
pub async fn get_challenge(
    //_request: web::Json<GetChallengeRequest>,
    agent: web::Data<Arc<RwLock<AttestationAgent>>>,
) -> Result<HttpResponse> {
    //let request = request.0;
    log::debug!("get challenge request");
    let challenge = agent.read().await.get_challenge().await?;

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
    let challenge = base64_url::decode(&request.challenge).expect("base64 decode challenge");
    let uuid = request.uuid;
    let ima =  request.ima;
    let input = EvidenceRequest {
        uuid: uuid,
        challenge: challenge,
        ima: ima,
        policy_id: None,
    };
    let evidence = agent.read().await.get_evidence(input).await?;


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
    let challenge = base64_url::decode(&request.challenge).expect("base64 decode challenge");
    let evidence = request.evidence;
    let policy_id =  request.policy_id;

    let claim = agent.read().await.verify_evidence(&challenge, evidence.as_bytes(), policy_id).await?;
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
    let challenge = base64_url::decode(&request.challenge).expect("base64 decode challenge");
    let uuid = request.uuid;
    let ima = request.ima;
    let policy_id =  request.policy_id;
    let input = EvidenceRequest {
        uuid: uuid,
        challenge: challenge,
        ima: ima,
        policy_id: policy_id,
    };
    let token = agent.read().await.get_token(input).await?;


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

    let claim = agent.read().await.verify_token(request.token).await?;
    let string_claim = serde_json::to_string(&claim)?;

    Ok(HttpResponse::Ok().body(string_claim))
}