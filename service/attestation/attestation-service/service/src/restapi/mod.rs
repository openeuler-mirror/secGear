use attestation_service::AttestationService;

use actix_web::{ post, get, web, HttpResponse, HttpRequest};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use log;
use base64_url;

use attestation_service::result::Result;

#[derive(Deserialize, Serialize, Debug)]
pub struct AttestationRequest {
    challenge: String,
    evidence: String,
}

#[post("/attestation")]
pub async fn attestation(
    request: web::Json<AttestationRequest>,
    service: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    let request = request.0;
    log::debug!("attest request: {:?}", request);
    let challenge = base64_url::decode(&request.challenge).expect("base64 decode challenge");
    let evidence = base64_url::decode(&request.evidence).expect("base64 decode evidence");
    let token = service.read().await.evaluate(&challenge, &evidence).await?;

    Ok(HttpResponse::Ok().body(token))
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ReferenceRequest {
    key: String,
    value: String,
}

#[post("/reference")]
pub async fn reference(
    request: web::Json<ReferenceRequest>,
    service: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    let request = request.0;
    log::debug!("reference request: {:?}", request);
    drop(service);

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
    log::debug!("reference request: {:?}", request);
    drop(service);

    Ok(HttpResponse::Ok().body("set policy success"))
}

#[get("/policy")]
pub async fn get_policy(
    request: HttpRequest,
    service: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    log::debug!("reference request: {:?}", request);
    drop(service);

    Ok(HttpResponse::Ok().body("set policy success"))
}