use attestation_service::AttestationService;

use actix_web::{ post, web, HttpResponse};
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

#[post("/attest")]
pub async fn attest(
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
