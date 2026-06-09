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
use crate::{ActiveTokenError, AgentError, AttestationAgent, AttestationAgentAPIs, TokenRequest};
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use attestation_types::resource::ResourceLocation;
use attester::EvidenceRequest;
use log;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[cfg(feature = "no_as")]
use crate::result::Error;

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
    #[cfg(feature = "no_as")]
    {
        log::debug!("get resource request: {:?}", request.0);
        let _ = agent;
        return Err(Error::AttestationAgentError(
            "Resource can only be got from attestation server.".to_string(),
        ));
    }

    #[cfg(not(feature = "no_as"))]
    {
        let request = request.0;
        log::debug!("get resource request: {:?}", request);
        let agent = agent.read().await;

        let challenge = match request.challenge.as_ref() {
            Some(challenge) => challenge.clone(),
            None => agent
                .get_challenge(None)
                .await
                .map_err(|err| AgentError::ChallengeError(err.to_string()))?,
        };

        let ev = EvidenceRequest {
            uuid: request.uuid.clone(),
            challenge: challenge.clone().into_bytes(),
            ima: request.ima,
        };
        let input = TokenRequest {
            ev_req: ev,
            policy_id: request.policy_id.clone(),
        };
        let token = agent
            .get_token(input)
            .await
            .map_err(|err| AgentError::GetTokenError(err.to_string()))?;

        let restful = format!("{}/resource/storage", agent.config.svr_url);
        let resource_content = agent
            .get_resource(&challenge, &restful, request.resource.clone(), &token)
            .await
            .map_err(|err| AgentError::GetTokenError(err.to_string()))?;

        Ok(HttpResponse::Ok().body(resource_content))
    }
}

#[derive(Deserialize, Serialize, Debug)]
struct GetCurrentTokenRequest {}

#[get("/current_token")]
pub async fn get_current_token(
    _request: Option<web::Json<GetCurrentTokenRequest>>,
    agent: web::Data<Arc<RwLock<AttestationAgent>>>,
) -> Result<HttpResponse> {
    log::debug!("get current token request");

    let agent_guard = agent.read().await;
    let mut token_info = Vec::new();

    for app in &agent_guard.config.app_list {
        let ttl = app.get_token_ttl().await.unwrap_or(0);
        let should_refresh = app.should_refresh_token().await;

        token_info.push(serde_json::json!({
            "app_uuid": app.uuid,
            "has_token": app.has_token().await,
            "expires_at": app.get_token_expires_at().await,
            "ttl_seconds": ttl,
            "should_refresh": should_refresh,
            "refresh_threshold": std::cmp::max(app.interval, (ttl as f64 * 0.1) as u64),
            "failure_count": app.get_failure_count(),
            "is_expired": app.is_token_expired().await
        }));
    }

    let response = serde_json::json!({
        "apps": token_info
    });

    Ok(HttpResponse::Ok().json(response))
}

#[derive(Deserialize, Serialize, Debug)]
struct ActiveTokenRequest {
    nonce: Option<String>,
    uuid: Option<String>,
}

pub struct ActiveTokenRateLimiter {
    limit_per_second: u32,
    clients: Mutex<HashMap<IpAddr, RateLimitState>>,
}

struct RateLimitState {
    window_started_at: Instant,
    request_count: u32,
}

impl ActiveTokenRateLimiter {
    pub fn new(limit_per_second: u32) -> Self {
        Self {
            limit_per_second,
            clients: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(&self, ip_addr: IpAddr) -> bool {
        let mut clients = self.clients.lock().unwrap();
        let now = Instant::now();
        let window = Duration::from_secs(1);
        clients.retain(|_, state| now.duration_since(state.window_started_at) < window);

        let state = clients.entry(ip_addr).or_insert(RateLimitState {
            window_started_at: now,
            request_count: 0,
        });

        if now.duration_since(state.window_started_at) >= window {
            state.window_started_at = now;
            state.request_count = 0;
        }

        if state.request_count >= self.limit_per_second {
            return false;
        }

        state.request_count += 1;
        true
    }
}

#[get("/active_token")]
pub async fn active_token(
    http_request: HttpRequest,
    request: web::Query<ActiveTokenRequest>,
    agent: web::Data<Arc<RwLock<AttestationAgent>>>,
    rate_limiter: Option<web::Data<ActiveTokenRateLimiter>>,
) -> Result<HttpResponse> {
    if let (Some(limiter), Some(peer_addr)) = (rate_limiter, http_request.peer_addr()) {
        if !limiter.check(peer_addr.ip()) {
            return Ok(HttpResponse::TooManyRequests().json(serde_json::json!({
                "error": "rate_limited",
                "message": "too many /active_token requests from this peer"
            })));
        }
    }

    let nonce_bytes = if let Some(ref nonce_hex) = request.nonce {
        if nonce_hex.len() != 64 {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "invalid_nonce",
                "message": "nonce must be exactly 32 bytes (64 hex characters)"
            })));
        }
        match hex::decode(nonce_hex) {
            Ok(bytes) if bytes.len() == 32 => Some(bytes),
            _ => {
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "invalid_nonce",
                    "message": "nonce must be exactly 32 bytes (64 hex characters)"
                })));
            }
        }
    } else {
        None
    };

    let agent_guard = agent.read().await;
    match agent_guard
        .get_active_token(request.uuid.as_deref(), nonce_bytes)
        .await
    {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => {
            log::error!("get_active_token failed: {:?}", e);
            Ok(active_token_error_response(e))
        }
    }
}

fn active_token_error_response(error: ActiveTokenError) -> HttpResponse {
    match error {
        ActiveTokenError::InvalidUuid => HttpResponse::BadRequest().json(serde_json::json!({
            "error": "invalid_uuid",
            "message": "uuid must not be auto"
        })),
        ActiveTokenError::MissingNonce => HttpResponse::BadRequest().json(serde_json::json!({
            "error": "missing_nonce",
            "message": "nonce is required for virtCCA active token"
        })),
        ActiveTokenError::PlatformMismatch => HttpResponse::BadRequest().json(serde_json::json!({
            "error": "platform_mismatch",
            "message": "selected app platform does not match current TEE platform"
        })),
        ActiveTokenError::AppNotFound => HttpResponse::NotFound().json(serde_json::json!({
            "error": "app_not_found",
            "message": "no active attestation app matches the request"
        })),
        ActiveTokenError::AmbiguousApp => HttpResponse::Conflict().json(serde_json::json!({
            "error": "ambiguous_app",
            "message": "multiple active attestation apps match the request"
        })),
        ActiveTokenError::NotSupported => HttpResponse::NotImplemented().json(serde_json::json!({
            "error": "not_supported",
            "message": "iTrustee nonce-bound active token is not supported in the current stage"
        })),
        ActiveTokenError::NoTokenAvailable => {
            HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "error": "no_token_available",
                "message": "no cached JWT token is available for challenge-response"
            }))
        }
        ActiveTokenError::TeeUnavailable => {
            HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "error": "tee_unavailable",
                "message": "failed to detect or access the current TEE platform"
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::StatusCode, test as awtest, App};
    use attestation_types::AAConfig;

    fn test_service_data() -> web::Data<Arc<RwLock<AttestationAgent>>> {
        let agent = AttestationAgent::new(AAConfig::default()).unwrap();
        web::Data::new(Arc::new(RwLock::new(agent)))
    }

    #[actix_web::test]
    async fn active_token_without_supported_platform_returns_unavailable() {
        let service = test_service_data();
        let app = awtest::init_service(
            App::new()
                .app_data(web::Data::clone(&service))
                .service(active_token),
        )
        .await;
        let request = awtest::TestRequest::get().uri("/active_token").to_request();
        let response = awtest::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[actix_web::test]
    async fn active_token_rejects_invalid_nonce_query() {
        let service = test_service_data();
        let app = awtest::init_service(
            App::new()
                .app_data(web::Data::clone(&service))
                .service(active_token),
        )
        .await;
        let request = awtest::TestRequest::get()
            .uri("/active_token?nonce=abc")
            .to_request();
        let response = awtest::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn active_token_error_response_maps_not_supported() {
        let response = active_token_error_response(ActiveTokenError::NotSupported);

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[cfg(feature = "virtcca-attester")]
    #[actix_web::test]
    async fn active_token_with_nonce_requires_cached_jwt() {
        let service = test_service_data();
        let app = awtest::init_service(
            App::new()
                .app_data(web::Data::clone(&service))
                .service(active_token),
        )
        .await;
        let nonce = "00".repeat(32);
        let request = awtest::TestRequest::get()
            .uri(&format!("/active_token?nonce={nonce}"))
            .to_request();
        let response = awtest::call_service(&app, request).await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn active_token_rate_limiter_rejects_eleventh_request_from_same_peer() {
        let limiter = ActiveTokenRateLimiter::new(10);
        let peer = "192.0.2.10".parse().unwrap();

        for _ in 0..10 {
            assert!(limiter.check(peer));
        }

        assert!(!limiter.check(peer));
    }

    #[test]
    fn active_token_rate_limiter_tracks_peers_independently() {
        let limiter = ActiveTokenRateLimiter::new(1);
        let first_peer = "192.0.2.10".parse().unwrap();
        let second_peer = "192.0.2.11".parse().unwrap();

        assert!(limiter.check(first_peer));
        assert!(!limiter.check(first_peer));
        assert!(limiter.check(second_peer));
    }

    #[test]
    fn active_token_rate_limiter_prunes_inactive_peers() {
        let limiter = ActiveTokenRateLimiter::new(1);
        let stale_peer = "192.0.2.10".parse().unwrap();
        let active_peer = "192.0.2.11".parse().unwrap();

        limiter.clients.lock().unwrap().insert(
            stale_peer,
            RateLimitState {
                window_started_at: Instant::now() - Duration::from_secs(2),
                request_count: 1,
            },
        );

        assert!(limiter.check(active_peer));
        assert!(!limiter.clients.lock().unwrap().contains_key(&stale_peer));
    }
}
