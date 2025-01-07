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
use crate::result::{self, Result};
use crate::AttestationService;
use actix_web::http::header::Header;
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use anyhow::Context;
use attestation_types::Claims;
use log;
use resource::resource::ResourceLocation;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use token_signer::verify;
use tokio::sync::RwLock;

/// When the consumer request for resource, he should provide the vendor name which owns the resource.
#[get("/resource/storage")]
pub async fn get_resource(
    req: HttpRequest,
    body: web::Json<ResourceLocation>,
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

    let claim: Claims = verify(&token).context("illegal token")?;

    let resource = body.0.clone();
    let claim: String = serde_json::to_string(&claim)?;

    log::debug!("Resource path: {}", resource);
    log::debug!("Receive claim: {}", claim);

    match agent
        .read()
        .await
        .resource_evaluate(resource.clone(), &claim)
        .await
    {
        Ok(r) => {
            if r {
                log::debug!("Resource evaluate success.");
                let content = agent.read().await.get_resource(resource).await?;

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

#[derive(Debug, Serialize, Deserialize, Clone)]
enum SetResourceOp {
    /// Add new resource.
    /// The vendor of each policy should be 'default' or the same with the resource.
    /// Otherwise error will be raised.
    ///
    /// If the resource already exists, the content will be overrided.
    Add {
        content: String,
        policy: Vec<String>,
    },
    /// Delete specific resource.
    Delete,
    /// Modify the content of specific resource. Other fields of the resource will be kept.
    Modify { content: String },
    /// Bind policy to specific resource.
    /// The vendor of any policy should be 'default' or the same with the resource.
    /// Otherwise error will be raised.
    Bind { policy: Vec<String> },
    /// Unbind policy of specific resource.
    /// The vendor of any policy should be 'default' or the same with the resource.
    /// Otherwise error will be raised.
    Unbind { policy: Vec<String> },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SetResourceRequest {
    op: SetResourceOp,
    /// The vendor of the resource should be the same with that granted in the token.
    resource: ResourceLocation,
}

#[post("/resource/storage")]
pub async fn set_resource(
    body: web::Json<SetResourceRequest>,
    agent: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    let agent = agent.read().await;
    let admin = agent.resource_admin.lock().await;
    let resource = body.0.resource.clone();
    match body.op.clone() {
        SetResourceOp::Add { content, policy } => {
            admin.add_resource(resource, content, policy).await?
        }
        SetResourceOp::Delete => admin.del_resource(resource).await?,
        SetResourceOp::Modify { content } => admin.modify_resource(resource, content).await?,
        SetResourceOp::Bind { policy } => admin.bind_policy(resource, policy).await?,
        SetResourceOp::Unbind { policy } => admin.unbind_policy(resource, policy).await?,
    }
    Ok(HttpResponse::Ok().body("successful"))
}
