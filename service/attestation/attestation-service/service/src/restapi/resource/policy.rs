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
use crate::AttestationService;
use actix_web::{get, post, web, HttpResponse};
use resource::policy::PolicyLocation;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Serialize, Deserialize)]
enum GetResourcePolicyOp {
    /// Get specific policy under a vendor.
    GetOne { policy: PolicyLocation },
    /// Get all policy under different vendors.
    /// The returned value is a vector of policy identifer, such as '["vendor_A/example.rego", "vendor_B/example.rego"]'.
    GetAll,
    /// Get all policy under particular vendor.
    /// The returned value is a vector of policy identifer, such as '["vendor_A/example_1.rego", "vendor_A/example_2.rego"]'.
    GetAllInVendor { vendor: String },
}

#[get("/resource/policy")]
pub async fn get_resource_policy(
    body: web::Json<GetResourcePolicyOp>,
    agent: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    let agent = agent.read().await;
    let admin = agent.resource_admin.lock().await;
    let op = body.0;
    match op {
        GetResourcePolicyOp::GetOne { policy } => {
            log::debug!("Request for getting policy {}", policy);
            match admin.get_policy(policy.clone()).await {
                Ok(content) => Ok(HttpResponse::Ok().body(content)),
                Err(e) => {
                    log::warn!("Failed to get policy '{}'", policy);
                    Err(crate::result::AsError::from(e))
                }
            }
        }
        GetResourcePolicyOp::GetAll => {
            log::debug!("Request for getting all policies");
            match admin.get_all_policies().await {
                Ok(policies) => {
                    let ret: Vec<String> = policies
                        .iter()
                        .map(|location| String::from(location))
                        .collect();
                    let s = serde_json::to_string(&ret)
                        .unwrap_or(format!("Failed to serialize '{:?}'", ret));
                    Ok(HttpResponse::Ok().body(s))
                }
                Err(e) => {
                    log::warn!("Failed to get all policies");
                    Err(crate::result::AsError::from(e))
                }
            }
        }
        GetResourcePolicyOp::GetAllInVendor { vendor } => {
            log::debug!("Request for getting all policies in vendor {}", vendor);
            match admin.get_all_policies_in_vendor(&vendor).await {
                Ok(policies) => {
                    let ret: Vec<String> = policies
                        .iter()
                        .map(|location| String::from(location))
                        .collect();
                    let s = serde_json::to_string(&ret)
                        .unwrap_or(format!("Failed to serialize '{:?}'", ret));
                    Ok(HttpResponse::Ok().body(s))
                }
                Err(e) => {
                    log::warn!("Failed to get policies in vendor {}", vendor);
                    Err(crate::result::AsError::from(e))
                }
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum SetResourcePolicyOp {
    /// Add new policy file, if it already exists, override its content.
    ///
    /// The vendor of policy should be the same with that in the token granted to the user.
    Add {
        policy: PolicyLocation,
        content: String,
    },
    /// Delete particular policy file.
    ///
    /// The vendor of policy should be the same with that in the token granted to the user.
    Delete { policy: PolicyLocation },
    /// Clear all policy files.
    ClearAll,
    /// Clear all policy files of particular vendor.
    ClearAllInVendor { vendor: String },
}

#[post("/resource/policy")]
pub async fn set_resource_policy(
    body: web::Json<SetResourcePolicyOp>,
    agent: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    let agent = agent.read().await;
    let admin = agent.resource_admin.lock().await;
    let op = body.0;

    match op {
        SetResourcePolicyOp::Add { policy, content } => {
            admin
                .add_policy(policy.clone(), &content)
                .await
                .map_err(|e| {
                    log::warn!("Failed to add policy {}: {}", policy, e);
                    e
                })?;
        }
        SetResourcePolicyOp::Delete { policy } => {
            admin.delete_policy(policy.clone()).await.map_err(|e| {
                log::warn!("Failed to delete policy {}: {}", policy, e);
                e
            })?;
        }
        SetResourcePolicyOp::ClearAll => {
            admin.clear_all_policies().await.map_err(|e| {
                log::warn!("Failed to clear policies: {}", e);
                e
            })?;
        }
        SetResourcePolicyOp::ClearAllInVendor { vendor } => {
            admin
                .clear_all_policies_in_vendor(&vendor)
                .await
                .map_err(|e| {
                    log::warn!("Failed to clear policies in vendor {}: {}", vendor, e);
                    e
                })?;
        }
    }

    Ok(HttpResponse::Ok().body("successful"))
}
