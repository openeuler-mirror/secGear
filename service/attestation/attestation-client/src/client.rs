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

//! Implement common web request to attestation service

use std::path::Display;

use crate::error::{ClientError, Result};
use async_trait::async_trait;
use attestation_types::{
    resource::ResourceLocation,
    service::{GetResourceOp, SetResourceOp, SetResourceRequest},
};
use reqwest::{header::Entry, Certificate, Client, ClientBuilder};

pub(crate) enum Protocal {
    Http { svr: String },
    // Https { svr: String, cert: String },
}

pub(crate) struct AsClient {
    protocal: Protocal,
    client: Client,
}

/// Use enum to generate URL endpoint.
pub(crate) enum Endpoint {
    ResourceStorage,
    ResourcePolicy,
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ep = match self {
            Endpoint::ResourceStorage => "resource/storage",
            Endpoint::ResourcePolicy => "resource/policy",
        };
        write!(f, "{}", ep)
    }
}

impl AsClient {
    pub(crate) fn new(cookie_store: bool, protocal: Protocal) -> Result<Self> {
        // let client = ClientBuilder::new().
        let client = match &protocal {
            Protocal::Http { svr } => Client::builder().cookie_store(cookie_store).build()?,
        };

        Ok(Self { protocal, client })
    }

    fn endpoint(&self, ep: Endpoint) -> String {
        match &self.protocal {
            Protocal::Http { svr } => format!("http://{}/{}", svr, ep),
        }
    }

    pub(crate) async fn vendor_get_resource(&self, vendor: &str) -> Result<Vec<String>> {
        let resource_ep = self.endpoint(Endpoint::ResourceStorage);

        let payload = GetResourceOp::VendorGet {
            vendor: vendor.to_string(),
        };

        let res = self
            .client
            .get(resource_ep)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;
        let status = res.status();
        if status.is_success() {
            Ok(res.json().await?)
        } else {
            Err(ClientError::HttpError(
                "failed to get resource".to_string(),
                status,
            ))
        }
    }

    pub(crate) async fn vendor_add_resource(
        &self,
        vendor: &str,
        path: &str,
        content: &str,
        policy: &Vec<String>,
    ) -> Result<String> {
        let resource_ep = self.endpoint(Endpoint::ResourceStorage);
        let op = SetResourceOp::Add {
            content: content.to_string(),
            policy: policy.clone(),
        };
        let payload = SetResourceRequest {
            op,
            resource: ResourceLocation::new(Some(vendor.to_string()), path.to_string()),
        };
        let res = self
            .client
            .post(resource_ep)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;
        let status = res.status();
        if status.is_success() {
            Ok(res.text().await?)
        } else {
            Err(ClientError::HttpError(
                "failed to add resource".to_string(),
                status,
            ))
        }
    }

    pub(crate) async fn vendor_delete_resource(&self, vendor: &str, path: &str) -> Result<String> {
        let resource_ep = self.endpoint(Endpoint::ResourceStorage);
        let op = SetResourceOp::Delete;
        let payload = SetResourceRequest {
            op,
            resource: ResourceLocation::new(Some(vendor.to_string()), path.to_string()),
        };
        let res = self
            .client
            .post(resource_ep)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;
        let status = res.status();
        if status.is_success() {
            Ok(res.text().await?)
        } else {
            Err(ClientError::HttpError(
                "failed to delete resource".to_string(),
                status,
            ))
        }
    }

    pub(crate) async fn vendor_modify_resource(
        &self,
        vendor: &str,
        path: &str,
        content: &str,
    ) -> Result<String> {
        let resource_ep = self.endpoint(Endpoint::ResourceStorage);
        let op = SetResourceOp::Modify {
            content: content.to_string(),
        };
        let payload = SetResourceRequest {
            op,
            resource: ResourceLocation::new(Some(vendor.to_string()), path.to_string()),
        };
        let res = self
            .client
            .post(resource_ep)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;
        let status = res.status();
        if status.is_success() {
            Ok(res.text().await?)
        } else {
            Err(ClientError::HttpError(
                "failed to modify resource".to_string(),
                status,
            ))
        }
    }

    pub(crate) async fn vendor_bind_resource(
        &self,
        vendor: &str,
        path: &str,
        policy: &Vec<String>,
    ) -> Result<String> {
        let resource_ep = self.endpoint(Endpoint::ResourceStorage);
        let op = SetResourceOp::Bind {
            policy: policy.clone(),
        };
        let payload = SetResourceRequest {
            op,
            resource: ResourceLocation::new(Some(vendor.to_string()), path.to_string()),
        };
        let res = self
            .client
            .post(resource_ep)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;
        let status = res.status();
        if status.is_success() {
            Ok(res.text().await?)
        } else {
            Err(ClientError::HttpError(
                "failed to bind policy".to_string(),
                status,
            ))
        }
    }

    pub(crate) async fn vendor_unbind_resource(
        &self,
        vendor: &str,
        path: &str,
        policy: &Vec<String>,
    ) -> Result<String> {
        let resource_ep = self.endpoint(Endpoint::ResourceStorage);
        let op = SetResourceOp::Unbind {
            policy: policy.clone(),
        };
        let payload = SetResourceRequest {
            op,
            resource: ResourceLocation::new(Some(vendor.to_string()), path.to_string()),
        };
        let res = self
            .client
            .post(resource_ep)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?;
        let status = res.status();
        if status.is_success() {
            Ok(res.text().await?)
        } else {
            Err(ClientError::HttpError(
                "failed to unbind policy".to_string(),
                status,
            ))
        }
    }
}

// async fn get_challenge() {
// let challenge_endpoint = format!("{}/challenge", self.config.svr_url);
// let client = self.create_client(self.config.protocal.clone(), true)?;
// let res = client
//     .get(challenge_endpoint)
//     .header("Content-Type", "application/json")
//     .header("content-length", 0)
//     .send()
//     .await?;
// let challenge = match res.status() {
//     reqwest::StatusCode::OK => {
//         let respone: String = res.json().await.unwrap();
//         log::debug!("get challenge success, AS Response: {:?}", respone);
//         respone
//     }
//     status => {
//         log::error!("get challenge Failed, AS Response: {:?}", status);
//         bail!("get challenge Failed")
//     }
// };
// }
