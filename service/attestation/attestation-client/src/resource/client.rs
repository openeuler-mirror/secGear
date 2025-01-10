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

//! Implement web request for resource to attestation service

use crate::client::AsClient;
use crate::error::{ClientError, Result};
use attestation_types::{
    resource::ResourceLocation,
    service::{GetResourceOp, SetResourceOp, SetResourceRequest},
};
use reqwest::Client;

pub(crate) struct ResourceClient {
    client: AsClient,
}

impl ResourceClient {
    pub(crate) fn new(client: AsClient) -> Self {
        Self { client }
    }

    fn endpoint(&self) -> String {
        format!("{}/resource/storage", self.client.base_url())
    }

    fn client(&self) -> Client {
        self.client.client()
    }

    pub(crate) async fn vendor_get_resource(&self, vendor: &str) -> Result<Vec<String>> {
        let payload = GetResourceOp::VendorGet {
            vendor: vendor.to_string(),
        };

        let res = self
            .client()
            .get(self.endpoint())
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
        let op = SetResourceOp::Add {
            content: content.to_string(),
            policy: policy.clone(),
        };
        let payload = SetResourceRequest {
            op,
            resource: ResourceLocation::new(Some(vendor.to_string()), path.to_string()),
        };
        let res = self
            .client()
            .post(self.endpoint())
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
        let op = SetResourceOp::Delete;
        let payload = SetResourceRequest {
            op,
            resource: ResourceLocation::new(Some(vendor.to_string()), path.to_string()),
        };
        let res = self
            .client()
            .post(self.endpoint())
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
        let op = SetResourceOp::Modify {
            content: content.to_string(),
        };
        let payload = SetResourceRequest {
            op,
            resource: ResourceLocation::new(Some(vendor.to_string()), path.to_string()),
        };
        let res = self
            .client()
            .post(self.endpoint())
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
        let op = SetResourceOp::Bind {
            policy: policy.clone(),
        };
        let payload = SetResourceRequest {
            op,
            resource: ResourceLocation::new(Some(vendor.to_string()), path.to_string()),
        };
        let res = self
            .client()
            .post(self.endpoint())
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
        let op = SetResourceOp::Unbind {
            policy: policy.clone(),
        };
        let payload = SetResourceRequest {
            op,
            resource: ResourceLocation::new(Some(vendor.to_string()), path.to_string()),
        };
        let res = self
            .client()
            .post(self.endpoint())
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
