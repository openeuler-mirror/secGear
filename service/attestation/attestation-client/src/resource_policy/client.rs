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

//! Implement web request for resource policy to attestation service
//!

use crate::client::AsClient;
use crate::error::{ClientError, Result};
use attestation_types::{
    resource::policy::PolicyLocation,
    service::{GetResourcePolicyOp, SetResourcePolicyOp},
};
use reqwest::Client;

pub(crate) struct ResourcePolicyClient {
    client: AsClient,
}

impl ResourcePolicyClient {
    pub(crate) fn new(client: AsClient) -> Self {
        Self { client }
    }

    fn endpoint(&self) -> String {
        format!("{}/resource/policy", self.client.base_url())
    }

    fn client(&self) -> Client {
        self.client.client()
    }

    pub(crate) async fn vendor_get_one(&self, vendor: &str, id: &str) -> Result<String> {
        let payload = GetResourcePolicyOp::GetOne {
            policy: PolicyLocation {
                vendor: Some(vendor.to_string()),
                id: id.to_string(),
            },
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
            Ok(res.text().await?)
        } else {
            Err(ClientError::HttpError(
                format!("failed to get resource policy: {}", res.text().await?),
                status,
            ))
        }
    }
    pub(crate) async fn vendor_get_all(&self) -> Result<Vec<String>> {
        let payload = GetResourcePolicyOp::GetAll;

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
                format!("failed to get all resource policy: {}", res.text().await?),
                status,
            ))
        }
    }
    pub(crate) async fn vendor_get_all_in_vendor(&self, vendor: &str) -> Result<Vec<String>> {
        let payload = GetResourcePolicyOp::GetAllInVendor {
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
                format!(
                    "failed to get all resource policy in vendor {}: {}",
                    vendor,
                    res.text().await?
                ),
                status,
            ))
        }
    }
    pub(crate) async fn vendor_add(&self, vendor: &str, id: &str, content: &str) -> Result<String> {
        let payload = SetResourcePolicyOp::Add {
            policy: PolicyLocation {
                vendor: Some(vendor.to_string()),
                id: id.to_string(),
            },
            content: content.to_string(),
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
                format!("failed to add resource policy: {}", res.text().await?),
                status,
            ))
        }
    }
    pub(crate) async fn vendor_delete(&self, vendor: &str, id: &str) -> Result<String> {
        let payload = SetResourcePolicyOp::Delete {
            policy: PolicyLocation {
                vendor: Some(vendor.to_string()),
                id: id.to_string(),
            },
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
                format!("failed to delete resource policy: {}", res.text().await?),
                status,
            ))
        }
    }

    pub(crate) async fn vendor_clear_all(&self, vendor: &str) -> Result<String> {
        let payload = SetResourcePolicyOp::ClearAll {
            vendor: vendor.to_string(),
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
                format!(
                    "failed to clear resource policy in vendor {}: {}",
                    vendor,
                    res.text().await?
                ),
                status,
            ))
        }
    }
}
