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
use crate::error::Result;
use attestation_types::{
    resource::policy::PolicyLocation,
    service::{GetResourcePolicyOp, SetResourcePolicyOp},
};
use reqwest::{Client, Response};

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

    pub(crate) async fn vendor_get_one(&self, vendor: &str, id: &str) -> Result<Response> {
        let payload = GetResourcePolicyOp::GetOne {
            policy: PolicyLocation {
                vendor: Some(vendor.to_string()),
                id: id.to_string(),
            },
        };

        Ok(self
            .client()
            .get(self.endpoint())
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?)
    }
    pub(crate) async fn vendor_get_all(&self) -> Result<Response> {
        let payload = GetResourcePolicyOp::GetAll;

        Ok(self
            .client()
            .get(self.endpoint())
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?)
    }
    pub(crate) async fn vendor_get_all_in_vendor(&self, vendor: &str) -> Result<Response> {
        let payload = GetResourcePolicyOp::GetAllInVendor {
            vendor: vendor.to_string(),
        };

        Ok(self
            .client()
            .get(self.endpoint())
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?)
    }
    pub(crate) async fn vendor_add(
        &self,
        vendor: &str,
        id: &str,
        content: &str,
    ) -> Result<Response> {
        let payload = SetResourcePolicyOp::Add {
            policy: PolicyLocation {
                vendor: Some(vendor.to_string()),
                id: id.to_string(),
            },
            content: content.to_string(),
        };

        Ok(self
            .client()
            .post(self.endpoint())
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?)
    }
    pub(crate) async fn vendor_delete(&self, vendor: &str, id: &str) -> Result<Response> {
        let payload = SetResourcePolicyOp::Delete {
            policy: PolicyLocation {
                vendor: Some(vendor.to_string()),
                id: id.to_string(),
            },
        };

        Ok(self
            .client()
            .post(self.endpoint())
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?)
    }

    pub(crate) async fn vendor_clear_all(&self, vendor: &str) -> Result<Response> {
        let payload = SetResourcePolicyOp::ClearAll {
            vendor: vendor.to_string(),
        };

        Ok(self
            .client()
            .post(self.endpoint())
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await?)
    }
}
