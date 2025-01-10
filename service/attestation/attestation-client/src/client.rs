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

//! Common web request client

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

impl AsClient {
    pub(crate) fn new(cookie_store: bool, protocal: Protocal) -> Result<Self> {
        let client = match &protocal {
            Protocal::Http { svr } => Client::builder().cookie_store(cookie_store).build()?,
        };

        Ok(Self { protocal, client })
    }

    pub(crate) fn default() -> Self {
        AsClient::new(
            false,
            Protocal::Http {
                svr: "127.0.0.1:8080".to_string(),
            },
        )
        .unwrap()
    }

    pub(crate) fn base_url(&self) -> String {
        match &self.protocal {
            Protocal::Http { svr } => format!("http://{}", svr),
        }
    }

    pub(crate) fn client(&self) -> Client {
        self.client.clone()
    }
}
