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

use crate::error::Result;
use reqwest::Client;

const DEFAULT_AS_ADDRESS: &str = "127.0.0.1:8080";

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
        let svr = std::env::var("AS_ADDRESS").unwrap_or(DEFAULT_AS_ADDRESS.to_string());
        AsClient::new(false, Protocal::Http { svr }).unwrap()
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
