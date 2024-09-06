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
use actix_web::cookie::{time::{Duration, OffsetDateTime}};
use scc::HashMap;
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct Session {
    pub challenge: String,
    pub as_client: reqwest::Client,
    timeout: OffsetDateTime,
    // pub token: Option<String>,
}

impl Session {
    pub fn new(challenge: String, as_client: reqwest::Client, timeout_m: i64) -> Result<Self> {

        let timeout = OffsetDateTime::now_utc() + Duration::minutes(timeout_m);
        // let token = None;
        Ok(Session {
            challenge,
            as_client,
            timeout,
            // token,
        })
    }
    pub fn is_expired(&self) -> bool {
        return self.timeout < OffsetDateTime::now_utc();
    }
}

#[derive(Debug, Clone)]
pub struct SessionMap {
    pub session_map: HashMap<String, Session>,
}

impl SessionMap {
    pub fn new() -> Self {
        SessionMap {
            session_map: HashMap::new(),
        }
    }
    pub fn insert(&self, session: Session) {
        let _ = self.session_map.insert(session.challenge.clone(), session);
    }
}