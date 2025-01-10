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

pub mod resource;
pub mod service;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SESSION_TIMEOUT_MIN: i64 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct VirtccaEvidence {
    pub evidence: Vec<u8>,
    pub dev_cert: Vec<u8>,
    pub ima_log: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TeeType {
    Itrustee = 1,
    Virtcca,
    Rustcca,
    Invalid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub tee: TeeType,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvlResult {
    pub eval_result: bool,
    pub policy: Vec<String>,
    pub report: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub iat: usize,
    pub nbf: usize,
    pub exp: usize,
    pub evaluation_reports: EvlResult,
    pub tee: String,
    pub tcb_status: Value,
}
