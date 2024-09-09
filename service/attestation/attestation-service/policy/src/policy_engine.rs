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
use std::{collections::HashMap, fmt::Display};

#[derive(Debug)]
pub enum PolicyEngineError {
    InvalidPolicy(String),
    InvalidPolicyId(String),
    InvalidPolicyDir(String),
    InvalidReport(String),
    CreatePolicyDirError(String),
    CreatePolicyError(String),
    ReadPolicyError(String),
    WritePolicyError(String),
    EngineLoadPolicyError(String),
    EngineLoadDataError(String),
    EngineEvalError(String),
    TeeTypeUnknown(String),
}
impl Display for PolicyEngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyEngineError::InvalidPolicy(msg) => write!(f, "invalid policy: {}", msg),
            PolicyEngineError::InvalidPolicyId(msg) => write!(f, "invalid policy id: {}", msg),
            PolicyEngineError::InvalidReport(msg) => write!(f, "invalid report: {}", msg),
            PolicyEngineError::CreatePolicyDirError(msg) => {
                write!(f, "create policy dir error: {}", msg)
            }
            PolicyEngineError::CreatePolicyError(msg) => write!(f, "create policy error: {}", msg),
            PolicyEngineError::ReadPolicyError(msg) => write!(f, "read policy error: {}", msg),
            PolicyEngineError::InvalidPolicyDir(msg) => write!(f, "invalid policy error: {}", msg),
            PolicyEngineError::WritePolicyError(msg) => write!(f, "write policy error: {}", msg),
            PolicyEngineError::EngineLoadPolicyError(msg) => {
                write!(f, "engine load policy error: {}", msg)
            }
            PolicyEngineError::EngineLoadDataError(msg) => {
                write!(f, "engine read data error: {}", msg)
            }
            PolicyEngineError::EngineEvalError(msg) => write!(f, "engine evaluate error: {}", msg),
            PolicyEngineError::TeeTypeUnknown(msg) => write!(f, "tee type error: {}", msg),
        }
    }
}

impl std::error::Error for PolicyEngineError {}

pub trait PolicyEngine {
    fn evaluate(
        &self,
        tee: &String,
        refs: &String,
        data_for_policy: &String,
        policy_id: &Vec<String>,
    ) -> impl std::future::Future<Output = Result<HashMap<String, String>, PolicyEngineError>> + Send;
    fn set_policy(
        &self,
        policy_id: &String,
        policy: &String,
    ) -> impl std::future::Future<Output = Result<(), PolicyEngineError>> + Send;
    fn get_all_policy(
        &self,
    ) -> impl std::future::Future<Output = Result<HashMap<String, String>, PolicyEngineError>> + Send;
    fn get_policy(
        &self,
        policy_id: &String,
    ) -> impl std::future::Future<Output = Result<String, PolicyEngineError>> + Send;
}
