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
use std::path::StripPrefixError;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, ResourceError>;

#[derive(Error, Debug)]
pub enum ResourceError {
    #[error("Trait is not implemented.")]
    NotImplemented,
    #[error("Policy is missing.")]
    PolicyMissing,
    #[error("Failed to load policy: {0}")]
    LoadPolicy(#[from] anyhow::Error),
    #[error("Resource error: {0}")]
    ResourceError(#[from] std::io::Error),
    #[error("Illegal resource path: {0}")]
    IllegalResource(String),
    #[error("Invalid resource content: {0}")]
    ResourceFromUtf8(#[from] std::string::FromUtf8Error),
    #[error("Serde deserialize failure: {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("Illegal policy location path: {0}")]
    IllegalPolicyLocation(String),
    #[error("Unmatched vendor between resource {0} and policy {1}")]
    UnmatchedPolicyResource(String, String),
    #[error("Convert error: {0}")]
    IoError(#[from] core::convert::Infallible),
    #[error("Strip Prefix fail: {0}")]
    StripPrefix(#[from] StripPrefixError),
    #[error("Illegal policy suffix: {0}")]
    IllegalPolicySuffix(String),
}
