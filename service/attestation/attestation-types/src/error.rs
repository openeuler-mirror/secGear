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

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("challenge error: {0}")]
    ChallengeError(String),
    #[error("get evidence error: {0}")]
    DecodeError(String),
    #[error("get evidence error: {0}")]
    GetEvidenceError(String),
    #[error("verify evidence error: {0}")]
    VerifyEvidenceError(String),
    #[error("get token error: {0}")]
    GetTokenError(String),
    #[error("verify token error: {0}")]
    VerifyTokenError(String),
}
