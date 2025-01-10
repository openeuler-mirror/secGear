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
use actix_web::{body::BoxBody, HttpResponse, ResponseError};
use thiserror::Error;
pub type Result<T, E = AsError> = std::result::Result<T, E>;

#[derive(Debug, Error)]
//#[non_exhaustive]
//#[allow(missing_docs)]
pub enum AsError {
    #[error("IO error: {source:?}")]
    Io {
        #[from]
        source: std::io::Error,
    },
    #[error("attestation error: {source:?}")]
    DecodeError {
        #[from]
        source: base64::DecodeError,
    },
    #[error("Policy Engine error: {source:?}")]
    PolicyEngine {
        #[from]
        source: policy::policy_engine::PolicyEngineError,
    },
    #[error("Reference error: {source:?}")]
    Reference {
        #[from]
        source: reference::reference::RefOpError,
    },
    #[error("Sign error: {source:?}")]
    Sign {
        #[from]
        source: token_signer::SignError,
    },

    #[error("Web error: {source:?}")]
    Web {
        #[from]
        source: actix_web::error::Error,
    },

    #[error("Deserialize error: {source:?}")]
    Deserialize {
        #[from]
        source: serde_json::Error,
    },

    #[error("Request cookie is missing")]
    CookieMissing,

    #[error("Request cookie session is not found")]
    SessionNotFound,

    #[error("The session of request cookie is expired")]
    SessionExpired,

    #[error("Request challenge is invalid")]
    ChallengeInvalid,

    #[error("Request Prameter is invalid")]
    ParameterInvalid(String),

    #[error("Illegal token")]
    TokenIllegal,

    #[error("Resource Policy Error: {0}")]
    ResourcePolicy(#[from] attestation_types::resource::error::ResourceError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl ResponseError for AsError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::InternalServerError().body(BoxBody::new(format!("{self:#?}")))
    }
}
