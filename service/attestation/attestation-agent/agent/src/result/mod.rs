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

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// libdevice error
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum Error {
    #[error("IO error: {source:?}")]
    Io {
        #[from]
        source: std::io::Error,
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

    #[error("Attestation Agent error:{0}")]
    AttestationAgentError(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl ResponseError for Error {
    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        HttpResponse::InternalServerError().body(BoxBody::new(format!("{self:#?}")))
    }
}
