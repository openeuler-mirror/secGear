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

    #[error("Invalid tee type: {tee}")]
    InvalidTee { tee: String },

    #[error("Unsupported digest function: {function}")]
    UnsupportedDigest { function: String },

    #[error("CCA verification error: {msg}")]
    CcaFailure { msg: String },

    #[error("Deserialize error: {source:?}")]
    Deserialize {
        #[from]
        source: serde_json::Error,
    },

    #[error("Flatten error: {msg}")]
    Flatten { msg: String },

    #[error("Invalid policy: {msg}")]
    Policy { msg: String },

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl ResponseError for Error {
    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        HttpResponse::InternalServerError().body(BoxBody::new(format!("{self:#?}")))
    }
}
