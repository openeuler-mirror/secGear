use attestation_service::AttestationService;
mod session;
mod restapi;

use anyhow::Result;
use env_logger;
use actix_web::{web, App, HttpServer};
use std::{sync::Arc};
use tokio::sync::RwLock;


#[actix_web::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));
    let server = AttestationService::default();

    let service = web::Data::new(Arc::new(RwLock::new(server)));
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(session::Session {}))
            .app_data(web::Data::clone(&service))
            .service(restapi::attest::attest)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await?;

    Ok(())
}