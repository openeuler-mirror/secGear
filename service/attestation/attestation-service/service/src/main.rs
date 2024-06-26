use attestation_service::AttestationService;
mod session;
mod restapi;

use anyhow::Result;
use env_logger;
use actix_web::{web, App, HttpServer};
use std::{net::{SocketAddr, IpAddr, Ipv4Addr}, sync::Arc};
use tokio::sync::RwLock;
use clap::{Parser, command, arg};

const DEFAULT_ASCONFIG_FILE: &str = "/etc/attestation/attestation-service/attestation-service.conf";
const DEFAULT_SOCKETADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Socket address to listen on
    #[arg(short, long, default_value_t = DEFAULT_SOCKETADDR)]
    socketaddr: SocketAddr,

    /// Attestation Service config file
    //    Load `ASConfig` from a configuration file like:
    //    {
    //         "token_cfg": {
    //             "key": "/etc/attestation/attestation-service/token/private.pem",
    //             "iss": "oeas",
    //             "nbf": 0,
    //             "valid_duration": 300,
    //             "alg": "PS256"
    //         }
    //    }
    #[arg(short, long, default_value_t = DEFAULT_ASCONFIG_FILE.to_string())]
    config: String,
}

#[actix_web::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let cli = Cli::parse();
    let server = AttestationService::new(Some(cli.config)).unwrap();

    let service = web::Data::new(Arc::new(RwLock::new(server)));
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(session::Session {}))
            .app_data(web::Data::clone(&service))
            .service(restapi::attest::attest)
    })
    .bind((cli.socketaddr.ip().to_string(), cli.socketaddr.port()))?
    .run()
    .await?;

    Ok(())
}