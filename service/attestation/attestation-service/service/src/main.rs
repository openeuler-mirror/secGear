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
/// RESTful Attestation Service
use attestation_service::AttestationService;
mod restapi;
use restapi::{attestation, get_challenge, get_policy, get_resource, reference, set_policy};
mod session;
use session::SessionMap;

use actix_web::{web, App, HttpServer};
use anyhow::Result;
use clap::{arg, command, Parser};
use env_logger;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use std::sync::Arc;
use tokio::sync::RwLock;

const DEFAULT_ASCONFIG_FILE: &str = "/etc/attestation/attestation-service/attestation-service.conf";
const DEFAULT_SOCKETADDR: &str = "localhost:8080";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Socket address to listen on
    #[arg(short, long, default_value_t = DEFAULT_SOCKETADDR.to_string())]
    socketaddr: String,

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

    #[arg(short = 'p', long = "protocol", default_value_t = String::from("http"))]
    protocol: String,
    #[arg(short = 't', long = "https_cert", default_value_t = String::from(""))]
    https_cert: String,
    #[arg(short = 'k', long = "https_key", default_value_t = String::from(""))]
    https_key: String,
}

#[actix_web::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let cli = Cli::parse();
    let server: AttestationService = AttestationService::new(Some(cli.config)).unwrap();
    let session_map = web::Data::new(SessionMap::new());

    let sessions_clone = session_map.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            sessions_clone
                .session_map
                .retain_async(|_, v| !v.is_expired())
                .await;
        }
    });

    let service = web::Data::new(Arc::new(RwLock::new(server)));
    let http_server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::clone(&service))
            .app_data(web::Data::clone(&session_map))
            .service(get_challenge)
            .service(attestation)
            .service(reference)
            .service(set_policy)
            .service(get_policy)
            .service(get_resource)
    });
    if cli.protocol == "https" {
        if cli.https_cert.is_empty() || cli.https_key.is_empty() {
            log::error!("cert or key is empty");
            return Ok(());
        }
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
        builder.set_private_key_file(cli.https_key, SslFiletype::PEM)?;
        builder.set_certificate_chain_file(cli.https_cert)?;
        http_server
            .bind_openssl(cli.socketaddr, builder)?
            .run()
            .await?;
    } else if cli.protocol == "http" {
        http_server.bind(cli.socketaddr)?.run().await?;
    } else {
        log::error!("unknown protocol {}", cli.protocol);
    }

    Ok(())
}
