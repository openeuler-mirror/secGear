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
use restapi::{get_challenge, attestation, reference, get_policy, set_policy};
mod session;
use session::SessionMap;

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
    let server:AttestationService = AttestationService::new(Some(cli.config)).unwrap();
    let session_map = web::Data::new(SessionMap::new());

    let service = web::Data::new(Arc::new(RwLock::new(server)));
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::clone(&service))
            .app_data(web::Data::clone(&session_map))
            .service(get_challenge)
            .service(attestation)
            .service(reference)
            .service(set_policy)
            .service(get_policy)
    })
    .bind((cli.socketaddr.ip().to_string(), cli.socketaddr.port()))?
    .run()
    .await?;

    Ok(())
}