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
use attestation_agent::AttestationAgent;
mod restapi;
use restapi::{get_challenge, get_evidence, verify_evidence, get_token, verify_token};

use anyhow::Result;
use env_logger;
use actix_web::{web, App, HttpServer, HttpResponse};
use std::{net::{SocketAddr, IpAddr, Ipv4Addr}, sync::Arc};
use tokio::sync::RwLock;
use clap::{Parser, command, arg};

const DEFAULT_AACONFIG_FILE: &str = "/etc/attestation/attestation-agent/attestation-agent.conf";
const DEFAULT_SOCKETADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Socket address to listen on
    #[arg(short, long, default_value_t = DEFAULT_SOCKETADDR)]
    socketaddr: SocketAddr,

    /// Load `AAConfig` from a configuration file like:
    ///    {
    ///        "svr_url": "http://127.0.0.1:8080",
    ///        "token_cfg": {
    ///            "cert": "/etc/attestation/attestation-agent/as_cert.pem",
    ///            "iss": "oeas"
    ///        }
    ///    }
    #[arg(short, long, default_value_t = DEFAULT_AACONFIG_FILE.to_string())]
    config: String,
}

#[actix_web::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let cli = Cli::parse();
    let server = AttestationAgent::new(Some(cli.config)).unwrap();

    let service = web::Data::new(Arc::new(RwLock::new(server)));
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::clone(&service))
            .service(get_challenge)
            .service(get_evidence)
            .service(verify_evidence)
            .service(get_token)
            .service(verify_token)
            .default_service(web::to(|| HttpResponse::NotFound()))
    })
    .bind((cli.socketaddr.ip().to_string(), cli.socketaddr.port()))?
    .run()
    .await?;

    Ok(())
}