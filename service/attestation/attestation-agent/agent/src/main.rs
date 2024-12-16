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
use attestation_agent::{AttestationAgent, DEFAULT_AACONFIG_FILE};
mod restapi;
use restapi::{
    get_challenge, get_evidence, get_resource, get_token, verify_evidence, verify_token,
};

use actix_web::{web, App, HttpResponse, HttpServer};
use anyhow::Result;
use clap::{arg, command, Parser};
use env_logger;
use std::sync::Arc;
use tokio::sync::RwLock;

const DEFAULT_SOCKETADDR: &str = "127.0.0.1:8081";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Socket address to listen on
    #[arg(short, long, default_value_t = DEFAULT_SOCKETADDR.to_string())]
    socketaddr: String,
    /// Socket address connect to
    #[arg(short = 'u', long, default_value_t = String::from(""))]
    serverurl: String,
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

    #[arg(short = 'p', long = "protocol", default_value_t = String::from("http"))]
    protocol: String,

    /// root certificate to verify peer
    #[arg(short = 't', long = "cert_root", default_value_t = String::from(""))]
    cert_root: String,
}

#[actix_web::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let cli = Cli::parse();
    let mut server = AttestationAgent::new(Some(cli.config)).unwrap();
    server.access_as_protocol = cli.protocol;
    if server.access_as_protocol == "https" {
        server.cert_root = std::fs::read_to_string(cli.cert_root)?;
    }
    if cli.serverurl != "" {
        server.config.svr_url = server.access_as_protocol.clone() + "://" + &cli.serverurl.clone();
    }
    let service = web::Data::new(Arc::new(RwLock::new(server)));
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::clone(&service))
            .service(get_challenge)
            .service(get_evidence)
            .service(verify_evidence)
            .service(get_token)
            .service(verify_token)
            .service(get_resource)
            .default_service(web::to(|| HttpResponse::NotFound()))
    })
    .bind(cli.socketaddr)?
    .run()
    .await?;

    Ok(())
}
