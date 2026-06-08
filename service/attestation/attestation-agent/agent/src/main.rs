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
use actix_web::{web, App, HttpResponse, HttpServer};
use anyhow::{bail, Result};
use attestation_agent::{
    restapi::{
        active_token, get_challenge, get_current_token, get_evidence, get_resource, get_token,
        verify_evidence, verify_token, ActiveTokenRateLimiter,
    },
    AttestationAgent,
};
use attestation_types::{AAConfig, HttpProtocal, DEFAULT_AACONFIG_FILE};
use clap::{arg, command, Parser};

use std::{net::SocketAddr, path::Path, sync::Arc};
use tokio::sync::RwLock;

const DEFAULT_SOCKETADDR: &str = "127.0.0.1:8081";
const ACTIVE_TOKEN_RATE_LIMIT_PER_SECOND: u32 = 10;

fn is_unspecified_listen_addr(socketaddr: &str) -> bool {
    socketaddr
        .parse::<SocketAddr>()
        .map(|addr| addr.ip().is_unspecified())
        .unwrap_or(false)
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Cli {
    /// Socket address to listen on
    #[arg(short = 'l', long, default_value_t = DEFAULT_SOCKETADDR.to_string())]
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

    /// global switch for active attestation
    #[arg(
        short = 's',
        long = "enable_active_attestation",
        default_value_t = false
    )]
    enable_active_attestation: bool,
}

#[actix_web::main]
async fn main() -> Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let cli = Cli::parse();
    // Load config content from file.
    let mut config = AAConfig::try_from(Path::new(&cli.config))?;

    // Override configurations if set by command line tool.
    match cli.protocol.as_ref() {
        "http" => {}
        "https" => {
            config.protocal = HttpProtocal::Https {
                protocal: "https".to_string(),
                cert_root: std::fs::read_to_string(cli.cert_root)?,
            }
        }
        _ => {
            bail!("Invalid http protocal!");
        }
    }

    // Override the listening url.
    if !cli.serverurl.is_empty() {
        config.svr_url = config.protocal.get_protocal() + "://" + &cli.serverurl.clone();
    }

    // Use command line parameter for enable_active_attestation
    let server = if cli.enable_active_attestation {
        AttestationAgent::new_with_interval(config, cli.enable_active_attestation).unwrap()
    } else {
        AttestationAgent::new(config).unwrap()
    };
    let service = web::Data::new(Arc::new(RwLock::new(server)));
    let active_token_rate_limiter = web::Data::new(ActiveTokenRateLimiter::new(
        ACTIVE_TOKEN_RATE_LIMIT_PER_SECOND,
    ));
    if is_unspecified_listen_addr(&cli.socketaddr) {
        log::warn!("AA is listening on an unspecified address, which exposes the service to all network interfaces. This may allow CVMs in the same VPC to access the /active_token endpoint, enabling real-time forwarding attacks. Consider binding to a specific IP address and using VPC security groups to restrict access.");
    }
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::clone(&service))
            .app_data(web::Data::clone(&active_token_rate_limiter))
            .service(get_challenge)
            .service(get_evidence)
            .service(verify_evidence)
            .service(get_token)
            .service(verify_token)
            .service(get_resource)
            .service(get_current_token)
            .service(active_token)
            .default_service(web::to(HttpResponse::NotFound))
    })
    .bind(cli.socketaddr)?
    .run()
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unspecified_listen_address_detection_covers_ipv4_and_ipv6() {
        assert!(is_unspecified_listen_addr("0.0.0.0:8081"));
        assert!(is_unspecified_listen_addr("[::]:8081"));
        assert!(!is_unspecified_listen_addr("127.0.0.1:8081"));
    }
}
