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

//! Subcommand for getting or setting resource.
//!

use crate::client::{AsClient, Protocal};
use clap::{Args, Subcommand};
use reqwest::ClientBuilder;

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
#[command(flatten_help = true)]
pub(crate) struct ResourceArgs {
    #[command(subcommand)]
    pub(crate) command: ResourceCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ResourceCommand {
    Get {
        vendor: String,
    },
    Add {
        vendor: String,
        path: String,
        content: String,
        policy: Vec<String>,
    },
    Delete {
        vendor: String,
        path: String,
    },
    Modify {
        vendor: String,
        path: String,
        content: String,
    },
    BindPolicy {
        vendor: String,
        path: String,
        policy: Vec<String>,
    },
    UnbindPolicy {
        vendor: String,
        path: String,
        policy: Vec<String>,
    },
}

impl ResourceArgs {
    pub(crate) fn process(&self) {
        self.command.dispatch();
    }
}

impl ResourceCommand {
    fn dispatch(&self) {
        let client = AsClient::new(
            false,
            Protocal::Http {
                svr: "127.0.0.1:8080".to_string(),
            },
        )
        .unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();

        match self {
            ResourceCommand::Get { vendor } => {
                let ret = runtime
                    .block_on(client.vendor_get_resource(vendor))
                    .unwrap();
                println!("{:?}", ret);
            }
            ResourceCommand::Add {
                vendor,
                path,
                content,
                policy,
            } => {
                let ret = runtime
                    .block_on(client.vendor_add_resource(vendor, path, content, policy))
                    .unwrap();
                println!("{:?}", ret);
            }
            ResourceCommand::Delete { vendor, path } => {
                let ret = runtime
                    .block_on(client.vendor_delete_resource(vendor, path))
                    .unwrap();
                println!("{:?}", ret);
            }
            ResourceCommand::Modify {
                vendor,
                path,
                content,
            } => {
                let ret = runtime
                    .block_on(client.vendor_modify_resource(vendor, path, content))
                    .unwrap();
                println!("{:?}", ret);
            }
            ResourceCommand::BindPolicy {
                vendor,
                path,
                policy,
            } => {
                let ret = runtime
                    .block_on(client.vendor_bind_resource(vendor, path, policy))
                    .unwrap();
                println!("{:?}", ret);
            }
            ResourceCommand::UnbindPolicy {
                vendor,
                path,
                policy,
            } => {
                let ret = runtime
                    .block_on(client.vendor_unbind_resource(vendor, path, policy))
                    .unwrap();
                println!("{:?}", ret);
            }
        }
    }
}
