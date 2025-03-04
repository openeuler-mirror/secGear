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

pub(crate) mod client;

use self::client::ResourceClient;
use crate::client::AsClient;
use crate::common::response_display;
use clap::{Args, Subcommand};

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
    pub(crate) fn process(&self, base_client: AsClient) {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(self.command.dispatch(base_client));
    }
}

impl ResourceCommand {
    async fn dispatch(&self, base_client: AsClient) {
        let client = ResourceClient::new(base_client);

        match self {
            ResourceCommand::Get { vendor } => match client.vendor_get_resource(vendor).await {
                Ok(ret) => {
                    response_display(ret).await;
                }
                Err(e) => {
                    println!("{:?}", e);
                }
            },
            ResourceCommand::Add {
                vendor,
                path,
                content,
                policy,
            } => {
                match client
                    .vendor_add_resource(vendor, path, content, policy)
                    .await
                {
                    Ok(ret) => {
                        response_display(ret).await;
                    }
                    Err(e) => {
                        println!("{:?}", e);
                    }
                }
            }
            ResourceCommand::Delete { vendor, path } => {
                match client.vendor_delete_resource(vendor, path).await {
                    Ok(ret) => {
                        response_display(ret).await;
                    }
                    Err(e) => {
                        println!("{:?}", e);
                    }
                }
            }
            ResourceCommand::Modify {
                vendor,
                path,
                content,
            } => match client.vendor_modify_resource(vendor, path, content).await {
                Ok(ret) => {
                    response_display(ret).await;
                }
                Err(rsp) => {
                    println!("{:?}", rsp);
                }
            },
            ResourceCommand::BindPolicy {
                vendor,
                path,
                policy,
            } => match client.vendor_bind_resource(vendor, path, policy).await {
                Ok(ret) => {
                    response_display(ret).await;
                }
                Err(rsp) => {
                    println!("{:?}", rsp);
                }
            },
            ResourceCommand::UnbindPolicy {
                vendor,
                path,
                policy,
            } => match client.vendor_unbind_resource(vendor, path, policy).await {
                Ok(ret) => {
                    response_display(ret).await;
                }
                Err(rsp) => {
                    println!("{:?}", rsp);
                }
            },
        }
    }
}
