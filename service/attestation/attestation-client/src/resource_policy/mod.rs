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

//! Subcommand for getting or setting resource policy.
//!

pub(crate) mod client;

use self::client::ResourcePolicyClient;
use crate::client::AsClient;
use crate::common::response_display;
use clap::{Args, Subcommand};

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
#[command(flatten_help = true)]
pub(crate) struct ResourcePolicyArgs {
    #[command(subcommand)]
    pub(crate) command: ResourcePolicyCommand,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ResourcePolicyCommand {
    GetOne {
        vendor: String,
        id: String,
    },
    GetAll,
    GetAllInVendor {
        vendor: String,
    },
    Add {
        vendor: String,
        id: String,
        content: String,
    },
    Delete {
        vendor: String,
        id: String,
    },
    ClearAll {
        vendor: String,
    },
}

impl ResourcePolicyArgs {
    pub(crate) fn process(&self, base_client: AsClient) {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(self.command.dispatch(base_client));
    }
}

impl ResourcePolicyCommand {
    async fn dispatch(&self, base_client: AsClient) {
        let client = ResourcePolicyClient::new(base_client);

        match self {
            ResourcePolicyCommand::GetOne { vendor, id } => {
                match client.vendor_get_one(vendor, id).await {
                    Ok(ret) => {
                        response_display(ret).await;
                    }
                    Err(e) => {
                        println!("{:?}", e);
                    }
                }
            }
            ResourcePolicyCommand::GetAll => match client.vendor_get_all().await {
                Ok(ret) => {
                    response_display(ret).await;
                }
                Err(rsp) => {
                    println!("{:?}", rsp);
                }
            },
            ResourcePolicyCommand::GetAllInVendor { vendor } => {
                match client.vendor_get_all_in_vendor(vendor).await {
                    Ok(ret) => {
                        response_display(ret).await;
                    }
                    Err(e) => {
                        println!("{:?}", e);
                    }
                }
            }
            ResourcePolicyCommand::Add {
                vendor,
                id,
                content,
            } => match client.vendor_add(vendor, id, content).await {
                Ok(ret) => {
                    response_display(ret).await;
                }
                Err(rsp) => {
                    println!("{:?}", rsp);
                }
            },
            ResourcePolicyCommand::Delete { vendor, id } => {
                match client.vendor_delete(vendor, id).await {
                    Ok(ret) => {
                        response_display(ret).await;
                    }
                    Err(e) => {
                        println!("{:?}", e);
                    }
                }
            }
            ResourcePolicyCommand::ClearAll { vendor } => {
                match client.vendor_clear_all(vendor).await {
                    Ok(ret) => {
                        response_display(ret).await;
                    }
                    Err(e) => {
                        println!("{:?}", e);
                    }
                }
            }
        }
    }
}
