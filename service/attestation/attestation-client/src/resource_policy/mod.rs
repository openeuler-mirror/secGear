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
use attestation_types::resource::policy::PolicyLocation;
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
    ClearAll,
    ClearAllInVendor {
        vendor: String,
    },
}

impl ResourcePolicyArgs {
    pub(crate) fn process(&self, base_client: AsClient) {
        self.command.dispatch(base_client);
    }
}

impl ResourcePolicyCommand {
    fn dispatch(&self, base_client: AsClient) {
        let client = ResourcePolicyClient::new(base_client);
        let runtime = tokio::runtime::Runtime::new().unwrap();

        match self {
            ResourcePolicyCommand::GetOne { vendor, id } => {
                let ret = runtime.block_on(client.vendor_get_one(vendor, id)).unwrap();
                println!("{}", ret);
            }
            ResourcePolicyCommand::GetAll => {
                let ret = runtime.block_on(client.vendor_get_all()).unwrap();
                println!("{}", serde_json::json!(ret).to_string());
            }
            ResourcePolicyCommand::GetAllInVendor { vendor } => {
                let ret = runtime
                    .block_on(client.vendor_get_all_in_vendor(vendor))
                    .unwrap();
                println!("{}", serde_json::json!(ret).to_string());
            }
            ResourcePolicyCommand::Add {
                vendor,
                id,
                content,
            } => {
                let ret = runtime
                    .block_on(client.vendor_add(vendor, id, content))
                    .unwrap();
                println!("{}", ret);
            }
            ResourcePolicyCommand::Delete { vendor, id } => {
                let ret = runtime
                    .block_on(client.vendor_delete(vendor, id))
                    .unwrap();
                println!("{}", ret);
            }
            ResourcePolicyCommand::ClearAll => {
                let ret = runtime
                    .block_on(client.vendor_clear_all())
                    .unwrap();
                println!("{}", ret);
            }
            ResourcePolicyCommand::ClearAllInVendor { vendor } => {
                let ret = runtime
                    .block_on(client.vendor_clear_all_in_vendor(vendor))
                    .unwrap();
                println!("{}", ret);
            }
        }
    }
}
