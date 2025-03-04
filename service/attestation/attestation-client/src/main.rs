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

//! This is the client tool for attestation service, which encapsulates frequently-used web request
//! into the sub-command of the command line tool.

mod client;
mod error;
mod resource;
mod resource_policy;
mod common;

use crate::resource::ResourceArgs;
use crate::resource_policy::ResourcePolicyArgs;
use clap::{Parser, Subcommand};
use client::AsClient;

/// A fictional versioning CLI
#[derive(Debug, Parser)] // requires `derive` feature
#[command(name = "attestation-client")]
#[command(about = "Web client of attestation service", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Resource(ResourceArgs),
    ResourcePolicy(ResourcePolicyArgs),
}

fn main() {
    let args = Cli::parse();
    let client = AsClient::default();
    match args.command {
        Commands::Resource(args) => {
            args.process(client);
        }
        Commands::ResourcePolicy(args) => {
            args.process(client);
        }
    }
}
