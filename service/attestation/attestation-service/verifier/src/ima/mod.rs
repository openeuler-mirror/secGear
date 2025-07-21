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

//! IMA verifier module
//! 
//! This module provides IMA (Integrity Measurement Architecture) verification functionality
//! for TEE attestation.

use anyhow::{bail, Result};
use ima_measurements::Event;
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

pub mod virtcca;
pub mod itrustee;

/// File reader utility function
pub fn file_reader(file_path: &str) -> io::Result<HashSet<String>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut set = HashSet::new();

    for line in reader.lines() {
        let line = line?;
        set.insert(line.trim_end().to_string());
    }

    Ok(set)
}

/// Common function to verify IMA events against reference values
/// This function handles the common logic of comparing file digests with reference values,
/// which is shared between different TEE implementations.
pub fn verify_ima_events(events: &[Event], ima_refs: &HashSet<String>) -> Result<Value> {
    if events.len() < 2 {
        bail!("No IMA measurement records for files found.");
    }

    let mut ima_detail = Map::new();
    // parse each file digest in ima log, and compare with reference base value
    for event in events {
        let (name, file_digest) = match &event.data {
            ima_measurements::EventData::ImaNg { digest, name } => (name, &digest.digest),
            _ => bail!("Invalid event {:?}", event),
        };
        if name == "boot_aggregate" {
            continue;
        }
        let hex_str_digest = hex::encode(file_digest);
        if ima_refs.contains(&hex_str_digest) {
            ima_detail.insert(name.clone(), Value::Bool(true));
        } else {
            log::error!(
                "there is no reference base value of file digest {:?}",
                hex_str_digest
            );
            ima_detail.insert(name.clone(), Value::Bool(false));
        }
    }
    
    let js_ima_detail: Value = ima_detail.into();
    log::debug!("ima verify detail result: {:?}", js_ima_detail);

    Ok(js_ima_detail)
}

/// IMA verifier trait for different TEE implementations
pub trait ImaVerifier {
    fn ima_verify(&self, ima_log: &[u8], addons: &[Vec<u8>]) -> Result<Value>;
} 