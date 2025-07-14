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
use fallible_iterator::FallibleIterator;
use ima_measurements::{Event, EventData, Parser};
use serde_json::{json, Map, Value};
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

/// Common IMA verification logic that can be shared between different TEE implementations
pub struct CommonImaVerifier {
    reference_file_path: String,
}

impl CommonImaVerifier {
    pub fn new(reference_file_path: String) -> Self {
        Self {
            reference_file_path,
        }
    }

    /// Parse IMA log and extract events
    pub fn parse_ima_events(&self, ima_log: &[u8]) -> Result<Vec<Event>> {
        if ima_log.is_empty() {
            return Ok(vec![]);
        }

        let mut parser = Parser::new(ima_log);
        let mut events: Vec<Event> = Vec::new();
        while let Some(event) = parser.next()? {
            events.push(event);
        }

        if events.len() < 2 {
            bail!("No IMA measurement records for files found.");
        }

        Ok(events)
    }

    /// Verify file digests against reference values
    pub fn verify_file_digests(&self, events: &[Event]) -> Result<Value> {
        let ima_refs = file_reader(&self.reference_file_path)?;

        let mut ima_detail = Map::new();
        // parse each file digest in ima log, and compare with reference base value
        for event in events {
            let (name, file_digest) = match &event.data {
                EventData::ImaNg { digest, name } => (name.clone(), digest.digest.clone()),
                _ => bail!("Invalid event {:?}", event),
            };
            if name == "boot_aggregate" {
                continue;
            }
            let hex_str_digest = hex::encode(file_digest);
            if ima_refs.contains(&hex_str_digest) {
                ima_detail.insert(name, Value::Bool(true));
            } else {
                log::error!(
                    "there is no reference base value of file digest {:?}",
                    hex_str_digest
                );
                ima_detail.insert(name, Value::Bool(false));
            }
        }
        
        let js_ima_detail: Value = ima_detail.into();
        log::debug!("ima verify detail result: {:?}", js_ima_detail);

        Ok(js_ima_detail)
    }

    /// Complete IMA verification process
    pub fn verify_ima(&self, ima_log: &[u8], hash_verifier: &dyn HashVerifier) -> Result<Value> {
        if ima_log.is_empty() {
            return Ok(json!({}));
        }

        let events = self.parse_ima_events(ima_log)?;
        
        // Verify hash using the provided verifier
        hash_verifier.verify_hash(ima_log, &events)?;
        
        // Verify file digests
        self.verify_file_digests(&events)
    }
}

/// Trait for different hash verification strategies
pub trait HashVerifier {
    fn verify_hash(&self, ima_log: &[u8], events: &[Event]) -> Result<()>;
}

/// IMA verifier trait for different TEE implementations
pub trait ImaVerifier {
    fn ima_verify(&self, ima_log: &[u8], addons: &[Vec<u8>]) -> Result<Value>;
} 