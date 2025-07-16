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

use anyhow::Result;
use serde_json::Value;
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

/// IMA verifier trait for different TEE implementations
pub trait ImaVerifier {
    fn ima_verify(&self, ima_log: &[u8], addons: &[Vec<u8>]) -> Result<Value>;
} 