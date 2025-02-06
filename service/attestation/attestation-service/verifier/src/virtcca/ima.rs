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
use anyhow::{bail, Result};
use fallible_iterator::FallibleIterator;
use ima_measurements::{Event, EventData, Parser};
use serde_json::{json, Map, Value};

#[cfg(not(feature = "no_as"))]
const IMA_REFERENCE_FILE: &str =
    "/etc/attestation/attestation-service/verifier/virtcca/ima/digest_list_file";

// attestation agent local ima reference
#[cfg(feature = "no_as")]
const IMA_REFERENCE_FILE: &str =
    "/etc/attestation/attestation-agent/local_verifier/virtcca/ima/digest_list_file";

#[derive(Debug, Default)]
pub struct ImaVerify {}

impl ImaVerify {
    pub fn ima_verify(&self, ima_log: &[u8], ima_log_hash: Vec<u8>) -> Result<Value> {
        if ima_log.to_vec().is_empty() {
            return Ok(json!({}));
        }

        let mut parser = Parser::new(ima_log);
        let mut events: Vec<Event> = Vec::new();
        while let Some(event) = parser.next()? {
            events.push(event);
        }

        let pcr_values = parser.pcr_values();
        let pcr_10 = pcr_values.get(&10).expect("PCR 10 not measured");
        let string_pcr_sha256 = hex::encode(pcr_10.sha256);
        let string_ima_log_hash = hex::encode(ima_log_hash);

        if string_pcr_sha256.clone() != string_ima_log_hash {
            log::error!(
                "ima log verify failed string_pcr_sha256 {}, string_ima_log_hash {}",
                string_pcr_sha256,
                string_ima_log_hash
            );
            bail!("ima log hash verify failed");
        }

        let ima_refs: Vec<_> = file_reader(IMA_REFERENCE_FILE)?
            .into_iter()
            .map(String::from)
            .collect();

        let mut ima_detail = Map::new();
        // parser each file digest in ima log, and compare with reference base value
        for event in events {
            let (name, file_digest) = match event.data {
                EventData::ImaNg { digest, name } => (name, digest.digest),
                _ => bail!("Invalid event {:?}", event),
            };
            if name == "boot_aggregate".to_string() {
                continue;
            }
            let hex_str_digest = hex::encode(file_digest);
            if ima_refs.contains(&hex_str_digest) {
                ima_detail.insert(name, Value::Bool(true));
            } else {
                log::error!(
                    "there is no refernce base value of file digest {:?}",
                    hex_str_digest
                );
                ima_detail.insert(name, Value::Bool(false));
            }
        }
        let js_ima_detail: Value = ima_detail.into();
        log::debug!("ima verify detail result: {:?}", js_ima_detail);

        Ok(js_ima_detail)
    }
}

use std::io::BufRead;
use std::io::BufReader;
fn file_reader(file_path: &str) -> ::std::io::Result<Vec<String>> {
    let file = std::fs::File::open(file_path).expect("open ima reference file failed");
    let mut strings = Vec::<String>::new();
    let mut reader = BufReader::new(file);
    let mut buf = String::new();
    let mut n: usize;
    loop {
        n = reader.read_line(&mut buf)?;
        if n == 0 {
            break;
        }
        buf.pop();
        strings.push(buf.clone());
        buf.clear();
    }
    Ok(strings)
}
