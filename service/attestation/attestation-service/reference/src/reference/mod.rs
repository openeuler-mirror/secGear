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
use crate::extractor::Extractor;
use crate::local_fs::LocalFs;
use crate::store::{KvError, KvStore};
use openssl::sha::sha256;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::{self, Error};

pub struct ReferenceOps {
    store: Box<dyn KvStore>,
}

impl Default for ReferenceOps {
    fn default() -> Self {
        ReferenceOps {
            store: Box::new(LocalFs::default()),
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub enum HashAlg {
    SHA256(String),
    SHA384(String),
    SHA512(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Ref {
    pub name: String,
    pub value: Value,
}

#[derive(Error, Debug, PartialEq)]
pub enum RefOpError {
    #[error("reference operation error {0}")]
    Err(String),
    #[error("reference store error: {0:?}")]
    StoreErr(#[from] KvError),
}

impl ReferenceOps {
    pub fn new(st: impl KvStore + 'static) -> ReferenceOps {
        let ops = ReferenceOps {
            store: Box::new(st),
        };
        ops
    }

    fn generate_reference_key(reference: &Ref) -> String {
        let key = reference.name.clone() + reference.value.to_string().as_str();
        hex::encode(sha256(key.as_bytes()))
    }

    fn register_reference(&mut self, reference: &Ref) -> Result<(), RefOpError> {
        // generate reference key
        let key = Self::generate_reference_key(reference);
        self.store.write(
            &key,
            serde_json::to_string(&reference)
                .unwrap()
                .as_bytes()
                .as_ref(),
        )?;
        Ok(())
    }

    fn unregister_reference(&mut self, reference: &Ref) -> Result<(), RefOpError> {
        let key = Self::generate_reference_key(reference);
        self.store.delete(&key)?;
        Ok(())
    }

    fn query_reference(&mut self, reference: &Ref) -> Option<Vec<u8>> {
        let key = Self::generate_reference_key(reference);
        self.store.read(&key)
    }
    /// ref_set is a json string like:{"refname1":xx,"refname2":yy}
    pub fn register(&mut self, ref_set: &String) -> Result<(), RefOpError> {
        let refs =
            Extractor::split(ref_set).ok_or(RefOpError::Err("parse reference fail".to_string()))?;
        for item in refs {
            self.register_reference(&item)?
        }
        Ok(())
    }

    pub fn unregister(&mut self, ref_set: &String) -> Result<(), RefOpError> {
        let refs =
            Extractor::split(ref_set).ok_or(RefOpError::Err("parse reference fail".to_string()))?;
        for item in refs {
            self.unregister_reference(&item)?
        }
        Ok(())
    }

    pub fn query(&mut self, ref_set: &String) -> Option<String> {
        let refs = Extractor::split(ref_set)?;
        let mut ret: Value = json!({});
        for item in refs {
            // query each reference, reference is set to NULL if not found
            match self.query_reference(&item) {
                Some(ref_store) => {
                    let ref_raw: Ref =
                        serde_json::from_str(String::from_utf8(ref_store).unwrap().as_str())
                            .ok()?;
                    ret.as_object_mut()
                        .unwrap()
                        .insert(ref_raw.name, ref_raw.value);
                }
                None => {
                    ret.as_object_mut().unwrap().insert(item.name, Value::Null);
                }
            }
        }
        Some(ret.to_string())
    }
}
