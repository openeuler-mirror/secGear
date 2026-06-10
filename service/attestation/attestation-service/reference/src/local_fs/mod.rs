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
use lazy_static::lazy_static;
use sled::Db;
use std::ops::Deref;
use std::sync::Arc;

use crate::store::{KvError, KvStore};

pub struct LocalFs {
    db: Arc<Db>,
}

impl Default for LocalFs {
    fn default() -> Self {
        lazy_static! {
            static ref db_handle: Arc<Db> =
                Arc::new(sled::open("/etc/attestation/attestation-service/reference").unwrap());
        }
        LocalFs {
            db: db_handle.clone(),
        }
    }
}

impl KvStore for LocalFs {
    fn write(&mut self, key: &str, value: &[u8]) -> Result<(), KvError> {
        if self.db.insert(key.as_bytes(), value).is_err() {
            return Err(KvError::Err("insert error".to_string()));
        }
        if self.db.flush().is_err() {
            Err(KvError::Err("write flush error".to_string()))
        } else {
            Ok(())
        }
    }
    fn read(&mut self, key: &str) -> Option<Vec<u8>> {
        match self.db.get(key) {
            Ok(val) => val.map(|iv| Vec::from(iv.deref())),
            Err(_err) => None,
        }
    }

    fn delete(&mut self, key: &str) -> Result<(), KvError> {
        if self.db.remove(key.as_bytes()).is_err() {
            return Err(KvError::Err("delete fail".to_string()));
        }
        if self.db.flush().is_err() {
            Err(KvError::Err("delete flush fail".to_string()))
        } else {
            Ok(())
        }
    }
}

impl LocalFs {
    pub fn new(path: &String) -> LocalFs {
        LocalFs {
            db: Arc::new(sled::open(path).unwrap()),
        }
    }
}
