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
use std::fs::File;
use std::io::Write;
use std::path::Path;
use thiserror::{self, Error};

const ITRUSTEE_REF_VALUE_DIR: &str = "/etc/attestation/attestation-service/reference-itrustee/";
const VERIFY_BY_POLICY: [&str; 2] = ["vcca.is_platform", "vcca.platform.measure_value"];
const ITRUSTEE_IMA_BASE_DIR: &str = "/etc/attestation/attestation-service/verifier/itrustee/ima";
const VIRTCCA_IMA_BASE_DIR: &str = "/etc/attestation/attestation-service/verifier/virtcca/ima";

const DIGEST_LIST_FILE_NAME: &str = "digest_list_file";
const ITRUSTEE_IMA_PREFIX: &str = "itrustee_ima_";
const VIRTCCA_IMA_PREFIX: &str = "virtcca_ima_";

const APP_ID_MAX_LEN: usize = 256;
const MAX_DIGEST_COUNT: usize = 10_000;
const DIGEST_SHA256_HEX_LEN: usize = 64;

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
        ReferenceOps {
            store: Box::new(st),
        }
    }

    fn generate_reference_key(reference: &Ref) -> String {
        let key = reference.name.clone() + reference.value.to_string().as_str();
        hex::encode(sha256(key.as_bytes()))
    }

    fn register_reference(&mut self, reference: &Ref) -> Result<(), RefOpError> {
        // generate reference key
        let key = Self::generate_reference_key(reference);
        self.store
            .write(&key, serde_json::to_string(&reference).unwrap().as_bytes())?;
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
    pub fn register(&mut self, ref_set: &str) -> Result<(), RefOpError> {
        let refs =
            Extractor::split(ref_set).ok_or(RefOpError::Err("parse reference fail".to_string()))?;
        for item in refs {
            self.register_item(&item)?;
        }
        Ok(())
    }

    fn register_item(&mut self, item: &Ref) -> Result<(), RefOpError> {
        self.register_item_with_ima_dirs(item, ITRUSTEE_IMA_BASE_DIR, VIRTCCA_IMA_BASE_DIR)
    }

    fn register_item_with_ima_dirs(
        &mut self,
        item: &Ref,
        itrustee_ima_base_dir: &str,
        virtcca_ima_base_dir: &str,
    ) -> Result<(), RefOpError> {
        if let Some(uuid) = item.name.strip_prefix(ITRUSTEE_IMA_PREFIX) {
            Self::write_ima_reference_file(itrustee_ima_base_dir, uuid, &item.value)?;
            self.register_reference(item)?;
            return Ok(());
        }

        if let Some(app_id) = item.name.strip_prefix(VIRTCCA_IMA_PREFIX) {
            Self::write_ima_reference_file(virtcca_ima_base_dir, app_id, &item.value)?;
            self.register_reference(item)?;
            return Ok(());
        }

        self.register_reference(item)?;
        // refnamex with prefix "itrustee_" should write to seperate file，itrustee sdk will use it
        if item.name.starts_with("itrustee_") {
            let file_name = ITRUSTEE_REF_VALUE_DIR.to_string() + item.name.as_str();
            let path = Path::new(file_name.as_str());
            let mut file = File::create(path).map_err(|_| {
                RefOpError::Err(
                    "create itrustee reference file failed: ".to_string() + file_name.as_str(),
                )
            })?;
            file.write_all(&item.value.as_str().unwrap().as_bytes())
                .map_err(|_| {
                    RefOpError::Err(
                        "write itrustee reference file failed".to_string() + file_name.as_str(),
                    )
                })?;
        }

        Ok(())
    }

    pub fn unregister(&mut self, ref_set: &str) -> Result<(), RefOpError> {
        let refs =
            Extractor::split(ref_set).ok_or(RefOpError::Err("parse reference fail".to_string()))?;
        for item in refs {
            self.unregister_reference(&item)?
        }
        Ok(())
    }

    pub fn query(&mut self, ref_set: &str) -> Option<String> {
        let refs = Extractor::split(ref_set)?;
        let mut ret: Value = json!({});
        for item in refs {
            if VERIFY_BY_POLICY.contains(&item.name.as_str()) {
                ret.as_object_mut().unwrap().insert(item.name, item.value);
                continue;
            }
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

impl ReferenceOps {
    fn write_ima_reference_file(
        base_dir: &str,
        app_id: &str,
        value: &Value,
    ) -> Result<(), RefOpError> {
        if app_id.is_empty()
            || app_id.len() > APP_ID_MAX_LEN
            || app_id.contains("..")
            || app_id.contains('/')
            || app_id.contains('\\')
        {
            return Err(RefOpError::Err(format!(
                "invalid app_id for IMA reference: {}",
                app_id
            )));
        }

        let digests: Vec<String> = match value {
            Value::String(s) => s
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect(),
            Value::Array(arr) => arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
                .filter(|s| !s.is_empty())
                .collect(),
            _ => {
                return Err(RefOpError::Err(
                    "invalid IMA reference format, expect string or array".to_string(),
                ))
            }
        };

        if digests.len() > MAX_DIGEST_COUNT {
            return Err(RefOpError::Err("too many digests".to_string()));
        }

        let app_dir = format!("{}/{}", base_dir, app_id);
        let file_path = format!("{}/{}", app_dir, DIGEST_LIST_FILE_NAME);
        let mut valid_digests = Vec::new();
        for digest in digests {
            if digest.len() != DIGEST_SHA256_HEX_LEN
                || !digest.chars().all(|c| c.is_ascii_hexdigit())
            {
                log::warn!(
                    "skip invalid digest for app_id {} file {} digest {}",
                    app_id,
                    file_path,
                    digest
                );
                continue;
            }
            valid_digests.push(digest);
        }

        if valid_digests.is_empty() {
            return Err(RefOpError::Err(format!(
                "no valid IMA reference digest for app_id {}",
                app_id
            )));
        }

        std::fs::create_dir_all(&app_dir).map_err(|e| {
            RefOpError::Err(format!("Failed to create directory {}: {}", app_dir, e))
        })?;

        let mut file = File::create(&file_path)
            .map_err(|e| RefOpError::Err(format!("Failed to create file {}: {}", file_path, e)))?;

        for digest in valid_digests {
            file.write_all(format!("{}\n", digest).as_bytes())
                .map_err(|e| {
                    RefOpError::Err(format!("Failed to write digest to {}: {}", file_path, e))
                })?;
        }

        file.sync_all()
            .map_err(|e| RefOpError::Err(format!("Failed to sync file {}: {}", file_path, e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    const VALID_DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[derive(Default)]
    struct MemoryStore {
        entries: HashMap<String, Vec<u8>>,
    }

    impl KvStore for MemoryStore {
        fn write(&mut self, key: &str, value: &[u8]) -> Result<(), KvError> {
            self.entries.insert(key.to_string(), value.to_vec());
            Ok(())
        }

        fn read(&mut self, key: &str) -> Option<Vec<u8>> {
            self.entries.get(key).cloned()
        }

        fn delete(&mut self, key: &str) -> Result<(), KvError> {
            self.entries.remove(key);
            Ok(())
        }
    }

    fn temp_base_dir(test_name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "secgear-reference-{test_name}-{}-{unique}",
            std::process::id()
        ))
    }

    fn digest_file(base_dir: &Path, app_id: &str) -> PathBuf {
        base_dir.join(app_id).join(DIGEST_LIST_FILE_NAME)
    }

    #[test]
    fn ima_reference_rejects_all_invalid_digests_without_overwriting_existing_file() {
        let base_dir = temp_base_dir("invalid-digests");
        let app_id = "app";
        let file_path = digest_file(&base_dir, app_id);
        fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        fs::write(&file_path, format!("{VALID_DIGEST}\n")).unwrap();

        let result = ReferenceOps::write_ima_reference_file(
            base_dir.to_str().unwrap(),
            app_id,
            &json!(["not-a-sha256-digest"]),
        );

        assert!(result.is_err());
        assert_eq!(
            fs::read_to_string(&file_path).unwrap(),
            format!("{VALID_DIGEST}\n")
        );
        let _ = fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn ima_reference_rejects_empty_digest_inputs() {
        let base_dir = temp_base_dir("empty-digests");

        assert!(ReferenceOps::write_ima_reference_file(
            base_dir.to_str().unwrap(),
            "empty-string",
            &Value::String("".to_string()),
        )
        .is_err());
        assert!(ReferenceOps::write_ima_reference_file(
            base_dir.to_str().unwrap(),
            "empty-array",
            &json!([]),
        )
        .is_err());

        assert!(!digest_file(&base_dir, "empty-string").exists());
        assert!(!digest_file(&base_dir, "empty-array").exists());
        let _ = fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn ima_reference_writes_only_valid_digests_when_input_is_mixed() {
        let base_dir = temp_base_dir("mixed-digests");
        let app_id = "app";

        ReferenceOps::write_ima_reference_file(
            base_dir.to_str().unwrap(),
            app_id,
            &json!(["invalid", VALID_DIGEST]),
        )
        .unwrap();

        assert_eq!(
            fs::read_to_string(digest_file(&base_dir, app_id)).unwrap(),
            format!("{VALID_DIGEST}\n")
        );
        let _ = fs::remove_dir_all(&base_dir);
    }

    #[test]
    fn ima_reference_register_does_not_update_store_when_file_write_fails() {
        let base_dir = temp_base_dir("register-failure");
        let mut ops = ReferenceOps::new(MemoryStore::default());
        let reference = Ref {
            name: format!("{VIRTCCA_IMA_PREFIX}app"),
            value: json!(["invalid"]),
        };

        let result = ops.register_item_with_ima_dirs(&reference, "", base_dir.to_str().unwrap());

        assert!(result.is_err());
        assert!(ops.query_reference(&reference).is_none());
        assert!(!digest_file(&base_dir, "app").exists());
        let _ = fs::remove_dir_all(&base_dir);
    }
}
