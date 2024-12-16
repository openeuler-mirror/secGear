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
#[derive(Debug, PartialEq)]
pub enum KvError {
    Err(String),
}
impl std::fmt::Display for KvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KvError::Err(msg) => write!(f, "kv store error:{}", msg),
        }
    }
}
impl std::error::Error for KvError {}
pub trait KvStore {
    fn write(&mut self, key: &str, value: &[u8]) -> Result<(), KvError>;
    fn read(&mut self, key: &str) -> Option<Vec<u8>>;
    fn delete(&mut self, key: &str) -> Result<(), KvError>;
}
