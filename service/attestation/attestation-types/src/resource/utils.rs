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

use crate::resource::error::Result;
use async_recursion::async_recursion;
use std::path::PathBuf;

#[async_recursion(Sync)]
pub(crate) async fn traverse_regular_file(base: &PathBuf) -> Result<Vec<PathBuf>> {
    let mut entries = tokio::fs::read_dir(base).await?;
    let mut ret: Vec<PathBuf> = vec![];
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_dir() {
            let mut parts = traverse_regular_file(&path).await?;
            ret.append(&mut parts);
        } else if path.is_file() {
            ret.push(path);
        }
    }

    Ok(ret)
}
