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
use crate::reference::Ref;
use serde_json::Value;
pub struct Extractor {}
impl Extractor {
    pub fn split(ref_set: &String) -> Option<Vec<Ref>> {
        // expect ref_set as a json string, like follow:
        // {"refname1":xx,"refname2":yy}
        let mut ret: Vec<Ref> = vec![];
        let refs: Value = serde_json::from_str(ref_set.as_str()).ok()?;
        for (key, val) in refs.as_object().unwrap() {
            let ref_obj = Ref {
                name: key.clone(),
                value: val.clone(),
            };
            ret.push(ref_obj);
        }
        Some(ret)
    }
}
