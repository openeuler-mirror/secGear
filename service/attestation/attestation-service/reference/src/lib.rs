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
mod extractor;
pub mod local_fs;
pub mod reference;
pub mod store;

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;
    use rand::{distributions::Alphanumeric, Rng};
    use serde_json::Value;

    #[test]
    fn localfs_default_test() {
        let mut ops_default = reference::ReferenceOps::default();
        let refs = r#"{"test1":"hash1","test2":"hash2"}"#.to_string();
        assert_eq!(ops_default.register(&refs), Ok(()));
        let ref_query = ops_default.query(&refs).unwrap();
        println!("ref:{refs}, query:{ref_query}");
        assert_eq!(ref_query, refs);
    }

    #[test]
    fn localfs_empty_reference_test() {
        let mut ops_default = reference::ReferenceOps::default();
        assert_ne!(ops_default.register(&r#""#.to_string()), Ok(()));
        assert_eq!(ops_default.query(&r#""#.to_string()), None);

        let refs = r#"{}"#.to_string();
        assert_eq!(ops_default.register(&refs), Ok(()));
        let ref_query = ops_default.query(&refs).unwrap();
        println!("ref:{refs}, query:{ref_query}");
        assert_eq!(ref_query, refs);
    }

    #[test]
    fn localfs_query_fail_test() {
        let mut ops_default = reference::ReferenceOps::default();
        let refs = r#"{"test1":"hash1"}"#.to_string();
        assert_eq!(ops_default.register(&refs), Ok(()));
        let ref_query = ops_default
            .query(&r#"{"test":"hash1"}"#.to_string())
            .unwrap();
        println!("ref:{refs}, query:{ref_query}");
        assert_ne!(ref_query, refs);
    }

    #[test]
    fn localfs_default_complex_reference_test() {
        let mut ops_default = reference::ReferenceOps::default();
        let refs = r#"{"test1": { "name1":123, "name2": "val2"},"test2":123}"#.to_string();
        assert_eq!(ops_default.register(&refs), Ok(()));
        let ref_query = ops_default.query(&refs).unwrap();
        let json_obj: Value = serde_json::from_str(refs.as_str()).unwrap();
        println!("ref:{}, query:{ref_query}", json_obj.to_string());
        assert_eq!(ref_query, json_obj.to_string());
    }

    #[test]
    fn localfs_new_test() {
        let store = local_fs::LocalFs::new(&String::from("/var/attestation/data_new"));
        let mut ops = reference::ReferenceOps::new(store);
        let refs = r#"{"test1":"hash1","test2":"hash2"}"#.to_string();
        assert_eq!(ops.register(&refs), Ok(()));
        let ref_query = ops.query(&refs).unwrap();
        println!("ref:{refs}, query:{ref_query}");
        assert_eq!(ref_query, refs);
    }

    #[test]
    fn localfs_register_reference_repeat_test() {
        let mut ops_default = reference::ReferenceOps::default();
        let refs = r#"{"test1":"hash1","test2":"hash2"}"#.to_string();
        assert_eq!(ops_default.register(&refs), Ok(()));
        assert_eq!(ops_default.register(&refs), Ok(()));
        let ref_query = ops_default.query(&refs).unwrap();
        println!("ref:{refs}, query:{ref_query}");
        assert_eq!(ref_query, refs);
    }

    #[test]
    fn localfs_unregister_reference_test() {
        let mut ops_default = reference::ReferenceOps::default();
        let refs = r#"{"name1":"hash1","name2":"hash2"}"#.to_string();
        assert_eq!(ops_default.register(&refs), Ok(()));
        let ref_query = ops_default.query(&refs).unwrap();
        println!("ref:{refs}, query:{ref_query}");
        assert_eq!(ref_query, refs);

        assert_eq!(ops_default.unregister(&refs), Ok(()));
        let ref_query = ops_default.query(&refs).unwrap();
        println!("ref:{refs}, query:{ref_query}");
        assert_ne!(refs, ref_query);
    }

    #[test]
    fn localfs_register_query_concurrently() {
        let mut thread_all = vec![];
        let thread_cnt = 1000;
        for i in 0..thread_cnt {
            let seq_start = i * thread_cnt;
            let seq_end = seq_start + thread_cnt;
            thread_all.push(thread::spawn(move || {
                let rng = rand::thread_rng();
                let mut ops_default = reference::ReferenceOps::default();

                for i in seq_start..seq_end {
                    //key
                    let key = format!("ref{}", i);
                    //value
                    let value: String = rng
                        .clone()
                        .sample_iter(&Alphanumeric)
                        .take(128)
                        .map(char::from)
                        .collect();
                    let mut reference = serde_json::json!({});
                    reference
                        .as_object_mut()
                        .unwrap()
                        .insert(key, Value::String(value));
                    let _ = ops_default.register(&reference.to_string());
                    let ref_query = ops_default.query(&reference.to_string()).unwrap();
                    println!("ref {} query {}", reference.to_string(), ref_query);
                    assert_eq!(ref_query, reference.to_string());
                }
            }));
        }
        for hd in thread_all {
            match hd.join() {
                Ok(_) => {}
                Err(_) => {
                    assert!(false)
                }
            }
        }
    }
}
