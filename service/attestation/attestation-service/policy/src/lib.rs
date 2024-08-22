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
pub mod opa;
pub mod policy_engine;

#[cfg(test)]
mod tests {
    use base64::Engine;
    use std::fs;

    use crate::{
        opa::OPA,
        policy_engine::{PolicyEngine, PolicyEngineError},
    };

    #[tokio::test]
    async fn test_new_policy_engine() {
        let policy_dir = String::from("/etc/attestation/attestation-service/policy");
        let ret = OPA::new(&policy_dir).await;
        assert!(ret.is_ok());
    }

    #[tokio::test]
    async fn test_new_policy_engine_dir_exist() {
        let policy_dir = String::from("/etc/attestation/attestation-service/policy");
        let _ = fs::create_dir_all(&policy_dir);
        let ret = OPA::new(&policy_dir).await;
        assert!(ret.is_ok());
    }

    #[tokio::test]
    async fn test_new_policy_engine_dir_failed() {
        let policy_dir = String::from("/sys/invalid_dir");
        let ret = OPA::new(&policy_dir).await;
        assert!(ret.is_err());
        if let PolicyEngineError::CreatePolicyDirError(msg) = ret.err().unwrap() {
            assert_eq!(msg, "policy dir create failed");
        } else {
            panic!("Unexpected error type");
        }
    }

    #[tokio::test]
    async fn test_set_policy() {
        let policy_dir = String::from("/etc/attestation/attestation-service/policy");
        let engine = OPA::new(&policy_dir).await;

        let policy_id = "test.rego".to_string();
        let policy = r#"package attestation
import rego.v1
expect_keys := ["RIM", "RPV"]
input_keys := object.keys(input)
output[exist] := input[exist] if {
    some exist in expect_keys
    exist in input_keys
}
output[exist] := null if {
    some exist in expect_keys
    not exist in input_keys
}
output["Other"] := "other" if {
    "test" in input_keys
}"#;
        let _ =
            tokio::fs::remove_file("/etc/attestation/attestation-service/policy/test.rego").await;

        let ret = engine
            .unwrap()
            .set_policy(
                &policy_id,
                &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(policy),
            )
            .await;
        assert!(ret.is_ok());
    }

    #[tokio::test]
    async fn test_get_all_policy() {
        let policy_dir = String::from("/etc/attestation/attestation-service/policy");
        let engine = OPA::new(&policy_dir).await;
        let ret = engine.unwrap().get_all_policy().await;
        println!("{:?}", ret);
        assert!(ret.is_ok());
    }

    #[tokio::test]
    async fn test_evaluate_by_default() {
        let policy_dir = String::from("/etc/attestation/attestation-service/policy");
        let engine = OPA::new(&policy_dir).await.unwrap();
        let refs_from_report = String::from(
            r#"{
            "RIM": "7d2e49c8d29f18b748e658e7243ecf26bc292e5fee93f72af11ad9da9810142a",
            "RPV": "igliurbwjlkfxvr3wk2kqrttyz4gds42h9sdf72dgpcw8lspts1nnmxuvqzeqyq0",
            "test": "u4eyoqgqsiju43aooetb02j0rymx6ijhhxs5oryj8344x7kehzjrwsi3vi7wqo2y"
        }"#,
        );
        let data = String::new();
        let policy_id: Vec<String> = vec![];
        let result = engine.evaluate(&String::from("vcca"), &refs_from_report, &data, &policy_id).await;
        println!("{:?}", result);
        assert!(result.is_ok());
        match result {
            Ok(ret) => {
                for i in ret.keys() {
                    println!("{} : {}", i, ret[i]);
                }
            }
            Err(err) => {
                println!("{err}");
            }
        }
    }

    #[tokio::test]
    async fn test_evaluate_use_specified_policy() {
        // 先设置指定的策略
        let policy_dir = String::from("/etc/attestation/attestation-service/policy");
        let engine = OPA::new(&policy_dir).await.unwrap();

        let policy_id = "test.rego".to_string();
        // 该策略提取期望的基线值，如果不存在则设置为null；同时包含“test”基线，则将Other设置为"other"
        let policy = r#"package attestation
import rego.v1
expect_keys := ["RIM", "RPV"]
input_keys := object.keys(input)
output[exist] := input[exist] if {
    some exist in expect_keys
    exist in input_keys
}
output[exist] := null if {
    some exist in expect_keys
    not exist in input_keys
}
output["Other"] := "other" if {
    "test" in input_keys
}"#;
        // 删除已重复存在的policy
        let _ =
            tokio::fs::remove_file("/etc/attestation/attestation-service/policy/test.rego").await;

        let ret = engine
            .set_policy(
                &policy_id,
                &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(policy),
            )
            .await;
        assert!(ret.is_ok());

        // 使用自定义的策略进行报告评估
        let refs_from_report = String::from(
            r#"{
            "RIM": "7d2e49c8d29f18b748e658e7243ecf26bc292e5fee93f72af11ad9da9810142a",
            "RPV": "v598upciquf97yngfi4g2k5r9z6pyl1gcudj1vsgpn7v49ad2oafs11m0esdgv7r",
            "test": "c4ca91mhcxwqi4ka6ysjgl8nn5hhhln9k2n7ppn3zs1jes4aohlflh5krsogqlpz"
        }"#,
        );
        let data = String::new();
        let policy_id: Vec<String> = vec!["test.rego".to_string()];
        let result = engine.evaluate(&String::from("vcca"), &refs_from_report, &data, &policy_id).await;
        assert!(result.is_ok());
        match result {
            Ok(ret) => {
                for i in ret.keys() {
                    println!("{} : {}", i, ret[i]);
                }
            }
            Err(err) => {
                println!("{err}");
            }
        }
    }
}
