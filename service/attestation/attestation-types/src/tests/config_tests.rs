use super::super::config::{AAConfig, AppConfig, HttpProtocal, TokenVerifyConfig};
use super::super::TeeType;
use serde_json;

#[cfg(test)]
mod tests {
    use super::*;

    fn current_time() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn fake_jwt(label: &str, exp: u64) -> String {
        let header = base64_url::encode(r#"{"alg":"none"}"#);
        let payload = base64_url::encode(&format!(r#"{{"exp":{exp},"label":"{label}"}}"#));
        format!("{header}.{payload}.signature")
    }

    #[test]
    fn test_appconfig_deserialization() {
        // 测试 AppConfig 的反序列化
        let json = r#"{
            "uuid": "f68fd704-6eb1-4d14-b218-722850eb3ef0",
            "ima": true,
            "interval": 30,
            "platform": "itrustee"
        }"#;

        let app_config: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(app_config.uuid, "f68fd704-6eb1-4d14-b218-722850eb3ef0");
        assert_eq!(app_config.ima, true);
        assert_eq!(app_config.interval, 30);
        assert_eq!(app_config.platform, TeeType::Itrustee);
        assert_eq!(app_config.rim_auto_discover, false);

        // 测试没有 platform 字段的情况（应该使用默认值）
        let json = r#"{
            "uuid": "0715F5BA-13A2-478B-BD60-B43B645E23DE",
            "ima": false,
            "interval": 60
        }"#;

        let app_config: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(app_config.platform, TeeType::Invalid);
    }

    #[test]
    fn test_appconfig_rim_auto_discover_deserialization() {
        let json = r#"{
            "uuid": "auto",
            "ima": true,
            "interval": 30,
            "platform": "virtcca",
            "rim_auto_discover": true
        }"#;

        let app_config: AppConfig = serde_json::from_str(json).unwrap();
        assert_eq!(app_config.uuid, "auto");
        assert_eq!(app_config.configured_uuid(), "auto");
        assert_eq!(app_config.platform, TeeType::Virtcca);
        assert_eq!(app_config.rim_auto_discover, true);
    }

    #[test]
    fn test_appconfig_serialization_uses_configured_uuid() {
        let mut app_config = AppConfig::new("auto".to_string(), false, 30, TeeType::Virtcca, true);
        app_config.uuid =
            "8b20beea9304b06459e7cd295145d643d8b93cd8f47c8ccabafc6979040dc7c0".to_string();

        let value = serde_json::to_value(&app_config).unwrap();

        assert_eq!(value["uuid"], "auto");
        assert!(value.get("configured_uuid").is_none());
        assert!(value.get("discovered_rim").is_none());
        assert!(value.get("token_manager").is_none());
    }

    #[test]
    fn test_http_protocal_default() {
        let protocal = HttpProtocal::default();
        assert_eq!(protocal.get_protocal(), "http");
        assert_eq!(protocal.get_cert_root(), None);
    }

    #[test]
    fn test_token_verify_config_default() {
        let config = TokenVerifyConfig::default();
        assert_eq!(
            config.cert,
            "/etc/attestation/attestation-agent/as_cert.pem"
        );
        assert_eq!(config.iss, "oeas");
    }

    #[test]
    fn test_aaconfig_default() {
        let config = AAConfig::default();
        assert_eq!(config.svr_url, "http://127.0.0.1:8080");
        assert_eq!(config.enable_active_attestation, false);
        assert_eq!(config.app_list.len(), 0);
    }

    #[test]
    fn test_aaconfig_deserialization() {
        // 测试完整的 AAConfig 反序列化
        let json = r#"{
            "svr_url": "http://127.0.0.1:8080",
            "token_cfg": {
                "cert": "/etc/attestation/attestation-agent/as_cert.pem",
                "iss": "oeas"
            },
            "protocal": {
                "Http": {
                    "protocal": "http"
                }
            },
            "enable_active_attestation": true,
            "app_list": [
                {
                    "uuid": "f68fd704-6eb1-4d14-b218-722850eb3ef0",
                    "ima": true,
                    "interval": 30,
                    "platform": "itrustee"
                },
                {
                    "uuid": "0715F5BA-13A2-478B-BD60-B43B645E23DE",
                    "ima": false,
                    "interval": 60
                }
            ]
        }"#;

        let config: AAConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.svr_url, "http://127.0.0.1:8080");
        assert_eq!(config.enable_active_attestation, true);
        assert_eq!(config.app_list.len(), 2);
        assert_eq!(
            config.app_list[0].uuid,
            "f68fd704-6eb1-4d14-b218-722850eb3ef0"
        );
        assert_eq!(config.app_list[0].ima, true);
        assert_eq!(config.app_list[0].interval, 30);
        assert_eq!(config.app_list[0].platform, TeeType::Itrustee);
        assert_eq!(
            config.app_list[1].uuid,
            "0715F5BA-13A2-478B-BD60-B43B645E23DE"
        );
        assert_eq!(config.app_list[1].ima, false);
        assert_eq!(config.app_list[1].interval, 60);
        assert_eq!(config.app_list[1].platform, TeeType::Invalid); // 默认值
    }

    #[tokio::test]
    async fn expired_token_does_not_replace_cache_or_reset_failures() {
        let app = AppConfig::new("ta-1".to_string(), false, 30, TeeType::Itrustee, false);
        let valid_exp = current_time() + 3600;
        let valid_token = fake_jwt("valid", valid_exp);
        app.store_token(valid_token.clone()).await.unwrap();
        app.record_failure();

        let result = app
            .store_token(fake_jwt("expired", current_time().saturating_sub(1)))
            .await;

        assert!(result.is_err());
        assert_eq!(app.get_token().await, Some(valid_token));
        assert_eq!(app.get_token_expires_at().await, Some(valid_exp));
        assert_eq!(app.get_failure_count(), 1);
    }

    #[tokio::test]
    async fn concurrent_reads_observe_one_complete_cached_token() {
        let app = AppConfig::new("ta-1".to_string(), false, 30, TeeType::Itrustee, false);
        let exp_a = current_time() + 3600;
        let exp_b = current_time() + 7200;
        let token_a = fake_jwt("a", exp_a);
        let token_b = fake_jwt("b", exp_b);
        app.store_token(token_a.clone()).await.unwrap();

        let writer_app = app.clone();
        let writer_token_a = token_a.clone();
        let writer_token_b = token_b.clone();
        let writer = tokio::spawn(async move {
            for iteration in 0..500 {
                let token = if iteration % 2 == 0 {
                    writer_token_a.clone()
                } else {
                    writer_token_b.clone()
                };
                writer_app.store_token(token).await.unwrap();
                tokio::task::yield_now().await;
            }
        });

        let reader_app = app.clone();
        let reader = tokio::spawn(async move {
            for _ in 0..1000 {
                let (token, exp, ttl) = reader_app.get_unexpired_token().await.unwrap();
                assert!((token == token_a && exp == exp_a) || (token == token_b && exp == exp_b));
                assert!(ttl > 0);
                tokio::task::yield_now().await;
            }
        });

        writer.await.unwrap();
        reader.await.unwrap();
    }
}
