use super::super::config::{AppConfig, AAConfig, HttpProtocal, TokenVerifyConfig};
use super::super::TeeType;
use serde_json;

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_http_protocal_default() {
        let protocal = HttpProtocal::default();
        assert_eq!(protocal.get_protocal(), "http");
        assert_eq!(protocal.get_cert_root(), None);
    }

    #[test]
    fn test_token_verify_config_default() {
        let config = TokenVerifyConfig::default();
        assert_eq!(config.cert, "/etc/attestation/attestation-agent/as_cert.pem");
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
        assert_eq!(config.app_list[0].uuid, "f68fd704-6eb1-4d14-b218-722850eb3ef0");
        assert_eq!(config.app_list[0].ima, true);
        assert_eq!(config.app_list[0].interval, 30);
        assert_eq!(config.app_list[0].platform, TeeType::Itrustee);
        assert_eq!(config.app_list[1].uuid, "0715F5BA-13A2-478B-BD60-B43B645E23DE");
        assert_eq!(config.app_list[1].ima, false);
        assert_eq!(config.app_list[1].interval, 60);
        assert_eq!(config.app_list[1].platform, TeeType::Invalid); // 默认值
    }
}
