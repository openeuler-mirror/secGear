use super::super::TeeType;
use serde_json;
use std::str::FromStr;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tee_type_from_str() {
        // 测试字符串到枚举的转换
        assert_eq!(TeeType::from_str("itrustee").unwrap(), TeeType::Itrustee);
        assert_eq!(TeeType::from_str("Itrustee").unwrap(), TeeType::Itrustee);
        assert_eq!(TeeType::from_str("ITRUSTEE").unwrap(), TeeType::Itrustee);
        
        assert_eq!(TeeType::from_str("virtcca").unwrap(), TeeType::Virtcca);
        assert_eq!(TeeType::from_str("VirtCCA").unwrap(), TeeType::Virtcca);
        assert_eq!(TeeType::from_str("VIRTCCA").unwrap(), TeeType::Virtcca);
        // 向下兼容旧标识 vcca
        assert_eq!(TeeType::from_str("vcca").unwrap(), TeeType::Virtcca);
        assert_eq!(TeeType::from_str("vCCA").unwrap(), TeeType::Virtcca);
        
        // 正向使用 cca
        assert_eq!(TeeType::from_str("cca").unwrap(), TeeType::Cca);
        assert_eq!(TeeType::from_str("CCA").unwrap(), TeeType::Cca);
        
        // 向下兼容旧标识 rustcca
        assert_eq!(TeeType::from_str("rustcca").unwrap(), TeeType::Cca);
        assert_eq!(TeeType::from_str("RustCCA").unwrap(), TeeType::Cca);
        assert_eq!(TeeType::from_str("RUSTCCA").unwrap(), TeeType::Cca);
        
        assert_eq!(TeeType::from_str("invalid").unwrap(), TeeType::Invalid);
        assert_eq!(TeeType::from_str("unknown").unwrap(), TeeType::Invalid);
    }

    #[test]
    fn test_tee_type_display() {
        // 测试枚举到字符串的转换
        assert_eq!(TeeType::Itrustee.to_string(), "itrustee");
        assert_eq!(TeeType::Virtcca.to_string(), "virtcca");
        assert_eq!(TeeType::Cca.to_string(), "cca");
        assert_eq!(TeeType::Invalid.to_string(), "invalid");
    }

    #[test]
    fn test_tee_type_serialization() {
        // 测试序列化
        let tee_type = TeeType::Itrustee;
        let json = serde_json::to_string(&tee_type).unwrap();
        assert_eq!(json, "\"itrustee\"");
        
        let tee_type = TeeType::Virtcca;
        let json = serde_json::to_string(&tee_type).unwrap();
        assert_eq!(json, "\"virtcca\"");
        
        let tee_type = TeeType::Cca;
        let json = serde_json::to_string(&tee_type).unwrap();
        assert_eq!(json, "\"cca\"");
    }

    #[test]
    fn test_tee_type_deserialization() {
        // 测试反序列化
        let tee_type: TeeType = serde_json::from_str("\"itrustee\"").unwrap();
        assert_eq!(tee_type, TeeType::Itrustee);
        
        let tee_type: TeeType = serde_json::from_str("\"virtcca\"").unwrap();
        assert_eq!(tee_type, TeeType::Virtcca);
        
        let tee_type: TeeType = serde_json::from_str("\"VirtCCA\"").unwrap();
        assert_eq!(tee_type, TeeType::Virtcca);
        
        let tee_type: TeeType = serde_json::from_str("\"cca\"").unwrap();
        assert_eq!(tee_type, TeeType::Cca);

        let tee_type: TeeType = serde_json::from_str("\"rustcca\"").unwrap();
        assert_eq!(tee_type, TeeType::Cca);
    }
}
