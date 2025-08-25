use anyhow::{bail, Result};
use ciborium;
use ciborium::Value;
use hex;
use log;
use serde::{ser::SerializeSeq, Serialize, Serializer};

/// cvm token相关标签定义
mod cvm_labels {
    pub const CHALLENGE: i128 = 10;
    pub const RPV: i128 = 44235;
    pub const HASH_ALG: i128 = 44236;
    pub const PUB_KEY: i128 = 44237;
    pub const RIM: i128 = 44238;
    pub const REM: i128 = 44239;
    pub const PUB_KEY_HASH_ALG: i128 = 44240;
}

/// platform token相关标签定义
mod platform_labels {
    pub const PROFILE: i128 = 265;
    pub const CHALLENGE: i128 = 10;
    pub const IMPLEMENTATION: i128 = 2396;
    pub const INSTANCE: i128 = 256;
    pub const CONFIG: i128 = 2401;
    pub const LIFESTYLE: i128 = 2395;
    pub const SW_COMPONENTS: i128 = 2399;
    pub const VERIFICATION_SERVICE: i128 = 2400;
    pub const HASH_ALGO: i128 = 2402;

    /// 软件组件子标签定义
    pub mod sw_component {
        pub const TYPE: i128 = 1;
        pub const MEASUREMENT_VALUE: i128 = 2;
        pub const VERSION: i128 = 4;
        pub const SIGNER_ID: i128 = 5;
        pub const ALGORITHM_ID: i128 = 6;
    }
}

/// cvm 数据大小定义
mod cvm_sizes {
    pub const CHALLENGE: usize = 64;
    pub const RPV: usize = 64;
    pub const REM_ARR: usize = 4;
    pub const PUB_KEY_ECC: usize = 133;
    pub const PUB_KEY_RSA: usize = 550;
}

/// platform 数据大小定义
mod platform_sizes {
    pub const SW_MEASUREMENT: usize = 32;
    pub const CHALLENGE: usize = 32;
    pub const IMPLEMENTATION: usize = 32;
    pub const INSTANCE: usize = 33;
    pub const SW_COUNTS: usize = 6;
}

fn serialize_hex<S>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_string = hex::encode(bytes);
    s.serialize_str(&hex_string)
}

fn serialize_rem<S>(rem: &[Vec<u8>; cvm_sizes::REM_ARR], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(rem.len()))?;
    for (index, vec) in rem.iter().enumerate() {
        let s = format!("rem{}: {}", index, hex::encode(vec));
        seq.serialize_element(&s)?;
    }
    seq.end()
}

#[derive(Debug, Serialize)]
pub struct CvmToken {
    #[serde(serialize_with = "serialize_hex")]
    pub challenge: [u8; cvm_sizes::CHALLENGE], //    10 => bytes .size 64
    #[serde(serialize_with = "serialize_hex")]
    pub rpv: [u8; cvm_sizes::RPV], // 44235 => bytes .size 64
    #[serde(serialize_with = "serialize_hex")]
    pub rim: Vec<u8>, // 44238 => bytes .size {32,48,64}
    #[serde(serialize_with = "serialize_rem")]
    pub rem: [Vec<u8>; cvm_sizes::REM_ARR], // 44239 => [ 4*4 bytes .size {32,48,64} ]
    pub hash_alg: String, // 44236 => text
    #[serde(serialize_with = "serialize_hex")]
    pub pub_key: Vec<u8>, // 44237 => bytes .size {133，550}
    pub pub_key_hash_alg: String, // 44240 => text
}

#[derive(Debug, Serialize, Clone)]
pub struct SwComp {
    pub firware_name: String,
    #[serde(serialize_with = "serialize_hex")]
    pub measurement: [u8; platform_sizes::SW_MEASUREMENT],
    pub firware_version: String,
    #[serde(skip_serializing)]
    pub signer: Vec<u8>,
    #[serde(skip_serializing)]
    pub hash_algorithm: String,
}

#[derive(Debug, Serialize)]
pub struct PlatformToken {
    pub profile: String,
    #[serde(serialize_with = "serialize_hex")]
    pub challenge: [u8; platform_sizes::CHALLENGE],
    #[serde(serialize_with = "serialize_hex")]
    pub implementation: [u8; platform_sizes::IMPLEMENTATION],
    #[serde(serialize_with = "serialize_hex")]
    pub instance: [u8; platform_sizes::INSTANCE],
    #[serde(serialize_with = "serialize_hex")]
    pub config: Vec<u8>,
    pub lifecycle: i128,
    pub sw_components: Vec<SwComp>,
    pub sw_comp_cnts: i128,
    pub verification_service: String,
    pub hash_algo: String,
}

impl Default for CvmToken {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SwComp {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for PlatformToken {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Default)]
pub struct Decode {}

impl Decode {
    pub fn get_vec(v: &Value, param: &str, size: Vec<usize>) -> Result<Vec<u8>, anyhow::Error> {
        let tmp = v
            .as_bytes()
            .ok_or_else(|| anyhow::anyhow!("{} is none", param))?
            .clone();
        if size.is_empty() {
            return Ok(tmp);
        }
        if !size.contains(&tmp.len()) {
            bail!("{} expecting {:?} bytes, got {}", param, size, tmp.len());
        }

        Ok(tmp)
    }

    pub fn get_string(v: &Value, param: &str) -> Result<String, anyhow::Error> {
        let tmp = v
            .as_text()
            .ok_or_else(|| anyhow::anyhow!(" {} must be str", param))?
            .trim_end_matches('\u{0}')
            .to_string();
        log::debug!("get_string: {}", tmp);
        Ok(tmp)
    }

    pub fn get_num(v: &Value, param: &str) -> Result<i128, anyhow::Error> {
        let tmp = v
            .as_integer()
            .ok_or_else(|| anyhow::anyhow!(" {} must be num", param))?
            .into();
        Ok(tmp)
    }

    fn get_array(v: &Value, param: &str, array_size: usize) -> Result<Vec<Value>, anyhow::Error> {
        let tmp = v
            .as_array()
            .ok_or_else(|| anyhow::anyhow!(" {} must be array", param))?
            .clone();
        if tmp.len() != array_size {
            bail!("{} expecting size {}, got {}", param, array_size, tmp.len());
        }
        Ok(tmp)
    }
}

impl CvmToken {
    pub fn new() -> Self {
        Self {
            challenge: [0; cvm_sizes::CHALLENGE],
            rpv: [0; cvm_sizes::RPV],
            rim: Vec::new(),
            rem: Default::default(),
            hash_alg: String::from(""),
            pub_key: Vec::new(),
            pub_key_hash_alg: String::from(""),
        }
    }
    pub fn decode(raw_payload: &Vec<u8>) -> Result<CvmToken> {
        let payload: Vec<u8> = ciborium::de::from_reader(raw_payload.as_slice())?;
        log::debug!("After decode CBOR payload, payload {:?}", payload);
        let payload: Value = ciborium::de::from_reader(payload.as_slice())?;
        log::debug!("After decode CBOR payload agin, payload {:?}", payload);
        let mut cvm_token: CvmToken = CvmToken::new();
        if let Value::Map(contents) = payload {
            for (k, v) in contents.iter() {
                if let Value::Integer(i) = k {
                    match (*i).into() {
                        cvm_labels::CHALLENGE => cvm_token.set_challenge(v)?,
                        cvm_labels::RPV => cvm_token.set_rpv(v)?,
                        cvm_labels::RIM => cvm_token.set_rim(v)?,
                        cvm_labels::REM => cvm_token.set_rem(v)?,
                        cvm_labels::HASH_ALG => cvm_token.set_hash_alg(v)?,
                        cvm_labels::PUB_KEY => cvm_token.set_pub_key(v)?,
                        cvm_labels::PUB_KEY_HASH_ALG => cvm_token.set_pub_key_hash_alg(v)?,
                        err => bail!("cvm payload unknown label {}", err),
                    }
                } else {
                    bail!("cvm payload expecting integer key");
                }
            }
        } else {
            bail!("expecting cvm payload map type");
        }
        log::debug!("cvm_token decode from raw payload, {:?}", cvm_token);
        Ok(cvm_token)
    }
    fn set_challenge(&mut self, v: &Value) -> Result<()> {
        let tmp = Decode::get_vec(v, "cvm challenge", vec![cvm_sizes::CHALLENGE])?;
        self.challenge[..].clone_from_slice(&tmp);
        Ok(())
    }
    fn set_rpv(&mut self, v: &Value) -> Result<()> {
        let tmp = Decode::get_vec(v, "cvm rpv", vec![cvm_sizes::RPV])?;
        self.rpv[..].clone_from_slice(&tmp);
        Ok(())
    }

    fn set_rim(&mut self, v: &Value) -> Result<()> {
        self.rim = Decode::get_vec(v, "cvm rim", vec![32, 48, 64])?;
        Ok(())
    }
    fn set_rem(&mut self, v: &Value) -> Result<()> {
        let tmp = Decode::get_array(v, "cvm rem", cvm_sizes::REM_ARR)?;
        for (i, val) in tmp.iter().enumerate() {
            self.rem[i] = Decode::get_vec(val, "cvm rem[{i}]", vec![32, 48, 64])?;
        }
        Ok(())
    }
    fn set_hash_alg(&mut self, v: &Value) -> Result<()> {
        self.hash_alg = Decode::get_string(v, "cvm hash alg")?;
        Ok(())
    }
    fn set_pub_key(&mut self, v: &Value) -> Result<()> {
        self.pub_key = Decode::get_vec(
            v,
            "cvm pub key",
            vec![cvm_sizes::PUB_KEY_ECC, cvm_sizes::PUB_KEY_RSA],
        )?;
        Ok(())
    }
    fn set_pub_key_hash_alg(&mut self, v: &Value) -> Result<()> {
        self.pub_key_hash_alg = Decode::get_string(v, "cvm pub key hash alg")?;
        Ok(())
    }
}

impl SwComp {
    pub fn new() -> Self {
        Self {
            firware_name: String::from(""),
            measurement: [0; platform_sizes::SW_MEASUREMENT],
            firware_version: String::from(""),
            signer: Vec::new(),
            hash_algorithm: String::from(""),
        }
    }

    pub fn decode(v: &Value) -> Result<SwComp> {
        let mut sw_comp: SwComp = SwComp::new();
        if let Value::Map(contents) = v {
            for (k, v) in contents.iter() {
                if let Value::Integer(i) = k {
                    match (*i).into() {
                        platform_labels::sw_component::TYPE => sw_comp.set_type(v)?,
                        platform_labels::sw_component::VERSION => sw_comp.set_version(v)?,
                        platform_labels::sw_component::MEASUREMENT_VALUE => {
                            sw_comp.set_measurement(v)?
                        }
                        platform_labels::sw_component::SIGNER_ID => sw_comp.set_signer(v)?,
                        platform_labels::sw_component::ALGORITHM_ID => sw_comp.set_algo(v)?,
                        err => bail!("sw_comp payload unknown label {}", err),
                    }
                } else {
                    bail!("Un-supported label type");
                }
            }
        } else {
            bail!("expecting sw_comp payload map type");
        }
        log::debug!("sw_comp decode from raw payload, {:?}", sw_comp);
        Ok(sw_comp)
    }

    fn set_measurement(&mut self, v: &Value) -> Result<()> {
        let tmp = Decode::get_vec(v, "measurement", vec![platform_sizes::SW_MEASUREMENT])?;
        self.measurement[..].clone_from_slice(&tmp);
        Ok(())
    }

    fn set_signer(&mut self, v: &Value) -> Result<()> {
        let tmp = Decode::get_vec(v, "signer", vec![])?;
        self.signer[..].clone_from_slice(&tmp);
        Ok(())
    }

    fn set_type(&mut self, v: &Value) -> Result<()> {
        self.firware_name = Decode::get_string(v, "component_type")?;
        Ok(())
    }

    fn set_version(&mut self, v: &Value) -> Result<()> {
        self.firware_version = Decode::get_string(v, "version")?;
        Ok(())
    }

    fn set_algo(&mut self, v: &Value) -> Result<()> {
        self.hash_algorithm = Decode::get_string(v, "hash_algo")?;
        Ok(())
    }
}

impl PlatformToken {
    pub fn new() -> Self {
        Self {
            profile: String::from(""),
            challenge: [0; platform_sizes::CHALLENGE],
            implementation: [0; platform_sizes::IMPLEMENTATION],
            instance: [0; platform_sizes::INSTANCE],
            config: Vec::new(),
            lifecycle: 0,
            sw_components: Vec::new(),
            sw_comp_cnts: 0,
            verification_service: String::from(""),
            hash_algo: String::from(""),
        }
    }
    pub fn decode(raw_payload: &Vec<u8>) -> Result<PlatformToken> {
        let payload: Value = ciborium::de::from_reader(raw_payload.as_slice())?;
        log::debug!("After decode CBOR payload agin, payload {:?}", payload);
        let mut platform_token: PlatformToken = PlatformToken::new();
        if let Value::Map(contents) = payload {
            for (k, v) in contents.iter() {
                if let Value::Integer(i) = k {
                    match (*i).into() {
                        platform_labels::PROFILE => platform_token.set_profile(v)?,
                        platform_labels::CHALLENGE => platform_token.set_challenge(v)?,
                        platform_labels::IMPLEMENTATION => platform_token.set_implementation(v)?,
                        platform_labels::INSTANCE => platform_token.set_instance(v)?,
                        platform_labels::CONFIG => platform_token.set_config(v)?,
                        platform_labels::LIFESTYLE => platform_token.set_lifecycle(v)?,
                        platform_labels::SW_COMPONENTS => platform_token.set_sw_components(v)?,
                        platform_labels::VERIFICATION_SERVICE => {
                            platform_token.set_verification_service(v)?
                        }
                        platform_labels::HASH_ALGO => platform_token.set_hash_algo(v)?,
                        err => bail!("platform_token payload unknown label {}", err),
                    }
                } else {
                    bail!("platform_token payload expecting integer key");
                }
            }
        } else {
            bail!("expecting platform_token payload map type");
        }
        log::debug!(
            "platform_token decode from raw payload, {:?}",
            platform_token
        );
        Ok(platform_token)
    }

    fn set_config(&mut self, v: &Value) -> Result<()> {
        let tmp = Decode::get_vec(v, "config", vec![])?;
        self.config[..].clone_from_slice(&tmp);
        Ok(())
    }
    fn set_challenge(&mut self, v: &Value) -> Result<()> {
        let tmp = Decode::get_vec(v, "challenge", vec![platform_sizes::CHALLENGE])?;
        self.challenge[..].clone_from_slice(&tmp);
        Ok(())
    }

    fn set_implementation(&mut self, v: &Value) -> Result<()> {
        let tmp = Decode::get_vec(v, "implementation id", vec![platform_sizes::IMPLEMENTATION])?;
        self.implementation[..].clone_from_slice(&tmp);
        Ok(())
    }

    fn set_instance(&mut self, v: &Value) -> Result<()> {
        let tmp = Decode::get_vec(v, "instance id", vec![platform_sizes::INSTANCE])?;
        self.instance[..].clone_from_slice(&tmp);
        Ok(())
    }

    fn set_lifecycle(&mut self, v: &Value) -> Result<()> {
        self.lifecycle = Decode::get_num(v, "lifecycle")?;
        Ok(())
    }

    fn set_verification_service(&mut self, v: &Value) -> Result<()> {
        self.verification_service = Decode::get_string(v, "verification_service")?;
        Ok(())
    }

    fn set_hash_algo(&mut self, v: &Value) -> Result<()> {
        self.hash_algo = Decode::get_string(v, "cvm token")?;
        Ok(())
    }

    fn set_profile(&mut self, v: &Value) -> Result<()> {
        self.profile = Decode::get_string(v, "profile")?;
        Ok(())
    }

    fn set_sw_components(&mut self, v: &Value) -> Result<()> {
        let tmp = Decode::get_array(v, "sw_components", platform_sizes::SW_COUNTS)?;
        for value in tmp {
            let sw_comp = SwComp::decode(&value)?;
            self.sw_components.push(sw_comp);
        }
        Ok(())
    }
}
