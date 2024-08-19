use serde::{Serialize, Deserialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct VirtccaEvidence {
    pub evidence: Vec<u8>,
    pub dev_cert: Vec<u8>,
    pub ima_log: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TeeType {
    Itrustee = 1,
    Virtcca,
    Invalid,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub tee: TeeType,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvlResult {
    pub eval_reulst: bool,
    pub policy: Vec<String>,
    pub report: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub iat: usize,
    pub nbf: usize,
    pub exp: usize,
    pub evaluation_reports: EvlResult,
    pub tee: String,
    pub tcb_status: Value,
}