use anyhow::{Result, bail};
use ima_measurements::{Event, EventData, Parser};
use fallible_iterator::FallibleIterator;
use std::fs;
use std::process::Command;
use serde_json::Value;
use rand::Rng;

use attester::Evidence;
pub use attester::virtcca::VirtccaEvidence;

#[derive(Debug)]
pub struct ImaVerify {
    log_path: String,
}

impl Default for ImaVerify {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        let n: u64 = rng.gen();
        ImaVerify {
            // log_path: format!("/tmp/attestation-service/ima-log-{}", n),  // todo fs::write depends attestation-service dir exist
            log_path: format!("/tmp/ima-log-{}", n),
        }
    }
}

impl ImaVerify {
    // todo return detail verify result list with policy
    pub fn ima_verify(&self, evidence: &[u8], claim: &Value, digest_list_file: String) -> Result<()> {
        let aa_evidence: Evidence = serde_json::from_slice(evidence)?;
        let evidence = aa_evidence.evidence.as_bytes();
        let virtcca_ev: VirtccaEvidence = serde_json::from_slice(evidence)?;
        let ima_log = match virtcca_ev.ima_log {
            Some(ima_log) => ima_log,
            _ => {log::info!("no ima log"); return Ok(())},
        };

        fs::write(&self.log_path, &ima_log).expect("write img log failed");
        let f = fs::File::open(&self.log_path).expect("ima log file not found");

        let claim_ima_log_hash = claim["payload"]["cvm"]["rem"][0].clone();
        let mut parser = Parser::new(f);

        let mut events: Vec<Event> = Vec::new();
        while let Some(event) = parser.next()? {
            events.push(event);
        }

        let pcr_values = parser.pcr_values();
        let pcr_10 = pcr_values.get(&10).expect("PCR 10 not measured");
        let string_pcr_sha256 = hex::encode(pcr_10.sha256);
 
        if Value::String(string_pcr_sha256.clone()) != claim_ima_log_hash {
            log::error!("ima log verify failed string_pcr_sha256 {}, string_claim_ima_log_hash {}", string_pcr_sha256, claim_ima_log_hash);
            bail!("ima log hash verify failed");
        }

        // parser each file digest in ima log, and compare with reference base value
        for event in events {
            let file_digest = match event.data {
                EventData::ImaNg{digest, name} => {drop(name); digest.digest},
                _ => bail!("Inalid event {:?}", event),
            };
            let hex_str_digest = hex::encode(file_digest);
            //log::info!("hex_str_digest {}", hex_str_digest);
            let output = Command::new("grep")
            .arg("-E")
            .arg("-i")
            .arg(&hex_str_digest)
            .arg(&digest_list_file)
            .output()?;
            if output.stdout.is_empty() {
                log::error!("there is no refernce base value of file digest {:?}", hex_str_digest);
            }
        }

        Ok(())
    }
}

