use agent::*;
pub mod agent;

// c interface
use safer_ffi::prelude::*;
use futures::executor::block_on;
use attester::EvidenceRequest;

#[ffi_export]
pub fn get_reprot(c_uuid: Option<&repr_c::String>, c_challenge: Option<&repr_c::Vec<u8>>) -> repr_c::Vec<u8> {
    let uuid = match c_uuid {
        None => {println!("uuid is null"); return Vec::new().into();},
        Some(uuid) => uuid.clone().to_string(),
    };
    let challenge = match c_challenge {
        None => {println!("challenge is null"); return Vec::new().into();},
        Some(cha) => cha.clone().to_vec(),
    };

    let input: EvidenceRequest = EvidenceRequest {
        uuid: uuid,
        challenge: challenge,
    };

    let fut = async {
        agent::AttestationAgent::default().get_evidence(input).await
    };
    let report: Vec<u8> = match block_on(fut) {
        Ok(report) => report,
        Err(e) => {
            println!("get report failed {:?}", e);
            Vec::new()
        },
    };

    report.into()
}

#[ffi_export]
pub fn verify_report(c_challenge: Option<&repr_c::Vec<u8>>, report: Option<&repr_c::Vec<u8>>) -> safer_ffi::libc::c_int {
    let challenge = match c_challenge {
        None => {println!("challenge is null"); return 1;},
        Some(cha) => cha.clone().to_vec(),
    };

    let report = match report {
        None => {println!("report is null"); return 1;},
        Some(report) => report.clone().to_vec(),
    };

    let fut = async {agent::AttestationAgent::default().verify_evidence(
            &challenge, &report).await};
    let ret = block_on(fut);
    if ret.is_err() {
        println!("verfiy report failed");
        return 1;
    }
    return 0;
}

#[ffi_export]
pub fn free_report(report: repr_c::Vec<u8>) {
    drop(report);
}

// The following function is only necessary for the header generation.
#[cfg(feature = "headers")]
pub fn generate_headers() -> ::std::io::Result<()> {
    ::safer_ffi::headers::builder()
        .to_file("rust_attestation_agent.h")?
        .generate()
}