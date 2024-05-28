use agent::*;
pub mod agent;

// c interface
use safer_ffi::prelude::*;
use futures::executor::block_on;
use attester::EvidenceRequest;

#[ffi_export]
pub fn get_reprot(c_uuid: &repr_c::String, c_challenge: &repr_c::Vec<u8>) -> repr_c::Vec<u8> {
    let input = EvidenceRequest {
        uuid: c_uuid.clone().to_string(),
        challenge: c_challenge.clone().to_vec(),
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
pub fn verify_report(c_challenge: &repr_c::Vec<u8>, report: &repr_c::Vec<u8>) -> safer_ffi::libc::c_int {
    let fut = async {agent::AttestationAgent::default().verify_evidence(
            &c_challenge.clone().to_vec(), &report.clone().to_vec()).await};
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