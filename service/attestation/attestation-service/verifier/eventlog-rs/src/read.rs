// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Context, Result};
use byteorder::{LittleEndian, ReadBytesExt};

use std::{
    fs,
    io::{Read, Seek},
    path::Path,
};

pub const CCEL_PATH: &str = "/sys/firmware/acpi/tables/data/CCEL";

/// Path to the ACPI table CCEL description
pub const CCEL_ACPI_DESCRIPTION: &str = "/sys/firmware/acpi/tables/CCEL";

/// Guest memory which is used to read the CCEL
pub const GUEST_MEMORY: &str = "/dev/mem";

/// Signature of CCEL's ACPI Description Header
pub const CCEL_SIGNATURE: &[u8] = b"CCEL";

/// Try to read CCEL from either ACPI data or guest memory
///
/// If read from guest memory, the offset and length will be read from the CCEL ACPI description.
/// defined as
/// ```no-run
/// pub struct EfiAcpiDescriptionHeader {
///     signature: u32,
///     length: u32,
///     revision: u8,
///     checksum: u8,
///     oem_id: [u8; 6],
///     oem_table_id: u64,
///     oem_revision: u32,
///     creator_id: u32,
///     creator_revision: u32,
/// }
///
/// pub struct TdxEventLogACPITable {
///     efi_acpi_description_header: EfiAcpiDescriptionHeader,
///     rsv: u32,
///     laml: u64,
///     lasa: u64,
/// }
/// ```
pub fn read_ccel() -> Result<Vec<u8>> {
    if Path::new(CCEL_PATH).exists() {
        let ccel = fs::read(CCEL_PATH)?;
        return Ok(ccel);
    }

    let efi_acpi_description =
        fs::read(CCEL_ACPI_DESCRIPTION).context("ccel description does not exist")?;
    if efi_acpi_description.len() < 56 {
        bail!("invalid CCEL ACPI description");
    }

    let mut index = 0;

    let signature = (&efi_acpi_description[index..index + 4]).read_u32::<LittleEndian>()?;
    index += 4;

    let length = (&efi_acpi_description[index..index + 4]).read_u32::<LittleEndian>()?;
    index += 32;

    let rsv = (&efi_acpi_description[index..index + 4]).read_u32::<LittleEndian>()?;
    index += 4;

    let laml = (&efi_acpi_description[index..index + 8]).read_u64::<LittleEndian>()?;
    index += 8;

    let lasa = (&efi_acpi_description[index..index + 8]).read_u64::<LittleEndian>()?;

    let ccel_signature = u32::from_le_bytes(CCEL_SIGNATURE.try_into()?);
    if signature != ccel_signature {
        bail!("invalid CCEL ACPI table: wrong CCEL signature");
    }

    if rsv != 0 {
        bail!("invalid CCEL ACPI table: RSV must be 0");
    }

    if length != efi_acpi_description.len() as u32 {
        bail!("invalid CCEL ACPI table: header length not match");
    }

    let mut guest_memory = fs::OpenOptions::new().read(true).open(GUEST_MEMORY)?;
    guest_memory.seek(std::io::SeekFrom::Start(lasa))?;
    let mut ccel = vec![0; laml as usize];
    let read_size = guest_memory.read(&mut ccel)?;
    if read_size == 0 {
        bail!("read CCEL failed");
    }

    Ok(ccel)
}

#[cfg(test)]
mod tests {
    use super::read_ccel;

    #[ignore]
    #[test]
    fn test_read_ccel() {
        let _ccel = read_ccel().unwrap();
    }
}
