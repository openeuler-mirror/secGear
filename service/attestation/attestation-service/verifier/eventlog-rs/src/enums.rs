use lazy_static::lazy_static;
use std::collections::HashMap;

lazy_static! {
    pub static ref TCG_ALGORITHMS: HashMap<u16, &'static str> = HashMap::from([
        (0x1, "TPM_ALG_RSA"),
        (0x3, "TPM_ALG_TDES"),
        (0x4, "TPM_ALG_SHA1"),
        (0xB, "TPM_ALG_SHA256"),
        (0xC, "TPM_ALG_SHA384"),
        (0xD, "TPM_ALG_SHA512"),
    ]);
}

lazy_static! {
    pub static ref EVENTLOG_TYPES: HashMap<u32, &'static str> = HashMap::from(
        [
            (0x0, "EV_PREBOOT_CERT"),
            (0x1, "EV_POST_CODE"),
            (0x2, "EV_UNUSED"),
            (0x3, "EV_NO_ACTION"),
            (0x4, "EV_SEPARATOR"),
            (0x5, "EV_ACTION"),
            (0x6, "EV_EVENT_TAG"),
            (0x7, "EV_S_CRTM_CONTENTS"),
            (0x8, "EV_S_CRTM_VERSION"),
            (0x9, "EV_CPU_MICROCODE"),
            (0xa, "EV_PLATFORM_CONFIG_FLAGS"),
            (0xb, "EV_TABLE_OF_DEVICES"),
            (0xc, "EV_COMPACT_HASH"),
            (0xd, "EV_IPL"),
            (0xe, "EV_IPL_PARTITION_DATA"),
            (0xf, "EV_NONHOST_CODE"),
            (0x10, "EV_NONHOST_CONFIG"),
            (0x11, "EV_NONHOST_INFO"),
            (0x12, "EV_OMIT_BOOT_DEVICE_EVENTS"),

            // TCG EFI Platform Specification For TPM Family 1.1 or 1.2
            (0x80000000, "EV_EFI_EVENT_BASE"),
            (0x80000001, "EV_EFI_VARIABLE_DRIVER_CONFIG"),
            (0x80000002, "EV_EFI_VARIABLE_BOOT"),
            (0x80000003, "EV_EFI_BOOT_SERVICES_APPLICATION"),
            (0x80000004, "EV_EFI_BOOT_SERVICES_DRIVER"),
            (0x80000005, "EV_EFI_RUNTIME_SERVICES_DRIVER"),
            (0x80000006, "EV_EFI_GPT_EVENT"),
            (0x80000007, "EV_EFI_ACTION"),
            (0x80000008, "EV_EFI_PLATFORM_FIRMWARE_BLOB"),
            (0x80000009, "EV_EFI_HANDOFF_TABLES"),
            (0x8000000a, "EV_EFI_PLATFORM_FIRMWARE_BLOB2"),
            (0x8000000b, "EV_EFI_HANDOFF_TABLES2"),
            (0x800000e0, "EV_EFI_VARIABLE_AUTHORITY"),
        ]
    );
}
