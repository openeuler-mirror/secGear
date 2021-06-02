/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <sys/utsname.h>

#include "status.h"
#include "enclave_internal.h"
#include "enclave_log.h"

/* list：maintain enclave information */
CC_API_SPEC list_ops_management  g_list_ops = {
    .count = 0,
    .pthread_flag = false,
    .mutex_work = PTHREAD_MUTEX_INITIALIZER,
    .list_head = NULL,
    .enclaveState = {
        .enclave_count = 0,
        }
};

static err2str g_secgearerror [] =
{
    {CC_SUCCESS,                          "Operation successful."},
    {CC_ERROR_INVALID_CMD,                "Invalid command."},
    {CC_ERROR_SERVICE_NOT_EXIST,          "Service not exist."},
    {CC_ERROR_ENCLAVE_LOST,               "Enclave not exist."},
    {CC_ERROR_ENCLAVE_MAXIMUM,            "The number of connections or enclave reaches the maximum."},
    {CC_ERROR_REGISTER_EXIST_SERVICE,     "Registering an Existing Service."},
    {CC_ERROR_TARGET_DEAD_FATAL,          "The target is crashed."},
    {CC_ERROR_READ_DATA,                  "Read file error."},
    {CC_ERROR_WRITE_DATA,                 "Write file error."},
    {CC_ERROR_TRUNCATE_OBJECT,            "File truncation error."},
    {CC_ERROR_SEEK_DATA,                  "Failed to find the file."},
    {CC_ERROR_SYNC_DATA,                  "File synchronization error."},
    {CC_ERROR_RENAME_OBJECT,              "An error occurred when renaming the file."},
    {CC_ERROR_INVALID_ENCLAVE, 	          "Invalid enclave."},
    {CC_ERROR_INVALID_PATH,               "Invalid path."},
    {CC_ERROR_INVALID_TYPE,               "Trust framwork sdk is not recognized."},
    {CC_ERROR_OUT_OF_TCS,                 "Out of TCS."},
    {CC_ERROR_ECALL_NOT_ALLOWED,          "Ecall function is not available."},
    {CC_ERROR_OCALL_NOT_ALLOWED,          "Ocall function is not available."},
    {CC_ERROR_INVALID_ENCLAVE_ID,         "Invalid enclave ID."},
    {CC_ERROR_NDEBUG_ENCLAVE,             "Cc_enclave is not in debug mode."},
    {CC_ERROR_OUT_OF_EPC,                 "Not enough EPC is available to load the enclave."},
    {CC_ERROR_NO_DEVICE,                  "Can't find enclave device."},
    {CC_ERROR_MEMORY_MAP_FAIL,            "Page mapping failed in driver."},
    {CC_ERROR_INVALID_METADATA,           "The metadata is incorrect."},
    {CC_ERROR_INVALID_VERSION,            "Metadata version is inconsistent."},
    {CC_ERROR_INVALID_MISC,               "The MiscSelct/MiscMask settings are not correct."},
    {CC_ERROR_INVALID_ATTRIBUTE,          "The enclave is not authorized."},
    {CC_ERROR_INVALID_CPUSVN,             "The cpu svn is beyond platform's cpu svn value."},
    {CC_ERROR_INVALID_ISVSVN,             "The isv svn is greater than the enclave's isv svn."},
    {CC_ERROR_INVALID_KEYNAME,            "The key name is an unsupported value."},
    {CC_ERROR_AE_INVALID_EPIDBLOB,        "Indicates epid blob verification error."},
    {CC_ERROR_SERVICE_INVALID_PRIVILEGE,  "Enclave not authorized to run."},
    {CC_ERROR_EPID_MEMBER_REVOKED,        "The EPID group membership is revoked."},
    {CC_ERROR_UPDATE_NEEDED,              "SDK need to be update."},
    {CC_ERROR_MC_NOT_FOUND,               "The Monotonic Counter doesn't exist or has been invalided."},
    {CC_ERROR_MC_NO_ACCESS_RIGHT,         "Caller doesn't have the access right to specified VMC."},
    {CC_ERROR_MC_USED_UP,                 "Monotonic counters are used out."},
    {CC_ERROR_MC_OVER_QUOTA,              "Monotonic counters exceeds quota limitation."},
    {CC_ERROR_KDF_MISMATCH,               "Key derivation function doesn't match during key exchange."},
    {CC_ERROR_UNRECOGNIZED_PLATFORM,      "EPID Provisioning failed due to platform not recognized by backend."},
    {CC_ERROR_UNSUPPORTED_CONFIG,         "The config is invalid."},
    {CC_ERROR_PCL_ENCRYPTED,              "Trying to encrypt an already encrypted enclave."},
    {CC_ERROR_PCL_NOT_ENCRYPTED,          "PCL enclave is not encrepted."},
    {CC_ERROR_PCL_MAC_MISMATCH,           "Section mac result does not match build time mac."},
    {CC_ERROR_PCL_SHA_MISMATCH,           "Unsealed key MAC does not match MAC of key hardcoded in enclave binary."},
    {CC_ERROR_PCL_GUID_MISMATCH,          "GUID in sealed blob does not match GUID hardcoded in enclave binary."},
    {CC_ERROR_UNSUPPORTED_ATT_KEY_ID,            "Platform quoting infrastructure does not support the key."},
    {CC_ERROR_ATT_KEY_CERTIFICATION_FAILURE,     "Failed to generate and certify the attestation key."},
    {CC_ERROR_ATT_KEY_UNINITIALIZED,             "Attestation key is not initialized."},
    {CC_ERROR_INVALID_ATT_KEY_CERT_DATA,         "Attestation data is not valid."},
    {CC_ERROR_PLATFORM_CERT_UNAVAILABLE,         "Cert is not available."},
    {CC_ERROR_OTRP_BASE,                         "OTRP base error num."},
    {CC_ERROR_STORAGE_EIO,                       "Secure storage I/O error."},
    {CC_ERROR_STORAGE_EAGAIN,                    "Secure storage partition is unavailable, try again."},
    {CC_ERROR_STORAGE_ENOTDIR,                   "Operation object is not a directory."},
    {CC_ERROR_STORAGE_EISDIR,                    "Operation object is a directory."},
    {CC_ERROR_STORAGE_ENFILE,                    "The number of open files reaches the maximum of system."},
    {CC_ERROR_STORAGE_EMFILE,                    "The number of open files reaches the maximum of process."},
    {CC_ERROR_STORAGE_EROFS,                     "Secure storage partition is read-only."},
    {CC_ERROR_STORAGE_INSE_NOTSUPPORT,           "SFS inse not supported."},
    {CC_ERROR_STORAGE_INSE_ERROR,                "SFS inse encrypto/decrypto error."},
    {CC_ERROR_STORAGE_NOT_FOUND,                 "Secure storage file not found."},
    {CC_ERROR_MSG_QUEUE_OVERFLOW,                "Sevice msg queue overflow."},
    {CC_ERROR_STORAGE_NO_KEY_ID,                 "Storage key id not found."},
    {CC_ERROR_FILE_FLUSH_FAILED,                 "Storage file flush fail."},
    {CC_ERROR_FILE_CLOSE_FAILED,                 "Storage file close fail."},
    {CC_ERROR_CORRUPT_OBJECT,                    "Object is damaged."},
    {CC_ERROR_STORAGE_NOT_AVAILABLE,             "Secure storage partition is unavailable."},
    {CC_ERROR_CIPHERTEXT_INVALID,                "ciphertext is incorrect."},
    {CC_ISOCKET_ERROR_PROTOCOL,                  "Isocket error protocol."},
    {CC_ISOCKET_ERROR_REMOTE_CLOSED,             "Isocket remote closed."},
    {CC_ISOCKET_ERROR_TIMEOUT,                   "Isocket timeout."},
    {CC_ISOCKET_ERROR_OUT_OF_RESOURCES,          "Isocket out of resources,"},
    {CC_ISOCKET_ERROR_LARGE_BUFFER,              "Isocket large buffer,"},
    {CC_ISOCKET_WARNING_PROTOCOL,                "Isocket warning protocal."},
    {CC_ERROR_GENERIC,                           "generic error."},
    {CC_ERROR_ACCESS_DENIED,                     "Permission denied."},
    {CC_ERROR_CANCEL,                            "Operation cancelled."},
    {CC_ERROR_ACCESS_CONFLICT,                   "Concurrent access causes conflicts."},
    {CC_ERROR_EXCESS_DATA,                       "The operation contains too much data."},
    {CC_ERROR_BAD_FORMAT,                        "The format is incorrect."},
    {CC_ERROR_BAD_PARAMETERS,                    "Invalid parameter."},
    {CC_ERROR_BAD_STATE,                         "Bad state."},
    {CC_ERROR_ITEM_NOT_FOUND,                    "The requested item is not found."},
    {CC_ERROR_NOT_IMPLEMENTED,                   "operation is not implemented."},
    {CC_ERROR_NOT_SUPPORTED,                     "feature or type is not support."},
    {CC_ERROR_NO_DATA,                           "There is no data."},
    {CC_ERROR_OUT_OF_MEMORY,                     "Out of memory."},
    {CC_ERROR_BUSY,                              "Busy system."},
    {CC_ERROR_COMMUNICATION,                     "communication failed."},
    {CC_ERROR_SECURITY,                          "Security error detected."},
    {CC_ERROR_SHORT_BUFFER,                      "Buffer is too short."},
    {CC_ERROR_EXTERNAL_CANCEL,                   "Operation is interrupted by external event."},
    {CC_PENDING,                                 "service is pending."},
    {CC_PENDING2,                                "service is pending2."},
    {CC_PENDING3,                                "service is pending3."},
    {CC_ERROR_TIMEOUT,                           "Request timed out."},
    {CC_ERROR_OVERFLOW,                          "Calculation overflow."},
    {CC_ERROR_ENCLAVE_DEAD,                      "Enclave crashed."},
    {CC_ERROR_STORAGE_NO_SPACE,                  "Insufficient space to store files."},
    {CC_ERROR_MAC_INVALID,                       "MAC value verification error."},
    {CC_ERROR_SIGNATURE_INVALID,                 "signature verification error."},
    {CC_CLIENT_INTR,                             "Interrupted by CFC. Broken control flow is detected."},
    {CC_ERROR_TIME_NOT_SET,                      "Time is not set."},
    {CC_ERROR_TIME_NEEDS_RESET,                  "Time needs reset."},
    {CC_FAIL,                                    "Operation fail."},
    {CC_ERROR_TIMER,                             "Errot timer."},
    {CC_ERROR_TIMER_CREATE_FAILED,               "Timer create failed."},
    {CC_ERROR_TIMER_DESTORY_FAILED,              "Timer destroy failed."},
    {CC_ERROR_TIMER_NOT_FOUND,                   "Timer not found."},
    {CC_ERROR_RPMB_BASE,                         "RPMB base error number."},
    {CC_ERROR_TUI_BASE,                          "Tui base error number."},
    {CC_ERROR_SEC_FLASH_NOT_AVAILABLE,           "Sec flash is not available."},
    {CC_ERROR_SESRV_NOT_AVAILABLE,               "Sesrv is not available."},
    {CC_ERROR_BIOSRV_NOT_AVAILABLE,              "Biosrv is not available."},
    {CC_ERROR_ROTSRV_NOT_AVAILABLE,              "Rotsrv is not available."},
    {CC_ERROR_ARTSRV_NOT_AVAILABLE,              "Artsrv is not available."},
    {CC_ERROR_ANTIROOT_RSP_FAIL,                 "Antiroot rsp failed."},
    {CC_ERROR_ANTIROOT_INVOKE_ERROR,             "Antiroot invoke error."},
    {CC_ERROR_AUDIT_FAIL,                        "Audit fail."},
    {CC_ERROR_UNEXPECTED,                        "Unexpected value."},
    {CC_ERROR_INVALID_HANDLE,                    "Invalid sdk or engine handler."},
    {CC_ERROR_NO_FIND_REGFUNC,                   "Can't find register function."},
    {CC_ERROR_NO_FIND_UNREGFUNC,                 "Can't find unregister function."},
    {CC_MAXIMUM_ERROR,                           "Maximum number."},
    {CC_MAXIMUM_ERROR + 1,                       NULL}
};

int print_log(cc_enclave_level_t level, const char *fmt, ...)
{
    va_list args;
    int ret;
    va_start(args, fmt);
    if (level == SECGEAR_LOG_LEVEL_NOTICE) {
        ret = vfprintf(stdout, fmt, args);
    } else {
        ret = vfprintf(stderr, fmt, args);
    }
    va_end(args);
    return ret;
}

const char *cc_enclave_res2_str(cc_enclave_result_t res)
{
    int i;
    for (i=0;g_secgearerror[i].errstr;i++)
    {
         if(res == g_secgearerror[i].errnum)
             return g_secgearerror[i].errstr;
    }
    return "Unknown reason! Can not find this error number in system!";
}

/* return 1 means find */
static int32_t check_handle_opened(enclave_type_version_t type, void **handle)
{
    int32_t res = 0;
    struct list_ops_desc *p = g_list_ops.list_head;
    while (p != NULL) {
        if (p->ops_desc->type_version == type) {
            res = 1;
            *handle = p->ops_desc->handle;
            break;
        }
        p = p->next;
    }
    return res;
}

/* open enclave engine, success return handle */
cc_enclave_result_t find_engine_open(enclave_type_version_t type, void **handle)
{
    cc_enclave_result_t res = CC_ERROR_INVALID_TYPE;
    /* avoid repeated open */
    if (check_handle_opened(type, handle)) {
        res = CC_SUCCESS;
        goto done;
    }

    *handle = NULL;

    switch (type) {
        case SGX_ENCLAVE_TYPE_0:
#ifdef CC_SIM
            *handle = dlopen("/lib64/libsgxsim_0.so", RTLD_LAZY);
#else
            *handle = dlopen("/lib64/libsgx_0.so", RTLD_LAZY);
#endif
            break;
        case GP_ENCLAVE_TYPE_0:
            /*todo: gp supported simulation*/
            *handle = dlopen("/lib64/libgp_0.so", RTLD_LAZY);
            break;
        default:
            print_error_goto("Input type and version are not supported\n");
    }
    if (!*handle) {
        res = CC_ERROR_INVALID_HANDLE;
        print_error_goto("%s\n", dlerror());
    } else {
        res = CC_SUCCESS;
    }
done:
    return res;
}

cc_enclave_result_t find_engine_registered(void *handle, p_tee_registered *p_func, p_tee_unregistered *p_unfun)
{
    cc_enclave_result_t res;
    dlerror();
    if (p_func != NULL) {
        *p_func = dlsym(handle, "cc_tee_registered");
    }
    if (dlerror() != NULL) {
        res = CC_ERROR_NO_FIND_REGFUNC;
        print_error_goto("cc_tee_registered function not found\n");
    }
    if (p_unfun != NULL) {
        *p_unfun = dlsym(handle, "cc_tee_unregistered");
    }
    if (dlerror() != NULL) {
        res = CC_ERROR_NO_FIND_UNREGFUNC;
        print_error_goto("cc_tee_unregistered function not found \n");
    }
    res = CC_SUCCESS;
done:
    return res;
}

static uint32_t check_processor()
{
    struct utsname buffer;
    if (uname(&buffer) != 0) {
        return ENCLAVE_TYPE_MAX;
    }
    const char *arch_name[] = {"x86_64", "aarch64"};
    const enclave_type_t type_name[] = {SGX_ENCLAVE_TYPE, GP_ENCLAVE_TYPE};
    for (size_t i = 0; i < sizeof(arch_name) / sizeof(char*); ++i) {
        if (!strcmp(arch_name[i], buffer.machine)) {
            return type_name[i];
        }
    }
    return ENCLAVE_TYPE_MAX;
}

enclave_type_version_t type_check_gp(uint32_t version)
{
    switch (version) {
        case 0:
            return GP_ENCLAVE_TYPE_0;
        default:
            print_error_term("This enclave version is not support\n");
            return ENCLAVE_TYPE_VERSION_MAX;
    }
}

enclave_type_version_t type_check_sgx(uint32_t version)
{
    switch (version) {
        case 0:
            return SGX_ENCLAVE_TYPE_0;
        default:
            print_error_term("This enclave version is not support\n");
            return ENCLAVE_TYPE_VERSION_MAX;
    }
}

/* Match enclave engine: lib<sgx/gp>_<version>.so */
enclave_type_version_t match_tee_type_version(enclave_type_t type, uint32_t version)
{
    type = (type == AUTO_ENCLAVE_TYPE) ? check_processor() : type;
    switch (type) {
        case SGX_ENCLAVE_TYPE:
            return type_check_sgx(version);
        case GP_ENCLAVE_TYPE:
            return type_check_gp(version);
        default:
            print_error_term("Detection platform type error: only support aarch64 and x86_64\n");
            return ENCLAVE_TYPE_VERSION_MAX;
    }
}

/* find return 1， otherwise 0
 * Lock: prevent it from being intercepted by other insertion
 * operations when searching, not in this function, but in the calling function */
uint32_t look_tee_in_list(enclave_type_version_t type, cc_enclave_t *context)
{
    uint32_t res = 0;
    struct list_ops_desc *p = g_list_ops.list_head;
    while (p != NULL) {
        if (p->ops_desc->type_version == type) {
            res = 1;
            /* this enclave ref +1 */
            ++(p->ops_desc->count);
            /* Assign the found node to the context */
            context->list_ops_node = p;
            break;
        }
        p = p->next;
    }
    return res;
}

/* check and insert node to list */
void add_ops_list(struct list_ops_desc *node)
{
    struct list_ops_desc *temp = NULL;
    /* if it already exists, just add 1 to the reference count */
    if (check_node_exists_add(node)) {
        /* create multiple contexts for an engine. The existing ones in
         * this list can be reused without inserting multiple same nodes.
         * Because the function interface in this node can be reused */
        print_debug("This node has been inserted into the global list \n");
    } else {
        temp = g_list_ops.list_head;
        g_list_ops.list_head = node;
        node->next = temp;
        /* corresponding to this node reference +1 */
        ++node->ops_desc->count;
        /* the number of global list maintenance engines +1 */
        ++g_list_ops.count;
    }
}

static void remove_ops(struct list_ops_desc *fp, const struct list_ops_desc *p)
{
    if (fp == NULL) {
        g_list_ops.list_head = p->next;
    } else {
        fp->next = p->next;
    }
    g_list_ops.count--;
}

void remove_ops_list(const struct list_ops_desc *node)
{
    struct list_ops_desc *fp = NULL;
    struct list_ops_desc *p = g_list_ops.list_head;
    while (p != NULL) {
        if (!strcmp(p->ops_desc->name, node->ops_desc->name) &&
            p->ops_desc->type_version == node->ops_desc->type_version) {
            /* reference count becomes 0 delete this node */
            if (!--(p->ops_desc->count)) {
                /* found the head node */
                remove_ops(fp, p);
            }
            break;
        }
        fp = p;
        p = p->next;
    }
}

/*
 * return 1 means exist;
 * otherwise return 0
 */
uint32_t check_node_exists_add(const struct list_ops_desc *node)
{
    uint32_t res = 0;
    struct list_ops_desc *p = g_list_ops.list_head;
    while (p != NULL) {
        if (!strcmp(p->ops_desc->name, node->ops_desc->name) &&
            p->ops_desc->type_version == node->ops_desc->type_version) {
            res = 1;
            ++p->ops_desc->count;
            break;
        }
        p = p->next;
    }
    return res;
}
