/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * CloudEnclave is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <string.h>

#include "persistent_object_manager.h"
#include "secgear_log.h"

uint32_t open_po(char *path, TEE_ObjectHandle *handle)
{
    uint32_t r_flags = (TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ);
    PrintInfo(PRINT_STRACE, "Secure Mapping: Open path: %s", path);
    TEE_Result ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, path, strlen(path), r_flags, handle);
    if (ret != TEE_SUCCESS) {
        PrintInfo(PRINT_STRACE, "Secure Mapping: File %s not exist", path);
        return ret;
    }
    return ret;
}

uint32_t open_and_create_po(char *path, TEE_ObjectHandle *handle)
{
    uint32_t w_flags = TEE_DATA_FLAG_ACCESS_WRITE;
    PrintInfo(PRINT_STRACE, "Secure Mapping: Open path: %s", path);
    TEE_Result ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, path, strlen(path), w_flags, handle);
    if (ret != TEE_SUCCESS) {
        PrintInfo(PRINT_STRACE, "Secure Mapping: File %s not exist, create", path);
        ret = TEE_CreatePersistentObject(TEE_OBJECT_STORAGE_PRIVATE,
                                         path, strlen(path), w_flags,
                                         TEE_HANDLE_NULL, NULL, 0, handle);
        if (ret != TEE_SUCCESS) {
            PrintInfo(PRINT_ERROR, "Secure Mapping: Create PO failed! errcode = 0x%x", ret);
            return ret;
        }
        return ret;
    }
    return ret;
}

uint32_t read_po(char *path, uint8_t *addr, size_t size)
{
    TEE_ObjectHandle persistent_data = NULL;
    TEE_Result ret = open_po(path, &persistent_data);
    if (ret != 0) {
        return ret;
    }

    uint32_t pos = 0;
    uint32_t len = 0;
    uint32_t count = 0;
    ret = TEE_InfoObjectData(persistent_data, &pos, &len);
    if (ret != TEE_SUCCESS) {
        TEE_CloseObject(persistent_data);
        PrintInfo(PRINT_ERROR, "Secure Mapping: Info PO failed! errcode = 0x%x", ret);
        return ret;
    }

    if (len != size) {
        PrintInfo(PRINT_WARNING, "Secure Mapping: Unmatch file size, expected: %ld, actual: %d", size, len);
    }

    if (len > 0) {
        ret = TEE_ReadObjectData(persistent_data, addr, len, &count);
        if (ret != TEE_SUCCESS || count != len) {
            TEE_CloseObject(persistent_data);
            PrintInfo(PRINT_ERROR, "Secure Mapping: Read PO failed! errcode = 0x%x", ret);
            return ret;
        }
    }

    PrintInfo(PRINT_STRACE, "Secure Mapping: Read data to path %s done", path);
    TEE_CloseObject(persistent_data);
    return ret;
}

uint32_t write_po(char *path, uint8_t *addr, size_t size)
{
    TEE_ObjectHandle persistent_data = NULL;
    TEE_Result ret = open_and_create_po(path, (&persistent_data));
    if (ret != 0) {
        return ret;
    }

    ret = TEE_WriteObjectData(persistent_data, addr, size);
    if (ret != TEE_SUCCESS) {
        PrintInfo(PRINT_ERROR, "Secure Mapping: Write PO failed! errcode = 0x%x", ret);
        TEE_CloseObject(persistent_data);
        return ret;
    }

    PrintInfo(PRINT_STRACE, "Secure Mapping: Write data to path %s done", path);
    TEE_CloseObject(persistent_data);
    return ret;
}
