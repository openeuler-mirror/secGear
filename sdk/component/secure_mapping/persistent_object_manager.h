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

#include "tee_mem_mgmt_api.h"
#include "tee_trusted_storage_api.h"
#include "tee_defines.h"

uint32_t open_po(char *path, TEE_ObjectHandle *handle);
uint32_t open_and_create_po(char *path, TEE_ObjectHandle *handle);
uint32_t read_po(char *path, uint8_t *addr, size_t size);
uint32_t write_po(char *path, uint8_t *addr, size_t size);