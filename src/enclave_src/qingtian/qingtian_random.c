/*
 * Copyright (c) IPADS@SJTU 2021. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "status.h"
#include "random_internal.h"
#include "qingtian_enclave_init.h"

extern __attribute__((weak)) int qtsm_get_random(int fd, uint8_t *rnd_data, uint32_t rnd_data_len);

int _cc_generate_random(void *buffer, size_t size)
{
    int qtsm_dev_fd = qt_get_qtsm_fd();
    if (qtsm_get_random == NULL) {
        printf("cant't find qtsm_get_random symbol\n");
        return CC_ERROR_NOT_IMPLEMENTED;
    }
    if (qtsm_get_random(qtsm_dev_fd, buffer, size) != 0) {
        return CC_FAIL;
    }

    return CC_SUCCESS;
}
