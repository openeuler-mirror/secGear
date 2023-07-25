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
//#include "qtsm_lib.h"

int _cc_generate_random(void *buffer, size_t size)
{
    /* TODO use qingtian's instead */
//     int fd = 0;
//     int ret = 0;
//     fd = qtsm_lib_init();
//     if (fd < 0) {
//         ret = 1;
//         goto end;
//     }
//     if (qtsm_get_random(fd, buffer, size) != 0) {
//         ret = 1;
//     }
//     qtsm_lib_exit(fd);
// end:
//     return ret;
    return CC_ERROR_NOT_SUPPORTED;
}
