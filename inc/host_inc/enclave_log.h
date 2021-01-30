/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef SECGEAR_ENCLAVE_LOG_H
#define SECGEAR_ENCLAVE_LOG_H

#include <stdarg.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum
{
    SECGEAR_LOG_LEVEL_ERROR = 0,
    SECGEAR_LOG_LEVEL_WARNING,
    SECGEAR_LOG_LEVEL_NOTICE,
    SECGEAR_LOG_LEVEL_DEBUG
} cc_enclave_level_t;

#ifndef SECGEAR_DEBUG_LEVEL
#define SECGEAR_DEBUG_LEVEL SECGEAR_LOG_LEVEL_ERROR
#endif

__attribute__((visibility("default"))) int print_log(cc_enclave_level_t level, const char * fmt,...);

#define print_log_internal(debug_level,fmt,...)         \
    do {                                                \
        if(debug_level <= SECGEAR_DEBUG_LEVEL)          \
            print_log(debug_level, fmt, ##__VA_ARGS__); \
    } while(0)

#ifdef DEBUG_FILE_LINE
#define print_error_goto(fmt,...)    \
    do {                        \
        print_log_internal(SECGEAR_LOG_LEVEL_ERROR, "ERROR:[%s %s:%d] " fmt, __FUNCTION__, __FILE__, __LINE__, ##__VA_ARGS__); \
        goto done;              \
    } while(0)

#define print_error_term(fmt,...)    \
    do {                        \
        print_log_internal(SECGEAR_LOG_LEVEL_ERROR, "ERROR:[%s %s:%d] " fmt, __FUNCTION__, __FILE__, __LINE__, ##__VA_ARGS__); \
    } while(0)

#define print_warning(fmt,...)  \
    print_log_internal(SECGEAR_LOG_LEVEL_WARNING, "WARNING:[%s %s:%d] " fmt, __FUNCTION__, __FILE__, __LINE__, ##__VA_ARGS__)

#define print_notice(fmt,...)   \
    print_log_internal(SECGEAR_LOG_LEVEL_NOTICE, "NOTICE:[%s %s: %d] " fmt, __FUNCTION__, __FILE__, __LINE__, ##__VA_ARGS__)

#define print_debug(fmt,...)    \
    print_log_internal(SECGEAR_LOG_LEVEL_DEBUG, "DEBUG:[%s %s: %d] " fmt, __FUNCTION__, __FILE__, __LINE__, ##__VA_ARGS__)

#else  //DEBUG_FILE_LINE

#define print_error_goto(fmt,...)    \
    do {                        \
        print_log_internal(SECGEAR_LOG_LEVEL_ERROR, "ERROR:[%s] " fmt, __FUNCTION__,  ##__VA_ARGS__); \
        goto done;              \
    } while(0)

#define print_error_term(fmt,...)    \
    do {                        \
        print_log_internal(SECGEAR_LOG_LEVEL_ERROR, "ERROR:[%s] " fmt, __FUNCTION__, ##__VA_ARGS__); \
    } while(0)

#define print_warning(fmt,...)  \
    print_log_internal(SECGEAR_LOG_LEVEL_WARNING, "WARNING:[%s] " fmt, __FUNCTION__, ##__VA_ARGS__)

#define print_notice(fmt,...)   \
    print_log_internal(SECGEAR_LOG_LEVEL_NOTICE, "NOTICE:[%s] " fmt, __FUNCTION__, ##__VA_ARGS__)

#define print_debug(fmt,...)    \
    print_log_internal(SECGEAR_LOG_LEVEL_DEBUG, "DEBUG:[%s] " fmt, __FUNCTION__, ##__VA_ARGS__)
#endif //DEBUG_FILE_LINE

# ifdef  __cplusplus
}
# endif
#endif //SECGEAR_ENCLAVE_LOG_H
