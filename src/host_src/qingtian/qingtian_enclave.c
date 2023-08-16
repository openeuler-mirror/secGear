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

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>

#include "enclave.h"
#include "enclave_internal.h"
#include "enclave_log.h"
#include "qt_rpc_proxy.h"
#include "qt_call.h"
#include "host_input.h"
#include "qingtian_enclave.h"

#define PRA_BUF_SIZE        (64)
#define CMD_PRA_BUF_SIZE    (128)
#define CMD_BUF_MAX         (128 + PATH_MAX)

#define CMD_BUF_RESULT_MAX      (1024 * 5)
#define CMD_BUF_RESULT_LINE_MAX (512)

#define CID_MIN             (4)

static const cc_startup_t default_startup = {
    .enclave_cid = CID_MIN,
    .cpus = 2, // at least 2 cpus
    .mem_mb = 0,
    .query_retry = 10 // query id by cid try 10 times by default
};
static int qt_query_id(unsigned int cid, unsigned int *id);
static int qt_stop(uint32_t enclave_id);
/************* port api *************/

// init connect to enclave
static int enclave_init(uint32_t cid, qt_handle_request_msg_t call_back)
{
    return qt_rpc_proxy_init(cid, call_back);
}

static int enclave_deinit(uint32_t cid)
{
    (void)cid;
    qt_rpc_proxy_destroy();
    return 0;
}
/************* port api *************/
// return cmd length
static int get_start_cmdline(char *cmd_buf, size_t cmd_buf_size, const cc_startup_t* pra,
                             const char *path, bool debug_mode)
{
    char *cmd = "qt enclave start";
    char buf[PRA_BUF_SIZE];
    if (cmd_buf == NULL || cmd_buf_size == 0) {
        print_error_term("command buf is NULL\n");
        return -1;
    }
    if (path == NULL) {
        print_error_term("command parameter path is NULL\n");
        return -1;
    }
    if (cmd_buf_size - 1 < strlen(cmd) + strlen(path) + CMD_PRA_BUF_SIZE) {
        return -1;
    }
    (void)sprintf(cmd_buf, "%s --eif %s", cmd, path);
    if (debug_mode) {
        strcat(cmd_buf, " --debug-mode");
    }
    if (pra == NULL) {
        goto end;
    }
    if (pra->cpus != 0) {
        (void)sprintf(buf, " --cpus %lu", (long unsigned int)pra->cpus);
        strcat(cmd_buf, buf);
    }
    if (pra->mem_mb != 0) {
        (void)sprintf(buf, " --mem %lu", (long unsigned int)pra->mem_mb);
        strcat(cmd_buf, buf);
    }
    if (pra->enclave_cid >= CID_MIN) {
        (void)sprintf(buf, " --cid %lu", (long unsigned int)pra->enclave_cid);
        strcat(cmd_buf, buf);
    } else {
        print_error_term("enclave id must not less %d\n", CID_MIN);
        return -1;
    }
end:
    return strlen(cmd_buf);
}

bool contain_illegal_char(const char *str)
{
    const char list[]={'|',';','&','$','>','<','`','\\','!','\n'};
    for (unsigned long int i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (strchr(str, list[i]) != NULL) {
            return true;
        }
    }
    return false;
}

static int check_eif(const char *path)
{
    // check forbidden character
    if (contain_illegal_char(path)) {
        print_error_term("%s contain illegal character\n", path);
        return -1;
    }
    if (access(path, F_OK) != 0) {
        print_error_term("%s can not access\n", path);
        return -1;
    }
    // file extern must be ".eif"
    char *ext = strrchr(path, '.');
    if (ext == NULL || strcmp(ext, ".eif") != 0) {
        print_error_term("%s must be end of .eif\n", path);
        return -1;
    }
    return 0;
}

static int get_eif_realpath(char *resolved_path, const char *path)
{
    int ret = 0;
    if (path == NULL) {
        print_error_term("path is NULL\n");
        ret = -1;
        goto end;
    }
    if (realpath(path, resolved_path) == NULL) {
        print_error_term("%s realpath fail\n", path);
        ret = -1;
        goto end;
    }
    if (check_eif(resolved_path) != 0) {
        print_error_term("check %s fail\n", resolved_path);
        ret = -1;
        goto end;
    }
end:
    return ret;
}

static long get_file_size(char *file)
{
    long fsize = 0;
    if (file == NULL) {
        return 0;
    }
    FILE *fp = fopen(file, "rb");
    if (fp == NULL) {
        print_error_term("%s file open fail\n", file);
        return 0; 
    }
    if (-1 == fseek(fp, 0, SEEK_END)) {
        goto end;
    }
    fsize = ftell(fp);
    if (fsize < 0) {
        fsize = 0;
    }
end:
    if (fclose(fp) != 0) {
        return 0;
    }
    return fsize;
}

static long long cal_mem_size(long fsize)
{
    long long size = fsize;
    size *= 4; // at least 4 times space size of eif for encalve
    size = (size / 1024) / 1024;// convert to MB by div 1024 twice
    if (size % 256) { // if not multiple of 256
        size = (size / 256) * 256 + 256; // alianed to 256
    }
    return size;
}

int auto_set_parameter(cc_startup_t *pra, char *eif_file)
{
    if (pra == NULL || eif_file == NULL) {
        return -1;
    }
    int ret = 0;
    long fsize = get_file_size(eif_file);
    if (fsize <= 0) {
        ret = -1;
        goto end;
    }
    long long mem_size = cal_mem_size(fsize);
    if (mem_size > UINT32_MAX) {
        ret = -1;
        goto end;
    }
    pra->mem_mb = mem_size;
    unsigned int id;
    uint32_t cid = pra->enclave_cid;
    while (qt_query_id(cid, &id) == 0) {
        cid++;
    }
    pra->enclave_cid = cid;
end:
    return ret;
}

// return length of command string
int qt_start_cmd_construct(char *command, cc_startup_t *pra, const char *eif, uint32_t flags, bool auto_cfg)
{
    int ret = 0;
    if (command == NULL || pra == NULL || eif == NULL) {
        return -1;
    }
    char *resolved_path = calloc(1, PATH_MAX);
    if (resolved_path == NULL) {
        ret = -1;
        goto end;
    }
    if (get_eif_realpath(resolved_path, eif) != 0) {
        ret = -1;
        goto end;
    }
    bool debug = false;
    if (flags & SECGEAR_DEBUG_FLAG) {
        debug = true;
    } else {
        debug = false;
    }
    if (auto_cfg) {
        ret = auto_set_parameter(pra, resolved_path);
        if(ret == -1) {
            goto end;
        }
    }
    ret = get_start_cmdline(command, CMD_BUF_MAX, pra, resolved_path, debug);
    if (ret < 0) {
        print_error_term("get start command fail\n");
        ret = -1;
        goto end;
    }
end:
    if (resolved_path != NULL) {
        free(resolved_path);
    }
    return ret;
}

static int get_tag_value(const char *str, const char *tag, unsigned int *value)
{
    char *target = NULL;
    int ret = 0;
    target = strstr(str, tag);
    if (target == NULL) {
        return -1;
    }
    ret = sscanf(target, "%*[^:]:%u", value);
    if (ret != 1) {
        return -1;
    }
    return 0;
}

static int get_id(char *str, unsigned int *cid, unsigned int *id)
{
    if (get_tag_value(str, "EnclaveCID", cid) != 0) {
        return -1;
    }
    if (get_tag_value(str, "EnclaveID", id) != 0) {
        return -1;
    }
    return 0;
}

static int get_match_id(char *str, unsigned int cid, unsigned int *id)
{
    char *cur = NULL;
    char *next = NULL;
    unsigned int tmp_cid;
    unsigned int tmp_id;
    const char *delimeter = "}";
    cur = strtok_r(str, delimeter, &next);
    while (cur != NULL) {
        if (get_id(cur, &tmp_cid, &tmp_id) == 0) {
            if (cid == tmp_cid) {
                *id = tmp_id;
                return 0;
            }
        }
        cur = strtok_r(NULL, delimeter, &next);
    }
    return -1;
}

static int qt_query_id(unsigned int cid, unsigned int *id)
{
    int ret = 0;
    FILE *fp = NULL;
    const char *cmd = "qt enclave query";
    char read_buf[CMD_BUF_RESULT_LINE_MAX];
    char *buf = calloc(1, CMD_BUF_RESULT_MAX);
    if (buf == NULL) {
        ret = -1;
        goto end;
    }
    fp = popen(cmd, "r");
    if (fp == NULL) {
        ret = -1;
        goto end;
    }
    while (fgets(read_buf, CMD_BUF_RESULT_LINE_MAX, fp) != NULL) {
        if (strlen(buf) + strlen(read_buf) < CMD_BUF_RESULT_MAX) {
            strcat(buf, read_buf);
        } else {
            break;
        }
    }
    print_debug("qt query: %s \n", buf);
    if (get_match_id(buf, cid, id) != 0) {
        print_debug("cid = %u, get id fail\n", cid);
        ret = -1;
        goto end;
    }
    print_debug("cid = %u, get id = %u\n", cid, *id);
end:
    if (fp != NULL) {
        if (pclose(fp) == -1) {
            print_error_term("pclose fail when query id\n");
        }
    }
    if (buf != NULL) {
        free(buf);
    }
    return ret;
}

static int qt_start(char *command, unsigned int cid, uint32_t *id, int retry)
{
    FILE *fp = NULL;
    int ret = 0;
    int left = retry;
    char buf[CMD_BUF_RESULT_LINE_MAX] = {0};
    if (command == NULL || id == NULL) {
        ret = -1;
        goto end;
    }
    if (qt_query_id(cid, id) == 0) {
        print_error_term("cid %u id %u already exist\n", cid, *id);
        ret = 1;
        goto end;
    }
    fp = popen(command, "r");
    if (fp == NULL) {
        print_error_term("command execute failed\n");
        ret = -1;
        goto end;
    } else {
        // get messages only when fail
        while(fgets(buf, CMD_BUF_RESULT_LINE_MAX, fp) != NULL) {
            if (strstr(buf, "error") != NULL) {
                ret = -1;
                goto end;
            }
            sleep(1);
        }
        print_debug("get enclave id, total retry %d\n", left);
        while (--left >= 0) {
            print_debug("try %d\n", (left + 1));
            if (qt_query_id(cid, id) != 0) {
                sleep(1);
                continue;
            } else {
                break;
            }
        }
        if (left < 0) {
            ret = -1;
            print_error_term("query id fail\n");
        } else {
            ret = 0;
            print_debug("qingtian enclave id  %u\n", *id);
        }
    }
end:
    if (fp != NULL) {
        if (pclose(fp) == -1) {
            print_error_term("pclose fail while qt start\n");
        }
        fp = NULL;
    }
    return ret;
}

cc_enclave_result_t _qingtian_create(cc_enclave_t *enclave, const enclave_features_t *features,
                                     const uint32_t features_count)
{
    cc_enclave_result_t result_cc = CC_SUCCESS;
    bool auto_cfg = false;
    bool qt_clean = false;
    char *command = NULL;
    cc_startup_t auto_pra = default_startup;
    if (enclave == NULL || (features == NULL && features_count != 0) || (features != NULL && features_count == 0)) {
        print_error_term("Context parameter is NULL\n");
        return CC_ERROR_BAD_PARAMETERS;
    }
    cc_startup_t *startup_pra = NULL;
    for (uint32_t index = 0; index < features_count; index++) {
        if (features[index].setting_type & QINGTIAN_STARTUP_FEATURES) {
            startup_pra = features[index].feature_desc;
            break;
        }
    }
    if (startup_pra == NULL) {
        print_error_term("enclave startup parameter is NULL, use default\n");
        startup_pra = &auto_pra;
        auto_cfg = true;
    }
    command = calloc(1, CMD_BUF_MAX);
    if (command == NULL) {
        print_error_term("malloc for start command is NULL\n");
        result_cc = CC_ERROR_OUT_OF_MEMORY;
        goto end;
    }
    if (qt_start_cmd_construct(command, startup_pra, enclave->path, enclave->flags, auto_cfg) <= 0) {
        print_error_term("construct qt start command fail\n");
        result_cc = CC_ERROR_BAD_PARAMETERS;
        goto end;
    }
    uint32_t id = 0;
    int ret = qt_start(command, (unsigned int)startup_pra->enclave_cid, &id, startup_pra->query_retry);
    if (ret < 0 || ret > 1) {
        print_error_term("qingtian enclave create fail! \n");
        result_cc = CC_ERROR_GENERIC;
        goto end;
    } else if (ret == 1) {
        print_error_term("qingtian enclave already exist\n");
        result_cc = CC_ERROR_GENERIC;
        goto end;
    }
    if (enclave_init(startup_pra->enclave_cid, (qt_handle_request_msg_t)handle_ocall_function) != 0) {
        print_error_term("qingtian enclave init fail\n");
        result_cc = CC_ERROR_GENERIC;
        qt_clean = true;
        goto end;
    }
    print_debug("qingtian enclave create successfully! \n");
    qingtian_private_data_t *priv_data = (qingtian_private_data_t *)malloc(sizeof(qingtian_private_data_t));
    if (priv_data == NULL) {
        print_error_term("malloc for private data is NULL\n");
        result_cc = CC_ERROR_OUT_OF_MEMORY;
        qt_clean = true;
        goto end;
    }
    priv_data->enclave_id = id;
    priv_data->startup = *startup_pra;
    enclave->private_data = (void *)priv_data;
    result_cc = CC_SUCCESS;
end:
    if (command != NULL) {
        free(command);
    }
    if (qt_clean) {
        if(qt_stop(id) != 0) {
            print_error_term("qt stop fail\n");
        }
    }
    return result_cc;
}

static int qt_stop(uint32_t enclave_id)
{
    int ret = 0;
    FILE *fp = NULL;
    char *target = NULL;
    char *cmd_result = NULL;
    char *command = calloc(1, CMD_BUF_MAX);
    if (command == NULL) {
        ret = -1;
        goto end;
    }
    ret = sprintf(command, "qt enclave stop --enclave-id %lu", (long unsigned int)enclave_id);
    if (ret <= 0) {
        print_error_term("host: construct command fail\n");
        ret = -1;
        goto end;
    }
    cmd_result = calloc(1, CMD_BUF_MAX);
    if (cmd_result == NULL) {
        ret = -1;
        goto end;
    }
    fp = popen(command, "r");
    if (fp == NULL) {
        print_error_term("popen failed\n");
        ret = -1;
        goto end;
    }
    ret = -1;
    while (fgets(cmd_result, CMD_BUF_MAX, fp) != NULL) {
        target = strstr(cmd_result, "success");
        if (target == NULL) {
            continue;
        }
        ret = 0;
        break;
    }
end:
    if (fp != NULL) {
        if (pclose(fp) == -1) {
            print_error_term("pclose fail while qt stop\n");
        }
    }
    if (command != NULL) {
        free(command);
    }
    if (cmd_result != NULL) {
        free(cmd_result);
    }
    return ret;
}

cc_enclave_result_t _qingtian_destroy(cc_enclave_t *context)
{
    cc_enclave_result_t result_cc;
    if (context == NULL) {
        print_error_term("qinttian destroy parameter error\n");
        result_cc = CC_ERROR_BAD_PARAMETERS;
        goto end;
    }
    qingtian_private_data_t *priv_data = context->private_data;
    if (priv_data == NULL) {
        result_cc = CC_ERROR_BAD_PARAMETERS;
        goto end;
    }
    enclave_deinit(priv_data->startup.enclave_cid);
    if (qt_stop(priv_data->enclave_id) != 0) {
        result_cc = CC_ERROR_GENERIC;
        goto end;
    }
    if (priv_data != NULL) {
        free(priv_data);
        context->private_data = NULL;
    }
    print_debug("qingtian destroy success\n");
    result_cc = CC_SUCCESS;
end:
    return result_cc;
}

cc_enclave_result_t cc_enclave_ecall_function(
    cc_enclave_t *enclave,
    uint32_t function_id,
    const void *input_buffer,
    size_t input_buffer_size,
    void *output_buffer,
    size_t output_buffer_size,
    void *ms,
    const void *ocall_table)
{
    (void)enclave;
    (void)ms;
    set_ocall_table(ocall_table);
    cc_enclave_result_t result_cc = CC_SUCCESS;
    result_cc = comm_call(function_id, input_buffer, input_buffer_size,
                          output_buffer, output_buffer_size);
    return result_cc;
}

const struct cc_enclave_ops global_qingtian_ops = {
    .cc_create_enclave = _qingtian_create,
    .cc_destroy_enclave = _qingtian_destroy,
    .cc_ecall_enclave = cc_enclave_ecall_function,
};

struct cc_enclave_ops_desc global_qingtian_ops_name = {
    .name = "qingtian",
    .ops = &global_qingtian_ops,
    .type_version = QINGTIAN_ENCLAVE_TYPE_0,
    .count = 0,
};

struct list_ops_desc global_qingtian_ops_node = {
    .ops_desc = &global_qingtian_ops_name,
    .next = NULL,
};

#define OPS_NAME global_qingtian_ops_name
#define OPS_NODE global_qingtian_ops_node
#define OPS_STRU global_qingtian_ops

cc_enclave_result_t cc_tee_registered(cc_enclave_t *context, void *handle)
{
    size_t len = strlen(OPS_NAME.name);
    if (OPS_NAME.type_version != context->type || OPS_NODE.ops_desc != &OPS_NAME ||
        len >= MAX_ENGINE_NAME_LEN || OPS_NAME.ops != &OPS_STRU) {
        print_error_term("The struct cc_enclave_ops_desc initialization error\n");
        return CC_ERROR_BAD_PARAMETERS;
    }
    OPS_NAME.handle = handle;
    context->list_ops_node = &OPS_NODE;
    add_ops_list(&OPS_NODE);
    return  CC_SUCCESS;
}

cc_enclave_result_t cc_tee_unregistered(cc_enclave_t *context, enclave_type_version_t type_version)
{
    if (context == NULL || context->list_ops_node != &OPS_NODE || type_version != OPS_NAME.type_version) {
        print_error_term("Engine parameter error \n");
        return CC_FAIL;
    }
    remove_ops_list(&OPS_NODE);
    return  CC_SUCCESS;
}
