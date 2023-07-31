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

#include "enclave.h"
#include "enclave_internal.h"
#include "enclave_log.h"
#include "qt_rpc_proxy.h"
#include "qt_call.h"
#include "qt_log.h"
#include "host_input.h"
#include "qingtian_enclave.h"

#define PRA_BUF_SIZE        (64)
#define CMD_PRA_BUF_SIZE    (128)
#define CMD_BUF_MAX         (128 + PATH_MAX)

#define CMD_BUF_RESULT_MAX      (1024 * 5)
#define CMD_BUF_RESULT_LINE_MAX (128)

#define CID_MIN             (4)

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

static int check_eif(const char* path)
{
    if (access(path, F_OK) != 0) {
        print_error_term("%s can not access\n", path);
        return -1;
    }
    // file extern must be "eif"
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

// return length of command string
int qt_start_cmd_construct(char *command, const cc_startup_t *pra, const char *eif, uint32_t flags)
{
    int ret = 0;
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
        if (get_id(cur, &tmp_cid, &tmp_id) != 0) {
            cur = strtok_r(NULL, delimeter, &next);
        }
        if (cid == tmp_cid) {
            *id = tmp_id;
            return 0;
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
        strcat(buf, read_buf);
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
        pclose(fp);
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
    if (command == NULL || id == NULL) {
        ret = -1;
        goto end;
    }
    if (qt_query_id(cid, id) == 0) {
        QT_ERR("cid %u id %u already exist\n", cid, *id);
        ret = 1;
        goto end;
    }
    QT_DEBUG("exec cmd: %s\n", command);
    fp = popen(command, "r");
    if (fp == NULL) {
        QT_ERR("command execute failed\n");
        ret = -1;
        goto end;
    } else {
        QT_DEBUG("get enclave id, total retry %d\n", left);
        while (left-- > 0) {
            QT_DEBUG("try %d\n", (left + 1));
            if (qt_query_id(cid, id) != 0) {
                sleep(1);
                continue;
            } else {
                break;
            }
        }
        if (left <= 0) {
            ret = -1;
            QT_ERR("query id fail\n");
        } else {
            ret = 0;
            QT_DEBUG("qingtian enclave id  %u\n", *id);
        }
        ret = 0;
    }
end:
    if (fp != NULL) {
        pclose(fp);
        fp = NULL;
    }
    return ret;
}

cc_enclave_result_t _qingtian_create(cc_enclave_t *enclave, const enclave_features_t *features,
                                     const uint32_t features_count)
{
    cc_enclave_result_t result_cc = CC_SUCCESS;
    char *command = NULL;
    if (enclave == NULL) {
        QT_ERR("Context parameter is NULL\n");
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
        QT_ERR("enclave startup parameter is NULL\n");
        return CC_ERROR_BAD_PARAMETERS;
    }
    command = calloc(1, CMD_BUF_MAX);
    if (command == NULL) {
        QT_ERR("malloc for start command is NULL\n");
        result_cc = CC_ERROR_OUT_OF_MEMORY;
        goto end;
    }
    if (qt_start_cmd_construct(command, startup_pra, enclave->path, enclave->flags) <= 0) {
        QT_ERR("construct qt start command fail\n");
        result_cc = CC_ERROR_GENERIC;
        goto end;
    }
#ifdef DEBUG_MOCK
    QT_DEBUG("qingtian enclave mock create successfully! \n");
    qingtian_private_data_t *priv_data = (qingtian_private_data_t *)malloc(sizeof(qingtian_private_data_t));
    if (priv_data == NULL) {
        QT_ERR("malloc for private data is NULL\n");
        result_cc = CC_ERROR_OUT_OF_MEMORY;
        goto end;
    }
    priv_data->enclave_id = 0;
    priv_data->startup = *startup_pra;
    enclave->private_data = (void *)priv_data;
    result_cc = CC_SUCCESS;
    goto end;
    uint32_t id;
    int ret = qt_start(command, (unsigned int)startup_pra->enclave_cid, &id, startup_pra->query_retry);
    if (ret < 0 || ret > 1) {
        QT_ERR("qingtian enclave create fail! \n");
        result_cc = CC_ERROR_GENERIC;
        goto end;
    } else if (ret == 1) {
        QT_ERR("qingtian enclave already exist\n");
        result_cc = CC_ERROR_GENERIC;
        goto end;
    }
#else
    QT_DEBUG("exec cmd: %s\n", command);
    uint32_t id = 0;
    int ret = qt_start(command, (unsigned int)startup_pra->enclave_cid, &id, startup_pra->query_retry);
    if (ret < 0 || ret > 1) {
        QT_ERR("qingtian enclave create fail! \n");
        result_cc = CC_ERROR_GENERIC;
        goto end;
    } else if (ret == 1) {
        QT_ERR("qingtian enclave already exist\n");
        result_cc = CC_ERROR_GENERIC;
        goto end;
    }
    if (enclave_init(startup_pra->enclave_cid, (qt_handle_request_msg_t)handle_ocall_function) != 0) {
        result_cc = CC_ERROR_GENERIC;
        goto end;
    }
    QT_DEBUG("qingtian enclave create successfully! \n");
    qingtian_private_data_t *priv_data = (qingtian_private_data_t *)malloc(sizeof(qingtian_private_data_t));
    if (priv_data == NULL) {
        QT_ERR("malloc for private data is NULL\n");
        result_cc = CC_ERROR_OUT_OF_MEMORY;
        goto end;
    }
    priv_data->enclave_id = id;
    priv_data->startup = *startup_pra;
    enclave->private_data = (void *)priv_data;
    result_cc = CC_SUCCESS;
#endif
end:
#ifdef DEBUG_MOCK
    QT_DEBUG("enclave mock init\n");
    enclave_init(startup_pra->enclave_cid, (qt_handle_request_msg_t)handle_ocall_function);
#endif
    if (command != NULL) {
        free(command);
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
        QT_ERR("host: construct command fail\n");
        ret = -1;
        goto end;
    }
    cmd_result = calloc(1, CMD_BUF_MAX);
    if (cmd_result == NULL) {
        ret = -1;
        goto end;
    }
    QT_DEBUG("exec cmd: %s\n", command);
#ifdef DEBUG_MOCK
    QT_DEBUG("exec mock, return success\n");
    ret = 0;
    goto end;
#endif
    fp = popen(command, "r");
    if (fp == NULL) {
        QT_ERR("popen failed\n");
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
        pclose(fp);
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
        QT_ERR("qinttian destroy parameter error\n");
        result_cc = CC_ERROR_BAD_PARAMETERS;
        goto end;
    }
    qingtian_private_data_t *priv_data = context->private_data;
    enclave_deinit(priv_data->startup.enclave_cid);

    if (priv_data == NULL) {
        result_cc = CC_ERROR_BAD_PARAMETERS;
        goto end;
    }
    if (qt_stop(priv_data->enclave_id) != 0) {
        result_cc = CC_ERROR_GENERIC;
        goto end;
    }
    if (priv_data != NULL) {
        free(priv_data);
        context->private_data = NULL;
    }
    QT_DEBUG("qingtian destroy success\n");
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
    (void)ocall_table;
#ifdef DEBUG
    QT_DEBUG("ecall input function id %lu\n", (long unsigned int)function_id);
    QT_DEBUG("ecall input buffer size %zu\n", input_buffer_size);
    QT_DEBUG("ecall output buffer size %zu\n", output_buffer_size);
    QT_DEBUG("ecall input data: ");
    for (size_t i = 0; i < input_buffer_size; i++) {
        QT_DEBUG("%02X", *((uint8_t*)input_buffer + i));
    }
    QT_DEBUG("\n");
#endif

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
        QT_ERR("The struct cc_enclave_ops_desc initialization error\n");
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
        QT_ERR("Engine parameter error \n");
        return CC_FAIL;
    }
    remove_ops_list(&OPS_NODE);
    return  CC_SUCCESS;
}