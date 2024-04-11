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
#ifndef _QT_ATTESTATION_API_H_
#define _QT_ATTESTATION_API_H_

#include "qt_attestation_def.h"

#ifdef __cplusplus
extern "C" {
#endif

/* global qingtian root cert */
extern X509 *g_qt_root_cert;

/*
 * qt_read_root_cert() - Load Qingtian root cert from given path.
 * @f_path (input): Qingtian root cert path.
 *
 * Context: Read qingtian root cert from f_path and store the content.
 *
 * Returns: The X509 cert.
 */
X509 *qt_read_root_cert(const char* f_path);

/*
 * free_qt_root_cert() - Free Qingtian root cert.
 * @cert (input): Qingtian root cert.
 *
 * Context: Free qingtian root cert.
 *
 * Returns: None.
 */
void free_qt_root_cert(X509 *cert);

/*
 * parse_cboren_doc() - Parse attestation doc encoded in cbor.
 * @doc_cose (input): The attestation doc in COSE format.
 * @doc_len (input): The length of doc_cose data.
 * @cur_doc (output): The actual attestation doc after parsing.
 * @sig_msg (output): The signature message of cbor-encoded attestation doc.
 * @sig_msg_len (output): The length of the signature message.
 *
 * Context: Process context.
 *
 * Returns: The status of the operation.
 */
int parse_cboren_doc(const uint8_t *doc_cose, 
                     const uint32_t doc_len,
                     attestation_document *cur_doc, 
                     unsigned char** sig_msg, 
                     size_t *sig_msg_len);

#ifdef __cplusplus
}
#endif

#endif