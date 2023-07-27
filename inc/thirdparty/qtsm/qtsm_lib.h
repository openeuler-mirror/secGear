/*
 * QTSM LIB API Implement
 *
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#ifndef QTSM_LIB_H
#define QTSM_LIB_H

#include <stdint.h>
#include <stdbool.h>
#include "qtsm_lib_comm.h"

/*
 * qtsm_lib_init() - Initialize the QTSM library.
 *
 * Context: Process context.
 *
 * Returns:
 * * Positive number on success.
 * * Negative return value on failure.
 */
int qtsm_lib_init(void);

/*
 * qtsm_lib_exit() - Exit the QTSM library
 * @qtsm_dev_fd (input): The descriptor for the opened device file,
 *                      as obtained from `qtsm_lib_init()`.
 *
 * Context: This function is called after `qtsm_lib_init()`.
 *
 * Returns: void
 */
void qtsm_lib_exit(int qtsm_dev_fd);

/*
 * qtsm_describe_pcr() - QTSM `DescribePCR` operation.
 * @fd (input): The descriptor to the QTSM device file.
 * @index (input): The index of the PCR to be described.
 * @locked (output): The lock state of the PCR.
 * @data (output): The buffer that will hold the PCR data.
 * @data_len (input/output): The PCR data buffer capacity (as input),
 *      and the actual size of the received data (as output)
 *
 * Context: Process context.
 *
 * Returns: The status of the operation.
 */
int qtsm_describe_pcr(const int fd, const uint16_t index, bool *locked,
    uint8_t *data, uint32_t *data_len);

/*
 * qtsm_extend_pcr() - QTSM `ExtendPCR` operation.
 * @fd (input): The descriptor to the QTSM device file.
 * @index (input): The index of the PCR to extend.
 * @req_data (input): The binary data to extend the PCR with.
 * @req_data_len (input): The length of the binary data, in bytes.
 * @pcr_data (output): The data from the extended PCR.
 * @pcr_data_len (input/output): The extended PCR data buffer capacity (as input),
        and the actual size of the received data (as output)
 *
 * Context: Process context.
 *
 * Returns: The status of the operation.
 */
int qtsm_extend_pcr(const int fd, const uint16_t index, const uint8_t *req_data,
    const uint32_t req_data_len, uint8_t *pcr_data, uint32_t *pcr_data_len);

/*
 * qtsm_lock_pcr() - QTSM `LockPCR` operation.
 * @fd (input): The descriptor to the QTSM device file.
 * @index (input): The index of the PCR to be locked.
 * @locked (output) : The locked status of the PCR.
 *
 * Context: Process context.
 *
 * Returns: The status of the operation.
 */
int qtsm_lock_pcr(const int fd, const uint16_t index, bool *locked);

/*
 * qtsm_lock_pcrs() - QTSM `LockPCRs` operation.
 * @fd (input): The descriptor to the QTSM device file.
 * @count (input): The total number of PCR indexes to be locked.
 * @range (input): The indexes of the PCRs.
 * @locked (output): The locked status of the PCRs.
 *
 * Context: Process context.
 *
 * Returns: The status of the operation.
 */
int qtsm_lock_pcrs(const int fd, const uint32_t count, const uint16_t *range,
    bool *locked);

/*
 * qtsm_get_describe() - QTSM `Describe` operation.
 * @fd (input): The descriptor to the QTSM device file.
 * @qtsm_description (output): The obtained QTSM description.
 *
 * Context: Process context.
 *
 * Returns: The status of the operation.
 */
int qtsm_get_describe(const int fd, describe_qtsm *qtsm_description);

/*
 * qtsm_get_attestation() - QTSM `GetAttestationDoc` operation.
 * @fd (input): The descriptor to the QTSM device file.
 * @user_data (input): The binary user data.
 * @user_data_len (input): The size of the user data buffer.
 * @nonce_data (input): The binary nonce data.
 * @nonce_data_len (input): The size of the nonce data buffer.
 * @pubkey_data (input): The public key data.
 * @pubkey_len (input): The size of the public key data buffer.
 * @att_doc_data (output): The obtained CBOR-encoded attestation document.
 * @att_doc_data_len (input/output): The attestation doc buffer capacity (as input),
 *      and the actual size of the received data (as output).
 *
 * Context: Process context.
 *
 * Returns: The status of the operation.
 */
int qtsm_get_attestation(const int fd,
    const uint8_t *user_data, const uint32_t user_data_len,
    const uint8_t *nonce_data, const uint32_t nonce_data_len,
    const uint8_t *pubkey_data, const uint32_t pubkey_len,
    uint8_t *att_doc_data, uint32_t *att_doc_data_len);

/*
 * qtsm_new_doc() - Create a attestation_document.
 *
 * Context: Process context.
 *
 * Returns:
 * * NULL on failure.
 * * Others on success.
 */
struct attestation_document* qtsm_new_doc(void);

/*
 * qtsm_free_doc() - Release the attestation_document.
 *
 * Context: Process context.
 *
 * Returns: void
 */
void qtsm_free_doc(struct attestation_document **doc);

/*
 * verify_parse_cboren_doc() - Verify and parse attestation doc encoded in cbor.
 * @doc_cose (input): The attestation doc in COSE format.
 * @doc_len (input): The length of doc_cose data.
 * @cur_doc (output): The actual attestation doc after parsing.
 *
 * Context: Process context.
 *
 * Returns: The status of the operation.
 */
int verify_parse_cboren_doc(const uint8_t *doc_cose, const uint32_t doc_len,
    struct attestation_document *cur_doc);

#endif
