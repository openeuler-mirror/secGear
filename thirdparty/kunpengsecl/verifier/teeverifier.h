/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.
*/

#ifndef __VERIFIER_LIB__
#define __VERIFIER_LIB__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <ctype.h>

#define UUID_SIZE 16
#define HASH_SIZE 32
//Attester will send the report by this type
typedef struct{
    uint32_t size;
    uint8_t *buf;
} buffer_data;

typedef struct
{
    uint8_t uuid[UUID_SIZE];
    uint8_t valueinfo[2][HASH_SIZE]; // valueinfo[0]=img measurement and valueinfo[1]=mem measurement
} base_value;

enum error_status_code {
    TVS_ALL_SUCCESSED = 0,
    TVS_VERIFIED_NONCE_FAILED = -1,
    TVS_VERIFIED_SIGNATURE_FAILED = -2,
    TVS_VERIFIED_HASH_FAILED = -3,
};

int tee_verify_report(buffer_data *data_buf,buffer_data *nonce,int type, char *filename);
int tee_validate_report(buffer_data *buf_data, buffer_data *nonce);
int tee_verify_report2(buffer_data *buf_data, int type,base_value *baseval);
bool tee_verify_akcert(buffer_data *akcert, int type, const char *refval);
bool tee_get_akcert_data(buffer_data *akcert, buffer_data *akpub, buffer_data *drkcrt);

#endif
