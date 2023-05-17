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

#ifndef CUSTOM_BASE64URL_H
#define CUSTOM_BASE64URL_H

#include <stdlib.h>

void base64urlencode(const uint8_t *src, int src_len, uint8_t *cipher, int *dest_len);
uint8_t *base64urldecode(const uint8_t *src, int src_len, int *dest_len);

#endif
