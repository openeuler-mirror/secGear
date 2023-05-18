/*
kunpengsecl licensed under the Mulan PSL v2.
You can use this software according to the terms and conditions of
the Mulan PSL v2. You may obtain a copy of Mulan PSL v2 at:
    http://license.coscl.org.cn/MulanPSL2
THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
See the Mulan PSL v2 for more details.

Author: leezhenxiang
Create: 2022-11-04
Description: ta authenticating module in kta.
	1. 2022-11-04	leezhenxiang
		define the structures.
*/
#include "base64url.h"

#include <string.h>
#include <stdlib.h>
#include "b64/b64.h"

//Encode unsigned char source to base64url.
//Neither of param source_len or dest_len include character '\0'.
//Return the first address of encoded string. 【warning】caller need free return ptr
char* kpsecl_base64urlencode(const uint8_t *source, size_t source_len, size_t *dest_len) {
    char *dest = b64_encode(source, source_len);
    *dest_len = strlen(dest);
    //change "+" to "-", "/" to "_", remove "=".
    for(int i = *(int *)dest_len; i >= 0; i--) {
        if(*(dest + i) == '+')
            *(dest + i) = '-';
        else if(*(dest + i) == '/')
            *(dest + i) = '_';
        else if(*(dest + i) == '=') 
            *(dest + i) = *(dest + i + 1);
    }
    return dest;
}

//Decode base64url string source to unsigned char.
//Neither of param source_len or dest_len include character '\0'.
//Return the first address of decoded unsigned string.  【warning】caller need free return ptr
uint8_t* kpsecl_base64urldecode(const char *source, size_t source_len, size_t *dest_len) {
    //change "-" to "+", "_" to "/", add back "=".
    size_t i = 0;
    char *tail1 = "=";
    char *tail2 = "==";
    char *b64 = calloc(1, source_len + 3);
    if (b64 == NULL) {
        return NULL;
    }
    memcpy(b64, source, source_len);
    for(i = 0; i < source_len; i++) {
        if(*(b64 + i) == '-')
            *(b64 + i) = '+';
        else if(*(b64 + i) == '_')
            *(b64 + i) = '/';
    }
    *(b64 + i) = '\0';
    if(source_len % 4 == 2) {
        strcat(b64, tail2);
        *dest_len = (source_len + 2) / 4 * 3 - 2;
    }
    else if(source_len % 4 == 3) {
        strcat(b64, tail1);
        *dest_len = (source_len + 1) / 4 * 3 - 1;
    }
    else if(source_len % 4 == 0)
        *dest_len = source_len / 4 * 3;
    uint8_t *dest = b64_decode(b64, strlen(b64));
    free(b64);
    return dest;
}
