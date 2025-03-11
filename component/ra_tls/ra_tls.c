/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include "base64url.h"
#include "ra_tls.h"

static char *agent_addr = NULL;

typedef enum {
    EVIDENCE,
    TOKEN
}extension_type;

/* internal api */
static size_t wb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t total = size * nmemb;
    ra_tls_buf *buf = (ra_tls_buf*)userdata;
    ra_tls_buf_init(buf, total + 1);
    memcpy(buf->buf, ptr, total);
    buf->filled = total;
    buf->buf[buf->filled] = '\0';
    return total;
}

static int http_request(const char *endpoint, const char *type, const char *data, ra_tls_buf *response)
{
    int ret = -1;
    CURLcode res;
    CURL *curl = NULL;
    struct curl_slist *plist = NULL;
    curl = curl_easy_init();
    if (curl == NULL) {
        goto err;
    }
    plist = curl_slist_append(NULL, "Content-Type:application/json;charset=UTF-8");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, plist);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, type);
    if (data) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    }
    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, wb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        ret = -1;
        goto err;
    }
    ret = 0;
    goto end;
err:
    ra_tls_buf_free(response);
end:
    if (plist)  {
        curl_slist_free_all(plist);
    }
    if (curl) {
        curl_easy_cleanup(curl);
    }
    return ret;
}

static int get_quote(ra_tls_buf *quote, const char *endpoint_prefix, const char *type,
                     const char *uuid, ra_tls_buf *challenge)
{
    int ret = -1;
    int res = 0;
    char *endpoint = NULL;
    size_t endpoint_len = 0;
    const char *http_data_format = "{\"challenge\":\"%s\",\"uuid\":\"%s\"}";
    char *http_data = NULL;
    int http_data_len;
    if (endpoint_prefix == NULL || quote == NULL || uuid == NULL || challenge == NULL) {
        return -1;
    }
    endpoint_len = strlen(endpoint_prefix) + strlen(type) + 1;
    endpoint = malloc(endpoint_len);
    if (endpoint == NULL) {
        goto err;
    }
    strcpy(endpoint, endpoint_prefix);
    strcat(endpoint, type);
    http_data_len = strlen(uuid) + challenge->filled + strlen(http_data_format) + 1;
    http_data = malloc(http_data_len);
    if (http_data == NULL) {
        ret = -1;
        goto err;
    }
    res = sprintf(http_data, http_data_format, challenge->buf, uuid);
    
    res = http_request(endpoint, "GET", http_data, quote);
    if (res < 0) {
        goto err;
    }
    ret = 0;
    goto end;
err:
    ra_tls_buf_free(quote);
end:
    if (http_data) {
        free(http_data);
    }
    if (endpoint) {
        free(endpoint);
    }
    return ret;
}

static int get_evidence_ok(const ra_tls_buf *evidence)
{
    int ret = -1;
    cJSON *json_root = NULL;
    if (evidence == NULL) {
        return ret;
    }
    if (evidence->filled <= 0) {
        return ret;
    }
    json_root = cJSON_Parse((char*)evidence->buf);
    if (json_root != NULL) {
        ret = 0;
    }
    cJSON_Delete(json_root);
    return ret;
}
static int get_evidence(ra_tls_buf *evidence, const char *endpoint_prefix, const char *uuid, ra_tls_buf *challenge)
{
    int ret = -1;
    int res = 0;
    res = get_quote(evidence, endpoint_prefix, "evidence", uuid, challenge);
    if (res < 0) {
        return ret;
    }
    res = get_evidence_ok(evidence);
    if (res < 0) {
        return ret;
    }
    ret = 0;
    return ret;
}

static int get_token_ok(const ra_tls_buf *token)
{
    int ret = -1;
    size_t offset = 0;
    cJSON *json_root = NULL;
    uint8_t *header_base64 = NULL;
    int header_base64_len = 0;
    char *header = NULL;
    size_t header_len = 0;
    if (token == NULL) {
        return ret;
    }
    if (token->filled <= 0) {
        return ret;
    }
    while (offset < token->filled) {
        // token sperated by '.'
        if (token->buf[offset] == '.') {
            break;
        }
        offset++;
    }
    if (offset == token->filled) {
        goto err;
    }
    header_base64_len = offset;
    header_base64 = malloc(header_base64_len + 1);
    memcpy(header_base64, token->buf, header_base64_len);
    header_base64[header_base64_len] = '\0';
    header = (char*)kpsecl_base64urldecode((const char*)header_base64, header_base64_len, &header_len);
    if  (header_len <= 0) {
        goto err;
    }
    json_root = cJSON_Parse((const char*)header);
    if (json_root != NULL) {
        ret = 0;
    }
err:
    if (json_root) {
        cJSON_Delete(json_root);
    }
    if (header_base64) {
        free(header_base64);
    }
    if (header) {
        free(header);
    }
    return ret;
}
static int get_token(ra_tls_buf *token, const char *endpoint_prefix, const char *uuid, ra_tls_buf *challenge)
{
    int ret = -1;
    int res = 0;
    res = get_quote(token, endpoint_prefix, "token", uuid, challenge);
    if (res < 0) {
        return ret;
    }
    res = get_token_ok(token);
    if (res < 0) {
        return ret;
    }
    ret = 0;
    return ret;
}

static int get_challenge(ra_tls_buf *challenge, const char *endpoint_prefix, ra_tls_buf *user_data)
{
    int res;
    int ret = -1;
    const size_t challenge_len = 32; // 32 means the length of challenge by default
    size_t base64_len = 0;
    uint8_t *base64 = NULL;
    ra_tls_buf key_hash = RA_TLS_BUF_INIT;
    ra_tls_buf challenge_raw = RA_TLS_BUF_INIT;
    ra_tls_buf *pub_key = user_data;
    if (endpoint_prefix == NULL || challenge == NULL || pub_key == NULL) {
        return -1;
    }
    ra_tls_buf_init(&key_hash, 0);
    get_hash(&key_hash, pub_key, SHA_256);
#ifdef DEBUG
    printf("public key hash:");
    for (size_t i = 0; i < key_hash.filled; i++) {
        printf("%02X", key_hash.buf[i]);
    }
    printf("\n");
#endif
// generate random 32B, concate with public key hash, then base64_url_encode
    ra_tls_buf_init(&challenge_raw, challenge_len + key_hash.filled);
    res = get_random(challenge_raw.buf, challenge_len);
    if (res < 0) {
        printf("get random failed\n");
        goto err;
    }
    memcpy(challenge_raw.buf + challenge_len, key_hash.buf, key_hash.filled);
    challenge_raw.filled = challenge_len + key_hash.filled;

    base64 = (uint8_t*)kpsecl_base64urlencode(challenge_raw.buf, challenge_raw.filled, &base64_len);
    if (base64 == NULL) {
        goto err;
    }

    ra_tls_buf_init(challenge, base64_len);
    memcpy(challenge->buf, base64, base64_len);
    challenge->filled = base64_len;
    ret = 0;
err:
    ra_tls_buf_free(&key_hash);
    ra_tls_buf_free(&challenge_raw);
    if (base64) {
        free(base64);
    }
    return ret;
}

static int generate_extension_string(ra_tls_buf *extension, ra_tls_buf *challenge, ra_tls_buf *quote)
{
    int ret = -1;
    cJSON *ext = NULL;
    char *json_str = NULL;
    if (extension == NULL || challenge == NULL || quote == NULL) {
        return ret;
    }
    ext = cJSON_CreateObject();
    if (ext == NULL) {
        return ret;
    }
    cJSON_AddStringToObject(ext, "challenge", (char *)challenge->buf);
    cJSON_AddStringToObject(ext, "quote", (char *)quote->buf);
    if ((json_str = cJSON_PrintUnformatted(ext)) == NULL) {
        goto err;
    }
    cJSON_Minify(json_str);
    ra_tls_buf_init(extension, strlen(json_str) + 1);
    strcpy((char *)extension->buf, json_str);
    extension->filled = strlen(json_str) + 1;
    ret = 0;
err:
    if (ext) {
        cJSON_Delete(ext);
    }
    if (json_str) {
        cJSON_free(json_str);
    }
    return ret;
}

static int get_quote_ra(ra_tls_buf *quote, ra_tls_buf *challenge, ra_tls_buf *pub_key, ra_cfg *cfg)
{
    int ret = -1;
    int res = 0;
/*
    get challenge
    The public key in the signature certificate needs to be protected.
    now we use pub_key hash concatenated with challenge.
*/
    res = get_challenge(challenge, cfg->aa_addr, pub_key);
    if (res < 0) {
        printf("get challenge failed\n");
        goto err;
    }
#ifdef DEBUG
    printf("challenge: %s\n", challenge->buf);
#endif
    if (cfg->mode == BACKGROUND) {
        // get evidence
        res = get_evidence(quote, cfg->aa_addr, cfg->uuid, challenge);
        if (res < 0) {
            printf("get evidence failed\n");
            goto err;
        }
#ifdef DEBUG
        printf("evidence: %s\n", quote->buf);
#endif
    } else if (cfg->mode == PASSPORT) {
        // get token
        res = get_token(quote, cfg->aa_addr, cfg->uuid, challenge);
        if (res < 0) {
            printf("get token failed\n");
            goto err;
        }
#ifdef DEBUG
        printf("token: %s\n", quote->buf);
#endif
    } else {
        printf("unknown work mode\n");
        goto err;
    }
    ret = 0;
err:
    return ret;
}

/* output certificate and private key */
int ra_tls_generate_certificate(ra_tls_buf *cert, ra_tls_buf *private_key, ra_cfg *cfg, key_size size)
{
    int res;
    int ret = -1;
    const char* oid = NULL;
    ra_tls_buf pub_key = RA_TLS_BUF_INIT;
    ra_tls_buf prv_key = RA_TLS_BUF_INIT;
    ra_tls_buf challenge = RA_TLS_BUF_INIT;
    ra_tls_buf extension = RA_TLS_BUF_INIT;
    ra_tls_buf quote = RA_TLS_BUF_INIT;
    if (cert == NULL || private_key == NULL || cfg == NULL) {
        return ret;
    }
    if (cfg->aa_addr == NULL || cfg->uuid == NULL) {
        return ret;
    }
    if (cfg->aa_addr[strlen(cfg->aa_addr) - 1] != '/') {
        printf("aa_addr should end with '/'\n");
        return ret;
    }
    res = generate_key_pair_der(size, &pub_key, &prv_key);
    if (res < 0) {
        return ret;
    }
    *private_key = prv_key;
    res = get_quote_ra(&quote, &challenge, &pub_key, cfg);
    if (res < 0) {
        goto err;
    }
// extension contained: evidence or token and challenge
    if (generate_extension_string(&extension, &challenge, &quote) < 0) {
        goto err;
    }
#ifdef DEBUG
    printf("certificate extension: %s\n", extension.buf);
#endif
// generate certificate
    oid = (cfg->mode == BACKGROUND)? EVIDENCE_OID : TOKEN_OID;
    res = generate_certificate_with_extension(cert, &extension, &pub_key, &prv_key, oid);
    if (res < 0) {
        ret = -1;
    }
    ret = 0;
err:
    ra_tls_buf_free(&pub_key);
    ra_tls_buf_free(&challenge);
    ra_tls_buf_free(&extension);
    ra_tls_buf_free(&quote);
    return ret;
}

// for client to verify externsion in certificate
int ra_tls_set_addr(char *addr)
{
    if (addr == NULL) {
        return -1;
    }
    if (addr[strlen(addr) - 1] != '/') {
        printf("host should end with '/'\n");
        return -1;
    }
    agent_addr = addr;
    return 0;
}

/*
    token is a string, separated by '.',  like this:
    HEADER.CLAIM.SIGNATURE
    HEADER,CLAIM encoded by base64_url
*/
static int parse_claim_from_token(ra_tls_buf *claim, ra_tls_buf *token)
{
    size_t claim_start = 0;
    size_t claim_end = 0;
    while (claim_start < token->filled) {
        if (token->buf[claim_start] != '.') {
            claim_start++;
        } else {
            break;
        }
    }
    claim_start++;
    claim_end = claim_start;
    while (claim_end < token->filled) {
        if (token->buf[claim_end] != '.') {
            claim_end++;
        } else {
            break;
        }
    }
    claim_end--;
    if (claim_end <= claim_start) {
        return -1;
    }
    ra_tls_buf_init(claim, claim_end - claim_start + 1);
    (void)memcpy(claim->buf, &token->buf[claim_start], claim_end - claim_start + 1);
    claim->filled = claim_end - claim_start + 1;
    return 0;
}

static int expect_response_true(ra_tls_buf *resp, extension_type mode)
{
    int ret = -1;
    cJSON *root = NULL;
    cJSON *obj_parse = NULL;
    cJSON *obj_get = NULL;
    if (resp == NULL || resp->buf == NULL) {
        return -1;
    }
    if (mode == EVIDENCE) {
        root = cJSON_Parse((const char *)resp->buf);
        cJSON *obj_get = cJSON_GetObjectItemCaseSensitive(root, "evaluation_reports");
        if (obj_get == NULL) {
            goto err;
        }
        if (NULL == (obj_get = cJSON_GetObjectItemCaseSensitive(obj_get, "eval_result"))) {
            goto err;
        }
        if (cJSON_IsTrue(obj_get)) {
            ret = 0;
        }
    } else {
        root = cJSON_Parse((const char*)resp->buf);
        obj_get = cJSON_GetObjectItemCaseSensitive(root, "claim");
        if (obj_get == NULL) {
            goto err;
        }
        char *str = cJSON_GetStringValue(obj_get);
        if (str == NULL) {
            goto err;
        }
        cJSON* obj_parse = cJSON_Parse(str);
        cJSON* obj_get = cJSON_GetObjectItemCaseSensitive(obj_parse, "evaluation_reports");
        if (obj_get == NULL) {
            goto err;
        }
        if (NULL == (obj_get = cJSON_GetObjectItemCaseSensitive(obj_get, "eval_result"))) {
            goto err;
        }
        if (cJSON_IsTrue(obj_get)) {
            ret = 0;
        }
    }
err:
    if (root) {
        cJSON_Delete(root);
    }
    if (obj_parse) {
        cJSON_Delete(obj_parse);
    }
    return ret;
}
// extension like this:"{"challenge":"base64_url string","quote":"token or evidence"}"
static int parse_challenge_from_extension(ra_tls_buf *challenge, ra_tls_buf *ext)
{
    int ret = -1;
    cJSON *json_root = NULL;
    cJSON *obj;
    char *str = NULL;
    if (challenge == NULL || ext == NULL) {
        return ret;
    }
    if (NULL == (json_root = cJSON_Parse((const char*)ext->buf))) {
        goto err;
    }
    if (NULL == (obj = cJSON_GetObjectItemCaseSensitive(json_root, "challenge"))) {
        goto err;
    }
    if (NULL == (str = cJSON_GetStringValue(obj))) {
        goto err;
    }
    ra_tls_buf_init(challenge, strlen(str) + 1);
    strcpy((char *)challenge->buf, str);
    challenge->filled = strlen(str) + 1;
    ret = 0;
err:
    if (json_root) {
        cJSON_Delete(json_root);
    }
    return ret;
}

static int parse_quote_from_extension(ra_tls_buf *quote, ra_tls_buf *ext)
{
    int ret = -1;
    cJSON *json_root = NULL;
    cJSON *obj;
    char *str = NULL;
    if (quote == NULL || ext == NULL) {
        return ret;
    }
    if (NULL == (json_root = cJSON_Parse((const char *)ext->buf))) {
        goto err;
    }
    if (NULL == (obj = cJSON_GetObjectItemCaseSensitive(json_root, "quote"))) {
        goto err;
    }
    if (NULL == (str = cJSON_GetStringValue(obj))) {
        goto err;
    }
    ra_tls_buf_init(quote, strlen(str) + 1);
    strcpy((char *)quote->buf, str);
    quote->filled = strlen(str) + 1;
    ret = 0;
err:
    if (json_root) {
        cJSON_Delete(json_root);
    }
    return ret;
}

static char *generate_ra_http_data(extension_type type, char **http_data, ra_tls_buf *quote, ra_tls_buf *challenge)
{
    if (type == EVIDENCE) {
        cJSON* obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "evidence", (const char *)quote->buf);
        cJSON_AddStringToObject(obj, "challenge", (const char *)challenge->buf);
        *http_data = cJSON_PrintUnformatted(obj);
        cJSON_Minify(*http_data);
        cJSON_Delete(obj);
    } else {
        cJSON* obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "token", (const char *)quote->buf);
        *http_data = cJSON_PrintUnformatted(obj);
        cJSON_Minify(*http_data);
        cJSON_Delete(obj);
    }
    return *http_data;
}

static int verify_extension_ra(extension_type type, ra_tls_buf *quote, ra_tls_buf *challenge)
{
    int ret = -1;
    int res = 0;
    ra_tls_buf response = RA_TLS_BUF_INIT;
    const char *source_name = NULL;
    char *endpoint = NULL;
    size_t endpoint_len = 0;
    char *http_data = NULL;

    if (type == EVIDENCE) {
        source_name = "evidence";
    } else if (type == TOKEN) {
        source_name = "token";
    } else {
        printf("unkonwn extension type\n");
        goto err;
    }
    endpoint_len = strlen(agent_addr) + strlen(source_name) + 1;
    endpoint = malloc(endpoint_len);
    if (endpoint == NULL) {
        goto err;
    }
    strcpy(endpoint, agent_addr);
    strcat(endpoint, source_name);
    generate_ra_http_data(type, &http_data, quote, challenge);
#ifdef DEBUG
    printf("http request\n");
    printf("endpoint: %s\n", endpoint);
    printf("http data: %s\n", http_data);
#endif
    res = http_request(endpoint, "POST", http_data, &response);
    if (res < 0) {
        goto err;
    }
#ifdef DEBUG
    printf("response: %s\n", response.buf);
#endif
    // check as service response
    if (expect_response_true(&response, type) != 0) {
        printf("expect evaluation_reports.eval_result = true, but false or not exist\n");
        goto err;
    }
    ret = 0;
err:
    if (endpoint) {
        free(endpoint);
    }
    if (http_data) {
        cJSON_free(http_data);
    }
    ra_tls_buf_free(&response);
    return ret;
}

static int verify_extension(ra_tls_buf *ext, extension_type type)
{
    int ret = -1;
    int res;
    ra_tls_buf challenge = RA_TLS_BUF_INIT;
    ra_tls_buf quote = RA_TLS_BUF_INIT;

    if (agent_addr == NULL || ext == NULL) {
        return ret;
    }
    res = parse_challenge_from_extension(&challenge, ext);
    if (res < 0) {
        goto err;
    }
    res = parse_quote_from_extension(&quote, ext);
    if (res < 0) {
        goto err;
    }
    res = verify_extension_ra(type, &quote, &challenge);
    if (res != 0) {
        ret = -1;
    } else {
        ret = 0;
    }
err:
    ra_tls_buf_free(&challenge);
    ra_tls_buf_free(&quote);
    return ret;
}

// challenge :last 32 bytes in base64_url_decode(challenge) is the public key hash
static int get_public_key_hash(ra_tls_buf *key_hash, ra_tls_buf *ext)
{
    int ret = -1;
    int res;
    ra_tls_buf challenge_base64 = RA_TLS_BUF_INIT;
    uint8_t* challenge = NULL;
    size_t challenge_len = 0;
    res = parse_challenge_from_extension(&challenge_base64, ext);
    if (res < 0) {
        goto err;
    }
    challenge = kpsecl_base64urldecode((const char*)challenge_base64.buf, challenge_base64.filled, &challenge_len);
    if (challenge == NULL || challenge_len < HASH_OFFSET + HASH_LEN) {
        goto err;
    }
    ra_tls_buf_init(key_hash, HASH_LEN);
    memcpy(key_hash->buf, &challenge[HASH_OFFSET], HASH_LEN);
    key_hash->filled = HASH_LEN;
    ret = 0;
err:
    ra_tls_buf_free(&challenge_base64);
    if (challenge) {
        free(challenge);
    }
    return ret;
}

static int check_public_key_hash(ra_tls_buf *key_hash, ra_tls_buf *ker_der)
{
    int ret = -1;
    ra_tls_buf cal_hash = RA_TLS_BUF_INIT;
    ra_tls_buf_init(&cal_hash, HASH_LEN);
    if (key_hash->filled != HASH_LEN) {
        return -1;
    }
    if (0 != get_hash(&cal_hash, ker_der, SHA_256)) {
        goto err;
    }
#ifdef DEBUG
    printf("compare key hash\n");
    printf("expected: ");
    for (size_t i = 0; i < key_hash->filled; i++) {
        printf("%02X", key_hash->buf[i]);
    }
    printf("\n");
    printf("get hash of input: ");
    for (size_t i = 0; i < cal_hash.filled; i++) {
        printf("%02X", cal_hash.buf[i]);
    }
    printf("\n");
#endif
    if (0 != memcmp(key_hash->buf, cal_hash.buf, cal_hash.filled)) {
        printf("public key hash check Failed\n");
        goto err;
    }
    ret = 0;
err:
    ra_tls_buf_free(&cal_hash);
    return ret;
}

bool ra_tls_cert_extension_expired(ra_tls_buf *cert)
{
    bool ret = true;
    ra_tls_buf token = RA_TLS_BUF_INIT;
    ra_tls_buf oid = RA_TLS_BUF_INIT;
    ra_tls_buf claim = RA_TLS_BUF_INIT;
    char *raw_claim = NULL;
    size_t raw_claim_len = 0;
    cJSON *root = NULL;
    cJSON *obj_get = NULL;
    size_t expired = 0;
    if (cert == NULL || cert->filled == 0) {
        goto err;
    }
    if (get_extension_from_certificate_der(&token, &oid, cert) < 0) {
        goto err;
    }
    // check extension expired
    if (parse_claim_from_token(&claim, &token) < 0) {
        goto err;
    }
    raw_claim = (char*)kpsecl_base64urldecode((const char *)claim.buf, claim.filled, &raw_claim_len);
    if (raw_claim == NULL) {
        goto err;
    }
#ifdef DEBUG
    printf("raw claim: %s", raw_claim);
#endif
    root = cJSON_Parse(raw_claim);
    if (root == NULL) {
        goto err;
    }
    obj_get = cJSON_GetObjectItemCaseSensitive(root, "exp");
    if (obj_get == NULL || !cJSON_IsNumber(obj_get)) {
        goto err;
    }
    expired = cJSON_GetNumberValue(obj_get);
    if ((size_t)time(NULL) + EXTENSION_EXPIRED_OFFSET_SECONDS >= expired) {
        ret = true;
    } else {
        ret = false;
    }
err:
    ra_tls_buf_free(&token);
    ra_tls_buf_free(&oid);
    ra_tls_buf_free(&claim);
    if (raw_claim) {
        free(raw_claim);
    }
    if (root) {
        cJSON_Delete(root);
    }
    return ret;
}

static int verify_certificate_extension(void *cert_ctx)
{
    int res;
    int ret = -1;
    ra_tls_buf ext = RA_TLS_BUF_INIT;
    ra_tls_buf key_hash = RA_TLS_BUF_INIT;
    ra_tls_buf key_der = RA_TLS_BUF_INIT;
    ra_tls_buf oid = RA_TLS_BUF_INIT;
    extension_type type;

//  below depend api declare in ra_tls_imp.h
    res = get_extension_from_certificate_context(&ext, &oid, cert_ctx);
    if (res < 0) {
        printf("get extension from certificate failed\n");
        goto err;
    }
    if (strcmp((const char*)oid.buf, EVIDENCE_OID) == 0) {
        type = EVIDENCE;
    } else if (strcmp((const char*)oid.buf, TOKEN_OID) == 0) {
        type = TOKEN;
    } else {
        goto err;
    }
    res = verify_extension(&ext, type);
    if (res < 0) {
        printf("extension verfiy failed\n");
        goto err;
    }
    res = get_public_key_from_certificate_context(&key_der, cert_ctx);
    if (res < 0) {
        printf("get public key failed\n");
    }
    res = get_public_key_hash(&key_hash, &ext);
    if (res < 0) {
        printf("get public key hash failed\n");
    }
    res = check_public_key_hash(&key_hash, &key_der);
    if (res < 0) {
        printf("public key hash check failed\n");
        goto err;
    }
    // success
    ret = 0;
err:
    ra_tls_buf_free(&ext);
    ra_tls_buf_free(&key_hash);
    ra_tls_buf_free(&key_der);
    ra_tls_buf_free(&oid);
    return ret;
}

#ifdef USE_OPENSSL
// 0 failed 1 ok
int ra_tls_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    int res;
    int ret = 1;
    if (preverify_ok == 0) {
        res = X509_STORE_CTX_get_error(x509_ctx);
        if (res == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
            printf("self-signed certificate\n");
            ret = 1;
            return ret;
        }
    }
    res = verify_certificate_extension(x509_ctx);
    if (res < 0) {
        ret = 0;
    }
    return ret;
}
#endif