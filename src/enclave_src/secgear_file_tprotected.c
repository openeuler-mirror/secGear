#include "secgear_file_tprotected.h"
#include "file_tprotected.h"
#include "error_conversion.h"



FILE_PTR* cc_enclave_fopen(const char* filename, const char* mode, void *key){
    if (filename == NULL) {
        return NULL;
    }
    if (mode == NULL) {
        return NULL;
    }
    if (key == NULL) {
        return NULL;
    }
    return internel_fopen(filename, mode, key);
}


cc_enclave_result_t cc_enclave_fwrite(const void* ptr, size_t size, size_t count, FILE_PTR* stream){
    cc_enclave_result_t ret;
    uint32_t result;

    if (ptr == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (size == 0) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (count == 0) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (stream == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }

    result =  internel_fwrite(ptr, size, count, stream);
    ret = conversion_res_status(result);
    return ret;
}

cc_enclave_result_t cc_enclave_fread(void* ptr, size_t size, size_t count, FILE_PTR* stream){
    cc_enclave_result_t ret;
    uint32_t result;

    if (ptr == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (size == 0) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (count == 0) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (stream == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }

    result =  internel_fread(ptr, size, count, stream);
    ret = conversion_res_status(result);
    return ret;
}


cc_enclave_result_t cc_enclave_fclose(FILE_PTR* stream){
    cc_enclave_result_t ret;
    uint32_t result;

    if (stream == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }

    result =  internel_fclose(stream);
    ret = conversion_res_status(result);
    return ret;
}
cc_enclave_result_t cc_enclave_remove(const char* filename){
    cc_enclave_result_t ret;
    uint32_t result;

    if (filename == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }

    result = internel_remove(filename);
    ret = conversion_res_status(result);
    return ret;
}

FILE_PTR* cc_enclave_fopen_auto_key(const char* filename, const char* mode){
    if (filename == NULL) {
        return NULL;
    }
    if (mode == NULL) {
        return NULL;
    }
    return internel_fopen_auto_key(filename, mode);
}
cc_enclave_result_t cc_enclave_fexport_auto_key(const char* filename, void *key){
    cc_enclave_result_t ret;
    uint32_t result;

    if (filename == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (key == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }

    result = internel_fexport_auto_key(filename, key);
    ret = conversion_res_status(result);
    return ret;
}
cc_enclave_result_t cc_enclave_fimport_auto_key(const char* filename, void *key){
    cc_enclave_result_t ret;
    uint32_t result;

    if (filename == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    if (key == NULL) {
        return CC_ERROR_BAD_PARAMETERS;
    }
    
    result = internel_fimport_auto_key(filename, key);
    ret = conversion_res_status(result);
    return ret;
}
