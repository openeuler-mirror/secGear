#include "secgear_file_tprotected.h"
#include "file_tprotected.h"



FILE_PTR* cc_enclave_get_fopen(const char* filename, const char* mode){
    return get_fopen_ex(filename, mode);
}
cc_enclave_result_t cc_enclave_fwrite_data(const void* ptr, size_t size, size_t count, FILE_PTR* stream){
    size_t result = 1;
    result =  internel_fwrite_data(ptr, size, count, stream);
    if(result == 0)
        return CC_SUCCESS;
    else return CC_ERROR_GENERIC;
}
cc_enclave_result_t cc_enclave_fread_data(void* ptr, size_t size, size_t count, FILE_PTR* stream){
    size_t result = 1;
    result =  internel_fread_data(ptr, size, count, stream);
    if(result == 0)
        return CC_SUCCESS;
    else return CC_ERROR_GENERIC;
}


cc_enclave_result_t cc_enclave_get_fclose(FILE_PTR* stream){
    int32_t result = 1;
    result =  get_fclose_ex(stream);
    if(result == 0)
        return CC_SUCCESS;
    else return CC_ERROR_GENERIC;
}
cc_enclave_result_t cc_enclave_get_remove(const char* filename){
    int32_t result = 1;
    result = get_remove_ex(filename);
    if(result == 0)
        return CC_SUCCESS;
    else return CC_ERROR_GENERIC;
}

FILE_PTR* cc_enclave_get_fopen_auto_key(const char* filename, const char* mode){
    return get_fopen_auto_key_ex(filename, mode);
}
cc_enclave_result_t cc_enclave_get_fexport_auto_key(const char* filename, void *key){
    int32_t result = 1;
    result = get_fexport_auto_key_ex(filename, key);
    if(result == 0)
        return CC_SUCCESS;
    else return CC_ERROR_GENERIC;
}
cc_enclave_result_t cc_enclave_get_fimport_auto_key(const char* filename, void *key){
    int32_t result = 1;
    result = get_fimport_auto_key_ex(filename, key);
    if(result == 0)
        return CC_SUCCESS;
    else return CC_ERROR_GENERIC;
}
