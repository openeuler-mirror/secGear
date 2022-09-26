#include "file_tprotected.h"

sgx_key_128bit_t *file_key;


SGX_FILE* get_fopen_ex(const char* filename, const char* mode){
    return sgx_fopen(filename, mode, file_key);
}

size_t internel_fwrite_data(const void* ptr, size_t size, size_t count, SGX_FILE* stream){
    return sgx_fwrite(ptr, size, count, stream);
}

size_t internel_fread_data(void* ptr, size_t size, size_t count, SGX_FILE* stream){
    return sgx_fread(ptr, size, count, stream);
}



int32_t get_fclose_ex(SGX_FILE* stream){
    return sgx_fclose(stream);
}
int32_t get_remove_ex(const char* filename){
    return sgx_remove(filename);
}


SGX_FILE* get_fopen_auto_key_ex(const char* filename, const char* mode){
    return sgx_fopen_auto_key(filename, mode);
}
int32_t get_fexport_auto_key_ex(const char* filename, void *key){
    file_key = (sgx_key_128bit_t *)key;
    return sgx_fexport_auto_key(filename, file_key);
}
int32_t get_fimport_auto_key_ex(const char* filename, void *key){
    file_key = (sgx_key_128bit_t *)key;
    return sgx_fimport_auto_key(filename, file_key);
}
