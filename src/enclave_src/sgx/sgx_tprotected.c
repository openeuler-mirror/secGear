#include "file_tprotected.h"


SGX_FILE* internel_fopen(const char* filename, const char* mode, void *key){
    return sgx_fopen(filename, mode, key);
}

size_t internel_fwrite(const void* ptr, size_t size, size_t count, SGX_FILE* stream){
    return sgx_fwrite(ptr, size, count, stream);
}

size_t internel_fread(void* ptr, size_t size, size_t count, SGX_FILE* stream){
    return sgx_fread(ptr, size, count, stream);
}



int32_t internel_fclose(SGX_FILE* stream){
    return sgx_fclose(stream);
}
int32_t internel_remove(const char* filename){
    return sgx_remove(filename);
}


SGX_FILE* internel_fopen_auto_key(const char* filename, const char* mode){
    return sgx_fopen_auto_key(filename, mode);
}
int32_t internel_fexport_auto_key(const char* filename, void *key){
    return sgx_fexport_auto_key(filename, key);
}
int32_t internel_fimport_auto_key(const char* filename, void *key){
    return sgx_fimport_auto_key(filename, key);
}
