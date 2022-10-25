#include "file_tprotected.h"
#include "tee_mem_mgmt_api.h"
#include "tee_trusted_storage_api.h"
#include "tee_defines.h"


uint32_t storageID = TEE_OBJECT_STORAGE_PRIVATE;
uint32_t r_flags   = TEE_DATA_FLAG_ACCESS_READ;
uint32_t w_flags   = TEE_DATA_FLAG_ACCESS_WRITE;
const void *create_objectID = "store_data_sample.txt";



ITRUSTEE_FILE* internel_fopen(const char* filename, const char* mode, void *key){
    return CC_ERROR_SERVICE_NOT_EXIST;
}

size_t internel_fwrite(const void* ptr, size_t size, size_t count, ITRUSTEE_FILE* stream){
    TEE_Result ret;
    char *write_buffer = (char *)ptr;

    ret = TEE_WriteObjectData(stream, write_buffer, count);
    if (ret != TEE_SUCCESS){
        TEE_CloseObject(stream);
        return TEE_FAIL;
    }
    else return TEE_SUCCESS;
}

size_t internel_fread(void* ptr, size_t size, size_t count, ITRUSTEE_FILE* stream){
    TEE_Result ret;
    uint32_t read_count = (uint32_t)count;

    ptr = TEE_Malloc(size + 1, 0);
    if (ptr == NULL) {
        TEE_CloseObject(stream);
        return TEE_FAIL;
    }

    ret = TEE_ReadObjectData(stream, ptr, size, &read_count);
    if (ret != TEE_SUCCESS) {
        TEE_CloseObject(stream);
        TEE_Free(ptr);
        return TEE_FAIL;
    }

    TEE_Free(ptr);
    return TEE_SUCCESS;
}



int32_t internel_fclose(ITRUSTEE_FILE* stream){
    TEE_CloseObject(stream);
    return TEE_SUCCESS;
}
int32_t internel_remove(const char* filename)
{
    return CC_ERROR_SERVICE_NOT_EXIST;
}


ITRUSTEE_FILE* internel_fopen_auto_key(const char* filename, const char* mode){
    uint32_t real_mode;
    TEE_Result ret;
    create_objectID = filename;
    TEE_ObjectHandle persistent_data = NULL;
    
    if(0 == strcmp("w",mode))
        real_mode = w_flags;
    else if(0 == strcmp("r",mode))
        real_mode = r_flags;
    else
        return NULL;

    ret = TEE_CreatePersistentObject(storageID, create_objectID, strlen(create_objectID), real_mode, TEE_HANDLE_NULL, NULL, 0, (&persistent_data));
    if (ret != TEE_SUCCESS) {
        return NULL;
    }
    else return persistent_data;
}

int32_t internel_fexport_auto_key(const char* filename, void *key)
{
    return CC_ERROR_SERVICE_NOT_EXIST;
}
int32_t internel_fimport_auto_key(const char* filename, void *key)
{
    return CC_ERROR_SERVICE_NOT_EXIST;
}