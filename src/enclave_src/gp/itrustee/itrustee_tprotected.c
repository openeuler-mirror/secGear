#include "file_tprotected.h"


uint32_t storageID = TEE_OBJECT_STORAGE_PRIVATE;
uint32_t r_flags   = TEE_DATA_FLAG_ACCESS_READ;
uint32_t w_flags   = TEE_DATA_FLAG_ACCESS_WRITE;
const void *create_objectID = "store_data_sample.txt";
TEE_ObjectHandle persistent_data = NULL;

uint32_t select_mode(const char* mode);

uint32_t select_mode(const char* mode)
{
    if(mode == "w")
        return w_flags;
    else
        return r_flags;
}


ITRUSTEE_FILE* get_fopen_ex(const char* filename, const char* mode){
    uint32_t real_mode;
    TEE_Result ret;
    create_objectID = filename;
    real_mode = select_mode(mode);
    
    ret = TEE_OpenPersistentObject(storageID, create_objectID, strlen(create_objectID), real_mode, (&persistent_data));
    if (ret != TEE_SUCCESS) {
        return NULL;
    }
    return persistent_data;
}

size_t internel_fwrite_data(const void* ptr, size_t size, size_t count, ITRUSTEE_FILE* stream){
    TEE_Result ret;
    char *write_buffer = (char *)ptr;

    ret = TEE_WriteObjectData(stream, write_buffer, strlen(write_buffer));
    if (ret != TEE_SUCCESS){
        TEE_CloseObject(stream);
        return 1;
    }
    else return 0;
}

size_t internel_fread_data(void* ptr, size_t size, size_t count, ITRUSTEE_FILE* stream){
    uint32_t len = 0;
    uint32_t pos = 0;
    TEE_Result ret;
    char *read_buffer = NULL;
    char *write_buffer = (char *)ptr;
    uint32_t read_count = (uint32_t)count;

    ret = TEE_InfoObjectData(stream, &pos, &len);
    if (ret != TEE_SUCCESS) {
        TEE_CloseObject(stream);
        return 1;
    }
    read_buffer = TEE_Malloc(len + 1, 0);
    if (read_buffer == NULL) {
        TEE_CloseObject(stream);
        return 1;
    }

    ret = TEE_ReadObjectData(stream, read_buffer, len, &read_count);
    if (ret != TEE_SUCCESS) {
        TEE_CloseObject(stream);
        TEE_Free(read_buffer);
        return 1;
    }
    if (TEE_MemCompare(write_buffer, read_buffer, strlen(write_buffer)) != 0) {
        TEE_CloseObject(stream);

        TEE_Free(read_buffer);
        return 1;
    }

    ptr = read_buffer;
    TEE_Free(read_buffer);
    return 0;
}



int32_t get_fclose_ex(ITRUSTEE_FILE* stream){
    TEE_CloseObject(stream);
    return 0;
}


ITRUSTEE_FILE* get_fopen_auto_key_ex(const char* filename, const char* mode){
    uint32_t real_mode;
    TEE_Result ret;
    create_objectID = filename;
    real_mode = select_mode(mode);

    ret = TEE_CreatePersistentObject(storageID, create_objectID, strlen(create_objectID), real_mode, TEE_HANDLE_NULL, NULL, 0, (&persistent_data));
    if (ret != TEE_SUCCESS) {
        return NULL;
    }
    else return persistent_data;
}

int32_t get_remove_ex(const char* filename)
{
    return 0;
}
int32_t get_fexport_auto_key_ex(const char* filename, void *key)
{
    return 0;
}
int32_t get_fimport_auto_key_ex(const char* filename, void *key)
{
    return 0;
}