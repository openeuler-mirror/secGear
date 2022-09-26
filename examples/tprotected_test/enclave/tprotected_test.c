/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * secGear is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <stdio.h>
#include <string.h>
#include "tprotected_test_t.h"
#include "secgear_file_tprotected.h"

#define BUF_MAX 128

int read_string(char *filename,char *str)
{
	 void *flie_ptr = NULL;
	 char str_r[BUF_MAX];

	 PrintInfo(0, "Open file\n");
	 flie_ptr = cc_enclave_get_fopen_auto_key(filename, "r");
	 if(flie_ptr == NULL){
		PrintInfo(0, "Open file error\n");
		strncpy(str, "File_Fail", strlen("File_Fail") + 1);
	 	return CC_FAIL;
	 }
	 PrintInfo(0, "Read file\n");
	 cc_enclave_fread_data(str_r,sizeof(char),strlen("File_SUCCESS") + 1, flie_ptr);
	 cc_enclave_get_fclose(flie_ptr);

    strncpy(str, str_r, strlen(str_r) + 1);

    return 0;
}
int write_string(char *filename,char *str)
{
	 void *flie_ptr = NULL;

	 PrintInfo(0, "Create file\n");
	 flie_ptr = cc_enclave_get_fopen_auto_key(filename, "w");
	 if(flie_ptr == NULL){
		PrintInfo(0, "Create file error\n");
	 	return CC_FAIL;
	 }
	 PrintInfo(0, "Write file\n");
	 cc_enclave_fwrite_data(str,sizeof(char), strlen(str) + 1, flie_ptr);
	 cc_enclave_get_fclose(flie_ptr);

    return 0;
}
