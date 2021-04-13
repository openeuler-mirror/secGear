# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

# steps to build example image:
# 1. build the secGear project at host
# 	# cd secGear/
# 	# source environment
# 	# source /opt/intel/sgxsdk/environment
# 	# mkdir debug && cd debug
#	# cmake -DCMAKE_BUILD_TYPE=Debug -DCC_SGX=ON -DSGXSDK=/opt/intel/sgxsdk ..
# 	# make 
# 2. build the example image
# 	# cd ../examples/lrt/
# 	# docker build -t secgear_hello -f ./Dockerfile ../../


FROM hub.oepkgs.net/lifeng2221dd1/sgx_base_hw:latest

COPY debug/lib/sgx/libsgx_0.so /lib64/
COPY debug/lib/libsecgear.so /usr/lib/
COPY debug/examples/lrt/host/secgear_lrt /home/
COPY debug/examples/lrt/enclave/enclave.signed.so /home/

WORKDIR /home

ENTRYPOINT ["/home/secgear_lrt"]
