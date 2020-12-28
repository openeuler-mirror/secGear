# Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
# secGear is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

#!/bin/bash
VERSION=3
TA_TYPE=1
OTRP_FLAG=0
API_LEVEL=1
DEBUG=0

localpath="$(cd "$(dirname "$0")"; pwd)"

print_help(){
    echo "sign tool usage: ./sign_tool.sh [options] ..."
    echo "[options]"
    echo "-d <parameter>: sign tool command, sign/digest."
    echo "                The sign command is used to generate a signed enclave."
    echo "                The digest command is used to generate a digest value."
    echo "-i <file>:      enclave to be signed."
    echo "-x <parameter>: enclave type, 1: SGX, 2:trustzone."
    echo "-m <file>:      manifest file, required by trustzone."
    echo "-a <parameter>: API_LEVEL, indicates trustzone GP API version, defalut is 1."
    echo "-f <parameter>: OTRP_FLAG, indicates whether the OTRP standard protocol is supported, default is 0."
    echo "-t <parameter>: trustzone TA_TYPE, default is 1."
    echo "-c <file>:      config file."
    echo "-k <file>:      private key required for single-step method, required when trustzone TA_TYPE is 2 or SGX."
    echo "-p <file>:      signing server public key certificate, required for two-step method."
    echo "-s <file>:      the signed digest value required for two-step method, this parameter is empty to indicate single-step method."
    echo "-e <file>:      the device's public key certificate, used to protect the AES key of the encrypted rawdata, required by trustzone."
    echo "-o <file>:      output parameters, the sign command outputs sigend enclave, the digest command outpus digest value."
    echo "-h:             printf help message."
}

while getopts "d:i:x:m:a:f:t:c:e:k:p:s:o:h" opt
do
    case $opt in
        d)
        typeset -l CMD
        CMD=$OPTARG
        ;;
        i)
        IN_ENCLAVE=$OPTARG
        ;;
        x)
        if [[ $OPTARG =~ ^[1-2]$ ]]; then
            ENCLAVE_TYPE=$OPTARG
        else
            echo "Error: illegal ENCLAVE TYPE"
        fi
        ;;
        m)
        MANIFIST=$OPTARG
        ;;
        a)
        if [[ $OPTARG =~ ^[1-3]$ ]]; then
            API_LEVEL=$OPTARG
        else
            echo "Error: illegal API LEVEL"
        exit -1
        fi
        ;;
        f)
        if [[ $OPTARG =~ ^[0-1]$ ]]; then
            OTRP_FLAG=$OPTARG
        else
            echo "Error: illegal OTRP FLAG"
            exit -1
        fi
        ;;
        t)
        if [[ $OPTARG =~ ^[1-2]$ ]]; then
            TA_TYPE=$OPTARG
        else
            echo "Error: illegal TA TYPE"
            exit -1
        fi
        ;;
        c)
        CONFIG_FILE=$OPTARG
        ;;
        e)
        DEVICE_PUBKEY=$OPTARG
        ;;
        k)
        SIG_KEY=$OPTARG
        ;;
        p)
        SERVER_PUBKEY=$OPTARG
        ;;
        s)
        SIGNATURE=$OPTARG
        ;;
        o)
        OUT_FILE=$OPTARG
        ;;
        h)
        print_help
        exit 0
        ;;
        ?)
        echo "ERROR: illegal parameter"
        print_help
        exit -1
    esac
done
if [ ${OPTIND} == 1 ]; then
    print_help
    exit 0
fi

itrustee_start_sign(){
#    check_native_sign
    if [ -z $IN_ENCLAVE ]; then
        echo "ERROR: missing enclave file"
        exit -1
    fi
    if [ -z $OUT_FILE ]; then
        echo "ERROR: missing out file"
        exit -1
    fi
    if [ -z $MANIFIST ]; then
        echo "ERROR: missing manifest file for signing iTrustee enclave"
        exit -1
    fi
    if [ -z $DEVICE_PUBKEY ]; then
        echo "ERROR: missing device pubkey for signing iTrustee enclave"
        exit -1
    fi

    if [ ${TA_TYPE} == 2 ]; then
        if [ -z $CONFIG_FILE]; then
            echo "ERROR: TA TYPE = 2,missing config file for signing iTrustee enclave"
            exit -1
        fi
    else
        CONFIG_FILE="NULL"
    fi

    if [ "${CMD}"x == "sign"x ]; then
        if [ -z $SIGNATURE ]; then
            DEBUG=1
            if [ -z $SIG_KEY ] && [ ${TA_TYPE} == 2 ]; then
                echo "missing the signature private key"
                exit -1
            fi
            python ${localpath}/sign_tool.py "sign" "${DEBUG}" "${IN_ENCLAVE}" "${OUT_FILE}" "${MANIFIST}" "${OTRP_FLAG}" "${TA_TYPE}" "${API_LEVEL}" "${DEVICE_PUBKEY}" "${CONFIG_FILE}" "${SIG_KEY}"
        else
            DEBUG=0
            if [ -z $SERVER_PUBKEY ]; then
                echo "ERROR: missing server public key for verifying signature"
                exit -1
            fi
            python ${localpath}/sign_tool.py "sign" "${DEBUG}" "${IN_ENCLAVE}" "${OUT_FILE}" "${MANIFIST}" "${OTRP_FLAG}" "${TA_TYPE}" "${API_LEVEL}" "${DEVICE_PUBKEY}" "${CONFIG_FILE}" "${SIGNATURE}" "${SERVER_PUBKEY}"
        fi
    elif [ "${CMD}"x == "digest"x ]; then
        DEBUG=0
        python ${localpath}/sign_tool.py "digest" "${DEBUG}" "${IN_ENCLAVE}" "${OUT_FILE}" "${MANIFIST}" "${OTRP_FLAG}" "${TA_TYPE}" "${API_LEVEL}" "${DEVICE_PUBKEY}" "${CONFIG_FILE}"
    else
        echo "ERROR: illegal command"
    fi
}

sgx_start_sign(){
    if [ -z $OUT_FILE ]; then
        echo "ERROR: missing out file"
        exit -1
    fi
    SIGDATA_FILE="signdata"
    if [ "${CMD}"x == "sign"x ]; then
        if [ -z $SIGNATURE ]; then
            if [ -z $CONFIG_FILE ]; then
                sgx_sign sign -enclave ${IN_ENCLAVE} -key ${SIG_KEY} -out ${OUT_FILE}
            else
                sgx_sign sign -enclave ${IN_ENCLAVE} -key ${SIG_KEY} -out ${OUT_FILE} -config ${CONFIG_FILE}
            fi
        else
            if [ -z $CONFIG_FILE ]; then
                sgx_sign catsig -enclave ${IN_ENCLAVE} -key ${SERVER_PUBKEY} -sig ${SIGNATURE} -unsignd ${SIGDATA_FILE} -out ${OUT_FILE}
            else
                sgx_sign catsig -enclave ${IN_ENCLAVE} -key ${SERVER_PUBKEY} -sig ${SIGNATURE} -unsignd ${SIGDATA_FILE} -out ${OUT_FILE} -config ${CONFIG_FILE}
            fi
            rm -rf ${SIGDATA_FILE}
        fi
    elif [ "${CMD}"x == "digest"x ]; then
        if [ -z $CONFIG_FILE ]; then
            sgx_sign gendata -enclave ${IN_ENCLAVE} -out ${SIGDATA_FILE}
        else
            sgx_sign gendata -enclave ${IN_ENCLAVE} -out ${SIGDATA_FILE} -config ${CONFIG_FILE}
        fi
        openssl dgst -sha256 -out ${OUT_FILE} ${SIGDATA_FILE}
    else
        echo "ERROR: illegal command"
    fi
}

echo "ENCLAVE TYPE: ${ENCLAVE_TYPE}"

if [ "${ENCLAVE_TYPE}"x == "1"x ]; then
    sgx_start_sign
elif [ "${ENCLAVE_TYPE}"x == "2"x ]; then
    itrustee_start_sign
else
    echo "ERROR: illegal ENCLAVE TYPE"
    exit -1
fi
