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
    echo "-a <parameter>  API_LEVEL, indicates trustzone GP API version, defalut is 1."
    echo "-c <file>       basic config file."
    echo "-d <parameter>  sign tool command, sign/digest."
    echo "                The sign command is used to generate a signed enclave."
    echo "                The digest command is used to generate a digest value."
    echo "-f <parameter>  OTRP_FLAG, indicates whether the OTRP standard protocol is supported, default is 0."
    echo "-i <file>       enclave to be signed."
    echo "-k <file>       private key required for single-step method, required when trustzone TA_TYPE is 2 or sgx."
    echo "-m <file>       additional config for trustzone when TA_TYPE is 2."
    echo "-o <file>       output parameters, the sign command outputs sigend enclave, the digest command outputs"
    echo "                digest value."
    echo "-p <file>       signing server public key certificate, required for two-step method."
    echo "-s <file>       the signed digest value required for two-step method, this parameter is empty to indicate"
    echo "                single-step method."
    echo "-t <parameter>  trustzone TA_TYPE, default is 1."
    echo "-x <parameter>  enclave type, sgx or trustzone."
    echo "-h              printf help message."

}

while getopts "d:i:x:m:a:f:t:c:k:p:s:o:h" opt
do
    case $opt in
        d)
        if [[ $OPTARG == -* ]]; then
            echo "Error: parameter for -d is missing or incorrect"
            exit -1
        fi
        typeset -l CMD
        CMD=$OPTARG
        ;;
        i)
        if [[ $OPTARG == -* ]]; then
            echo "Error: parameter for -i is missing or incorrect"
            exit -1
        fi 
        IN_ENCLAVE=$OPTARG
        ;;
        x)
        if [[ $OPTARG == -* ]]; then
            echo "Error: parameter for -x is missing or incorrect"
            exit -1
        fi
        typeset -l ENCLAVE_TYPE
        ENCLAVE_TYPE=$OPTARG
        ;;
        m)
        if [[ $OPTARG == -* ]]; then
            echo "Error: parameter for -m is missing or incorrect"
            exit -1
        fi 
        A_CONFIG_FILE=$OPTARG
        ;;
        a)
        if [[ $OPTARG =~ ^[1-3]$ ]]; then
            API_LEVEL=$OPTARG
        else
            if [[ $OPTARG == -* ]]; then
                echo "Error: parameter for -a is missing or incorrect"
                exit -1
            fi 
            echo "Error: illegal API LEVEL"
            exit -1
        fi
        ;;
        f)
        if [[ $OPTARG =~ ^[0-1]$ ]]; then
            OTRP_FLAG=$OPTARG
        else
            if [[ $OPTARG == -* ]]; then
                echo "Error: parameter for -f is missing or incorrect"
                exit -1
            fi 
            echo "Error: illegal OTRP FLAG"
            exit -1
        fi
        ;;
        t)
        if [[ $OPTARG =~ ^[1-2]$ ]]; then
            TA_TYPE=$OPTARG
        else
            if [[ $OPTARG == -* ]]; then
                echo "Error: parameter for -t is missing or incorrect"
                exit -1
            fi 
            echo "Error: illegal TA TYPE"
            exit -1
        fi
        ;;
        c)
        if [[ $OPTARG == -* ]]; then
            echo "Error: parameter for -c is missing or incorrect"
            exit -1
        fi 
        CONFIG_FILE=$OPTARG
        ;;
        k)
        if [[ $OPTARG == -* ]]; then
            echo "Error: parameter for -k is missing or incorrect"
            exit -1
        fi 
        SIG_KEY=$OPTARG
        ;;
        p)
        if [[ $OPTARG == -* ]]; then
            echo "Error: parameter for -p is missing or incorrect"
            exit -1
        fi 
        SERVER_PUBKEY=$OPTARG
        ;;
        s)
        if [[ $OPTARG == -* ]]; then
            echo "Error: parameter for -s is missing or incorrect"
            exit -1
        fi 
        SIGNATURE=$OPTARG
        ;;
        o)
        if [[ $OPTARG == -* ]]; then
            echo "Error: parameter for -o is missing or incorrect"
            exit -1
        fi 
        OUT_FILE=$OPTARG
        ;;
        h)
        print_help
        exit 0
        ;;
        ?)
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
    MANIFEST=$CONFIG_FILE
    if [ -z $MANIFEST ]; then
        echo "Error: missing config file for signing iTrustee enclave"
        exit -1
    fi

    if [ ${TA_TYPE} == 2 ]; then
        if [ -z $A_CONFIG_FILE]; then
            echo "Error: TA TYPE = 2, missing additional config file for signing iTrustee enclave"
            exit -1
        fi
    else
        A_CONFIG_FILE="NULL"
    fi
    DEVICE_PUBKEY=${localpath}/rsa_public_key_cloud.pem

    if [ "${CMD}"x == "sign"x ]; then
        if [ -z $SIGNATURE ]; then
            DEBUG=1
            if [ -z $SIG_KEY ] && [ ${TA_TYPE} == 2 ]; then
                echo "missing the signature private key"
                exit -1
            fi
            python ${localpath}/sign_tool.py "sign" "${DEBUG}" "${IN_ENCLAVE}" "${OUT_FILE}" "${MANIFEST}" "${OTRP_FLAG}" "${TA_TYPE}" "${API_LEVEL}" "${DEVICE_PUBKEY}" "${A_CONFIG_FILE}" "${SIG_KEY}"
        else
            DEBUG=0
            if [ -z $SERVER_PUBKEY ]; then
                echo "Error: missing server public key for verifying signature"
                exit -1
            fi
            python ${localpath}/sign_tool.py "sign" "${DEBUG}" "${IN_ENCLAVE}" "${OUT_FILE}" "${MANIFEST}" "${OTRP_FLAG}" "${TA_TYPE}" "${API_LEVEL}" "${DEVICE_PUBKEY}" "${A_CONFIG_FILE}" "${SIGNATURE}" "${SERVER_PUBKEY}"
        fi
    elif [ "${CMD}"x == "digest"x ]; then
        DEBUG=0
        python ${localpath}/sign_tool.py "digest" "${DEBUG}" "${IN_ENCLAVE}" "${OUT_FILE}" "${MANIFEST}" "${OTRP_FLAG}" "${TA_TYPE}" "${API_LEVEL}" "${DEVICE_PUBKEY}" "${A_CONFIG_FILE}"
    else
        echo "Error: illegal command"
    fi
}

sgx_start_sign(){
    SIGDATA_FILE="signdata"
    if [ "${CMD}"x == "sign"x ]; then
        if [ -z $SIG_KEY ]; then
            echo "Error: missing sign key"
            exit -1
        fi  
        if [ -z $SIGNATURE ]; then
            if [ -z $CONFIG_FILE ]; then
                sgx_sign sign -enclave ${IN_ENCLAVE} -key ${SIG_KEY} -out ${OUT_FILE}
            else
                sgx_sign sign -enclave ${IN_ENCLAVE} -key ${SIG_KEY} -out ${OUT_FILE} -config ${CONFIG_FILE}
            fi
        else
            if [ -z $SERVER_PUBKEY ]; then
                echo "Error: missing server public key"
                exit -1
            fi  
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
        echo "Error: illegal command"
    fi
}


if [ -z $CMD ]; then
    echo "Error: missing command"
    exit -1
fi
if [ -z $ENCLAVE_TYPE ]; then
    echo "Error: missing enclave type"
    exit -1
fi
if [ -z $IN_ENCLAVE ]; then
    echo "Error: missing enclave file"
    exit -1
fi
if [ -z $OUT_FILE ]; then
    echo "Error: missing out file"
    exit -1
fi
umask 0077
check_results=`uname -m`
if [ "${ENCLAVE_TYPE}"x == "sgx"x ]; then
    if [ "${check_results}"x != "x86_64"x ]; then
        echo "Warning: the enclave type does not comply with current architecture"
    fi
    sgx_start_sign
elif [ "${ENCLAVE_TYPE}"x == "trustzone"x ]; then
    if [ "${check_results}"x != "aarch64"x ]; then
        echo "Warning: the enclave type does not comply with current architecture"
    fi
    itrustee_start_sign
else
    echo "Error: illegal enclave type"
    exit -1
fi
