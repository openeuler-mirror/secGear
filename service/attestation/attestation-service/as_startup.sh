#!/usr/bin/env bash
DOCKER_TAR="openEuler-docker.aarch64.tar.xz"
OPENEULER_DOCKER_URL="http://121.36.84.172/dailybuild/EBS-openEuler-24.09/rc5_openeuler-2024-09-12-18-14-43/docker_img/aarch64/${DOCKER_TAR}"
IMAGE_NAME="openeuler-24.09"
CONTAINER_NAME="openeuler-2409"
PRIVATE_KEY="private.pem"
CSR="server.csr"
CERT="as_cert.pem"
DIR_TMP="tmp"
SERVICE_NAME="attestation-service"

generate_config() {
    if [ -d ${DIR_TMP} ]; then
        cd ${DIR_TMP} 
        if [ -a ${CERT} ] && [ -a ${PRIVATE_KEY} ]; then
            echo "configuration already exist in ${DIR_TMP}, reuse it"
            return
        else
            echo "${DIR_TMP} exist but broken, rename or delete it"
            exit 1
        fi
    fi
    mkdir ${DIR_TMP} 
    cd ${DIR_TMP}

    openssl genrsa -out ${PRIVATE_KEY} 2048
    openssl req -subj "/C=CN/ST=ST/L=CITY/O=Company/CN=test.com" -new -key ${PRIVATE_KEY} -out ${CSR} 
    openssl x509 -req -in ${CSR} -out ${CERT}  -signkey ${PRIVATE_KEY}  -days 3650

    echo "config files generated in ${DIR_TMP}"
}

setup() {
    mkdir -p /etc/attestation/attestation-agent/
    mkdir -p /etc/attestation/attestation-service/token
    cp ${CERT} /etc/attestation/attestation-agent/
    cp ${PRIVATE_KEY} /etc/attestation/attestation-service/token
    yum install secGear-as -y
}

as_start_in_host() {
    listen_at=$1
    setup
    /usr/bin/${SERVICE_NAME} -s ${listen_at} 2>&1 &
}

start_container() {
    wget -V||yum install wget
    docker -v||yum install docker
    docker images | grep -E "^${IMAGE_NAME}[ ]"
    if [ $? -ne 0 ]; then
        wget ${OPENEULER_DOCKER_URL}
        docker load -i ${DOCKER_TAR}
    fi

    docker ps -a | grep -E "\s${CONTAINER_NAME}$"
    if [ $? -eq 0 ]; then
        echo  "Error: container ${CONTAINER_NAME} already exist, please delete it or rename it"
        echo  -e "\tdelete command:docker rm ${CONTAINER_NAME} --force"
        echo  -e "\trename command:docker rename ${CONTAINER_NAME} {any_name_you_want}"
        exit 1
    fi
    docker run -d --name ${CONTAINER_NAME} --network host ${IMAGE_NAME}:latest /bin/bash -c "while true; do sleep 1;done"
}

setup_container() {
    docker exec  ${CONTAINER_NAME} mkdir -p /etc/attestation/attestation-agent/
    docker exec  ${CONTAINER_NAME} mkdir -p /etc/attestation/attestation-service/token
    docker cp ${CERT}  ${CONTAINER_NAME}:/etc/attestation/attestation-agent/
    docker cp ${PRIVATE_KEY}  ${CONTAINER_NAME}:/etc/attestation/attestation-service/token
    yum download kunpengsecl-attester kunpengsecl-qcaserver secGear-as cjson compat-openssl11-libs
    ls *.rpm | xargs -i docker cp {} ${CONTAINER_NAME}:/home
    docker exec ${CONTAINER_NAME} rpm -ivh /home/*.rpm
}

as_start_in_docker() {
    start_container
    setup_container
    docker exec -d ${CONTAINER_NAME} /bin/bash -c "/usr/bin/${SERVICE_NAME} -s ${listen_at} 2>&1"
}

start_attestation_service() {
    run_in=$1
    listen_at=$2
    generate_config
    if [[ ${run_in} == "host" ]]; then
        as_start_in_host ${listen_at}
    else
        as_start_in_docker ${listen_at}
    fi
    echo ${SERVICE_NAME} started ${listen_at}
}


print_usage() {
    echo "Usage: ./as_startup [-t docker|host] [-l 127.0.0.1:8080]"
    echo "example: ./as_startup run in host,listen at 127.0.0.1:8080 by default"
}

run_in=""
listen_at=""
while getopts "t:l:h" optname
    do
        case "$optname" in 
        "t")
            run_in="$OPTARG"
            echo "run in $run_in"
        ;;
        "l")
            listen_at="$OPTARG"
            echo "listen at $listen_at"
        ;;
        "h")
            print_usage
            exit 1
        ;;
        *)
            print_usage
            exit 1
        ;;
        esac
    done
if [[ ${run_in} == "" ]]; then
    run_in="host"
fi

if [[ ${listen_at} == "" ]]; then
    listen_at="127.0.0.1:8080"
fi

service_run=$(ps aux | grep "/usr/bin/${SERVICE_NAME}" | wc -l)
if [ ${service_run} -gt 1 ]; then
    echo "${SERVICE_NAME} already run"
    exit 1
fi

echo "${SERVICE_NAME} run in $run_in, listen at $listen_at"
start_attestation_service ${run_in} ${listen_at}
