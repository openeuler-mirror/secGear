#!/usr/bin/env python
# coding:utf-8
#----------------------------------------------------------------------------
# Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
# iTrustee licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# Description: tools for generating a trusted application load image
# Author: Li mingjuan
# Create: 2018-02-20
#----------------------------------------------------------------------------

import struct
import os
import sys
import stat
import hashlib
import binascii
import subprocess
import shutil
import getpass
import argparse

try:
    from configparser import SafeConfigParser
except ImportError:
    from ConfigParser import SafeConfigParser

from manifest import parser_manifest
from generate_signature import gen_ta_signature
from generate_signature import gen_hash

# fixed value, {1, 2} version are abandoned.
VERSION = 3
TA_VERSION = 3

MAX_EXT_PROP_LEN = 152

MAGIC1 = 0xA5A55A5A
MAGIC2 = 0x55AA

# ELF Definitions
ELF_TYPE = 32
ELF_HDR_SIZE = 52
ELF_PHDR_SIZE = 32
ELF_INFO_MAGIC0_INDEX = 0
ELF_INFO_MAGIC1_INDEX = 1
ELF_INFO_MAGIC2_INDEX = 2
ELF_INFO_MAGIC3_INDEX = 3
#'\x7f'
ELF_INFO_MAGIC0 = 127
#'E'
ELF_INFO_MAGIC1 = 69
#'L'
ELF_INFO_MAGIC2 = 76
#'F'
ELF_INFO_MAGIC3 = 70
ELF_INFO_CLASS_INDEX = 4
ELF_INFO_CLASS_32 = 1
ELF_INFO_CLASS_64 = 2
ELF_INFO_VERSION_INDEX = 6
ELF_INFO_VERSION_CURRENT = 1
ELF_BLOCK_ALIGN = 0x1000


#----------------------------------------------------------------------------
# Verify ELF header contents from an input ELF file
#----------------------------------------------------------------------------
def verify_elf_header(elf_path):
    elf_type = 0
    with open(elf_path, 'rb') as elf:
        elf_data = struct.unpack('B'*16, elf.read(16))
        elf_type = elf_data[4]
        if ((elf_data[ELF_INFO_MAGIC0_INDEX] != ELF_INFO_MAGIC0) or \
                (elf_data[ELF_INFO_MAGIC1_INDEX] != ELF_INFO_MAGIC1) or \
                (elf_data[ELF_INFO_MAGIC2_INDEX] != ELF_INFO_MAGIC2) or \
                (elf_data[ELF_INFO_MAGIC3_INDEX] != ELF_INFO_MAGIC3) or \
                (elf_data[ELF_INFO_VERSION_INDEX] != \
                ELF_INFO_VERSION_CURRENT)):
            print("invalid elf header info")
            raise RuntimeError

        if ((elf_type == 1 and elf_data[ELF_INFO_CLASS_INDEX] != \
                ELF_INFO_CLASS_32) or \
                (elf_type == 2 and elf_data[ELF_INFO_CLASS_INDEX] != \
                ELF_INFO_CLASS_64) or \
                (elf_type != 1 and elf_type != 2)):
            print("invliad elf format")
            raise RuntimeError
    return


class Configuration:
    release_type = 0
    otrp_flag = 0
    sign_type = 0
    public_key = ""
    pub_key_len = 0
    server_ip = ""
    config_path = ""
    sign_key = ""
    sign_key_len = 2048
    hash_type = 0
    padding_type = 0

    def __init__(self, file_name):
        parser = SafeConfigParser()
        parser.read(file_name)
        self.release_type = parser.get("config", "releaseType")
        self.otrp_flag = parser.get("config", "otrpFlag")
        self.sign_type = parser.get("config", "signType")
        self.public_key = parser.get("config", "encryptKey")
        self.pub_key_len = parser.get("config", "encryptKeyLen")
        self.server_ip = parser.get("config", "serverIp")
        self.config_path = parser.get("config", "configPath")
        self.sign_key = parser.get("config", "signKey")
        self.sign_key_len = parser.get("config", "signKeyLen")
        self.hash_type = parser.get("config", "hashType")
        self.padding_type = parser.get("config", "paddingType")


def gen_header(content_len, key_version):
    return struct.pack('IHHII', MAGIC1, MAGIC2, VERSION, content_len, \
            key_version)


def gen_aes_key_info(cfg, iv_file_path, key_file_path, out_file_path):
    rand_iv_cmd = "openssl rand -out {} 16".format(iv_file_path)
    rand_key_cmd = "openssl rand -out {} 32".format(key_file_path)
    try:
        subprocess.check_output(rand_iv_cmd.split(), shell=False)
        subprocess.check_output(rand_key_cmd.split(), shell=False)
    except Exception:
        print("rand operation failed")
        raise RuntimeError

    os.chmod(iv_file_path, stat.S_IWUSR | stat.S_IRUSR)
    os.chmod(key_file_path, stat.S_IWUSR | stat.S_IRUSR)

    sign_alg = 0
    sign_alg = sign_alg | (int(cfg.release_type) << 28)
    sign_alg = sign_alg | (int(cfg.padding_type) << 27)
    sign_alg = sign_alg | (int(cfg.hash_type) << 26)
    if cfg.sign_key_len == "2048":
        sign_alg = sign_alg | 0x00002048
    elif cfg.sign_key_len == "4096":
        sign_alg = sign_alg | 0x00004096

    print("sign_alg value is 0x%x" % sign_alg)
    with open(out_file_path, 'wb') as out_file:
        out_file.write(struct.pack('I', 32))
        out_file.write(struct.pack('I', 16))
        out_file.write(struct.pack('I', sign_alg))

        with open(key_file_path, 'rb') as key_file:
            out_file.write(key_file.read(32))

        with open(iv_file_path, 'rb') as iv_file:
            out_file.write(iv_file.read(16))

    os.chmod(out_file_path, stat.S_IWUSR | stat.S_IRUSR)
    return


def encrypt_aes_key(pubkey_path, in_path, out_path):
    cmd = "openssl rsautl -encrypt -pubin -oaep -inkey {} -in {} -out {}". \
        format(pubkey_path, in_path, out_path)
    try:
        subprocess.check_output(cmd.split(), shell=False)
    except Exception:
        print("RSA encrypt operation failed")
        raise RuntimeError
    os.chmod(out_path, stat.S_IWUSR | stat.S_IRUSR)
    return

def gen_signature(cfg, uuid_str, raw_data_path, hash_file_path, out_file_path):
    gen_ta_signature(cfg, uuid_str, raw_data_path, hash_file_path, out_file_path)
    os.chmod(out_file_path, stat.S_IWUSR | stat.S_IRUSR)
    return

def gen_raw_data(manifest_data_path, manifest_ext_path, elf_file_path, \
        config_path, raw_file_path):
    manifest_size = os.path.getsize(manifest_data_path)
    manifest_ext_size = os.path.getsize(manifest_ext_path)
    elf_size = os.path.getsize(elf_file_path)
    config_size = 0

    if manifest_ext_size > MAX_EXT_PROP_LEN:
        print("too much data in \"manifest.txt\" to be handled. \
                extra string len %d" \
                % manifest_ext_size)
        raise RuntimeError

    verify_elf_header(elf_file_path)

    with open(raw_file_path, 'wb') as file_op:
        header = ""
        if os.path.isfile(config_path):
            config_size = os.path.getsize(config_path)
        header = struct.pack('IIIII', TA_VERSION, manifest_size, \
                manifest_ext_size, \
                elf_size, config_size)
        file_op.write(header)

        with open(manifest_data_path, 'rb') as manifest_data:
            file_op.write(manifest_data.read(manifest_size))

        with open(manifest_ext_path, 'rb') as manifest_ext:
            file_op.write(manifest_ext.read(manifest_ext_size))

        with open(elf_file_path, 'rb') as elf:
            file_op.write(elf.read(elf_size))
        if config_size != 0:
            with open(config_path, 'rb') as config:
                file_op.write(config.read(config_size))
    return


def aes_encrypt(key_path, iv_path, in_file_path, out_file_path):
    key_size = os.path.getsize(key_path)
    with open(key_path, 'rb') as key_file:
        key_data = key_file.read(key_size)
    hex_key_str = binascii.b2a_hex(key_data)

    iv_size = os.path.getsize(iv_path)
    with open(iv_path, 'rb') as iv_file:
        iv_data = iv_file.read(iv_size)
    hex_iv_str = binascii.b2a_hex(iv_data)

    cmd = "openssl enc -aes-256-cbc  -in {}  -out {}  -K {} -iv {}".\
                 format(in_file_path, out_file_path, \
                 bytes.decode(hex_key_str), bytes.decode(hex_iv_str))
    try:
        subprocess.check_output(cmd.split(), shell=False)
    except Exception:
        print("AES encrypt operation failed")
        raise RuntimeError

    os.chmod(out_file_path, stat.S_IWUSR | stat.S_IRUSR)
    return

def update_api_level(api_level, manifest):
    data = ''
    with open(manifest, 'r') as file_op:
        for line in file_op:
            if line.startswith("#") or not "gpd.ta.api_level" in line:
                data += line
    line = "\ngpd.ta.api_level:{}\n".format(api_level)
    data += line
    with open(manifest, "w") as file_op:
        file_op.writelines(data)


def update_otrp_flag(manifest):
    data = ''
    with open(manifest, 'r') as file_op:
        for line in file_op:
            if line.startswith("#") or not "gpd.ta.otrp_flag" in line:
                data += line
    line = "\ngpd.ta.otrp_flag:{}\n".format('true')
    data += line
    with open(manifest, "w") as file_op:
        file_op.writelines(data)


def gen_data_for_sign(header, key_info, raw_file, data_sign):
    key_info_len = os.path.getsize(key_info)
    raw_file_len = os.path.getsize(raw_file)

    with open(data_sign, 'wb') as data_fp, \
            open(key_info, 'rb') as key_fp, open(raw_file, 'rb') as raw_fp:
        data_fp.write(header)
        data_fp.write(key_fp.read(key_info_len))
        data_fp.write(raw_fp.read(raw_file_len))


def gen_key_version(cfg):
    if cfg.pub_key_len == '3072':
        return int(0x0202)
    if cfg.pub_key_len == '2048':
        return int(0x0002)
    print("unhandled pulic key len %s" % cfg.pub_key_len)
    raise RuntimeError


def generate_digest(cfg, api_level, enclave_file,  manifest_file, hash_path, enc_key_path, enc_raw_path):
    # temporary files
    in_path = os.path.dirname(os.path.abspath(manifest_file))
    temp_path = os.path.join(in_path, "temp")
    shutil.rmtree(temp_path, ignore_errors=True)
    os.mkdir(temp_path)
    os.chmod(temp_path, stat.S_IRWXU)
    iv_file_path = os.path.join(temp_path, "iv.bin")
    key_file_path = os.path.join(temp_path, "aeskey.bin")
    key_info_path = os.path.join(temp_path, "KeyInfo")
    raw_file_path = os.path.join(temp_path, "rawData")
    manifest_data_path = os.path.join(temp_path, "manifestData.bin")
    manifest_ext_path = os.path.join(temp_path, "manifestExt.bin")
    data_for_sign_path = os.path.join(temp_path, "dataForSign.bin")
    signature_path = os.path.join(temp_path, "signature.bin")

    # mandentory input files
    manifest_path = manifest_file
    elf_file_path = enclave_file
    
    ret, product_name = parser_manifest(manifest_path, \
            manifest_data_path, manifest_ext_path)
    if ret is False:
        raise RuntimeError

    update_api_level(api_level, manifest_ext_path)

    if cfg.otrp_flag == 1:
        print("package otrp sec file\n")
        update_otrp_flag(manifest_ext_path)

    gen_raw_data(manifest_data_path, manifest_ext_path, elf_file_path, \
            cfg.config_path, raw_file_path)

    # generate AES key info to encrypt raw data
    gen_aes_key_info(cfg, iv_file_path, key_file_path, key_info_path)
    encrypt_aes_key(cfg.public_key, key_info_path, enc_key_path)

    aes_encrypt(key_file_path, iv_file_path, raw_file_path, enc_raw_path)

    # generate Main Header
    content_len = os.path.getsize(enc_key_path) + \
            (int(cfg.sign_key_len) / 8) + \
            os.path.getsize(enc_raw_path)
    key_version = gen_key_version(cfg)
    header = gen_header(int(content_len), key_version)

    gen_data_for_sign(header, key_info_path, raw_file_path, data_for_sign_path)
    
    gen_hash(cfg.hash_type, data_for_sign_path, hash_path)
    
    #remove temp files
    os.remove(iv_file_path)
    os.remove(key_file_path)
    os.remove(key_info_path)
    os.remove(raw_file_path)
    os.remove(manifest_data_path)
    os.remove(manifest_ext_path)
    os.remove(data_for_sign_path)
    return

def gen_sec_image(cfg, enc_raw_path, enc_key_path, signature_path, out_file):
    content_len = os.path.getsize(enc_key_path) + \
            (int(cfg.sign_key_len) / 8) + \
            os.path.getsize(enc_raw_path)
    key_version = gen_key_version(cfg)
    header = gen_header(int(content_len), key_version)
    sec_img_path = out_file
    with open(sec_img_path, 'wb') as sec_image:
        # write to sec file [1.header info]
        sec_image.write(header)
        # write to sec file [2.AES key info]
        enc_key_size = os.path.getsize(enc_key_path)
        with open(enc_key_path, 'rb') as enc_key_info:
            sec_image.write(enc_key_info.read(enc_key_size))
        # write to sec file [3.signature]
        signature_size = os.path.getsize(signature_path)
        with open(signature_path, 'rb') as signature_file:
            sec_image.write(signature_file.read(signature_size))
        # write to sec file [4.encrypted raw data]
        enc_raw_size = os.path.getsize(enc_raw_path)
        with open(enc_raw_path, 'rb') as enc_raw_data:
            sec_image.write(enc_raw_data.read(enc_raw_size))

    print("=========================SUCCESS============================")
    print("generate TA(V3 format) load image success: ")
    print(sec_img_path)
    print("============================================================")

    return


def main():
    argvs = sys.argv
    cmd = argvs[1]
    one_step_mode = int(argvs[2])
    enclave_path = argvs[3]
    out_file = argvs[4]
    manifest_file = argvs[5]
    cloud_config = argvs[6]
    cfg = Configuration(cloud_config)
    api_level = int(argvs[7])

    os.umask(127)
    
    in_path = os.path.dirname(os.path.abspath(cloud_config))
    temp_path = os.path.join(in_path, "temp")
    enc_key_path = os.path.join(temp_path, "KeyInfo.enc")
    enc_raw_path = os.path.join(temp_path, "rawData.enc")
    hash_path = os.path.join(temp_path, "rawDataHash.bin")
    temp_signature = os.path.join(temp_path, "tempSignature")
    
    sign_tool_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(sign_tool_dir)    
    if cmd == "digest":
        generate_digest(cfg, api_level, enclave_path, manifest_file, hash_path, enc_key_path, enc_raw_path)
        shutil.copy(hash_path, out_file)
    elif cmd == "sign":
        if one_step_mode == 0:
            in_signature = argvs[8]
            gen_sec_image(cfg, enc_raw_path, enc_key_path, in_signature, out_file)
        else:
            generate_digest(cfg,  api_level, enclave_path, manifest_file, hash_path, enc_key_path, enc_raw_path)
            gen_ta_signature(cfg, hash_path, temp_signature)
            in_signature = temp_signature
            gen_sec_image(cfg, enc_raw_path, enc_key_path, in_signature, out_file)
            os.remove(temp_signature)
        os.remove(enc_key_path)
        os.remove(enc_raw_path)
        os.remove(hash_path)   
        #remove temp files
        shutil.rmtree(temp_path)


if __name__ == '__main__':
    main()

