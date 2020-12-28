#!/usr/bin/env python
# coding:utf-8
#----------------------------------------------------------------------------
# Copyright @ Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
# tools for generating a trusted application load image
#----------------------------------------------------------------------------

import struct
import sys
import os
import hashlib
import binascii
import subprocess
import shutil

from manifest import *

DEBUG      = 0
VERSION     = 3
TA_VERSION     = 3
# TA_TYPE 1 stand for v3.0
# TA_TYPE 2 stand for v3.1(with config and cert)
TA_TYPE    = 0

API_LEVEL = 1
PRODUCT_NAME = ""

# OTRP_FLAG 1 stand for otrp sec, and only can load sec by otrp mode
# OTRP_FLAG 0 stand for no-otrp sec, and only can load sec by tzdriver mode
OTRP_FLAG  = 0

MAGIC1         = 0xA5A55A5A
MAGIC2         = 0x55AA

# low 8 bits:key is derived from root key
# high 8 bits:key len is 3072, if value is 0 or 1, then key len is 2048
KEY_VERSION    = 0x0202

SIGN_ALG_V3    = 0x10002048
SIGN_ALG_V4    = 0x10004096

HASH256_LEN    = 256
HASH512_LEN    = 512

ENCRYPTED_KEYINFO_LEN  =256
SIGNATURE_LEN_256      = 256
SIGNATURE_LEN_512      = 512

SUCCESS = 0

# ELF Definitions
ELF_TYPE                  = 32
ELF_HDR_SIZE              = 52
ELF_PHDR_SIZE             = 32
ELF_INFO_MAGIC0_INDEX        = 0
ELF_INFO_MAGIC1_INDEX        = 1
ELF_INFO_MAGIC2_INDEX        = 2
ELF_INFO_MAGIC3_INDEX        = 3
ELF_INFO_MAGIC0              = 127 #'\x7f'
ELF_INFO_MAGIC1              = 69  #'E'
ELF_INFO_MAGIC2              = 76  #'L'
ELF_INFO_MAGIC3              = 70  #'F'
ELF_INFO_CLASS_INDEX       = 4
ELF_INFO_CLASS             = 1   #'\x01'
ELF_INFO_VERSION_INDEX     = 6
ELF_INFO_VERSION_CURRENT   = 1   #'\x01'
ELF_BLOCK_ALIGN           = 0x1000
ELF_HEAD_FORMAT           = ''

#----------------------------------------------------------------------------
# ELF File Header Check
#----------------------------------------------------------------------------
class Elf_Header:
    def __init__(self, data):
      # Algin data obj in ELF header
      if(ELF_TYPE == 64):
         self.s = struct.Struct('16sHHIQQQIHHHHHH')
      else:
         self.s = struct.Struct('16sHHIIIIIHHHHHH')

      unpacked_data       = (self.s).unpack(data)
      self.unpacked_data  = unpacked_data
      self.elf_ident        = unpacked_data[0]
      self.elf_type         = unpacked_data[1]
      self.elf_machine      = unpacked_data[2]
      self.elf_version      = unpacked_data[3]
      self.elf_entry        = unpacked_data[4]
      self.elf_phoff        = unpacked_data[5]
      self.elf_shoff        = unpacked_data[6]
      self.elf_flags        = unpacked_data[7]
      self.elf_ehsize       = unpacked_data[8]
      self.elf_phentsize    = unpacked_data[9]
      self.elf_phnum        = unpacked_data[10]
      self.elf_shentsize    = unpacked_data[11]
      self.elf_shnum        = unpacked_data[12]
      self.elf_shstrndx     = unpacked_data[13]

    def printValues(self):
        print("ATTRIBUTE / VALUE")
        for attr, value in self.__dict__.items():
            print(attr, value)

    def getPackedData(self):
        values = [self.elf_ident,
                  self.elf_type,
                  self.elf_machine,
                  self.elf_version,
                  self.elf_entry,
                  self.elf_phoff,
                  self.elf_shoff,
                  self.elf_flags,
                  self.elf_ehsize,
                  self.elf_phentsize,
                  self.elf_phnum,
                  self.elf_shentsize,
                  self.elf_shnum,
                  self.elf_shstrndx
                 ]

        return (self.s).pack(*values)

#----------------------------------------------------------------------------
# Verify ELF header contents from an input ELF file
#----------------------------------------------------------------------------
def verify_elf_header(elf_header):
    s = struct.unpack('BBBBBBBBBBBBBBBB', elf_header.elf_ident)
    if (s[ELF_INFO_MAGIC0_INDEX] != ELF_INFO_MAGIC0) or \
        (s[ELF_INFO_MAGIC1_INDEX] != ELF_INFO_MAGIC1) or \
        (s[ELF_INFO_MAGIC2_INDEX] != ELF_INFO_MAGIC2) or \
        (s[ELF_INFO_MAGIC3_INDEX] != ELF_INFO_MAGIC3) or \
        (s[ELF_INFO_CLASS_INDEX] != ELF_INFO_CLASS) or \
        (s[ELF_INFO_VERSION_INDEX] != ELF_INFO_VERSION_CURRENT):

        return False
    else:
        return True

def get_elf_type(elfFile):
    EI_NIDENT = 16
    global ELF_TYPE
    global ELF_HDR_SIZE
    global ELF_HEAD_FORMAT
    global ELF_INFO_CLASS

    elfFile.seek(0x0, 0)
    elf_ident = elfFile.read(EI_NIDENT)
    ''' check EI_CLASS, 32-bit or 64-bit'''
    elfStr = bytes.decode(elf_ident)
    s = struct.unpack('BBBBBBBBBBBBBBBB', elf_ident)
    if s[4] == 2:
        print("64 bit type")
        ELF_TYPE = 64
        ELF_HDR_SIZE = 64
        ELF_HEAD_FORMAT = "HHIQQQIHHHHHH"
        ELF_INFO_CLASS = 2
    elif s[4] == 1:
        print("32 bit type")
        ELF_TYPE = 32
        ELF_HDR_SIZE = 52
        ELF_HEAD_FORMAT = "HHIIIIIHHHHHH"
        ELF_INFO_CLASS = 1
    else:
        raise RuntimeError("Unknown ELF file type")
    return

def generateHeader(contentLen):
    return struct.pack('IHHII', MAGIC1, MAGIC2, VERSION, contentLen, KEY_VERSION)

def generateAesKeyInfo(ivFilePath, keyFilePath, outFilePath):
    # Aes key is randomly generated and temporarily stored in the file in plaintext, please ensure security.
    try:
        subprocess.check_output(["openssl", "rand", "-out", format(ivFilePath), "16"], shell=False)
        subprocess.check_output(["openssl", "rand", "-out", format(keyFilePath), "32"], shell=False)
    except:
        print("rand operation failed")
        raise RuntimeError

    with open(outFilePath, 'wb') as outFile:
        outFile.write(struct.pack('I', 32))
        outFile.write(struct.pack('I', 16))
        if DEBUG == 0 or TA_TYPE == 1:
            outFile.write(struct.pack('I', SIGN_ALG_V3))
        elif TA_TYPE == 2:
            outFile.write(struct.pack('I', SIGN_ALG_V4))
        else:
            print("target sign type is not supported: {}".format(TA_TYPE))
            raise RuntimeError

        with open(keyFilePath, 'rb') as keyFile:
            outFile.write(keyFile.read(32))

        with open(ivFilePath, 'rb') as ivFile:
            outFile.write(ivFile.read(16))

    return

def encryptAesKeyInfo(pubkeyFilePath, inFilePath, outFilePath):
    try:
        subprocess.check_output(["openssl", "rsautl", "-encrypt", "-pubin", "-oaep", \
        "-inkey", format(pubkeyFilePath), "-in", format(inFilePath), "-out", format(outFilePath)], shell=False)
    except:
        print("RSA encrypt operation failed")
        raise RuntimeError
    return

def generateHash(hashLen, inFilePath, outFilePath):
    inFileSize = os.path.getsize(inFilePath)
    # Initialize a SHA256 object from the Python hash library
    if hashLen == HASH256_LEN:
        hashOp = hashlib.sha256()
    elif hashLen == HASH512_LEN:
        hashOp = hashlib.sha512()
    # Set the input buffer and return the output digest
    with  open(inFilePath, 'rb') as inFile:
        hashOp.update(inFile.read(inFileSize))

    #-----hash file used for ras sign---
    with open(outFilePath, 'wb') as hash_fp:
        # fixed hash prefix value
        hash_fp.write(struct.pack('B'*19, 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60,
            0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20))
        hash_fp.write(hashOp.digest())
    return

def generateSignature(priKeyPath, inFilePath, outFilePath):
    if TA_TYPE == 1:
        print("generate dummy signature for DEBUG version")
        with open(outFilePath, 'wb') as f:
            f.write(str.encode('\0'*256, encoding='utf-8'))
    elif TA_TYPE == 2:
        try:
            subprocess.check_output(["openssl", "rsautl", "-sign", "-inkey", format(priKeyPath), \
            "-in", format(inFilePath), " -out", format(outFilePath)], shell=False)
        except:
            print("sign operation failed")
            raise RuntimeError
    return

def checkSignature(rawDataHashPath, inSignature, serverPubKey):
    try:
        subprocess.check_output(["openssl", "pkeyutl", "-verify", "-in", format(rawDataHashPath), \
        "-sigfile", format(inSignature), "-pubin", "-inkey", format(serverPubKey)], shell=False)
    except:
        print("check operation failed")
        raise RuntimeError
    return

def generateRawData(manifestDataPath, manifestExtFilePath, elfFilePath, configFilePath, rawFilePath):
    manifestDataSize = os.path.getsize(manifestDataPath)
    manifestExtSize = os.path.getsize(manifestExtFilePath)
    elfFileSize = os.path.getsize(elfFilePath)
    configFileSize = 0

    with open(rawFilePath, 'wb') as f:
        header  = ""
        if TA_TYPE == 2:
            configFileSize = os.path.getsize(configFilePath)
        header = struct.pack('IIIII', TA_VERSION, manifestDataSize, manifestExtSize, elfFileSize, configFileSize)
        f.write(header)

        with open(manifestDataPath, 'rb') as manifestData:
            f.write(manifestData.read(manifestDataSize))

        with open(manifestExtFilePath, 'rb') as manifestExt:
            f.write(manifestExt.read(manifestExtSize))

        with open(elfFilePath, 'rb') as elfFile:
            get_elf_type(elfFile)
            elfFile.seek(0x0, 0)
            elfFileHaderBuf = elfFile.read(ELF_HDR_SIZE)
            elfFileHader = Elf_Header(elfFileHaderBuf)
            if verify_elf_header(elfFileHader) is False:
                print("verify elf header failed")
                raise RuntimeError
            elfFile.seek(0x0, 0)
            f.write(elfFile.read(elfFileSize))

        if TA_TYPE == 2:
            with open(configFilePath, 'rb') as configFile:
                f.write(configFile.read(configFileSize))
    return

def aesEncrypt(keyPath, ivPath, inFilePath, outfilePath):
    keySize = os.path.getsize(keyPath)
    with open(keyPath, 'rb') as key:
        keyData = key.read(keySize)
    hexKeyStr = binascii.b2a_hex(keyData)

    ivSize = os.path.getsize(ivPath)
    with open(ivPath, 'rb') as iv:
        ivData = iv.read(ivSize)
    hexIvStr = binascii.b2a_hex(ivData)

    try:
        subprocess.check_output(["openssl", "enc", "-aes-256-cbc", "-in", format(inFilePath), \
         "-out", format(outfilePath), "-K", format(bytes.decode(hexKeyStr)), \
         "-iv", format(bytes.decode(hexIvStr))], shell=False)
    except:
        print("AES encrypt operation failed")
        raise RuntimeError

    return

def updateManifestTaApiLevel(manifest):
    line = "\ngpd.ta.api_level:{}\n".format(API_LEVEL)
    with open(manifest, "w") as f:
        f.writelines(line)

def updateManifestTaOtrpFlag(manifest):
    data = ''
    with open(manifest, 'r') as f:
        for line in f:
            if line.startswith("#") or not "gpd.ta.otrp_flag" in line:
                data += line
    line = "\ngpd.ta.otrp_flag:{}\n".format('true')
    data += line
    with open(manifest, "w") as f:
        f.writelines(data)

def generateDataForSign(contentLen, key_info, raw_file, data_sign):
    keyInfoLen = os.path.getsize(key_info)
    rawFileLen = os.path.getsize(raw_file)

    with open(data_sign, 'wb') as data_fp, \
            open(key_info, 'rb') as key_fp, open(raw_file, 'rb') as raw_fp:
        data_fp.write(generateHeader(contentLen))
        data_fp.write(key_fp.read(keyInfoLen))
        data_fp.write(raw_fp.read(rawFileLen))


def generateDigest(enclavePath, manifestPath, deviceKeyPath, configFilePath, rawDataHashPath, encKeyInfoFilePath, \
    encRawFilePath):
    inPath = os.getcwd()
    ivFilePath = os.path.join(inPath, "iv.bin")
    keyFilePath = os.path.join(inPath, "aeskey.bin")
    keyInfoFilePath = os.path.join(inPath, "KeyInfo")
    rawFilePath = os.path.join(inPath, "rawData")
    manifestDataPath = os.path.join(inPath, "manifestData.bin")
    manifestExtPath = os.path.join(inPath, "manifestExt.bin")
    dataForSignPath = os.path.join(inPath, "dataForSign.bin")

    #mandentory input files
    manifestFilePath = manifestPath
    elfFilePath = enclavePath
    pubkeyFilePath = deviceKeyPath

    (ret, PRODUCT_NAME, flag) = parserManifest(manifestFilePath, manifestDataPath, manifestExtPath)
    updateManifestTaApiLevel(manifestExtPath)

    if OTRP_FLAG == 1:
        print("package otrp sec file\n")
        updateManifestTaOtrpFlag(manifestExtPath)

    generateRawData(manifestDataPath, manifestExtPath, elfFilePath, configFilePath, rawFilePath)

    #generate AES key info to encrypt raw data
    generateAesKeyInfo(ivFilePath, keyFilePath, keyInfoFilePath)
    encryptAesKeyInfo(pubkeyFilePath, keyInfoFilePath, encKeyInfoFilePath)

    aesEncrypt(keyFilePath, ivFilePath, rawFilePath, encRawFilePath)

    contentLen = 0
    if DEBUG == 0 or TA_TYPE == 1:
        contentLen = os.path.getsize(encKeyInfoFilePath) + SIGNATURE_LEN_256 + os.path.getsize(encRawFilePath)
    elif TA_TYPE == 2:
        contentLen = os.path.getsize(encKeyInfoFilePath) + SIGNATURE_LEN_512 + os.path.getsize(encRawFilePath)
    else:
        print("target sign type is not supported: {}".format(TA_TYPE))
        raise RuntimeError

    generateDataForSign(contentLen, keyInfoFilePath, rawFilePath, dataForSignPath)

    generateHash(HASH256_LEN, dataForSignPath, rawDataHashPath)

    #remove temp files
    os.remove(ivFilePath)
    os.remove(keyFilePath)
    os.remove(keyInfoFilePath)
    os.remove(rawFilePath)
    os.remove(manifestDataPath)
    os.remove(manifestExtPath)
    os.remove(dataForSignPath)
    return

def generateSecEnclave(priKeyPath, rawDataHashPath, encKeyInfoFilePath, encRawFilePath, inSignature, serverPubKey, \
    outFile):
    inPath = os.getcwd()
    signatureFilePath = inSignature
    if DEBUG == 1:
        signatureFilePath = os.path.join(inPath, "signature.bin")
        generateSignature(priKeyPath, rawDataHashPath, signatureFilePath)
    else:
        checkSignature(rawDataHashPath, inSignature, serverPubKey)

    contentLen = 0
    if DEBUG == 0 or TA_TYPE == 1:
        contentLen = os.path.getsize(encKeyInfoFilePath) + SIGNATURE_LEN_256 + os.path.getsize(encRawFilePath)
    elif TA_TYPE == 2:
        contentLen = os.path.getsize(encKeyInfoFilePath) + SIGNATURE_LEN_512 + os.path.getsize(encRawFilePath)
    else:
        print("target sign type is not supported: {}".format(TA_TYPE))
        raise RuntimeError

 #   secImagePath = os.path.join(outPath, productName)
    secImagePath = outFile
    with open(secImagePath, 'wb') as secImage:
        # write to sec file [1.header info]
        secImage.write(generateHeader(contentLen))
        # write to sec file [2.AES key info]
        encKeyInfoSize = os.path.getsize(encKeyInfoFilePath)
        with open(encKeyInfoFilePath, 'rb') as encKeyInfo:
            secImage.write(encKeyInfo.read(encKeyInfoSize))
        # write to sec file [3.signature]
        signatureSize = os.path.getsize(signatureFilePath)
        with open(signatureFilePath, 'rb') as signatureFile:
            secImage.write(signatureFile.read(signatureSize))
        # write to sec file [4.encrypted raw data]
        encRawDataSize = os.path.getsize(encRawFilePath)
        with open(encRawFilePath, 'rb') as encRawData:
            secImage.write(encRawData.read(encRawDataSize))

    if DEBUG == 1:
        os.remove(signatureFilePath)

    print("=========================SUCCESS============================")
    print("generate TA(V3 format) load image success: ")
    print(secImagePath)
    print("============================================================")
    return

if __name__ == '__main__':
    argvs = sys.argv
    priKeyPath = ""
    configFilePath = ""
    cmd = argvs[1]
    DEBUG = int(argvs[2])
    enclavePath = argvs[3]
    outFile = argvs[4]
    manifestPath = argvs[5]
    OTRP_FLAG = int(argvs[6])
    TA_TYPE = int(argvs[7])
    API_LEVEL = int(argvs[8])
    DEVICE_PUBKEY = argvs[9]
    configFilePath = argvs[10]

    os.umask(127)
    inPath = os.getcwd()
    encKeyInfoFilePath = os.path.join(inPath, "KeyInfo.enc")
    encRawFilePath = os.path.join(inPath, "rawData.enc")
    rawDataHashPath = os.path.join(inPath, "rawDataHash.bin")

    if cmd == "digest":
        generateDigest(enclavePath, manifestPath, DEVICE_PUBKEY, configFilePath, rawDataHashPath, encKeyInfoFilePath, \
        encRawFilePath)
        shutil.copy(rawDataHashPath, outFile)
    elif cmd == "sign":
        if DEBUG == 0:
            inSignature = argvs[11]
            serverPubKey = argvs[12]
        else:
            if TA_TYPE == 2:
                priKeyPath = argvs[11]
            inSignature = ""
            serverPubKey = ""
            generateDigest(enclavePath, manifestPath, DEVICE_PUBKEY, configFilePath, rawDataHashPath, \
            encKeyInfoFilePath, encRawFilePath)
        generateSecEnclave(priKeyPath, rawDataHashPath, encKeyInfoFilePath, encRawFilePath, inSignature, \
        serverPubKey, outFile)
        os.remove(rawDataHashPath)
        os.remove(encKeyInfoFilePath)
        os.remove(encRawFilePath)
