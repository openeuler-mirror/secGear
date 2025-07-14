import socket
import struct
import faulthandler
import sys
sys.path.append('../../../../component/secure_channel/client/python')

from sec_chl_client import *
global server_socket
SEC_CHL_MSG_TYPE = 55
APP_MSG_TYPE = 11
@ffi.callback("int(void *chl_ctx, unsigned char *buf, size_t count)")
def send_callback(chl_ctx, buf, count):
    global server_socket
    session_id = sec_chl_session_id(chl_ctx)
    #发送安全通道建立过程数据，添加数据包头
    send_msg_type = SEC_CHL_MSG_TYPE
    send_header = struct.pack("IQI", send_msg_type, session_id, count)
    send_msg_body = bytes(ffi.buffer(buf, count))
    send_data = send_header + send_msg_body
    server_socket.send(send_data)
    print(f"send to server[{len(send_data)}]: {send_data.hex()}")

    while True:
        try:
            recv_data = server_socket.recv(10240)
            if not recv_data or len(recv_data) == 0:
                continue
            print(f"received from server[{(len(recv_data))}]: {recv_data}")
            #接收安全通道数据，解析包头
            header_len = 20
            recv_msg_type, session_id, recv_msg_body_len = struct.unpack("IQI", recv_data[:header_len])
            recv_msg_body = recv_data[header_len:header_len+recv_msg_body_len]
            print(f"message body[{len(recv_msg_body)}]: {recv_msg_body}")

            if recv_msg_type == SEC_CHL_MSG_TYPE:
                return sec_chl_msg_recv_handle(chl_ctx, recv_msg_body)
        except socket.error as e:
            print(f"exception{e}")
            server_socket.close()
            exit()
        except KeyboardInterrupt:
            print("Ctrl+C exit")
            exit()
    return int(0)
    

if __name__ == "__main__":
    faulthandler.enable()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect(("127.0.0.1", 12306))
    sec_chl_log_init(b"debug")
    uuid = b"f68fd704-6eb1-4d14-b218-722850eb3ef0"
    chl_ctx = sec_chl_open(send_callback, uuid)
    if chl_ctx is None:
        print("secure channel create failed")
        exit()
    print(f"session id {sec_chl_session_id(chl_ctx)}")

    print("create cipher data")
    plain_text_len = 6
    plain_text = b"123456"
    cipher = sec_chl_encrypt(chl_ctx, plain_text)
    if not cipher or len(cipher) == 0:
        print("encrpyt failed")
        exit()

    send_len = len(cipher)
    print(f"send cipher data {send_len}: {cipher.hex()}")
    send_msg_type = APP_MSG_TYPE
    send_header = struct.pack("IQI", send_msg_type, sec_chl_session_id(chl_ctx), send_len)
    send_data = send_header + cipher
    server_socket.send(send_data)

    # 接收数据并解密
    while True:
        recv_data = server_socket.recv(10240)
        if not recv_data or len(recv_data) == 0:
            continue
        header_len = 20
        recv_msg_type, session_id, msg_body_len = struct.unpack("IQI", recv_data[:header_len])
        cipher = recv_data[header_len:header_len+msg_body_len]
        plain = sec_chl_decrypt(chl_ctx, cipher)
        print(f"decrypt data[{len(plain)}]:  {plain.decode('utf-8')}")
        break

    sec_chl_close(chl_ctx)
    server_socket.close()
