import socket
import struct
import faulthandler
import sys
sys.path.append('../../../../component/secure_channel/host/python')
from sec_chl_server import *

global client_socket
global session_id
SEC_CHL_MSG_TYPE = 55
APP_MSG_TYPE = 11
@ffi.callback("int(void *conn, unsigned char *buf, size_t count)")
def send_callback(conn, buf, count):
    global client_socket
    global session_id
    send_msg_type = SEC_CHL_MSG_TYPE
    send_header = struct.pack("IQI", send_msg_type, session_id, count)
    send_msg_body = bytes(ffi.buffer(buf, count))
    send_data = send_header + send_msg_body
    print(f"send to client[%d]: {send_data.hex()}"%(len(send_data)))
    return client_socket.send(send_data)

if __name__ == "__main__":
    enclave_path = b"/data/f68fd704-6eb1-4d14-b218-722850eb3ef0.sec"
    sec_chl_log_init(b"debug")
    sec_chl_open(send_callback, enclave_path)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('localhost', 12306))
    server_socket.listen(5)
    print("server listening")

    client_socket, client_address = server_socket.accept()
    print(f"client {client_address}")
    while True:
        try:
            recv_data = client_socket.recv(10240)
            if not recv_data:
                break
            print(f"received from client[%d]: {recv_data.hex()}"%(len(recv_data)))
            #接收数据，提取包头，根据消息类型分别调用不同的接口
            header_len = 20
            recv_msg_type, session_id, msg_body_len = struct.unpack("IQI", recv_data[:header_len])
            print(f"message type[%d] body len[%d]"%(recv_msg_type, msg_body_len))
            print(f"message body: {recv_data[header_len:header_len + msg_body_len]}")

            recv_msg_body = recv_data[header_len:header_len + msg_body_len]
            if recv_msg_type == SEC_CHL_MSG_TYPE:
                sec_chl_msg_recv_handle(recv_msg_body)
            elif recv_msg_type == APP_MSG_TYPE:
                # 接收用户数据并调用ecall解密接口
                print(f"recv application message session id {session_id}")
                ret, ecall_ret = sec_chl_recv_client_data_ex(session_id, recv_msg_body)
                if ret != 0 or ecall_ret != 0:
                    print(f"ecall faild ret = {ret} retval = {ecall_ret}")

                # ecall调用加密后的数据发送给用户
                outbuf_max_len = 1024
                print(f"send ecall result session_id = {session_id}")
                ret, ecall_ret, output = sec_chl_get_client_data_handle_result_ex(session_id, outbuf_max_len)
                print(f"ecall result[{len(output)}] {output}")
                send_msg_type = APP_MSG_TYPE
                send_header = struct.pack("IQI", send_msg_type, session_id, len(output))
                send_data = send_header + output
                print(f"send message [{len(send_data)}] {send_data}")
                client_socket.send(send_data)
        except socket.error as e:
            print(f"exception{e}")
            break
    sec_chl_close()
    client_socket.close()
    server_socket.close()

