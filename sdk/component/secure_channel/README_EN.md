# Security Channel

## Customer Pain Points

When requesting the confidential computing service on the cloud, the data owner needs to upload the data to be processed to the TEE on the cloud for processing. Because the TEE is not connected to the network, the data needs to be transferred to the REE over the network in plaintext and then transferred to the TEE from the REE. The plaintext data is exposed in the REE memory, which poses security risks.

## Solution

A secure channel is a technology that combines remote attestation of confidential computing to implement secure key negotiation between the data owner and the TEE on the cloud. It negotiates a session key owned only by the data owner and the TEE on the cloud. Then the session key is used to encrypt user data transferred over the network. After receiving the ciphertext data, the REE transfers the data to the TEE for decryption and processing.

## Usage

The secure channel is provided as a library and consists of the client, server host, and server enclave, which are called by the client, server client application (CA), and server trusted application (TA) of the service program respectively.

| Module        | Header File                     | Library File                  | Dependency     |
|------------|--------------------------|-----------------------|---------|
| Client       | secure_channel_client.h  | libcsecure_channel.so | openssl |
| Server host   | secure_channel_host.h    | libusecure_channel.so | openssl |
| Server enclave| secure_channel_enclave.h | libtsecure_channel.a| TEE and TEE software stack    |

### APIs

| API                                                                                                                                         | Header File and Library                  | Function          | Remarks|
|----------------------------------------------------------------------------------------------------------------------------------------------|-----------------------|--------------|----|
| cc_sec_chl_client_init                                                 | secure_channel_client.h libcsecure_channel.so | Initializes the secure channel on the client.  | Before calling this API, initialize the network connection and message sending hook function in the **ctx** parameter.  |
| cc_sec_chl_client_fini                                                                                         | secure_channel_client.h libcsecure_channel.so | Destroys the secure channel on the client.   | Instructs the server to destroy the local client information and local secure channel information.  |
| cc_sec_chl_client_callback                                              | secure_channel_client.h libcsecure_channel.so | Function for processing secure channel negotiation messages.| Processes messages sent from the server to the client during secure channel negotiation. This API is called when messages are received on the client.  |
| cc_sec_chl_client_encrypt | secure_channel_client.h libcsecure_channel.so | Encryption API of the secure channel on the client.    |  None |
| cc_sec_chl_client_decrypt | secure_channel_client.h libcsecure_channel.so | Decryption API of the secure channel on the client.    |  None |
|  int (*cc_conn_opt_funcptr_t)(void *conn, void *buf, size_t count);                                                                                                                                            |    secure_channel.h                    |    Prototype of the message sending hook function.         | Implemented by the client and server to specify the secure channel negotiation message type. It sends secure channel negotiation messages to the peer end.  |
|  cc_sec_chl_svr_init                                                                                                                                            |  secure_channel_host.h  libusecure_channel.so                    |  Initializes the secure channel on the server.           | Before calling this API, initialize **enclave_ctx** in **ctx**.  |
|  cc_sec_chl_svr_fini                                                                                                                                            |   secure_channel_host.h  libusecure_channel.so                    |  Destroys the secure channel on the server.           |  Destroys information about the secure channel on the server and all clients. |
|  cc_sec_chl_svr_callback                                                                                                                                            |  secure_channel_host.h  libusecure_channel.so                     |  Function for processing secure channel negotiation messages.           | Processes messages sent from the client to the server during security channel negotiation. This API is called when messages are received on the server. Before calling this API, you need to initialize the network connection to the client and the message sending function. For details, see [examples](https://gitee.com/openeuler/secGear/blob/master/examples/secure_channel/host/server.c#:~:text=conn_ctx.conn_kit.send).  |
| cc_sec_chl_enclave_encrypt                                                                                                                                             |    secure_channel_enclave.h libtsecure_channel.a                   | Encryption API of the secure channel on the enclave.            |  None |
|   cc_sec_chl_enclave_decrypt                                                                                                                                           |   secure_channel_enclave.h libtsecure_channel.a                    | Decryption API of the secure channel on the enclave.            |  None |

### Precautions

A secure channel encapsulates only the key negotiation process and encryption and decryption APIs, but does not establish any network connection. Instead, the negotiation process reuses the network connection of the service. The network connection between the client and server is established and maintained by the service. The message sending hook function and network connection pointer are transferred during the initialization of the secure channel on the client and the server. For details, see [Security Channel Sample](https://gitee.com/openeuler/secGear/tree/master/examples/secure_channel).
