Host-side secure channel cffi interface definition: `component/secure_channel/host/python/sec_chl_wrapper.py`
The `*.h` and `*.c` files generated from the enclave's edl file must be copied to `component/secure_channel/host/python/`.

Execution examples:

1. Compile and generate an `.so` file.

    ```shell
    python sec_chl_wrapper.py
    ```

2. Run the client example
    
    ```shell
    /usr/bin/python server.py
    ```
