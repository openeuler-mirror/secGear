Client-side secure channel cffi interface definition: `component/secure_channel/client/python/sec_chl_wrapper.py`
The `*.h` files generated from the enclave's edl file must be copied to `component/secure_channel/client/python/`.

Execution examples:

1. Compile and generate an `.so` file.

    ```shell
    python sec_chl_wrapper.py
    ```

2. Run the client example (the host-side secure channel service must be started first).
   
    ```shell
    python client.py
    ```
    