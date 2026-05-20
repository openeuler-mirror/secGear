# ra-tls

secGear supports ra-tls, which establishes a TLS connection between the confidential environment and the data provider based on the remote attestation service to ensure reliable data transmission.

# Environment Dependency

Remote attestation services AS and AA. For details about the service configuration, see service/attestation/README.md.

# Compilation and Installation

Run the following commands to perform compilation:

```sh
cd component/ra_tls
mkdir build
cmake ../
// Alternatively, specify the default TLS library and enable the debug mode.
cmake ../ -DCMAKE_BUILD_TYPE=Debug -DTLS_LIB=OPENSSL
make
make install

# Running Example
Run the following commands in the **examples/ra_tls** directory:
mkdir build
cd build
cmake ../
make
./server
./client
```
