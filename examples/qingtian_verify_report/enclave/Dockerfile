FROM openeuler-22.03-lts 
SHELL ["bash"]
WORKDIR /home

COPY libqtsm.so /usr/lib64/
COPY libcbor.so.0.10.2 /usr/lib64/
COPY libcbor.so.0.10 /usr/lib64/
COPY libqingtian_verify_report.so /usr/lib64/

COPY enclave-main /home

CMD ["/home/enclave-main"]
