FROM openeuler-22.03-lts 
SHELL ["bash"]
WORKDIR /home

COPY libsecgear_tee.a /usr/lib64/
COPY libtest_ta.so /usr/lib64/
COPY libqtsm.so /usr/lib64/

COPY enclave /home

CMD ["/home/enclave"]
