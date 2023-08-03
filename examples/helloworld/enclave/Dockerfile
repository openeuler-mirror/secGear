FROM openeuler-22.03-lts 
SHELL ["bash"]
WORKDIR /home

COPY secgear /etc/logrotate.d/
COPY secgear.conf /etc/rsyslog.d/
COPY libsecgear_tee.a /usr/lib64/
COPY libsecgear.so  /usr/lib64/
COPY libsecgearsim.so /usr/lib64/
COPY libqingtian_0.so /usr/lib64/
COPY libhelloworld.so /usr/lib64/
COPY libqtsm.so /usr/lib64/


COPY enclave /home

CMD ["/home/enclave"]
