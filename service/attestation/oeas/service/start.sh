#!/usr/bin/bash
yes | cp -r /opt/attestation/* /etc/attestation/
supervisord -c /etc/attestation/supervisord.conf