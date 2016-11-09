#!/bin/bash

export SECRET=this_is_a_secret

sudo -E  osqueryd \
    --verbose \
    --host_identifier uuid \
    --pidfile /tmp/oseryd.pid \
    --database_path /tmp/osquery.db/ \
    --tls_hostname localhost:5000 \
    --tls_server_certs server.crt \
    --config_plugin tls \
    --config_tls_endpoint /config \
    --logger_tls_endpoint /log \
    --logger_plugin tls \
    --logger_tls_period 300 \
    --enroll_tls_endpoint /enroll \
    --disable_distributed=false \
    --distributed_plugin tls \
    --distributed_interval 300 \
    --distributed_tls_max_attempts 3 \
    --distributed_tls_read_endpoint /distributed_read \
    --distributed_tls_write_endpoint /distributed_write \
    --enroll_secret_env SECRET
