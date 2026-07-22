#!/bin/sh
set -eu

config_path=${SSHGATEW_CONFIG:-/etc/sshgatew/config.toml}
data_dir=${SSHGATEW_DATA_DIR:-/var/lib/sshgatew}
admin=${SSHGATEW_ADMIN:-admin}
listen=${SSHGATEW_LISTEN:-0.0.0.0:2222}
authorized_key=${SSHGATEW_AUTHORIZED_KEY_FILE:-/run/secrets/admin_public_key}

config_dir=$(dirname "$config_path")
mkdir -p "$config_dir" "$data_dir"
chown sshgatew:sshgatew "$config_dir"
chown -R sshgatew:sshgatew "$data_dir"
chmod 0750 "$config_dir" "$data_dir"

if [ ! -f "$config_path" ]; then
    if [ ! -s "$authorized_key" ]; then
        echo "SSHGateW first-run setup requires a public key at $authorized_key" >&2
        exit 1
    fi
    echo "Initializing SSHGateW for administrator $admin..."
    su-exec sshgatew:sshgatew /usr/local/bin/sshgatew \
        --config "$config_path" \
        init \
        --admin "$admin" \
        --authorized-key "$authorized_key" \
        --data-dir "$data_dir" \
        --listen "$listen"
fi

chown root:sshgatew "$config_dir" "$config_path"
chmod 0750 "$config_dir"
chmod 0640 "$config_path"

exec su-exec sshgatew:sshgatew /usr/local/bin/sshgatew --config "$config_path" "$@"
