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
    # Compose implementations may bind a local secret with its original 0600
    # mode. Copy the public key while privileged so the runtime user can read
    # it without requiring the host file to be world-readable.
    bootstrap_key=/tmp/sshgatew-bootstrap-admin.pub
    cp "$authorized_key" "$bootstrap_key"
    chown sshgatew:sshgatew "$bootstrap_key"
    chmod 0400 "$bootstrap_key"
    echo "Initializing SSHGateW for administrator $admin..."
    su-exec sshgatew:sshgatew /usr/local/bin/sshgatew \
        --config "$config_path" \
        init \
        --admin "$admin" \
        --authorized-key "$bootstrap_key" \
        --data-dir "$data_dir" \
        --listen "$listen"
    rm -f -- "$bootstrap_key"
fi

chown root:sshgatew "$config_dir" "$config_path"
chmod 0750 "$config_dir"
chmod 0640 "$config_path"

exec su-exec sshgatew:sshgatew /usr/local/bin/sshgatew --config "$config_path" "$@"
