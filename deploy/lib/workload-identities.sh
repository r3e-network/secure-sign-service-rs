# Shared identity-source checks for the production gateway entry.
# Never print token bytes. Never accept argv as a source.

workload_identities_mode() {
    local path="$1"
    if [[ "$(uname -s)" == "Darwin" ]]; then
        stat -f %Lp "$path"
    else
        stat -c %a "$path"
    fi
}

workload_identities_file_ok() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        echo "GATEWAY_WORKLOAD_IDENTITIES_FILE is missing: $path" >&2
        return 1
    fi
    local mode
    mode="$(workload_identities_mode "$path")"
    if [[ -z "$mode" ]]; then
        echo "GATEWAY_WORKLOAD_IDENTITIES_FILE mode is unreadable" >&2
        return 1
    fi
    if ((8#$mode & 8#077)); then
        echo "GATEWAY_WORKLOAD_IDENTITIES_FILE must be mode 0600 or stricter" >&2
        return 1
    fi
    if [[ ! -s "$path" ]]; then
        echo "GATEWAY_WORKLOAD_IDENTITIES_FILE is empty" >&2
        return 1
    fi
    return 0
}

require_gateway_identities() {
    if [[ -n "${CREDENTIALS_DIRECTORY:-}" && -f "${CREDENTIALS_DIRECTORY}/workload-identities" ]]; then
        if [[ -z "${GATEWAY_WORKLOAD_IDENTITIES_FILE:-}" ]]; then
            GATEWAY_WORKLOAD_IDENTITIES_FILE="${CREDENTIALS_DIRECTORY}/workload-identities"
            export GATEWAY_WORKLOAD_IDENTITIES_FILE
        fi
    fi

    local env_set=0 file_set=0 fd_set=0
    if [[ -n "${GATEWAY_WORKLOAD_IDENTITIES:-}" ]]; then
        env_set=1
    fi
    if [[ -n "${GATEWAY_WORKLOAD_IDENTITIES_FILE:-}" ]]; then
        file_set=1
    fi
    if [[ -n "${GATEWAY_WORKLOAD_IDENTITIES_FD:-}" ]]; then
        fd_set=1
    fi
    local sources=$((env_set + file_set + fd_set))
    if ((sources == 0)); then
        echo "GATEWAY_WORKLOAD_IDENTITIES, GATEWAY_WORKLOAD_IDENTITIES_FILE, or GATEWAY_WORKLOAD_IDENTITIES_FD is required" >&2
        return 1
    fi
    if ((sources > 1)); then
        echo "exactly one of GATEWAY_WORKLOAD_IDENTITIES, GATEWAY_WORKLOAD_IDENTITIES_FILE, or GATEWAY_WORKLOAD_IDENTITIES_FD must be set" >&2
        return 1
    fi
    if ((file_set)); then
        workload_identities_file_ok "$GATEWAY_WORKLOAD_IDENTITIES_FILE" || return 1
    fi
    if ((fd_set)); then
        if ! [[ "$GATEWAY_WORKLOAD_IDENTITIES_FD" =~ ^[0-9]+$ ]] || ((GATEWAY_WORKLOAD_IDENTITIES_FD < 3)); then
            echo "GATEWAY_WORKLOAD_IDENTITIES_FD must be an integer >= 3" >&2
            return 1
        fi
    fi
    return 0
}
