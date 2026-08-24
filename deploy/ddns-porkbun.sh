#!/bin/sh
# ddns-porkbun.sh — keep Porkbun DNS A records pointing at the right IPv4.
#
# Subcommands:
#   sync            resolve the current public IPv4 and sync A records to it
#                   (home deployment with a dynamic IP; the default)
#   set <ip>        point the A records at an explicit IP (failover flip)
#   get             print the current A record contents
#
# Idempotent: sync only calls the Porkbun API when the resolved IP differs
# from the current record; set always applies. Requirements: curl + jq.
#
# Configuration (environment, or deploy/.env next to this script):
#   DDNS_PORKBUN_API_KEY   Porkbun API key (https://porkbun.com/account/api)
#   DDNS_PORKBUN_SECRET    Porkbun API secret
#   DDNS_PORKBUN_DOMAIN    apex domain (default: DDNS_DOMAIN, else required)
#   DDNS_PORKBUN_HOSTS     space-separated hosts (default: "<domain> *.<domain>")
#   DDNS_PORKBUN_TTL       TTL seconds (default 300; Porkbun min 300)
#   DDNS_PORKBUN_IP_SOURCE URL returning the public IPv4 (default https://api.ipify.org)
#
# Usage:
#   ddns-porkbun.sh sync             # dynamic-IP sync (home)
#   ddns-porkbun.sh set 1.2.3.4      # explicit flip (failover)
#   ddns-porkbun.sh get              # show current records
#   ddns-porkbun.sh --dry-run <cmd>  # print what would change, change nothing
#
# NOTE: sync does NOT work behind CGNAT — the WAN must be a real public IPv4.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# --- load deploy/.env (KEY=VAL lines; environment wins) --------------------
if [ -f "$SCRIPT_DIR/.env" ]; then
    while IFS='=' read -r key val; do
        case "$key" in
            '' | \#*) continue ;;
            *) [ -z "${!key:-}" ] && export "$key=$val" ;;
        esac
    done < "$SCRIPT_DIR/.env"
fi

DRY_RUN=0
CMD=
IP_ARG=
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        sync | get) CMD=$arg ;;
        set)
            CMD=set
            ;;
        --help|-h)
            sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            if [ "$CMD" = set ] && [ -z "$IP_ARG" ]; then
                IP_ARG=$arg
            else
                echo "unknown arg: $arg (sync | set <ip> | get | --dry-run | --help)" >&2
                exit 2
            fi
            ;;
    esac
done
CMD=${CMD:-sync}

API_KEY=${DDNS_PORKBUN_API_KEY:-}
SECRET=${DDNS_PORKBUN_SECRET:-}
DOMAIN=${DDNS_PORKBUN_DOMAIN:-${DDNS_DOMAIN:-}}
TTL=${DDNS_PORKBUN_TTL:-300}
IP_SOURCE=${DDNS_PORKBUN_IP_SOURCE:-https://api.ipify.org}
API=https://api.porkbun.com/api/json/v3

[ -n "$API_KEY" ] || { echo "error: DDNS_PORKBUN_API_KEY is required" >&2; exit 2; }
[ -n "$SECRET" ] || { echo "error: DDNS_PORKBUN_SECRET is required" >&2; exit 2; }
[ -n "$DOMAIN" ] || { echo "error: DDNS_PORKBUN_DOMAIN (or DDNS_DOMAIN) is required" >&2; exit 2; }

HOSTS=${DDNS_PORKBUN_HOSTS:-"$DOMAIN *.$DOMAIN"}

# --- API helpers ------------------------------------------------------------
api() { # api <path> <json-body>
    curl -fsS --max-time 20 -X POST "$API/$1" \
        -H 'Content-Type: application/json' \
        -d "$2" 2>/dev/null || true
}

retrieve() {
    api "dns/retrieve/$DOMAIN" \
        "{\"secretapikey\":\"$SECRET\",\"apikey\":\"$API_KEY\"}"
}

set_record() { # set_record <host> <ip>  -> create or edit the A record
    local host=$1 ip=$2
    local resp record_id current
    resp=$(retrieve)
    record_id=$(printf '%s' "$resp" | jq -r --arg h "$host" \
        '.records[]? | select(.name == $h and .type == "A") | .id' 2>/dev/null | head -1)
    current=$(printf '%s' "$resp" | jq -r --arg h "$host" \
        '.records[]? | select(.name == $h and .type == "A") | .content' 2>/dev/null | head -1)

    if [ -z "$record_id" ]; then
        echo "$host: no A record (create)"
        [ "$DRY_RUN" = 1 ] && return 0
        resp=$(api "dns/create/$DOMAIN" \
            "{\"secretapikey\":\"$SECRET\",\"apikey\":\"$API_KEY\",\"name\":\"$host\",\"type\":\"A\",\"content\":\"$ip\",\"ttl\":\"$TTL\"}")
    elif [ "$current" != "$ip" ]; then
        echo "$host: $current -> $ip"
        [ "$DRY_RUN" = 1 ] && return 0
        resp=$(api "dns/edit/$DOMAIN/$record_id" \
            "{\"secretapikey\":\"$SECRET\",\"apikey\":\"$API_KEY\",\"content\":\"$ip\",\"ttl\":\"$TTL\"}")
    else
        echo "$host: in sync ($ip)"
        return 0
    fi

    if [ "$(printf '%s' "$resp" | jq -r .status 2>/dev/null)" = SUCCESS ]; then
        echo "$host: ok (ttl $TTL)"
    else
        echo "$host: API failed: $(printf '%s' "$resp" | jq -r .message 2>/dev/null)" >&2
        return 1
    fi
}

# --- commands ---------------------------------------------------------------
case "$CMD" in
    get)
        resp=$(retrieve)
        for host in $HOSTS; do
            host=$(echo "$host" | tr '[:upper:]' '[:lower:]')
            printf '%s' "$resp" | jq -r --arg h "$host" \
                '.records[]? | select(.name == $h and .type == "A") | "\(.name) \(.content)"' \
                2>/dev/null || true
        done
        ;;
    set)
        case "$IP_ARG" in
            '' | *[!0-9.]*) echo "error: set requires an IPv4, got '$IP_ARG'" >&2; exit 2 ;;
            *) ;;
        esac
        rc=0
        for host in $HOSTS; do
            host=$(echo "$host" | tr '[:upper:]' '[:lower:]')
            set_record "$host" "$IP_ARG" || rc=1
        done
        exit $rc
        ;;
    sync)
        public_ip=$(curl -4 -fsS --max-time 20 "$IP_SOURCE" 2>/dev/null || true)
        case "$public_ip" in
            '' | *[!0-9.]*) echo "error: could not resolve public IPv4 from $IP_SOURCE" >&2; exit 1 ;;
            *) ;;
        esac
        [ "$(echo "$public_ip" | awk -F. '{ print NF }')" = 4 ] ||
            { echo "error: not an IPv4: $public_ip" >&2; exit 1; }
        echo "public ip: $public_ip"
        rc=0
        for host in $HOSTS; do
            host=$(echo "$host" | tr '[:upper:]' '[:lower:]')
            set_record "$host" "$public_ip" || rc=1
        done
        exit $rc
        ;;
esac
