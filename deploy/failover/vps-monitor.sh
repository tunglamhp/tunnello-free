#!/bin/sh
# vps-monitor.sh — run on the BACKUP VPS. Watches the home broker; when it
# stops answering, restores the latest DB snapshot, starts the local broker
# stack and flips the Porkbun DNS to this VPS. When home recovers, flips the
# DNS back and stops the local stack.
#
# Configuration (environment, or deploy/.env):
#   DDNS_HOME_IP           public IPv4 of the home broker (required)
#   DDNS_VPS_IP            public IPv4 of this VPS (required)
#   DDNS_DOMAIN            apex domain (required; used for the health check)
#   DDNS_FAILOVER_CHECKS   consecutive failures before failover (default 3)
#   DDNS_FAILOVER_INTERVAL seconds between checks (default 60)
#   DDNS_VPS_DEPLOY_DIR    this deploy dir (default /opt/ddns-deploy)
#   DDNS_VOLUME            broker data volume name (default ddns_broker-data)
#   (all DDNS_PORKBUN_* vars are also required — the DNS flip uses them)
#
# Install (VPS, as root):
#   cp deploy/failover/vps-monitor.sh /opt/ddns-deploy/
#   cp deploy/failover/systemd/vps-monitor.service /etc/systemd/system/
#   systemctl daemon-reload && systemctl enable --now vps-monitor
#
# Manual control:
#   vps-monitor.sh --once             run a single check pass
#   vps-monitor.sh --force-to-vps     failover now (home assumed dead)
#   vps-monitor.sh --force-to-home    switch back to home now

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -f "$SCRIPT_DIR/.env" ]; then
    while IFS='=' read -r key val; do
        case "$key" in
            '' | \#*) continue ;;
            *) [ -z "${!key:-}" ] && export "$key=$val" ;;
        esac
    done < "$SCRIPT_DIR/.env"
fi

HOME_IP=${DDNS_HOME_IP:-}
VPS_IP=${DDNS_VPS_IP:-}
DOMAIN=${DDNS_DOMAIN:-}
CHECKS=${DDNS_FAILOVER_CHECKS:-3}
INTERVAL=${DDNS_FAILOVER_INTERVAL:-60}
DEPLOY_DIR=${DDNS_VPS_DEPLOY_DIR:-/opt/ddns-deploy}
VOLUME=${DDNS_VOLUME:-ddns_broker-data}
STATE_FILE=${DDNS_FAILOVER_STATE:-/var/lib/ddns-failover/state}
DNS_SCRIPT=$SCRIPT_DIR/ddns-porkbun.sh

[ -n "$HOME_IP" ] || { echo "error: DDNS_HOME_IP is required" >&2; exit 2; }
[ -n "$VPS_IP" ] || { echo "error: DDNS_VPS_IP is required" >&2; exit 2; }
[ -n "$DOMAIN" ] || { echo "error: DDNS_DOMAIN is required" >&2; exit 2; }

MODE=loop
for arg in "$@"; do
    case "$arg" in
        --once) MODE=once ;;
        --force-to-vps) MODE=force-vps ;;
        --force-to-home) MODE=force-home ;;
        --help|-h)
            sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

mkdir -p "$(dirname "$STATE_FILE")"
[ -f "$STATE_FILE" ] || printf 'home\n' > "$STATE_FILE"

home_up() { # health-check the HOME broker directly (not via DNS)
    curl --resolve "$DOMAIN:443:$HOME_IP" -k -fsS --max-time 10 \
        "https://$DOMAIN/install.sh" -o /dev/null 2>/dev/null
}

state() { cat "$STATE_FILE"; }
set_state() { printf '%s\n' "$1" > "$STATE_FILE"; echo "state -> $1"; }

start_stack() { # restore the latest snapshot, then bring the broker up
    cd "$DEPLOY_DIR"
    docker compose stop >/dev/null 2>&1 || true
    if [ -f "$DEPLOY_DIR/backup/ddns.db.ready" ]; then
        docker run --rm -v "$VOLUME":/data -v "$DEPLOY_DIR/backup":/backup \
            alpine sh -c 'rm -rf /data/* && cp /backup/ddns.db.ready /data/ddns.db' \
            >/dev/null 2>&1 || echo "warning: snapshot restore failed (volume $VOLUME?)" >&2
    fi
    docker compose up -d >/dev/null 2>&1 || { echo "error: docker compose up failed" >&2; exit 1; }
    echo "local broker stack started"
}

stop_stack() {
    cd "$DEPLOY_DIR"
    docker compose stop >/dev/null 2>&1 || true
    echo "local broker stack stopped"
}

flip_to_vps() {
    "$DNS_SCRIPT" set "$VPS_IP" || { echo "error: DNS flip to VPS failed" >&2; exit 1; }
    set_state vps
}

flip_to_home() {
    "$DNS_SCRIPT" set "$HOME_IP" || { echo "error: DNS flip to home failed" >&2; exit 1; }
    set_state home
}

failover() {
    echo "$(date -u +%FT%TZ) failover: home unreachable -> VPS"
    start_stack
    flip_to_vps
}

recover() {
    echo "$(date -u +%FT%TZ) recovery: home reachable -> home"
    flip_to_home
    stop_stack
}

case "$MODE" in
    force-vps) failover ;;
    force-home) recover ;;
    once) ;&
    loop)
        fails=0
        while :; do
            if home_up; then
                fails=0
                [ "$(state)" = vps ] && recover
            else
                fails=$((fails + 1))
                [ "$fails" -ge "$CHECKS" ] && [ "$(state)" = home ] && failover
            fi
            [ "$MODE" = once ] && break
            sleep "$INTERVAL"
        done
        ;;
esac
