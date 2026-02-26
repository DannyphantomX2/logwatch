#!/usr/bin/env bash

LOG_FILE="${1:-auth.log}"
ALERTS_LOG="alerts.log"

# Colors via tput
RED=$(tput setaf 1)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
CYAN=$(tput setaf 6)
BOLD=$(tput bold)
RESET=$(tput sgr0)

# Track failed attempts per IP
declare -A failed_counts
declare -A brute_alerted

BRUTE_THRESHOLD=5

write_alert() {
    local level="$1"
    local message="$2"
    local ts
    ts=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$ts] [$level] $message" >> "$ALERTS_LOG"
}

print_header() {
    echo ""
    echo "${BOLD}${CYAN}╔══════════════════════════════════════════════════════╗${RESET}"
    echo "${BOLD}${CYAN}║          ThreatIntel — Log Monitor v1.0              ║${RESET}"
    echo "${BOLD}${CYAN}╚══════════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo "  Monitoring : ${BOLD}$LOG_FILE${RESET}"
    echo "  Alerts log : ${BOLD}$ALERTS_LOG${RESET}"
    echo "  Started    : $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    echo "${CYAN}──────────────────────────────────────────────────────${RESET}"
    echo ""
}

process_line() {
    local line="$1"
    local ts
    ts=$(date "+%H:%M:%S")

    # Detect failed SSH login
    if echo "$line" | grep -q "Failed password"; then
        local ip
        ip=$(echo "$line" | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}')

        if [[ -n "$ip" ]]; then
            # Increment failed count
            failed_counts["$ip"]=$(( ${failed_counts["$ip"]:-0} + 1 ))
            local count=${failed_counts["$ip"]}

            # Failed login alert
            echo "${YELLOW}${BOLD}[FAILED LOGIN]${RESET}${YELLOW} $ts — $ip attempted login (attempt #$count)${RESET}"
            write_alert "FAILED LOGIN" "$ip attempted login (attempt #$count)"

            # Brute force threshold check
            if (( count >= BRUTE_THRESHOLD )) && [[ -z "${brute_alerted[$ip]}" ]]; then
                brute_alerted["$ip"]=1
                echo "${RED}${BOLD}[BRUTE FORCE] $ip has $count failed attempts — BLOCKING RECOMMENDED${RESET}"
                write_alert "BRUTE FORCE" "$ip has $count failed attempts — BLOCKING RECOMMENDED"
            elif (( count > BRUTE_THRESHOLD )) && [[ -n "${brute_alerted[$ip]}" ]]; then
                # Keep alerting every 5 additional attempts
                local prev_alert=$(( (count - BRUTE_THRESHOLD) % 5 ))
                if (( prev_alert == 0 )); then
                    echo "${RED}${BOLD}[BRUTE FORCE] $ip now has $count failed attempts — BLOCKING RECOMMENDED${RESET}"
                    write_alert "BRUTE FORCE" "$ip now has $count failed attempts — BLOCKING RECOMMENDED"
                fi
            fi
        fi
    fi

    # Detect successful login — check if IP had prior failures
    if echo "$line" | grep -q "Accepted password"; then
        local ip
        ip=$(echo "$line" | grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}')

        if [[ -n "$ip" ]]; then
            local prior=${failed_counts["$ip"]:-0}
            if (( prior > 0 )); then
                echo "${GREEN}${BOLD}[SUSPICIOUS LOGIN]${RESET}${GREEN} $ts — $ip succeeded after $prior failed attempt(s)${RESET}"
                write_alert "SUSPICIOUS LOGIN" "$ip succeeded after $prior failed attempt(s)"
            fi
        fi
    fi

    # Detect sudo abuse — escalation via /bin/bash or /bin/su
    if echo "$line" | grep -q "sudo" && echo "$line" | grep -qE "COMMAND=/bin/bash|COMMAND=/bin/su"; then
        local user
        user=$(echo "$line" | grep -oP '(?<=sudo:\s)\S+')
        local cmd
        cmd=$(echo "$line" | grep -oP 'COMMAND=\S+')

        echo "${RED}${BOLD}[SUDO ABUSE]${RESET}${RED} $ts — ${user:-unknown} attempted privilege escalation via $cmd${RESET}"
        write_alert "SUDO ABUSE" "${user:-unknown} attempted privilege escalation via $cmd"
    fi
}

# Validate log file
if [[ ! -f "$LOG_FILE" ]]; then
    echo "Error: log file '$LOG_FILE' not found."
    echo "Usage: $0 [log_file]"
    exit 1
fi

print_header

# Monitor the log file line by line
tail -f "$LOG_FILE" | while IFS= read -r line; do
    process_line "$line"
done
