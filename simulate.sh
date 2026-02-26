#!/usr/bin/env bash

LOG_FILE="auth.log"
HOSTNAME="server"

> "$LOG_FILE"

NORMAL_USERS=("admin" "deploy" "ubuntu" "ec2-user" "devops")
NORMAL_IPS=("10.0.0.5" "10.0.0.12" "172.16.4.3" "203.0.113.8" "198.51.100.22" "10.10.1.7" "172.31.0.9")
ATTACKER_IP="192.168.1.105"
SUDO_ABUSER="baduser"

get_timestamp() {
    date "+%b %d %H:%M:%S"
}

random_pid() {
    echo $((RANDOM % 40000 + 1000))
}

random_port() {
    echo $((RANDOM % 30000 + 20000))
}

random_element() {
    local arr=("$@")
    echo "${arr[$((RANDOM % ${#arr[@]}))]}"
}

write_entry() {
    local line="$1"
    echo "$line" | tee -a "$LOG_FILE"
    sleep 0.5
}

echo "Starting SSH auth log simulation..."
echo "Writing to: $LOG_FILE"
echo "-------------------------------------------"

# Phase 1: Normal successful logins
echo ""
echo "[Phase 1] Normal successful SSH logins..."
echo ""

for i in {1..5}; do
    TS=$(get_timestamp)
    PID=$(random_pid)
    PORT=$(random_port)
    USER=$(random_element "${NORMAL_USERS[@]}")
    IP=$(random_element "${NORMAL_IPS[@]}")
    write_entry "$TS $HOSTNAME sshd[$PID]: Accepted password for $USER from $IP port $PORT ssh2"
    
    TS=$(get_timestamp)
    write_entry "$TS $HOSTNAME sshd[$PID]: pam_unix(sshd:session): session opened for user $USER by (uid=0)"
done

# Phase 2: Brute force attack from 192.168.1.105
echo ""
echo "[Phase 2] Brute force attack from $ATTACKER_IP..."
echo ""

BRUTE_PID=$(random_pid)
BRUTE_PORT=$(random_port)

for i in {1..12}; do
    TS=$(get_timestamp)
    write_entry "$TS $HOSTNAME sshd[$BRUTE_PID]: Failed password for root from $ATTACKER_IP port $BRUTE_PORT ssh2"
    
    if (( i % 3 == 0 )); then
        TS=$(get_timestamp)
        write_entry "$TS $HOSTNAME sshd[$BRUTE_PID]: message repeated 3 times: [ Failed password for root from $ATTACKER_IP port $BRUTE_PORT ssh2]"
    fi
done

TS=$(get_timestamp)
write_entry "$TS $HOSTNAME sshd[$BRUTE_PID]: error: maximum authentication attempts exceeded for root from $ATTACKER_IP port $BRUTE_PORT ssh2 [preauth]"

TS=$(get_timestamp)
write_entry "$TS $HOSTNAME sshd[$BRUTE_PID]: Disconnecting authenticating user root $ATTACKER_IP port $BRUTE_PORT: Too many authentication failures [preauth]"

# Phase 3: Attacker succeeds
echo ""
echo "[Phase 3] Attacker logs in successfully..."
echo ""

SUCCESS_PID=$(random_pid)
SUCCESS_PORT=$(random_port)

TS=$(get_timestamp)
write_entry "$TS $HOSTNAME sshd[$SUCCESS_PID]: Accepted password for root from $ATTACKER_IP port $SUCCESS_PORT ssh2"

TS=$(get_timestamp)
write_entry "$TS $HOSTNAME sshd[$SUCCESS_PID]: pam_unix(sshd:session): session opened for user root by (uid=0)"

TS=$(get_timestamp)
write_entry "$TS $HOSTNAME sshd[$SUCCESS_PID]: New session 7 of user root."

# Phase 4: Sudo abuse
echo ""
echo "[Phase 4] Sudo abuse attempts from $SUDO_ABUSER..."
echo ""

SUDO_CMDS=("/bin/bash" "/bin/sh" "/usr/bin/passwd" "/bin/su" "/usr/bin/cat /etc/shadow" "/usr/bin/id")

for CMD in "${SUDO_CMDS[@]}"; do
    TS=$(get_timestamp)
    write_entry "$TS $HOSTNAME sudo: $SUDO_ABUSER : command not allowed ; TTY=pts/0 ; PWD=/home/$SUDO_ABUSER ; USER=root ; COMMAND=$CMD"
done

TS=$(get_timestamp)
write_entry "$TS $HOSTNAME sudo: pam_unix(sudo:auth): authentication failure; logname=$SUDO_ABUSER uid=1002 euid=0 tty=/dev/pts/0 ruser=$SUDO_ABUSER rhost="

TS=$(get_timestamp)
write_entry "$TS $HOSTNAME sudo: pam_unix(sudo:auth): 3 incorrect password attempts; logname=$SUDO_ABUSER uid=1002 euid=0 tty=/dev/pts/0"

# Phase 5: Normal logins resume
echo ""
echo "[Phase 5] Normal activity resumes..."
echo ""

for i in {1..4}; do
    TS=$(get_timestamp)
    PID=$(random_pid)
    PORT=$(random_port)
    USER=$(random_element "${NORMAL_USERS[@]}")
    IP=$(random_element "${NORMAL_IPS[@]}")
    write_entry "$TS $HOSTNAME sshd[$PID]: Accepted password for $USER from $IP port $PORT ssh2"

    TS=$(get_timestamp)
    write_entry "$TS $HOSTNAME sshd[$PID]: pam_unix(sshd:session): session opened for user $USER by (uid=0)"

    TS=$(get_timestamp)
    write_entry "$TS $HOSTNAME sudo: $USER : TTY=pts/1 ; PWD=/home/$USER ; USER=root ; COMMAND=/usr/bin/apt-get update"
done

echo ""
echo "-------------------------------------------"
echo "Simulation complete. Log written to: $LOG_FILE"
echo "Total lines: $(wc -l < "$LOG_FILE")"
