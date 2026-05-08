#!/usr/bin/env bash
#
# NFS failure test for mmap-shield.
#
# Starts an NFS server in Docker, mounts it, creates a file,
# mmaps it, kills the server mid-read, and verifies that
# mmap-shield returns Err instead of crashing the process.
#
# Requirements:
#   - Docker + docker compose
#   - Root (for NFS mount)
#   - Linux (NFS client kernel module)
#
# Usage:
#   sudo ./tests/nfs_failure_test/run_test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
MOUNT_DIR="/tmp/mmap-shield-nfs-test"
TEST_FILE="$MOUNT_DIR/test_data.bin"

cleanup() {
    echo "[cleanup] unmounting..."
    umount "$MOUNT_DIR" 2>/dev/null || true
    rmdir "$MOUNT_DIR" 2>/dev/null || true
    echo "[cleanup] stopping NFS server..."
    cd "$SCRIPT_DIR" && docker compose down -v 2>/dev/null || true
}

trap cleanup EXIT

echo "=== mmap-shield NFS failure test ==="
echo ""

# 1. Build the test binary
echo "[1/6] Building test binary..."
cd "$PROJECT_DIR"
cargo build --release --bin sigbus_victim 2>&1 | tail -1

# 2. Start NFS server
echo "[2/6] Starting NFS server..."
cd "$SCRIPT_DIR"
docker compose up -d 2>&1 | tail -1

echo "    Waiting for NFS server to be ready..."
for i in $(seq 1 30); do
    if nc -z 127.0.0.1 2049 2>/dev/null; then
        echo "    NFS server ready after ${i}s"
        sleep 2
        break
    fi
    sleep 1
    if [ "$i" = "30" ]; then
        echo "    ERROR: NFS server did not start within 30s"
        docker logs mmap-shield-nfs 2>&1 | tail -10
        exit 1
    fi
done

# 3. Mount NFS
echo "[3/6] Mounting NFS..."
mkdir -p "$MOUNT_DIR"

OS="$(uname -s)"
if [ "$OS" = "Darwin" ]; then
    # macOS: use mount_nfs with soft mount and short timeouts
    mount_nfs -o soft,timeo=10,retrans=1,vers=3,resvport,nolock 127.0.0.1:/export "$MOUNT_DIR"
else
    # Linux: try NFSv4 first, fall back to v3
    if ! mount -t nfs -o vers=4,soft,timeo=10,retrans=1 127.0.0.1:/ "$MOUNT_DIR" 2>/dev/null; then
        mount -t nfs -o vers=3,soft,timeo=10,retrans=1,nolock 127.0.0.1:/export "$MOUNT_DIR"
    fi
fi

echo "    Mounted at $MOUNT_DIR"

# 4. Create test file on NFS
echo "[4/6] Creating test file on NFS mount..."
dd if=/dev/urandom of="$TEST_FILE" bs=1M count=4 2>/dev/null
sync
echo "    Created 4MB test file"

# 5. Verify normal read works
echo "[5/8] Verifying normal read works..."
RESULT=$("$PROJECT_DIR/target/release/sigbus_victim" --scenario=nfs_read --file="$TEST_FILE" 2>&1) || true
echo "    Result: $RESULT"

# 6. Kill NFS server and verify SIGBUS recovery
echo "[6/8] Killing NFS server and testing SIGBUS recovery..."

"$PROJECT_DIR/target/release/sigbus_victim" --scenario=nfs_failure --file="$TEST_FILE" &
VICTIM_PID=$!

sleep 1

docker compose stop nfs-server 2>/dev/null

set +e
wait $VICTIM_PID
EXIT_CODE=$?
set -e

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "PASS: Process survived NFS failure (exit code 0)"
elif [ $EXIT_CODE -eq 1 ]; then
    echo "PASS: Process detected error and exited cleanly (exit code 1)"
elif [ $EXIT_CODE -gt 128 ]; then
    SIGNAL=$((EXIT_CODE - 128))
    echo "FAIL: Process killed by signal $SIGNAL (exit code $EXIT_CODE)"
    echo "      SIGBUS recovery did not work!"
    exit 1
else
    echo "PASS: Process exited with code $EXIT_CODE (not killed by signal)"
fi

# 7. Restart NFS server
# 7. Restart NFS server, remount, and verify reads work again
echo ""
echo "[7/7] Testing full reconnect cycle..."
echo "    Restarting NFS server..."
docker compose start nfs-server 2>/dev/null

echo "    Waiting for NFS server..."
for i in $(seq 1 30); do
    if nc -z 127.0.0.1 2049 2>/dev/null; then
        echo "    NFS server ready after ${i}s"
        sleep 2
        break
    fi
    sleep 1
done

# Remount to clear stale NFS state
echo "    Remounting NFS..."
umount "$MOUNT_DIR" 2>/dev/null || umount -f "$MOUNT_DIR" 2>/dev/null || true
sleep 1

OS="$(uname -s)"
if [ "$OS" = "Darwin" ]; then
    mount_nfs -o soft,timeo=10,retrans=1,vers=3,resvport,nolock 127.0.0.1:/export "$MOUNT_DIR"
else
    if ! mount -t nfs -o vers=4,soft,timeo=10,retrans=1 127.0.0.1:/ "$MOUNT_DIR" 2>/dev/null; then
        mount -t nfs -o vers=3,soft,timeo=10,retrans=1,nolock 127.0.0.1:/export "$MOUNT_DIR"
    fi
fi
echo "    Remounted at $MOUNT_DIR"

# Recreate test file (volume data persists across server restart)
echo "    Verifying test file exists..."
if [ ! -f "$TEST_FILE" ]; then
    echo "    Recreating test file..."
    dd if=/dev/urandom of="$TEST_FILE" bs=1M count=4 2>/dev/null
    sync
fi

# Read after reconnect
echo "    Reading after reconnect..."
set +e
RESULT=$("$PROJECT_DIR/target/release/sigbus_victim" --scenario=nfs_read --file="$TEST_FILE" 2>&1)
RECONNECT_CODE=$?
set -e
echo "    Result: $RESULT"

if [ $RECONNECT_CODE -eq 0 ]; then
    echo ""
    echo "PASS: Full reconnect cycle succeeded (mount → read → kill → recover → remount → read)"
elif [ $RECONNECT_CODE -gt 128 ]; then
    SIGNAL=$((RECONNECT_CODE - 128))
    echo ""
    echo "FAIL: Process killed by signal $SIGNAL during reconnect read"
    exit 1
else
    echo ""
    echo "FAIL: Reconnect read failed with exit code $RECONNECT_CODE"
    exit 1
fi

echo ""
echo "=== NFS failure test complete ==="
