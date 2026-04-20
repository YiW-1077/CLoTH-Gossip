#!/bin/bash
# Single simulation runner
# Usage: run-simulation.sh <seed> <output-directory> [setting_key=setting_value]

if [ $# -lt 3 ]; then
    echo "usage: $0 <seed> <output-directory> [setting_key=setting_value]"
    exit
fi

seed="$1"
environment_dir="$2/environment"
result_dir="$2"
max_attempts=2

mkdir -p "$result_dir"
mkdir -p "$result_dir/log"

prepare_environment() {
    rm -rf "$environment_dir"
    mkdir -p "$environment_dir"
    rsync -av -q \
      --exclude='result' \
      --exclude='cmake-build-debug' \
      --exclude='cloth.dSYM' \
      --exclude='.idea' \
      --exclude='.git' \
      --exclude='.cmake' \
      --exclude='202*' \
      --exclude='CMakeCache.txt' \
      --exclude='CMakeFiles' \
      --exclude='cmake_install.cmake' \
      --exclude='Makefile' \
      --exclude='CLoTH_Gossip' \
      --exclude='cloth' \
      "." "$environment_dir"

    for arg in "$@"; do
        key="${arg%=*}"
        value="${arg#*=}"
        sed -i -e "s/$key=.*/$key=$value/" "$environment_dir/config/cloth_input.txt"
    done

    cp "$environment_dir/config/cloth_input.txt" "$result_dir"
}

run_once() {
    cd "$environment_dir" || return 1
    cmake . > "$result_dir/log/cmake.log" 2>&1 || return 1
    make > "$result_dir/log/make.log" 2>&1 || return 1
    GSL_RNG_SEED="$seed" nice -n 4 ./CLoTH_Gossip "$result_dir/" > "$result_dir/log/cloth.log" 2>&1 || return 1
    return 0
}

attempt=1
success=0
while [ "$attempt" -le "$max_attempts" ]; do
    prepare_environment "${@:3}"
    if run_once; then
        success=1
        break
    fi
    echo "Attempt $attempt/$max_attempts failed; repairing and retrying." >> "$result_dir/log/retry.log"
    attempt=$((attempt + 1))
done

if [ "$success" -eq 1 ]; then
    cat "$result_dir/output.log"
    echo "seed=$seed" >> "$result_dir/cloth_input.txt"
    echo "1" > "$result_dir/progress.tmp"

    echo ""
    echo "===== Payment Timing Measurement ====="
    bash "$(dirname "$0")/scripts/measure_payment_time.sh" "$result_dir"
else
    {
        echo "Simulation failed after $max_attempts attempts."
        echo "See logs in $result_dir/log/"
    } > "$result_dir/log/error_summary.log"
    echo "failed" > "$result_dir/progress.tmp"
fi

rm -rf "$environment_dir"
if [ "$success" -ne 1 ]; then
    exit 1
fi
