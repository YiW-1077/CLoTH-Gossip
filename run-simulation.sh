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
max_attempts=5
project_root="$(cd "$(dirname "$0")" && pwd)"

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
      "$project_root"/ "$environment_dir"

    for arg in "$@"; do
        key="${arg%=*}"
        value="${arg#*=}"
        # Escape special characters in value for sed
        value_escaped=$(printf '%s\n' "$value" | sed -e 's/[\/&]/\\&/g')
        echo "[PARAM] Replacing $key with value=$value" >> "$result_dir/log/setup.log" 2>&1
        sed -i -e "s/^$key=.*/$key=$value_escaped/" "$environment_dir/config/cloth_input.txt"
        # Verify the replacement
        new_val=$(grep "^$key=" "$environment_dir/config/cloth_input.txt" || echo "NOT_FOUND")
        echo "[PARAM] After sed: $new_val" >> "$result_dir/log/setup.log" 2>&1
    done

    cp "$environment_dir/config/cloth_input.txt" "$result_dir"
}

run_once() {
    (
        viewer_pid=""
        cd "$environment_dir" || exit 1
        cmake . > "$result_dir/log/cmake.log" 2>&1 || exit 1
        make > "$result_dir/log/make.log" 2>&1 || exit 1
        
        # Re-apply parameter replacements after CMake build
        # (CMake copies the original cloth_input.txt, so we need to reapply sed)
        echo "[POST-CMAKE] Re-applying parameter replacements..." >> "$result_dir/log/setup.log" 2>&1
        for arg in "$@"; do
            key="${arg%=*}"
            value="${arg#*=}"
            value_escaped=$(printf '%s\n' "$value" | sed -e 's/[\/&]/\\&/g')
            echo "[POST-CMAKE] Replacing $key=$value" >> "$result_dir/log/setup.log" 2>&1
            sed -i -e "s/^$key=.*/$key=$value_escaped/" "$environment_dir/config/cloth_input.txt"
            # Verify
            new_val=$(grep "^$key=" "$environment_dir/config/cloth_input.txt" || echo "NOT_FOUND")
            echo "[POST-CMAKE] After sed: $new_val" >> "$result_dir/log/setup.log" 2>&1
        done
        
        # Build environment variable exports for parameter overrides
        # These will take precedence over values in cloth_input.txt
        env_exports=""
        for arg in "$@"; do
            key="${arg%=*}"
            value="${arg#*=}"
            # Convert parameter names to environment variable names (CLOTH_PARAM_NAME)
            env_var="CLOTH_$(echo "$key" | tr 'a-z' 'A-Z')"
            env_exports="$env_exports $env_var=$value"
        done
        
        # Debug: log environment variables being set
        if [ -n "$env_exports" ]; then
            echo "[ENV] Setting environment variables: $env_exports" >> "$result_dir/log/setup.log" 2>&1
        fi
        
        if grep -q '^enable_simple_progress_mode=true$' "$environment_dir/config/cloth_input.txt"; then
            if grep -q '^enable_simple_progress_window=true$' "$environment_dir/config/cloth_input.txt"; then
                python3 "$environment_dir/scripts/simple_live_view.py" "$result_dir" > "$result_dir/log/simple_view.log" 2>&1 &
                viewer_pid=$!
            fi
            eval "export $env_exports; GSL_RNG_SEED=$seed nice -n 4 ./CLoTH_Gossip $result_dir/" 2>&1 | tee "$result_dir/log/cloth.log"
            sim_status=${PIPESTATUS[0]}
            if [ -n "$viewer_pid" ]; then
                wait "$viewer_pid" 2>/dev/null || true
            fi
            if [ "$sim_status" -ne 0 ]; then
                exit "$sim_status"
            fi
        else
            eval "export $env_exports; GSL_RNG_SEED=$seed nice -n 4 ./CLoTH_Gossip $result_dir/" 2>&1 | tee "$result_dir/log/cloth.log"
            sim_status=${PIPESTATUS[0]}
            if [ "$sim_status" -ne 0 ]; then
                exit "$sim_status"
            fi
        fi
        exit 0
    )
}

attempt=1
success=0
while [ "$attempt" -le "$max_attempts" ]; do
    prepare_environment "${@:3}"
    if run_once "${@:3}"; then
        success=1
        break
    fi
    echo "Attempt $attempt/$max_attempts failed; repairing and retrying." >> "$result_dir/log/retry.log"
    attempt=$((attempt + 1))
done

if [ "$success" -eq 1 ]; then
    echo "seed=$seed" >> "$result_dir/cloth_input.txt"
    echo "1" > "$result_dir/progress.tmp"

    if [ -f "$project_root/scripts/measure_payment_time.sh" ]; then
        bash "$project_root/scripts/measure_payment_time.sh" "$result_dir" > "$result_dir/log/measure_payment_time.log" 2>&1
        if grep -q '^===== Payment Timing Summary =====$' "$result_dir/log/measure_payment_time.log"; then
            sed -n '/^===== Payment Timing Summary =====$/,$p' "$result_dir/log/measure_payment_time.log"
        fi
    else
        echo "measure_payment_time.sh not found; skipping timing post-process." > "$result_dir/log/measure_payment_time.log"
    fi
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
