# =============================================================================
# run_monitor_sweep.sh の進み具合を小さなウィンドウに出す (source して使う)。
#
# sweep は状態ファイル (key=value の行) を書き、ウィンドウ (sweep_progress_window.swift) が
# それを 1 秒ごとに読む。ウィンドウは一番外側の sweep が開き、複数シードの子はファイルに書くだけ。
# ウィンドウは macOS の画面のあるセッション (Aqua) で swiftc があるときだけ出す。
# 出せなくても sweep は止めない。閉じても sweep は止まらない。
#   SWEEP_PROGRESS_WINDOW=0 : ウィンドウを出さない (状態ファイルは書く)
#   閉じたウィンドウを開き直す: bash scripts/sweep_progress.sh  (走っている sweep の分を全部開く)
#
#   sweep_progress_init <seeds> <out>   : 一番外側なら状態ファイルを決めてウィンドウを開く
#   sweep_status_write <state> [k=v...] : 状態ファイルを書き直す (実行中の進みを書くとき)
#   sweep_status_set <state> [k=v...]   : 状態と、渡した key だけを変える (前に書いた数は残す)
#   sweep_status_exit <rc>              : 終わったときの状態を書く (trap EXIT から呼ぶ)
#
# state: starting / running / transfer (NAS へ移している) / summary (集計中) /
#        seed_done / seed_failed (複数シードの 1 つが終わった) / done / failed
# =============================================================================

sweep_progress_lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sweep_progress_cache="${TMPDIR:-/tmp}/cloth_sweep_progress"

# ウィンドウを作って (ソースが変わったときだけ swiftc でビルドする) 開く。$1 = 状態ファイル
function sweep_window_open() {
    [[ "${SWEEP_PROGRESS_WINDOW:-1}" == "0" ]] && return 0
    [[ "$(uname)" == "Darwin" && "$(launchctl managername 2>/dev/null)" == "Aqua" ]] || return 0   # ssh などで画面がない
    command -v swiftc >/dev/null 2>&1 || { echo "[WARN] swiftc がないので進行状況のウィンドウは出さない"; return 0; }
    local src="$sweep_progress_lib_dir/sweep_progress_window.swift"
    local bin="$sweep_progress_cache/sweep_progress_window_$(md5 -q "$src")"
    # ビルド (初回 20 秒ほど) を待たずに sweep を進めるため、ビルドと起動は裏で行う
    (
        if [[ ! -x "$bin" ]]; then
            if ! nice -n 8 swiftc -O "$src" -o "$bin.$BASHPID" > "$sweep_progress_cache/build.log" 2>&1 || ! mv -f "$bin.$BASHPID" "$bin"; then
                echo "[WARN] 進行状況のウィンドウを作れなかった ($sweep_progress_cache/build.log)。sweep はそのまま続ける"
                exit 0
            fi
            find "$sweep_progress_cache" -name 'sweep_progress_window_*' ! -name "${bin##*/}" -delete 2>/dev/null   # 前のソースのもの
        fi
        exec nice -n 8 "$bin" "$1" < /dev/null > /dev/null 2>&1
    ) &
    disown 2>/dev/null || true
}

function sweep_progress_init() {
    [[ -n "${SWEEP_STATUS_FILE:-}" ]] && return 0   # 複数シードの子 (親が決めた状態ファイルに書く)
    mkdir -p "$sweep_progress_cache" || return 0
    find "$sweep_progress_cache" -name 'status_*' -mtime +2 -delete 2>/dev/null   # 古い sweep の状態ファイル
    export SWEEP_STATUS_FILE="$sweep_progress_cache/status_$$.txt"
    export SWEEP_TOP_PID=$$ SWEEP_RUN_START=$EPOCHSECONDS SWEEP_OUT="$2"
    local s seeds
    IFS=', ' read -r -a seeds <<< "$1"
    sweep_first_seed="${seeds[0]}" sweep_seed_total=0
    for s in "${seeds[@]}"; do [[ -n "$s" ]] && sweep_seed_total=$((sweep_seed_total + 1)); done
    sweep_status_write starting
    sweep_window_open "$SWEEP_STATUS_FILE"
}

# 書きかけを読まれないよう一時ファイルに書いてから mv する
function sweep_status_write() {
    [[ -n "${SWEEP_STATUS_FILE:-}" ]] || return 0
    local st="$1"; shift
    {
        printf 'state=%s\nupdated=%s\npid=%s\nrun_start=%s\nout=%s\nseed=%s\nseed_index=%s\nseed_count=%s\nfailed_seeds=%s\n' \
            "$st" "$EPOCHSECONDS" "$SWEEP_TOP_PID" "$SWEEP_RUN_START" "$SWEEP_OUT" "${seed_base:-${sweep_first_seed:-}}" \
            "${SWEEP_SEED_INDEX:-1}" "${SWEEP_SEED_COUNT:-${sweep_seed_total:-1}}" "${SWEEP_FAILED_SEEDS:-}"
        if [[ $# -gt 0 ]]; then printf '%s\n' "$@"; fi
    } > "$SWEEP_STATUS_FILE.$$" 2>/dev/null && mv -f "$SWEEP_STATUS_FILE.$$" "$SWEEP_STATUS_FILE" 2>/dev/null
    return 0
}

function sweep_status_set() {
    [[ -n "${SWEEP_STATUS_FILE:-}" && -f "$SWEEP_STATUS_FILE" ]] || return 0
    local st="$1"; shift
    local drop='^(state|updated|sim)=' kv
    for kv in "$@"; do drop+="|^${kv%%=*}="; done
    {
        grep -Ev "$drop" "$SWEEP_STATUS_FILE"
        printf 'state=%s\nupdated=%s\n' "$st" "$EPOCHSECONDS"
        if [[ $# -gt 0 ]]; then printf '%s\n' "$@"; fi
    } > "$SWEEP_STATUS_FILE.$$" 2>/dev/null && mv -f "$SWEEP_STATUS_FILE.$$" "$SWEEP_STATUS_FILE" 2>/dev/null
    return 0
}

# 複数シードの子は seed_done / seed_failed を書き、全体の done / failed は親が書く
function sweep_status_exit() {
    local rc="$1" child=""
    [[ -n "${SWEEP_SEED_COUNT:-}" ]] && child="seed_"
    if [[ "$rc" -ne 0 ]]; then sweep_status_set "${child}failed" "rc=$rc"
    else sweep_status_set "${child:-}done" "rc=0"
    fi
}

# 直接実行したとき: 走っている sweep のウィンドウを開き直す
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    shopt -s nullglob
    opened=0
    for f in "$sweep_progress_cache"/status_*.txt; do
        pid=$(sed -n 's/^pid=//p' "$f")
        [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null || continue
        SWEEP_PROGRESS_WINDOW=1 sweep_window_open "$f"
        opened=$((opened + 1))
    done
    echo "開いたウィンドウ: $opened (走っている sweep の数)"
fi
