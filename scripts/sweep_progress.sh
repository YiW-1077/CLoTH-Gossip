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
#   sweep_status_traps                  : 終わったとき・Ctrl-C や kill で止められたときに状態を書く trap を張る
#   sweep_die <行...>                   : 行を出して (今までの echo と同じ)、エラーの内容として覚えてから止まる
#   sweep_cell_errors <output_base>     : 失敗したセルの err 行を出す
#   sweep_nas_errors <nas_error_log>    : NAS へ移せなかったものの err 行を出す
#
# state: starting / running / transfer (NAS へ移している) / summary (集計中) /
#        seed_done / seed_failed (複数シードの 1 つが終わった) / done / failed
# エラーの内容 (ウィンドウの「エラーの内容」に出す):
#   err=<シード>|<文>                              : sweep が止まった理由・NAS へ移せなかったもの
#   errcell=<シード>|<セル>|<理由>|<ログの最後の行> : 失敗したセル (理由は run-simulation.sh の log/fail_reason.txt)
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

sweep_error_lines=()

function sweep_die() {
    local line
    for line in "$@"; do
        echo "$line"
        sweep_error_lines+=("err=${seed_base:-}|$line")
    done
    exit 1
}

# 複数シードの子は seed_done / seed_failed を書き、全体の done / failed は親が書く
function sweep_status_exit() {
    local rc="$1" child=""
    [[ -n "${SWEEP_SEED_COUNT:-}" ]] && child="seed_"
    if [[ "$rc" -ne 0 ]]; then
        if [[ ${#sweep_error_lines[@]} -eq 0 ]]; then   # sweep_die を通らずに終わった
            if [[ "$rc" -gt 128 && "$rc" -lt 160 ]]; then
                sweep_error_lines=("err=${seed_base:-}|$(sweep_signal_message "$rc")")
            else
                sweep_error_lines=("err=${seed_base:-}|終了コード $rc で終わった (理由の記録なし。sweep のログを見ること)")
            fi
        fi
        sweep_status_set "${child}failed" "rc=$rc" "${sweep_error_lines[@]}"
    else
        sweep_status_set "${child:-}done" "rc=0"
    fi
}

# $1 = 終了コード (128 + シグナルの番号)
function sweep_signal_message() {
    case $(($1 - 128)) in
        2) echo "Ctrl-C で止められた (SIGINT)" ;;
        15) echo "kill で止められた (SIGTERM)" ;;
        1) echo "端末が閉じられて止まった (SIGHUP)" ;;
        *) echo "シグナル $(($1 - 128)) で止められた" ;;
    esac
}

# シグナルで止められたときは EXIT の trap に $? が渡らない (0 になる) ので、シグナルごとに張る。
# sweep_on_stop があれば先に呼ぶ (run_monitor_sweep.sh が走っているセルを止める)。
# 書いたあとは同じシグナルで止まり直す
function sweep_status_traps() {
    trap 'sweep_status_exit $?' EXIT
    local s
    for s in INT:130 TERM:143 HUP:129; do
        trap "declare -F sweep_on_stop > /dev/null && sweep_on_stop; sweep_stop_display; sweep_status_exit ${s#*:}; trap - ${s%%:*} EXIT; kill -${s%%:*} \$\$" "${s%%:*}"
    done
}

# 進み具合を書く display_progress (run_monitor_sweep.sh の裏の処理、pid は display_pid) を止める。
# 裏の処理は Ctrl-C を受けないので、止めないと「止められた」を「走行中」で上書きし続ける
function sweep_stop_display() {
    [[ -n "${display_pid:-}" ]] || return 0
    kill "$display_pid" 2>/dev/null && wait "$display_pid" 2>/dev/null
    return 0
}

# ログの最後の中身のある行 (進み具合の \r で上書きされた行は最後の分だけ)。make.log は最初の error の行
function sweep_log_tail() {
    [[ -f "$1" ]] || { echo "($1 がない)"; return; }
    local line=""
    [[ "$1" == */make.log ]] && line=$(grep -m 1 -i 'error' "$1")
    [[ -z "$line" ]] && line=$(tr '\r' '\n' < "$1" | grep -v '^[[:space:]]*$' | tail -1)
    echo "${line:0:300}"
}

function sweep_cell_errors() {
    local base="$1" f d real reason logname n=0
    while IFS= read -r f; do
        [[ "$(<"$f")" == "failed" ]] || continue
        n=$((n + 1))
        [[ $n -gt 5 ]] && continue
        d="${f%/progress.tmp}"
        real="$d"
        [[ -f "$d/.moved_to_remote" ]] && real="$(<"$d/.moved_to_remote")"   # もう NAS へ移した
        reason="理由の記録なし"; logname="log/cloth.log"
        if [[ -f "$real/log/fail_reason.txt" ]]; then
            reason=$(sed -n 1p "$real/log/fail_reason.txt"); logname=$(sed -n 2p "$real/log/fail_reason.txt")
        fi
        echo "errcell=${seed_base:-}|${d#$base/}|$reason|$(sweep_log_tail "$real/$logname")"
    done < <(find "$base" -type d -name environment -prune -o -type f -name progress.tmp -print 2>/dev/null | sort)
    [[ $n -gt 5 ]] && echo "err=${seed_base:-}|ほかにも失敗したセルが $((n - 5)) 個ある"
    return 0
}

function sweep_nas_errors() {
    [[ -s "$1" ]] || return 0
    grep '^\[ERROR\]' "$1" | head -3 | sed "s/^/err=${seed_base:-}|NAS: /"
    return 0
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
