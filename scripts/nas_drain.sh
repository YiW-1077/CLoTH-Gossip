#!/opt/homebrew/bin/bash
# =============================================================================
# 完了したシミュレーション結果を NAS へ順次移し、ローカルから消す。
# run_monitor_sweep.sh を NAS なしで起動してしまった run や、scripts/run_*_grid.sh のように
# 自前の転送を持たない run の横で回す。
#
# Usage: scripts/nas_drain.sh <local_base> <nas_base> <watch_pattern>
#   local_base 以下の結果 dir (cloth_input.txt を持つ dir。environment/ の中は除く) を
#   nas_base 以下の同じ相対パスへ移す。watch_pattern (pgrep -f の正規表現) に一致する
#   プロセスが全部終わるまで回り、最後にもう一度移してから、結果 dir が残っていなければ
#   ログ等の残りも NAS へ写してローカルの local_base を消す。
#
# 完了の判定 (3つ全部):
#   - progress.tmp が 1 か failed
#   - environment/ が消えている (run-simulation.sh は progress=1 を書いた後に
#     measure_payment_time.sh を回し、最後に environment を消す)
#   - そのパスを含むプロセスが無い
# 移した後は run_monitor_sweep.sh の組み込み転送と同じく、空の dir に progress.tmp と
# .moved_to_remote だけ残す (スイープの進捗表示が完了数を数えられるように)。
# =============================================================================
set -u
local_base="${1:?usage: $0 <local_base> <nas_base> <watch_pattern>}"; local_base="${local_base%/}"
nas_base="${2:?usage}"; nas_base="${nas_base%/}"
pattern="${3:?usage}"
interval="${DRAIN_INTERVAL:-30}"
n_err=0

busy() {  # $1 を引数に含むプロセスがまだあるか (パスの後ろが 空白・/・行末 のときだけ一致とみなす)
    # パスは環境変数で渡す (awk -v で渡すと awk 自身のコマンド行に載り、常に「使用中」になる)
    ps -axo command= | BUSY_PATH="$1" awk '{
        p = ENVIRON["BUSY_PATH"]; i = index($0, p)
        if (i) { c = substr($0, i + length(p), 1); if (c == "" || c == " " || c == "/") f = 1 }
    } END { exit !f }'
}

drain_once() {
    local f d prog rel dest
    while IFS= read -r -d '' f; do
        d="$(dirname "$f")"
        [ -f "$d/.moved_to_remote" ] && continue
        prog="$(cat "$d/progress.tmp" 2>/dev/null)"
        [[ "$prog" == "1" || "$prog" == "failed" ]] || continue
        [ -d "$d/environment" ] && continue
        busy "$d" && continue
        rel="${d#"$local_base"/}"; dest="$nas_base/$rel"
        if ! mkdir -p "$dest"; then echo "[ERROR] mkdir $dest"; n_err=$((n_err + 1)); continue; fi
        # SMB は権限・時刻の精度が違うので -rlt と --modify-window で比べる
        if rsync -rlt "$d/" "$dest/" &&
           [ -z "$(rsync -rlt --dry-run --itemize-changes --modify-window=2 "$d/" "$dest/")" ]; then
            rm -rf "$d"; mkdir -p "$d"
            echo "$prog" > "$d/progress.tmp"; echo "$dest" > "$d/.moved_to_remote"
            echo "$(date '+%H:%M:%S') moved ($prog) $rel"
        else
            echo "[ERROR] rsync/照合に失敗: $rel (ローカルに残す)"; n_err=$((n_err + 1))
        fi
    done < <(find "$local_base" -name cloth_input.txt ! -path '*/environment/*' -print0 2>/dev/null)
}

echo "$(date '+%F %T') 開始: $local_base -> $nas_base (監視: $pattern)"
mkdir -p "$nas_base" || { echo "[ERROR] NAS に書けない: $nas_base"; exit 1; }
while pgrep -f "$pattern" > /dev/null; do
    drain_once
    sleep "$interval"
done
sleep 5
drain_once

left=$(find "$local_base" -name cloth_input.txt ! -path '*/environment/*' 2>/dev/null | wc -l | tr -d ' ')
if [ "$left" -eq 0 ] && [ "$n_err" -eq 0 ]; then
    # 残り (スイープのログ等) を写す。移した dir の目印と、移した後に作られた中身のない
    # results_summary.csv (集計は NAS から作り直す) は写さない
    if rsync -rlt --exclude environment --exclude .moved_to_remote --exclude progress.tmp \
            --exclude results_summary.csv --exclude '*.tmp' "$local_base/" "$nas_base/"; then
        rm -rf "$local_base"
        echo "$(date '+%F %T') 完了: 全部 NAS に移した。ローカルの $local_base を削除"
    else
        echo "[ERROR] 残りのファイルの転送に失敗。ローカルは残す"
    fi
else
    echo "$(date '+%F %T') 終了: 移せていない結果 dir $left 件・エラー $n_err 件。ローカルは残す"
fi
