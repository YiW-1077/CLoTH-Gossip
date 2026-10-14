# =============================================================================
# scripts/run_*_grid.sh の NAS 出力の共通部分 (source して使う)。
#
# 結果の置き場所は環境変数 REMOTE_OUTPUT_DIR で決める:
#   省略  = /Volumes/public1*/$NAS_SUBDIR/<ローカルの出力先の名前> (見つからなければ止まる)
#   パス  = そこ
#   local = NAS を使わずローカルに残す
# ローカルの出力先は走っている間の作業場所。終わったセルから NAS へ移し (写して照合してから
# ローカルを消す)、集計 CSV は NAS 上の結果から作って NAS に置き、ローカルにも写す。
# 最後はローカルに集計 CSV だけが残る。
#
# 置き場所 (ローカルか NAS) にもうセルがあるときは止める。NAS は消えないので、同じ名前で
# 後日回すと古いコードで作ったセルを黙って使い回し、そのまま集計してしまうため。
# 続きから回すときだけ RESUME=1 を明示する。
#
#   nas_setup <local_out_base>    : NAS_DEST (空 = ローカルのみ) と RESULT_BASE (集計が読む所) を決める
#   nas_cell_done <cell_dir>      : 終わったセル (成功でも失敗でも) を NAS の同じ相対パスへ移す
#   nas_finish [<csv の名前>...]  : 集計 CSV をローカルへ写し、ローカルの作業場所を片付ける
# =============================================================================

NAS_SUBDIR="thesis/2026bachelor-af23/AF23027王毅恒"
LOCAL_BASE=""; NAS_DEST=""; RESULT_BASE=""

# セル (cloth.log を持つ dir) の数。_work_template と各セルの _work は数えない
_count_cells() {
    find "$1" -name cloth.log ! -path '*/_work*' 2>/dev/null | wc -l | tr -d ' '
}

nas_setup() {
    local m n_local n_nas
    LOCAL_BASE="${1%/}"
    case "${REMOTE_OUTPUT_DIR:-}" in
        local)
            echo "[Config] 出力はローカルのみ (REMOTE_OUTPUT_DIR=local)。NAS には送らない" ;;
        "")
            # 二重マウントで /Volumes/public1-1 等になることがあるので、書き込めるものを使う
            for m in /Volumes/public1 /Volumes/public1-*; do
                if [[ -d "$m/$NAS_SUBDIR" && -w "$m/$NAS_SUBDIR" ]]; then
                    NAS_DEST="$m/$NAS_SUBDIR/$(basename "$LOCAL_BASE")"; break
                fi
            done
            if [[ -z "$NAS_DEST" ]]; then
                echo "ERROR: NAS ($NAS_SUBDIR) が見つからないか書き込めない。"
                echo "       open smb://morinolab@172.20.86.110/public1 でマウントするか、REMOTE_OUTPUT_DIR で置き場所を渡すこと"
                return 1
            fi ;;
        smb://*)
            echo "ERROR: SMB URI は使えない: $REMOTE_OUTPUT_DIR (マウントしてから /Volumes/... のパスを渡すこと)"
            return 1 ;;
        *)
            NAS_DEST="${REMOTE_OUTPUT_DIR%/}" ;;
    esac
    RESULT_BASE="${NAS_DEST:-$LOCAL_BASE}"

    n_local=$(_count_cells "$LOCAL_BASE"); n_nas=0
    [[ -n "$NAS_DEST" ]] && n_nas=$(_count_cells "$NAS_DEST")
    if [[ $((n_local + n_nas)) -gt 0 ]]; then
        if [[ "${RESUME:-0}" != "1" ]]; then
            echo "ERROR: 置き場所にもうセルがある (ローカル $n_local 件: $LOCAL_BASE${NAS_DEST:+ / NAS $n_nas 件: $NAS_DEST})。"
            echo "       別の名前で回すか、続きから回すなら RESUME=1 を付けること (終わっているセルは使い回す)"
            return 1
        fi
        echo "[Config] RESUME=1: 既にあるセル (ローカル $n_local 件 / NAS $n_nas 件) のうち終わっているものは使い回す"
    fi

    if [[ -n "$NAS_DEST" ]]; then
        mkdir -p "$NAS_DEST" || { echo "ERROR: NAS に出力先を作れない: $NAS_DEST"; return 1; }
        echo "[Config] 出力先 NAS: $NAS_DEST (終わったセルから移し、ローカルには集計 CSV だけ残す)"
    fi
}

# 写して照合してからローカルを消す。失敗したらローカルに残して 1 を返す。
# SMB は権限・時刻の精度が違うので -rlt と --modify-window で比べる (scripts/nas_drain.sh と同じ)。
# 回し直したセルを同じ所へ移すときに古いファイルが残らないよう --delete を付ける。
_nas_move() {
    local src="${1%/}" dest="${2%/}"
    mkdir -p "$dest" || return 1
    if rsync -rlt --delete "$src/" "$dest/" &&
       [ -z "$(rsync -rlt --delete --dry-run --itemize-changes --modify-window=2 "$src/" "$dest/")" ]; then
        rm -rf "$src"
    else
        return 1
    fi
}

nas_cell_done() {
    local cell="${1%/}" rel
    [[ -n "$NAS_DEST" ]] || return 0
    rel="${cell#"$LOCAL_BASE"/}"
    # 失敗したセルに残る _work の入力 CSV は symlink。SMB で失敗しうるので先に消す
    [ -d "$cell/_work" ] && find "$cell/_work" -type l -delete
    if _nas_move "$cell" "$NAS_DEST/$rel"; then
        echo "  [NAS] $rel"
    else
        echo "  [ERROR] NAS への転送/照合に失敗: $rel (ローカルに残す)"; return 1
    fi
}

nas_finish() {
    local f left
    [[ -n "$NAS_DEST" ]] || return 0
    for f in "$@"; do
        if cp "$NAS_DEST/$f" "$LOCAL_BASE/$f" && cmp -s "$NAS_DEST/$f" "$LOCAL_BASE/$f"; then
            echo "集計 CSV: $NAS_DEST/$f (ローカルにも写した: $LOCAL_BASE/$f)"
        else
            echo "[ERROR] 集計 CSV をローカルへ写せない: $f"
        fi
    done
    rm -rf "$LOCAL_BASE/_work_template"
    left=$(_count_cells "$LOCAL_BASE")
    if [[ "$left" -eq 0 ]]; then
        find "$LOCAL_BASE" -type d -empty -delete 2>/dev/null
        echo "ローカルの作業場所を片付けた ($([[ $# -gt 0 ]] && echo "残したのは集計 CSV だけ" || echo "何も残していない"))。結果は $NAS_DEST"
    else
        echo "[WARN] NAS へ移せていないセルが $left 件ローカルに残っている: $LOCAL_BASE"
    fi
}
