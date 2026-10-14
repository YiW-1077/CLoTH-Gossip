"""NAS の結果置き場を探す (集計スクリプト用。シェル側は scripts/nas_lib.sh の nas_find_dir)。

候補はプロジェクト直下の nas.conf に書く (1行1つ・glob 可・# で始まる行はコメント。書き方は nas.conf.example)。
nas.conf は実際のアドレスを含むので git に入れない (.gitignore)。
"""
import glob
import os

CONF = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "nas.conf")
NAS_HINT = "NAS が見えない: NAS をマウントし、nas.conf (書き方は nas.conf.example) に置き場所を書くこと"


def find_nas():
    """nas.conf の候補を上から見て、最初にある dir を返す。nas.conf が無いか、どれも無ければ None。"""
    if not os.path.isfile(CONF):
        return None
    with open(CONF, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # glob は同じ共有が二重マウントされて /Volumes/<共有>-1 等になったときのため
            for d in sorted(glob.glob(line)):
                if os.path.isdir(d):
                    return d
    return None
