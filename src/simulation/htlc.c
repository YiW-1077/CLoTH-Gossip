#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>

#include <gsl/gsl_rng.h>
#include <gsl/gsl_randist.h>
#include <gsl/gsl_math.h>

#include "simulation/htlc.h"
#include "data_structures/array.h"
#include "data_structures/heap.h"
#include "core/payments.h"
#include "network/routing.h"
#include "network/network.h"
#include "network/monitoring.h"
#include "core/event.h"
#include "data_structures/utils.h"
#include "simulation/m3_hmac.h"
#include <time.h>

/* 使用ライブラリの役割（このCファイル）
 * - 標準Cライブラリ（stdlib/stdio/string/stdint/unistd）:
 *   基本I/O、メモリ管理、文字列操作、型、ユーティリティ機能に利用する。
 * - pthread:
 *   経路事前計算や共有データ更新時の並列処理・同期で利用する。
 * - GSL（gsl_rng/gsl_randist/gsl_math）:
 *   乱数生成や分布サンプリングにより、HTLC成功/失敗の確率イベントを表現する。
 * - プロジェクト内ヘッダ（simulation/network/core/data_structures）:
 *   HTLCイベント処理、経路探索、支払い情報、内部データ構造を連携させる。
 */

/* Functions in this file simulate the HTLC mechanism for exchanging payments, as implemented in the Lightning Network.
   They are a (high-level) copy of functions in lnd-v0.9.1-beta (see files `routing/missioncontrol.go`, `htlcswitch/switch.go`, `htlcswitch/link.go`) */


/* AUXILIARY FUNCTIONS */

/* compute the fees to be paid to a hop for forwarding the payment */
uint64_t compute_fee(uint64_t amount_to_forward, struct policy policy) {
  uint64_t fee;
  fee = (policy.fee_proportional*amount_to_forward) / 1000000;
  return policy.fee_base + fee;
}

static uint64_t sample_base_forward_delay(struct simulation* simulation, struct network_params net_params) {
  return net_params.average_payment_forward_interval +
         (long)(fabs(net_params.variance_payment_forward_interval *
                     gsl_ran_ugaussian(simulation->random_generator)));
}

/* 攻撃側の warmup 判定は payment->is_warmup(cloth.c で先頭500件を固定)に一本化。
 * 旧 get_attack_warmup_threshold は完了数 processed_payments と比較していたが、完了数は
 * 決済の in-flight 重なりで開始index基準の is_warmup から乖離し、小 n では計測窓の決済が
 * settle する時点でも完了数がしきい値(500)に届かず攻撃遅延が一切注入されない不整合を
 * 起こした(n=200 は総700件でも完了数が最大432止まり→no_defense の grief=0 の根因)。よって
 * 撤去し、ゲートを is_warmup に揃えた(判定は呼び出し側 apply_attack_delay_if_needed)。
 * hold-to-timeout 型の失敗攻撃も warmup 決済では発動しない (fail_attack_in_warmup)。
 * 検知器側の warmup 判定も同じ is_warmup に揃えた (monitoring.c::detector_in_warmup)。
 * 揃える前は完了数で判定しており、境界で攻撃サンプルを warmup 学習して baseline を汚染した。 */

/* 攻撃遅延の発動判定(config チェックのみ; warmup 判定は呼び出し側で per-payment)。
 * 時刻窓 [start_time,+duration] は既定窓が warmup にほぼ収まり信号が乗らず廃止。 */
static unsigned int is_attack_delay_active(struct network_params net_params) {
  if (!net_params.enable_network_attack_delay) return 0;
  if (net_params.attack_delay_intensity <= 1.0 && net_params.attack_delay_jitter <= 0.0) return 0;
  return 1;
}

/* ⚠️ 出力列 is_timeout の意味論: この列は
 *   (a) 真のタイムアウト (elapsed > payment_timeout, find_path の冒頭)
 *   (b) 経路なし NOPATH (空経路, find_path 内の4か所)
 *   (c) 残高不足 NOBALANCE (この関数経由, 呼び出し元 send_payment / forward_payment)
 * の3種が合流する。解析側で分離するには no_balance_count>0 → NOBALANCE を
 * 先に判定してから is_timeout を見ること (offline>0 は攻撃/オフライン)。
 * 列のスキーマは既存の解析スクリプト群が index 依存で読むため変更しない。 */
static void mark_no_response_failure(struct payment* payment, struct route_hop* hop) {
  payment->error.type = NORESPONSE;
  payment->error.hop = hop;
  payment->is_timeout = 1;
}

/* === 攻撃遅延のばらつきモデル (CLOTH_ATTACK_DELAY_DIST) =========================
 * 従来の注入遅延は base×attack_delay_intensity の決定論値だった。既定値
 * (interval=100ms, intensity=2.0, jitter=0) では注入量が毎回ほぼ一律 +100ms になり、
 * 「攻撃者の保持時間は常に同じ」という非現実的な仮定が入っていた。実網のグリーフィングは
 * 保持時間が攻撃者・決済ごとにばらつくので、倍率の超過分に平均1の確率変数 X を掛けて
 *     multiplier = 1 + (intensity - 1)·X,   E[X] = 1
 * とする。E[X]=1 の分布だけを使うので「平均注入遅延は従来と同一・分散だけが変わる」形に
 * なり、平均を動かした効果とばらつきの効果を分離して評価できる(平均も変えたいときは
 * attack_delay_intensity 自体を上げる)。
 *   fixed       : X=1  (既定。従来と完全同一で RNG も引かない = 既存結果と byte 一致)
 *   lognormal   : X=exp(σZ-σ²/2)            σ=CLOTH_ATTACK_DELAY_SIGMA (既定 1.0)
 *   exponential : X~Exp(1)                  メモリレスな保持時間
 *   pareto      : X=xm·U^(-1/α), xm=(α-1)/α α=CLOTH_ATTACK_DELAY_ALPHA (既定 2.0, 重い裾)
 *   uniform     : X~U(0,2)                  有界なばらつき
 *   range       : 倍率を使わず、足す遅れを [MIN, MAX] ms の一様乱数で直接決める (平均は保存しない)
 *                 MIN=CLOTH_ATTACK_DELAY_MIN_MS (既定 100), MAX=CLOTH_ATTACK_DELAY_MAX_MS (既定 10000)。
 *                 jitter も通さない。保持の長さそのものを広げたときの検証用
 * ⚠️ 注入点は apply_attack_delay_if_needed の全呼び出し箇所 (hold-to-timeout型のフォワード遅延と
 *    hold型の settle 保持、および悪意ノード経由時のフォワード遅延) で共通。hold モードでは
 *    1決済あたりフォワード側と settle 側で独立に2回サンプルされる。 */
#define ATTACK_DELAY_DIST_FIXED       0
#define ATTACK_DELAY_DIST_LOGNORMAL   1
#define ATTACK_DELAY_DIST_EXPONENTIAL 2
#define ATTACK_DELAY_DIST_PARETO      3
#define ATTACK_DELAY_DIST_UNIFORM     4
#define ATTACK_DELAY_DIST_RANGE       5

static double get_attack_delay_min_ms(void);
static double get_attack_delay_max_ms(void);

static int get_attack_delay_dist(void) {
  static int cached = -1;
  if (cached >= 0) return cached;
  const char* e = getenv("CLOTH_ATTACK_DELAY_DIST");
  if (e == NULL || e[0] == '\0' || strcmp(e, "fixed") == 0)        cached = ATTACK_DELAY_DIST_FIXED;
  else if (strcmp(e, "lognormal") == 0)                            cached = ATTACK_DELAY_DIST_LOGNORMAL;
  else if (strcmp(e, "exponential") == 0 || strcmp(e, "exp") == 0) cached = ATTACK_DELAY_DIST_EXPONENTIAL;
  else if (strcmp(e, "pareto") == 0)                               cached = ATTACK_DELAY_DIST_PARETO;
  else if (strcmp(e, "uniform") == 0)                              cached = ATTACK_DELAY_DIST_UNIFORM;
  else if (strcmp(e, "range") == 0)                                cached = ATTACK_DELAY_DIST_RANGE;
  else {
    fprintf(stderr, "WARNING: unknown CLOTH_ATTACK_DELAY_DIST='%s' -> fixed\n", e);
    cached = ATTACK_DELAY_DIST_FIXED;
  }
  if (cached == ATTACK_DELAY_DIST_RANGE)
    printf("[Config] 攻撃遅延分布 CLOTH_ATTACK_DELAY_DIST=range (足す遅れ = 一様乱数 %.0f〜%.0f ms、平均は保存しない)\n",
           get_attack_delay_min_ms(), get_attack_delay_max_ms());
  else if (cached != ATTACK_DELAY_DIST_FIXED)
    printf("[Config] 攻撃遅延分布 CLOTH_ATTACK_DELAY_DIST=%s (平均保持は fixed と同一・分散のみ変化)\n", e);
  return cached;
}

/* range の範囲 [MIN, MAX] ms。MIN>=0 かつ MIN<=MAX でなければ既定 (100, 10000) に戻す。 */
static void load_attack_delay_range(double* lo, double* hi) {
  static int loaded = 0;
  static double c_lo = 100.0, c_hi = 10000.0;
  if (!loaded) {
    const char* a = getenv("CLOTH_ATTACK_DELAY_MIN_MS");
    const char* b = getenv("CLOTH_ATTACK_DELAY_MAX_MS");
    double v_lo = (a != NULL && a[0] != '\0') ? atof(a) : 100.0;
    double v_hi = (b != NULL && b[0] != '\0') ? atof(b) : 10000.0;
    if (v_lo >= 0.0 && v_lo <= v_hi) { c_lo = v_lo; c_hi = v_hi; }
    else fprintf(stderr, "WARNING: CLOTH_ATTACK_DELAY_MIN_MS/MAX_MS が不正 (%g, %g) -> 100〜10000 ms\n", v_lo, v_hi);
    loaded = 1;
  }
  *lo = c_lo; *hi = c_hi;
}

static double get_attack_delay_min_ms(void) { double lo, hi; load_attack_delay_range(&lo, &hi); return lo; }
static double get_attack_delay_max_ms(void) { double lo, hi; load_attack_delay_range(&lo, &hi); return hi; }

static double get_attack_delay_sigma(void) {
  static double cached = -1.0;
  if (cached >= 0.0) return cached;
  const char* e = getenv("CLOTH_ATTACK_DELAY_SIGMA");
  cached = 1.0;
  if (e != NULL && e[0] != '\0') { double v = atof(e); if (v > 0.0) cached = v; }
  return cached;
}

static double get_attack_delay_alpha(void) {
  static double cached = -1.0;
  if (cached >= 0.0) return cached;
  const char* e = getenv("CLOTH_ATTACK_DELAY_ALPHA");
  cached = 2.0;
  /* α<=1 は平均が発散するので平均保存の前提が崩れる。1 超のみ受け付ける。 */
  if (e != NULL && e[0] != '\0') { double v = atof(e); if (v > 1.0) cached = v; }
  return cached;
}

/* 平均1の倍率係数 X を1個サンプルする。fixed のときは RNG を一切引かない
 * (= 乱数ストリームが従来と同一で既存結果と byte 一致する条件)。 */
static double sample_attack_delay_factor(struct simulation* simulation) {
  switch (get_attack_delay_dist()) {
    case ATTACK_DELAY_DIST_LOGNORMAL: {
      double s = get_attack_delay_sigma();
      return gsl_ran_lognormal(simulation->random_generator, -0.5 * s * s, s);
    }
    case ATTACK_DELAY_DIST_EXPONENTIAL:
      return gsl_ran_exponential(simulation->random_generator, 1.0);
    case ATTACK_DELAY_DIST_PARETO: {
      double a = get_attack_delay_alpha();
      return gsl_ran_pareto(simulation->random_generator, a, (a - 1.0) / a);
    }
    case ATTACK_DELAY_DIST_UNIFORM:
      return 2.0 * gsl_rng_uniform(simulation->random_generator);
    default:
      return 1.0;
  }
}

static uint64_t apply_attack_delay_if_needed(struct simulation* simulation,
                                             struct network_params net_params,
                                             struct payment* payment,
                                             uint64_t base_delay,
                                             unsigned int attacked_path) {
  if (!attacked_path || payment == NULL || payment->is_warmup ||
      !is_attack_delay_active(net_params)) {
    return base_delay;
  }

  uint64_t adjusted_delay;
  if (get_attack_delay_dist() == ATTACK_DELAY_DIST_RANGE) {
    /* range: 倍率ではなく、足す遅れを [MIN, MAX] ms の一様乱数で直接決める (jitter も通さない) */
    double lo = get_attack_delay_min_ms(), hi = get_attack_delay_max_ms();
    adjusted_delay = base_delay + (uint64_t)llround(lo + (hi - lo) * gsl_rng_uniform(simulation->random_generator));
  } else {
    double multiplier = net_params.attack_delay_intensity;
    /* ばらつきモデル有効時は超過分 (intensity-1) を平均1の確率変数でスケールする。
     * intensity<=1.0 のときは超過分が無いのでサンプルせず従来どおり。 */
    if (get_attack_delay_dist() != ATTACK_DELAY_DIST_FIXED) {
      double excess = multiplier - 1.0;
      if (excess > 0.0)
        multiplier = 1.0 + excess * sample_attack_delay_factor(simulation);
    }
    if (net_params.attack_delay_jitter > 0.0) {
      multiplier += gsl_ran_gaussian(simulation->random_generator, net_params.attack_delay_jitter);
    }
    if (multiplier < 1.0) multiplier = 1.0;

    adjusted_delay = (uint64_t)llround((double)base_delay * multiplier);
    if (adjusted_delay < base_delay) adjusted_delay = base_delay;
  }

  if (payment != NULL && adjusted_delay > base_delay) {
    payment->attack_delay_added_total += (adjusted_delay - base_delay);
    payment->attack_delay_event_count += 1;
  }

  return adjusted_delay;
}

/* ============================================================================
 * === 偽報告(嘘の報告)の検証ハーネス ==========================================
 * 悪意ノードは報告者にもなれるので、自分の観測時刻を偽って隣接ノードを陥れたり
 * 自分の保持を隠したりできる。これを定量するための実験用ノブ群。攻撃側のノブ
 * (FALSE_REPORT_MS / CLOCK_SKEW_MS) は既定 0 = 無効で、無効時は乱数も引かない。
 *
 *  CLOTH_FALSE_REPORT_MS = X : 悪意ノードが自分の申告を X[ms] 水増しする。
 *      申告 RT = recv - send を膨らませる方向(recv を +X, send を -X)に偽る。
 *      旧方式 (CLOTH_REPORT_ATTEST=0) の帰属 Δ[i]=RT[i]-RT[i+1] では、これは同時に
 *        (a) 自分への嫌疑 Δ[i-1] を縮める = 自己免罪
 *        (b) 下流への嫌疑 Δ[i]   を膨らませる = 下流の冤罪
 *      の両方を達成する。preimage を上流へ送った申告時刻も -X して、相互証明側も偽る。
 *  CLOTH_CLOCK_SKEW_MS = E : 各ノードに固定の時計オフセット(-E..+E)を与える。
 *      ノード ID から決定論的に作るので乱数ストリームは動かない。
 *      自ノード内の差分(RT)では相殺されるが、ノードをまたぐ突き合わせには効く。
 *  CLOTH_REPORT_ATTEST (既定 1 = 相互証明、0 で旧方式): 帰属を「隣接ノードの申告のみ」で行う。
 *      詳細は receive_success 側の実装コメント参照。
 * ========================================================================== */
static long get_false_report_ms(void) {
  static long v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_FALSE_REPORT_MS");
  v = 0; if (e != NULL && e[0] != '\0') { long t = atol(e); if (t > 0) v = t; }
  return v;
}
static long get_clock_skew_ms(void) {
  static long v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_CLOCK_SKEW_MS");
  v = 0; if (e != NULL && e[0] != '\0') { long t = atol(e); if (t > 0) v = t; }
  return v;
}
/* 報告の帰属方式。**2026-10-06 に既定を 1(相互証明) へ変更**。
 * 0 にすると旧来の「被疑者自身の申告 RT を使う」方式に戻る。
 * 旧方式は悪意ノードが報告者になれる前提の下では成立しない:
 *   嘘100ms/毎回 → 冤罪152件・precision 42.4%、黙秘100% → recall 16.1%。
 * 相互証明は hold[p]=recv[p-1]-send_back[p+1] と被疑者の申告を使わないので、
 * 両側の嘘にも黙秘にも不感 (seed{7,42,123} で recall 90.5-93.7%・冤罪0・precision100%)。
 * 片側だけの嘘 (食い違いが1本) は CLOTH_ATTEST_SINGLE_DISPUTE 以下のノブで扱う。
 * ⚠️ 挙動変更: この既定変更以前の検知結果とは直接比較できない。 */
static int get_report_attest(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_REPORT_ATTEST");
  if (e != NULL && e[0] != '\0') return (v = (strcmp(e, "0") != 0) ? 1 : 0);
  return (v = 1);   /* 既定 = 相互証明 */
}
/* 食い違い(dispute)が起きたときの扱い (CLOTH_ATTEST_DISPUTE_POLICY, 既定 1)。
 *   0 = 旧: どちらか一方でも食い違えば帰属を破棄する。
 *       → 被疑者が自分の2つの申告を偽ると d1,d2 が両方跳ね、**自分に不利な帰属を自分で消せる**。
 *   1 = 共通点による特定: 被疑者 p の2本のリンクが**両方**食い違うなら、2本の共通ノードは
 *       p しかいないので原因は p の申告だと断定できる。帰属式
 *       hold[p]=recv[p-1]-send_back[p+1] は p の申告を使わないので、そのまま帰属してよい。
 *       片方だけの食い違いはどちらが嘘か決められないので CLOTH_ATTEST_SINGLE_DISPUTE に従う
 *       (既定 2 = (4a) 被疑者に有利な時刻で検定 + (4b) ペア検定 + (5) ペア集計。0 のときだけ破棄)。
 *       これにより (a) 嘘つき本人は検出され (b) 嘘つきの申告を使う隣人の帰属は捨てられる。 */
static int get_attest_dispute_policy(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_ATTEST_DISPUTE_POLICY");
  if (e != NULL && e[0] != '\0') return (v = (strcmp(e, "0") != 0) ? 1 : 0);
  return (v = 1);   /* 既定 ON (CLOTH_REPORT_ATTEST=1 のときだけ効く) */
}

/* 相互証明の突き合わせ許容差[ms]。既定は時計ずれ幅の2倍(両ノードのオフセット差の上界)。 */
static long get_attest_tolerance_ms(void) {
  static long v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_ATTEST_TOL_MS");
  if (e != NULL && e[0] != '\0') { long t = atol(e); v = (t >= 0) ? t : 0; }
  else { long sk = get_clock_skew_ms(); v = (sk > 0) ? (2 * sk) : 1; }
  return v;
}
/* ノード固有の時計オフセット[ms]。ID からの決定論的ハッシュ(乱数を引かない)。 */
static long node_clock_offset(long node_id) {
  long E = get_clock_skew_ms();
  if (E <= 0) return 0;
  unsigned long h = (unsigned long)node_id * 2654435761UL;
  h ^= (h >> 13); h *= 2246822519UL; h ^= (h >> 16);
  return (long)(h % (unsigned long)(2 * E + 1)) - E;
}
/* 嘘をつく確率 (CLOTH_FALSE_REPORT_PROB, 既定 1.0 = 攻撃時は必ず嘘をつく)。 */
static double get_false_report_prob(void) {
  static double v = -1.0;
  if (v >= 0.0) return v;
  const char* e = getenv("CLOTH_FALSE_REPORT_PROB");
  v = 1.0;
  if (e != NULL && e[0] != '\0') { double t = atof(e); if (t >= 0.0 && t <= 1.0) v = t; }
  return v;
}

/* この決済でこのノードが嘘をつくか。
 * 嘘をつけるのは**その決済で実際に保持攻撃を行っている本人のみ**に限定する
 * (payment->grief_hold_node_id == nd->id)。攻撃していない悪意ノードや、たまたま
 * 経路に乗っただけの悪意ノードは正直に申告する。
 * 嘘をつくかは確率 CLOTH_FALSE_REPORT_PROB で決める。決済ID×ノードID の決定論的
 * ハッシュで判定するので (a) 乱数ストリームを動かさない (b) 同一決済内の複数の
 * 申告 (受領時刻と送出時刻) で判断がブレない、の2点が同時に満たされる。 */
static int lies_on_this_payment(struct node* nd, struct payment* pm) {
  if (nd == NULL || pm == NULL) return 0;
  if (!nd->is_malicious) return 0;
  if (get_false_report_ms() <= 0) return 0;
  if (pm->grief_hold_node_id != nd->id) return 0;   /* 攻撃者本人のみ */
  double pr = get_false_report_prob();
  if (pr >= 1.0) return 1;
  if (pr <= 0.0) return 0;
  unsigned long h = ((unsigned long)pm->id * 1000003UL) ^ ((unsigned long)nd->id * 2654435761UL);
  h ^= (h >> 13); h *= 2246822519UL; h ^= (h >> 16);
  return ((double)(h % 100000UL) / 100000.0) < pr;
}

/* 黙秘(自分の時刻記録を提出しない)の確率 (CLOTH_SILENT_REPORT_PROB, 既定 0)。
 * 嘘をつくより簡単な回避策: 旧方式 (CLOTH_REPORT_ATTEST=0) の帰属は Δ=RT[i]−RT[i+1] に被疑者本人の
 * 記録を必要とするので、記録を出さないだけで検定が成立しなくなる (既定の相互証明は本人の記録を使わない)。嘘と同じく「その決済の保持者本人」に限定し、
 * 決済ID×ノードIDの決定論的ハッシュで判定する(嘘とは別ソルトなので両者は独立に振れる)。 */
static double get_silent_report_prob(void) {
  static double v = -1.0;
  if (v >= 0.0) return v;
  const char* e = getenv("CLOTH_SILENT_REPORT_PROB");
  v = 0.0;
  if (e != NULL && e[0] != '\0') { double t = atof(e); if (t >= 0.0 && t <= 1.0) v = t; }
  return v;
}
/* 欠測(黙秘)の扱い。0 = 従来どおり黙ってスキップ(=逃がす), 1 = 証拠として扱う
 * (被疑者の記録が無くても両隣の記録だけで帰属し、黙秘回数を計上する)。
 * 相互証明の帰属式 hold[p]=recv[p-1]−send_back[p+1] は被疑者の記録を使わないので、
 * 本来は黙秘に強い。突き合わせができないだけで帰属は成立する。 */
static int get_attest_silence_policy(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_ATTEST_SILENCE_POLICY");
  if (e != NULL && e[0] != '\0') return (v = (strcmp(e, "0") != 0) ? 1 : 0);
  return (v = 1);   /* 既定 ON (CLOTH_REPORT_ATTEST=1 のときだけ効く) */
}
static int stays_silent_on_payment(struct node* nd, struct payment* pm) {
  if (nd == NULL || pm == NULL) return 0;
  if (!nd->is_malicious) return 0;
  double pr = get_silent_report_prob();
  if (pr <= 0.0) return 0;
  if (pm->grief_hold_node_id != nd->id) return 0;   /* 保持者本人のみ */
  if (pr >= 1.0) return 1;
  unsigned long h = ((unsigned long)pm->id * 2246822519UL) ^ ((unsigned long)nd->id * 374761393UL);
  h ^= (h >> 15); h *= 2654435761UL; h ^= (h >> 13);
  return ((double)(h % 100000UL) / 100000.0) < pr;
}

/* 嘘をつく側 (CLOTH_FALSE_REPORT_SIDE, 既定 both)。
 *   both = 受領時刻を遅く・送出時刻を早く、の両方を偽る(従来)。2本のリンクが両方
 *          食い違うので共通点ルール(CLOTH_ATTEST_DISPUTE_POLICY)で本人と断定される。
 *   recv = 受領時刻だけ遅く申告する = 「下流がなかなか渡してこなかった」となすりつける。
 *   send = 送出時刻だけ早く申告する = 「すぐ渡したのに上流(報告者)が遅れた」と逆告発する。
 * 片側だけだと食い違うリンクは1本だけになり、従来ルールではどちらが嘘か決められず
 * 帰属ごと破棄される(=攻撃者が逃げる)。それを測るためのノブ。 */
enum { FALSE_REPORT_SIDE_BOTH = 0, FALSE_REPORT_SIDE_RECV = 1, FALSE_REPORT_SIDE_SEND = 2 };
static int get_false_report_side(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_FALSE_REPORT_SIDE");
  v = FALSE_REPORT_SIDE_BOTH;
  if (e != NULL && strcmp(e, "recv") == 0) v = FALSE_REPORT_SIDE_RECV;
  if (e != NULL && strcmp(e, "send") == 0) v = FALSE_REPORT_SIDE_SEND;
  return v;
}
/* 賢い嘘 (CLOTH_FALSE_REPORT_SMART, 既定 0)。1 のとき、嘘の量を固定の CLOTH_FALSE_REPORT_MS ではなく
 * 「その決済で自分が攻撃として足した遅れ」(grief_hold_extra_ms) にする。CLOTH_FALSE_REPORT_MS は
 * 嘘をつくかどうかのスイッチとしてだけ使う (正の値なら何でもよい)。片側の嘘で保持の攻撃分をちょうど消す量で、
 * 保持より大きな嘘は「受け取る前に送った」(因果違反) で本人の記録が使えなくなるので、これが隠せる最大に近い。 */
static int get_false_report_smart(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_FALSE_REPORT_SMART");
  return (v = (e != NULL && e[0] != '\0' && strcmp(e, "0") != 0) ? 1 : 0);
}

/* 片側だけの食い違い(1本のリンクだけ申告が合わない)の扱い (CLOTH_ATTEST_SINGLE_DISPUTE, 既定 2)。
 *   0 = 従来: 帰属を破棄する。
 *   1 = (4a) 食い違ったリンクの時刻は「被疑者に一番有利なほう」を採って検定する。
 *       hold_fav = min(上流の受領, 本人の送出) - max(下流の送出, 本人の受領)。
 *       正直なノードには自分の正しい申告が必ず選択肢にあるので、隣人の嘘で冤罪にならない。
 *       嘘つきは嘘の分しか軽くならない。食い違った標本は null の学習に使わない。
 *       あわせて「受け取る前に送った」申告(因果違反)を本人の記録が使えない扱いにする。
 *   2 = 1 に加えて (4b) 外側2人の記録で2人の合計保持を検定し、異常ならペアとして記録、
 *       (5) 違う相手とのペアが CLOTH_ATTEST_PAIR_MIN_PARTNERS 個以上になったノードを報告する。 */
static int get_attest_single_dispute(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_ATTEST_SINGLE_DISPUTE");
  v = 2;
  if (e != NULL && e[0] != '\0') { int t = atoi(e); if (t >= 0 && t <= 2) v = t; }
  return v;
}
/* (5) の「違う相手」の数のしきい値 (CLOTH_ATTEST_PAIR_MIN_PARTNERS, 既定 2)。 */
static int get_attest_pair_min_partners(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_ATTEST_PAIR_MIN_PARTNERS");
  v = 2;
  if (e != NULL && e[0] != '\0') { int t = atoi(e); if (t >= 1) v = t; }
  return v;
}
/* 送金者の記録を信頼する (CLOTH_ATTEST_TRUST_SENDER, 既定 1。0 で信頼しない)。
 * 送金者は判定をする本人なので、自分の受領時刻と食い違ったら相手(経路の最初の中継)の
 * 申告が嘘だと決められる。ペア検定は外側の基準点が無いので送金者を含むペアを扱えない。 */
static int get_attest_trust_sender(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_ATTEST_TRUST_SENDER");
  return (v = (e != NULL && e[0] != '\0') ? (strcmp(e, "0") != 0) : 1);
}

/* 受取人の記録を信頼する (CLOTH_ATTEST_TRUST_RECEIVER, 既定 1。0 で信頼しない)。送金者信頼と対称。
 * 受取人の送出申告と食い違ったら相手(経路の最後の中継)の受領申告が嘘と決める。 */
static int get_attest_trust_receiver(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_ATTEST_TRUST_RECEIVER");
  return (v = (e != NULL && e[0] != '\0') ? (strcmp(e, "0") != 0) : 1);
}

/* (5) 説明済みのペアを除く (CLOTH_ATTEST_PAIR_EXPLAIN, 既定 1。0 で除かない)。
 * 相手が個別の検定(従来経路/4a/端点の信頼)で既に報告されていれば、そのペアは相手の保持で
 * 説明がつくので、こちらの「違う相手」にも割合の分子にも数えない。判定のたびに数え直すので、
 * 後から相手が確定しても以降の判定ではそのペアが外れる(既に出た報告は取り消さない)。 */
static int get_attest_pair_explain(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_ATTEST_PAIR_EXPLAIN");
  return (v = (e != NULL && e[0] != '\0') ? (strcmp(e, "0") != 0) : 1);
}
/* (5) 露出で正規化 (CLOTH_ATTEST_PAIR_MIN_RATE, 既定 0.2。0 で使わない)。
 * ペア記録数 / そのノードの hold 検定数 (warmup 後, 判定時点の累計) がこの値未満なら報告しない。
 * 正直なハブは通る決済が多いので、相手の数は増えても割合は小さい。 */
static double get_attest_pair_min_rate(void) {
  static int init = 0;
  static double v = 0.2;
  if (init) return v;
  init = 1;
  const char* e = getenv("CLOTH_ATTEST_PAIR_MIN_RATE");
  if (e != NULL && e[0] != '\0') { double t = atof(e); v = (t > 0.0) ? t : 0.0; }
  return v;
}

/* (5) の報告を後から取り消す (CLOTH_ATTEST_PAIR_REVOKE, 既定 0)。
 * ペアの相手が後から個別の検定で確定したとき、その相手とペアになったノードについて (5) のルール
 * (説明のつかない相手の数・割合、いずれもその時点の値) を判定し直し、もう満たさなければ
 * 集計で出した報告を取り消して評判を戻す。本人が個別の検定で確定していれば取り消さない。 */
static int get_attest_pair_revoke(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_ATTEST_PAIR_REVOKE");
  return (v = (e != NULL && e[0] != '\0' && strcmp(e, "0") != 0) ? 1 : 0);
}

/* (5) 割合の分母から説明済みのペアを除く (CLOTH_ATTEST_PAIR_RATE_EXCL_EXPLAINED, 既定 0)。
 * 外す処理で分子から除いたペア(相手が個別の検定で確定)は、こちらにとって証拠にも反証にもならない
 * 決済なので、分母の検定数からもその数だけ引く(ペア1件 ≈ 検定1回)。 */
static int get_attest_pair_rate_excl(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_ATTEST_PAIR_RATE_EXCL_EXPLAINED");
  return (v = (e != NULL && e[0] != '\0' && strcmp(e, "0") != 0) ? 1 : 0);
}

/* 食い違いをそのままペアの記録にする (CLOTH_ATTEST_DISPUTE_FLAGS, 既定 0)。
 * もめたときに判定ノードが鍵を預かる方式 (受領証＋エスクロー) のモデル: 受け渡しの食い違いは
 * 判定ノードへのエスカレーションとして記録に残るので、(4b) のペア検定を経ずに、食い違った
 * リンクの2人をそのままペアとして (5) の集計に回す。(4b) の代わりに使う(二重計上しない)。
 * 時刻をずらせる幅の上限 D は嘘の大きさ (CLOTH_FALSE_REPORT_MS) で表す。 */
static int get_attest_dispute_flags(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_ATTEST_DISPUTE_FLAGS");
  return (v = (e != NULL && e[0] != '\0' && strcmp(e, "0") != 0) ? 1 : 0);
}

static void add_pair_partner(struct node* nd, long partner_id) {
  for (int k = 0; k < nd->pair_partner_count; k++)
    if (nd->pair_partners[k] == partner_id) { nd->pair_partner_flags[k]++; return; }
  if (nd->pair_partner_count >= nd->pair_partner_cap) {
    int cap = (nd->pair_partner_cap == 0) ? 4 : nd->pair_partner_cap * 2;
    long* p = (long*)realloc(nd->pair_partners, cap * sizeof(long));
    if (p == NULL) return;
    nd->pair_partners = p;
    long* f = (long*)realloc(nd->pair_partner_flags, cap * sizeof(long));
    if (f == NULL) return;
    nd->pair_partner_flags = f;
    nd->pair_partner_cap = cap;
  }
  nd->pair_partner_flags[nd->pair_partner_count] = 1;
  nd->pair_partners[nd->pair_partner_count++] = partner_id;
}

/* (4b) で合計保持が異常だったペア {a(上流), b(下流)} を記録し、(5) 違う相手との
 * ペアが規定数に達したメンバーを報告する。env CLOTH_ATTEST_PAIR_LOG=<path> で
 * ペアを1行ずつ追記する(集計ルールをオフラインで比較するため)。 */
/* (5) のルール: 説明のつかない相手が K 人以上、かつ (正規化ありなら) その相手とのペア数 / hold 検定数
 * がしきい値以上。報告するときと取り消しを判定し直すときで同じものを使う。 */
static int pair_rule_holds(struct network* network, struct node* x, int* n_partners_out, long* n_flags_out) {
  int explain = get_attest_pair_explain();
  double min_rate = get_attest_pair_min_rate();
  int n_partners = 0;
  long n_flags = 0, n_explained = 0;
  for (int j = 0; j < x->pair_partner_count; j++) {
    if (explain) {
      struct node* y = (struct node*)array_get(network->nodes, x->pair_partners[j]);
      if (y != NULL && y->hold_reports_main + y->hold_reports_fav > 0) {
        n_explained += x->pair_partner_flags[j];
        continue;
      }
    }
    n_partners++;
    n_flags += x->pair_partner_flags[j];
  }
  if (n_partners_out) *n_partners_out = n_partners;
  if (n_flags_out) *n_flags_out = n_flags;
  if (n_partners < get_attest_pair_min_partners()) return 0;
  if (min_rate > 0.0) {
    long t = x->settle_test_count;
    if (get_attest_pair_rate_excl()) t -= n_explained;
    if (t < 1) t = 1;
    if ((double)n_flags / (double)t < min_rate) return 0;
  }
  return 1;
}

/* 取り消しの判定し直し。集計の報告が残っていて、本人が個別の検定で確定しておらず、
 * いまの値でルールを満たさなければ、残っている集計の報告を全部取り消す。 */
static void pair_recheck(struct network* network, struct node* x, struct network_params net_params) {
  if (x == NULL || x->pair_reports_active <= 0) return;
  if (x->hold_reports_main + x->hold_reports_fav > 0) return;
  if (pair_rule_holds(network, x, NULL, NULL)) return;
  revoke_reports_from_judges(network, x->id, x->pair_reports_active, net_params);
  x->pair_reports_revoked += x->pair_reports_active;
  x->pair_reports_active = 0;
}

static void handle_pair_flag(struct network* network, struct simulation* simulation,
                             struct payment* payment, struct network_params net_params,
                             struct node* a, struct node* b, double sum_ms) {
  add_pair_partner(a, b->id);
  add_pair_partner(b, a->id);
  a->pair_flag_count++;
  b->pair_flag_count++;
  const char* log_path = getenv("CLOTH_ATTEST_PAIR_LOG");
  if (log_path != NULL && log_path[0] != '\0') {
    FILE* f = fopen(log_path, "a");
    if (f != NULL) {
      fprintf(f, "%ld,%llu,%ld,%ld,%u,%u,%ld,%ld,%ld,%.0f\n",
              payment->id, (unsigned long long)simulation->current_time,
              a->id, b->id, a->is_malicious, b->is_malicious,
              array_len(a->open_edges), array_len(b->open_edges), payment->grief_hold_node_id, sum_ms);
      fclose(f);
    }
  }
  struct node* m[2] = { a, b };
  for (int k = 0; k < 2; k++) {
    struct node* x = m[k];
    /* 説明のつかない相手の数と、その相手とのペア記録数 */
    int n_partners = 0;
    long n_flags = 0;
    if (!pair_rule_holds(network, x, &n_partners, &n_flags)) continue;
    if (x->id == payment->sender || x->id == payment->receiver) continue;
    if (!is_node_observed_by_judges(network, x->id)) continue;
    if (has_attack_reporter(payment, x->id)) continue;
    register_attack_reporter(payment, x->id);
    if (report_attacked_node_to_judges(network, payment->sender, x->id,
            payment->id, simulation->current_time, net_params))
      x->pair_reports_active++;   /* 実際に数えられた報告だけを取り消しの対象にする */
    x->hold_reports_pair++;
    /* 診断ログ (env CLOTH_ATTEST_PAIR_REPORT_LOG=<path>): 集計で報告した時点の判定材料。
     * payment_id,time,node,is_mal,deg,tests,n_partners(説明なし),n_flags(説明なし),相手の内訳
     * 相手の内訳 = id:ペア数:個別検定で報告済みか を ; 区切り */
    const char* rlog = getenv("CLOTH_ATTEST_PAIR_REPORT_LOG");
    if (rlog != NULL && rlog[0] != '\0') {
      FILE* rf = fopen(rlog, "a");
      if (rf != NULL) {
        fprintf(rf, "%ld,%llu,%ld,%u,%ld,%ld,%d,%ld,", payment->id,
                (unsigned long long)simulation->current_time, x->id, x->is_malicious,
                array_len(x->open_edges), x->settle_test_count, n_partners, n_flags);
        for (int j = 0; j < x->pair_partner_count; j++) {
          struct node* y = (struct node*)array_get(network->nodes, x->pair_partners[j]);
          int conf = (y != NULL && y->hold_reports_main + y->hold_reports_fav > 0);
          fprintf(rf, "%s%ld:%ld:%d", (j > 0) ? ";" : "", x->pair_partners[j],
                  x->pair_partner_flags[j], conf);
        }
        fprintf(rf, "\n");
        fclose(rf);
      }
    }
  }
}

/* === もめたら判定ノードが鍵を預かる方式 (受領証＋エスクロー) のモデル (CLOTH_ESCROW, 既定 0) ===
 * preimage の受け渡し (送り手 → 受け手) ごとに、受け手が受領証を返し送り手が鍵を渡す往復 r が掛かる。
 * r はリンクごとに中央値の違う対数正規 (中央値 m·exp(σ_b·Z_link)) に、受け渡しごとのばらつき (σ_j) を掛けたもの。
 * 送り手は期限 D までに受領証が来なければ判定ノードへエスカレーションし、判定ノードが e 後に鍵を渡す (タイムアウト)。
 * 保持の起点: 通常はオファー時刻 + そのリンクの予想往復 E[r] (期限内に受領証を遅らせても隠せない)。
 *             タイムアウトしたら判定ノードが鍵を渡した時刻 (待ちは免除される, CLOTH_ESCROW_EXCUSE_TIMEOUT=1 既定)。
 * 攻撃者 (保持者) の手口: わざとタイムアウトさせて D + e - E[r] を隠す (記録が残る)、または
 *   普段から受領証を Δ 遅らせて予想往復に混ぜ (CLOTH_ESCROW_INFLATE_MS)、Δ を記録なしで隠す。大きいほうを使う。
 *   送出側の嘘は、保持の終わりが上流の受け手自身の受領証で決まるので意味がない (受領側だけ)。
 * 往復はリンクと決済のハッシュから決める (乱数列を消費しない)。シミュの時刻 (イベント) には往復を足さない。
 * 正直な遅いノード (既定 OFF):
 *   Tor 経由 (CLOTH_ESCROW_TOR_FRAC): どちらかの端が Tor なら、その接続の往復に Tor の遅れが足され、ばらつきも大きい。
 *     ネットワークの遅れは両方向に共通 (CLOTH_ESCROW_NET_SYMMETRIC=1 で向きによらず同じ値)。判定ノードとのやり取りも遅れる。
 *   処理が遅い (CLOTH_ESCROW_SLOW_FRAC): 受け手として受領証を返す前の処理 (保存など) に時間が掛かる。
 * 期限と予想往復の決め方 (CLOTH_ESCROW_D_MODE): fixed / adaptive (この向きの受領証の往復) /
 *   ref (同じリンクのコミットメント更新の往復: 正直なら受領証と同じ分布、受領証だけの水増しは入らない) /
 *   reverse (同じリンクの逆向きの受領証の往復: 処理の遅れは相手のものになる)。
 * CLOTH_ESCROW_JITTER_IN_HOLD=1: 起点がオファー時刻 + 予想往復なので、期限内の往復のぶれ (r - E[r]) を保持に混ぜる。
 * CLOTH_ESCROW_ANCHOR=key: 起点を送り手が鍵を渡した時刻にする。ぶれは混ざらないが、期限内に受領証を遅らせた分は
 *   記録なしで隠せる (D - E[r])。攻撃者は記録の残らない手口で足りるならそちらを使う。
 * CLOTH_ESCROW_HOLD_LEGS=n: 測る保持に片道 n 本ぶんのネットワークの遅れ (Tor ならぶれも大きい) を足す。
 *   起点=鍵 なら 1 (鍵が届くまで)、エスクローなし (CLOTH_ESCROW=0 でも効く) なら 2 (下流→本人, 本人→上流)。
 * CLOTH_ESCROW_HOLD_LEGS_NORM=1: 片道ごとにそのリンクの本当の平均を引く (理想的なリンクごとの正規化の上限を見る試験用)。
 *   =2: Tor を通るかどうかで分けた平均だけを引く (リンク固有の差は残る。ノードごとの性質から学べる範囲)。 */
static double escrow_env(const char* name, double def) {
  const char* e = getenv(name);
  return (e != NULL && e[0] != '\0') ? atof(e) : def;
}
static int get_escrow(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_ESCROW");
  return (v = (e != NULL && e[0] != '\0' && strcmp(e, "0") != 0) ? 1 : 0);
}
struct escrow_params {
  double m, sigma_link, sigma_jitter, esc_ms, d_fixed, d_z, d_cap, inflate;
  double tor_frac, tor_ms, tor_sigma_link, tor_sigma_jitter, slow_frac, slow_ms, slow_sigma;
  int d_mode, excuse, symmetric, mimic, tor_attacker, tor_max_degree, jitter_in_hold, anchor_key, hold_legs, legs_norm;
};
enum { ESCROW_D_FIXED = 0, ESCROW_D_ADAPTIVE = 1, ESCROW_D_REF = 2, ESCROW_D_REVERSE = 3 };
static const struct escrow_params* escrow_params(void) {
  static int init = 0;
  static struct escrow_params P;
  if (init) return &P;
  init = 1;
  P.m            = escrow_env("CLOTH_ESCROW_RTT_MEDIAN_MS", 20.0);
  P.sigma_link   = escrow_env("CLOTH_ESCROW_RTT_LINK_SIGMA", 0.5);
  P.sigma_jitter = escrow_env("CLOTH_ESCROW_RTT_JITTER_SIGMA", 0.3);
  P.esc_ms       = escrow_env("CLOTH_ESCROW_ESC_MS", 40.0);
  P.d_fixed      = escrow_env("CLOTH_ESCROW_D_MS", 50.0);
  P.d_z          = escrow_env("CLOTH_ESCROW_D_Z", 2.326);      /* リンクごと: 往復の 99% 点 */
  P.d_cap        = escrow_env("CLOTH_ESCROW_D_CAP_MS", 0.0);   /* 0 = 上限なし */
  P.inflate      = escrow_env("CLOTH_ESCROW_INFLATE_MS", 0.0);
  P.mimic        = (int)escrow_env("CLOTH_ESCROW_INFLATE_MIMIC", 0.0);   /* 1 = コミットメント更新も同じだけ遅らせる */
  const char* mode = getenv("CLOTH_ESCROW_D_MODE");
  P.d_mode = ESCROW_D_FIXED;
  if (mode != NULL && strcmp(mode, "adaptive") == 0) P.d_mode = ESCROW_D_ADAPTIVE;
  if (mode != NULL && strcmp(mode, "ref") == 0) P.d_mode = ESCROW_D_REF;
  if (mode != NULL && strcmp(mode, "reverse") == 0) P.d_mode = ESCROW_D_REVERSE;
  P.excuse = (int)escrow_env("CLOTH_ESCROW_EXCUSE_TIMEOUT", 1.0);
  P.symmetric        = (int)escrow_env("CLOTH_ESCROW_NET_SYMMETRIC", 0.0);
  P.tor_frac         = escrow_env("CLOTH_ESCROW_TOR_FRAC", 0.0);
  P.tor_ms           = escrow_env("CLOTH_ESCROW_TOR_MS", 100.0);       /* Tor の遅れの中央値 */
  P.tor_sigma_link   = escrow_env("CLOTH_ESCROW_TOR_LINK_SIGMA", 0.5);
  P.tor_sigma_jitter = escrow_env("CLOTH_ESCROW_TOR_JITTER_SIGMA", 0.5);
  P.tor_attacker     = (int)escrow_env("CLOTH_ESCROW_TOR_ATTACKER", -1.0);  /* -1 = 正直と同じ決め方, 0 = 使わない, 1 = 全員 */
  P.tor_max_degree   = (int)escrow_env("CLOTH_ESCROW_TOR_MAX_DEGREE", 0.0); /* 0 = 次数によらない */
  P.slow_frac        = escrow_env("CLOTH_ESCROW_SLOW_FRAC", 0.0);
  P.slow_ms          = escrow_env("CLOTH_ESCROW_SLOW_MS", 30.0);       /* 処理の遅れの中央値 */
  P.slow_sigma       = escrow_env("CLOTH_ESCROW_SLOW_SIGMA", 0.5);
  P.jitter_in_hold   = (int)escrow_env("CLOTH_ESCROW_JITTER_IN_HOLD", 0.0);
  const char* anchor = getenv("CLOTH_ESCROW_ANCHOR");
  P.anchor_key = (anchor != NULL && strcmp(anchor, "key") == 0);  /* key = 送り手が鍵を渡した時刻を保持の起点にする */
  P.hold_legs = (int)escrow_env("CLOTH_ESCROW_HOLD_LEGS", 0.0);
  P.legs_norm = (int)escrow_env("CLOTH_ESCROW_HOLD_LEGS_NORM", 0.0);  /* 1 = リンクの本当の平均 / 2 = Tor かどうかの平均を引く */
  return &P;
}
static double escrow_hash_u01(unsigned long a, unsigned long b, unsigned long salt) {
  unsigned long h = a * 0x9E3779B97F4A7C15UL;
  h ^= (b + 0x632BE59BD9B4E019UL) * 0xBF58476D1CE4E5B9UL;
  h ^= salt * 0x94D049BB133111EBUL;
  h ^= h >> 31; h *= 0xBF58476D1CE4E5B9UL; h ^= h >> 27; h *= 0x94D049BB133111EBUL; h ^= h >> 31;
  return ((double)(h >> 11) + 0.5) / 9007199254740992.0;
}
static double escrow_hash_normal(unsigned long a, unsigned long b, unsigned long salt) {
  double u1 = escrow_hash_u01(a, b, salt), u2 = escrow_hash_u01(a, b, salt + 7919UL);
  return sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
}
/* ノードの性質 (Tor 経由か・処理の遅れ) は最初の決済の成功時に一度だけ決める。
 * ノードの一覧 (env CLOTH_ESCROW_NODE_LOG): node_id,is_malicious,degree,tor,proc_ms */
static long escrow_n_nodes = 0;
static unsigned char* escrow_tor = NULL;
static unsigned char* escrow_mal = NULL;
static double* escrow_proc = NULL;
static void escrow_bind(struct network* network) {
  if (escrow_tor != NULL || network == NULL) return;
  const struct escrow_params* P = escrow_params();
  long n = array_len(network->nodes);
  escrow_tor = calloc((size_t)n + 1, 1);
  escrow_mal = calloc((size_t)n + 1, 1);
  escrow_proc = calloc((size_t)n + 1, sizeof(double));
  escrow_n_nodes = n;
  const char* nlog = getenv("CLOTH_ESCROW_NODE_LOG");
  FILE* f = (nlog != NULL && nlog[0] != '\0') ? fopen(nlog, "w") : NULL;
  if (f != NULL) fprintf(f, "node_id,is_malicious,degree,tor,proc_ms\n");
  for (long i = 0; i < n; i++) {
    struct node* nd = (struct node*)array_get(network->nodes, i);
    if (nd == NULL || nd->id < 0 || nd->id >= n) continue;
    unsigned long id = (unsigned long)nd->id;
    long deg = (nd->open_edges != NULL) ? array_len(nd->open_edges) : 0;
    int tor = 0;
    if (P->tor_frac > 0.0) {
      if (nd->is_malicious && P->tor_attacker >= 0) tor = (P->tor_attacker > 0);
      else if (P->tor_max_degree <= 0 || deg <= P->tor_max_degree)
        tor = escrow_hash_u01(id, 0UL, 21UL) < P->tor_frac;
    }
    double proc = 0.0;
    if (P->slow_frac > 0.0 && escrow_hash_u01(id, 0UL, 23UL) < P->slow_frac)
      proc = P->slow_ms * exp(P->slow_sigma * escrow_hash_normal(id, 0UL, 25UL));
    escrow_tor[nd->id] = (unsigned char)tor;
    escrow_mal[nd->id] = nd->is_malicious ? 1 : 0;
    escrow_proc[nd->id] = proc;
    if (f != NULL) fprintf(f, "%ld,%d,%ld,%d,%.1f\n", nd->id, escrow_mal[nd->id], deg, tor, proc);
  }
  if (f != NULL) fclose(f);
}
static int escrow_tor_of(long id) { return (escrow_tor != NULL && id >= 0 && id < escrow_n_nodes) ? escrow_tor[id] : 0; }
static int escrow_mal_of(long id) { return (escrow_mal != NULL && id >= 0 && id < escrow_n_nodes) ? escrow_mal[id] : 0; }
static double escrow_proc_of(long id) { return (escrow_proc != NULL && id >= 0 && id < escrow_n_nodes) ? escrow_proc[id] : 0.0; }
struct escrow_link {
  double r;        /* この受け渡しの往復 (水増し込み) */
  double leg;      /* この決済での片道のネットワークの遅れ */
  double leg_mean; /* そのリンクの片道の平均 */
  double leg_var;  /* 片道のばらつき (分散, ms²): HOLD_LEGS_NORM=1 ならリンクの本当の値、それ以外は Tor かどうかの区分の値 */
  double er_true;  /* リンクの本来の予想往復 */
  double er;       /* 送り手が学習している予想往復 (保持の起点に使う) */
  double D;        /* 期限 */
  double e;        /* 判定ノードが鍵を渡すまでの時間 */
  int tor;         /* Tor を通る接続か */
};
/* 受け手 recv_id が送り手 offer_id から preimage を受け取る受け渡しの往復と期限 */
static void escrow_link_eval(long recv_id, long offer_id, long pid, int recv_mal, struct escrow_link* L) {
  const struct escrow_params* P = escrow_params();
  unsigned long la = (unsigned long)recv_id, lb = (unsigned long)offer_id;
  if (P->symmetric && la > lb) { unsigned long t = la; la = lb; lb = t; }   /* ネットワークの遅れは両方向に共通 */
  int tor = escrow_tor_of(recv_id) || escrow_tor_of(offer_id);
  double net = P->m * exp(P->sigma_link * escrow_hash_normal(la, lb, 11UL));
  if (tor) net += P->tor_ms * exp(P->tor_sigma_link * escrow_hash_normal(la, lb, 17UL));
  double sj = tor ? P->tor_sigma_jitter : P->sigma_jitter;
  double b = net + escrow_proc_of(recv_id);          /* 受け手の処理の遅れは受領証の側だけに乗る */
  double infl = recv_mal ? P->inflate : 0.0;
  L->tor = tor;
  L->e = P->esc_ms + (tor ? P->tor_ms : 0.0);
  L->er_true = b * exp(0.5 * sj * sj);
  L->r = b * exp(sj * escrow_hash_normal((unsigned long)pid,
                   (unsigned long)recv_id * 1000003UL + (unsigned long)offer_id, 13UL)) + infl;
  L->leg = 0.5 * net * exp(sj * escrow_hash_normal((unsigned long)pid,
                   (unsigned long)recv_id * 1000003UL + (unsigned long)offer_id, 31UL));
  if (P->legs_norm == 2)   /* Tor かどうかで分けた平均 (ノードごとの性質から学べる範囲) */
    L->leg_mean = 0.5 * (P->m * exp(0.5 * P->sigma_link * P->sigma_link)
                         + (tor ? P->tor_ms * exp(0.5 * P->tor_sigma_link * P->tor_sigma_link) : 0.0)) * exp(0.5 * sj * sj);
  else
    L->leg_mean = 0.5 * net * exp(0.5 * sj * sj);
  {
    double ej = exp(0.5 * sj * sj), ej2 = exp(2.0 * sj * sj);
    if (P->legs_norm == 1) {
      L->leg_var = 0.25 * net * net * (ej2 - ej * ej);
    } else {   /* 区分の中でリンクごとの差と1回ごとのぶれを合わせた分散 */
      double ea = P->m * exp(0.5 * P->sigma_link * P->sigma_link), ea2 = P->m * P->m * exp(2.0 * P->sigma_link * P->sigma_link);
      double eb = tor ? P->tor_ms * exp(0.5 * P->tor_sigma_link * P->tor_sigma_link) : 0.0;
      double eb2 = tor ? P->tor_ms * P->tor_ms * exp(2.0 * P->tor_sigma_link * P->tor_sigma_link) : 0.0;
      double m1 = 0.5 * (ea + eb) * ej;
      double m2 = 0.25 * (ea2 + 2.0 * ea * eb + eb2) * ej2;
      L->leg_var = m2 - m1 * m1;
    }
  }
  /* 送り手が期限と予想往復を何から学ぶか */
  double bb = b, add = infl;                         /* adaptive / fixed: この向きの受領証 (水増し込み) */
  if (P->d_mode == ESCROW_D_REF) {
    add = (recv_mal && P->mimic) ? P->inflate : 0.0; /* コミットメント更新: 全部遅らせる攻撃者だけ水増しが入る */
  } else if (P->d_mode == ESCROW_D_REVERSE) {
    bb = net + escrow_proc_of(offer_id);             /* 逆向き: 処理の遅れと水増しは相手のもの */
    add = escrow_mal_of(offer_id) ? P->inflate : 0.0;
  }
  L->er = bb * exp(0.5 * sj * sj) + add;
  if (P->d_mode == ESCROW_D_FIXED) {
    L->D = P->d_fixed;
  } else {
    L->D = bb * exp(sj * P->d_z) + add;
    if (P->d_cap > 0.0 && L->D > P->d_cap) L->D = P->d_cap;
  }
}
/* 保持者が隠せる量 (最大 CLOTH_FALSE_REPORT_MS)。*via_timeout = わざとタイムアウトさせる手口を使ったか */
static double escrow_hide(const struct escrow_link* L, int* via_timeout) {
  const struct escrow_params* P = escrow_params();
  double X = (double)get_false_report_ms();
  double h_in = L->er - L->er_true;
  if (P->anchor_key && L->D - L->er_true > h_in) h_in = L->D - L->er_true;
  if (h_in >= X) { *via_timeout = 0; return X; }   /* 記録の残らない手口で足りる */
  double h_to = P->excuse ? (L->D + L->e - L->er_true) : 0.0;
  double h = (h_to > h_in) ? h_to : h_in;
  *via_timeout = (P->excuse && h_to > h_in && h_to > 0.0);
  if (h < 0.0) h = 0.0;
  if (h > X) h = X;
  return h;
}
/* 経路上で node_id が preimage を受け取る相手 (= hop の to_node) */
static int escrow_offerer_of(struct payment* pm, long node_id, long* offer_id) {
  if (pm == NULL || pm->route == NULL || pm->route->route_hops == NULL) return 0;
  int nh = array_len(pm->route->route_hops);
  for (int k = 0; k < nh; k++) {
    struct route_hop* rh = (struct route_hop*)array_get(pm->route->route_hops, k);
    if (rh != NULL && rh->from_node_id == node_id) { *offer_id = rh->to_node_id; return 1; }
  }
  return 0;
}

/* === 判定ノード経由の受け渡し (CLOTH_JUDGE_COPY, 既定 0) の検証モデル ===
 * preimage を上流へ渡すとき、送り手は同じものの写しを判定ノードにも送る。受け手は署名つきの受領書を送り手に返し、
 * 送り手はそれを判定ノードに転送する (受け手の署名なので送り手は偽造できない)。判定ノードは写しを受け取ってから
 * T (CLOTH_JUDGE_COPY_T_MS, 既定 100) 以内に受領書が届かなければ、自分で受け手に preimage を渡して時刻を記録する。
 * タイムアウトは罪の証拠にしない (判定ノードが渡すだけ)。保持の長さは判定ノードの時計の時刻だけで測る:
 *     保持 = (本人の写しが判定ノードに届いた時刻) − (本人の受領書が届いた時刻。判定ノードが渡したならその時刻)
 * 本人の申告は使わないので、申告時刻の嘘は効かない。攻撃者 (その決済の保持者で、嘘をつくと決まった本人) に残る手口は
 *   受け取り側: 受領書を返すのを遅らせる → T を過ぎると判定ノードが渡した時刻が残るので、隠せるのは T まで
 *   渡す側:     写しだけ先に送り、上流に渡すのを遅らせる → T を過ぎると判定ノードが上流に渡して攻撃が切れるので T まで
 * で、攻撃で足した遅れ (grief_hold_extra_ms) を上限にできるだけ隠す (使う側は CLOTH_FALSE_REPORT_SIDE)。
 * ネットワークの遅れは 0 とみなす (シミュの 1 ホップの遅れはほぼ一定で、他の結果と同じ世界で比べるため)。
 * 判定ノードとのやり取りの遅れとそのばらつきは入れていない。シミュの時刻 (イベント) は変えない。
 * 帰属は相互証明 (CLOTH_REPORT_ATTEST=1) の位置で行い、食い違いの処理 (4a・ペア集計など) は使わない。
 * 攻撃ごとの記録は出力 dir の judge_copy_attacks.csv (この機能か賢い嘘か method3 の記録の書き換えを使うときだけ書く)。 */
static int get_judge_copy(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_JUDGE_COPY");
  return (v = (e != NULL && e[0] != '\0' && strcmp(e, "0") != 0) ? 1 : 0);
}
static double get_judge_copy_t_ms(void) {
  static double v = -1.0;
  if (v >= 0.0) return v;
  const char* e = getenv("CLOTH_JUDGE_COPY_T_MS");
  v = 100.0;
  if (e != NULL && e[0] != '\0') { double t = atof(e); if (t >= 0.0) v = t; }
  return v;
}
struct jc_eval { double hidden_in, hidden_out; int delivered; };
/* 位置 q の中継の保持を判定ノードの時計で測る。位置 k が preimage を受け取った本当の時刻は hop_settle_recv_times[k]
 * (この機能を使うときは申告に嘘を乗せないので本当の時刻のまま)。ネットワークの遅れ 0 では、写しの時刻 = 本当に渡した時刻、
 * 受領書の時刻 = 本当に受け取った時刻になるので、ずらせるのは保持者本人の手口の分だけ。戻り値 <= 0 は測れない。 */
static double judge_copy_hold(struct network* network, struct payment* pm, int q, struct jc_eval* ev) {
  ev->hidden_in = ev->hidden_out = 0.0; ev->delivered = 0;
  uint64_t t_out = pm->hop_settle_recv_times[q - 1];   /* 本人が上流 (位置 q-1) に渡した時刻 */
  uint64_t t_in  = pm->hop_settle_recv_times[q];       /* 本人が下流から受け取った時刻 */
  if (t_out == 0 || t_in == 0 || t_out <= t_in) return 0.0;
  struct route_hop* rh = (struct route_hop*)array_get(pm->route->route_hops, q);
  struct node* nd = (rh != NULL) ? (struct node*)array_get(network->nodes, rh->from_node_id) : NULL;
  if (nd != NULL && nd->id == pm->grief_hold_node_id && lies_on_this_payment(nd, pm)) {
    double T = get_judge_copy_t_ms(), h = (double)pm->grief_hold_extra_ms;
    int side = get_false_report_side();
    if (side != FALSE_REPORT_SIDE_SEND) {   /* 受け取り側: 受領書を h 遅らせる */
      ev->hidden_in = (h < T) ? h : T;
      ev->delivered = (h > T);              /* 判定ノードが渡す */
    }
    if (side != FALSE_REPORT_SIDE_RECV) {   /* 渡す側: 写しを先に送る。判定ノードに先に渡されないよう T まで */
      double r = h - ev->hidden_in;
      ev->hidden_out = (r < T) ? r : T;
    }
  }
  return (double)(t_out - t_in) - ev->hidden_in - ev->hidden_out;
}
/* 攻撃ごとの記録 (judge_copy_attacks.csv)。warmup 後に保持者が実際に遅れを足した決済 1 件につき 1 行。 */
struct jc_record {
  long pid, holder, degree;
  double extra, hold_true, hold_meas, hidden_in, hidden_out;
  int evaluated, delivered, fav_test, reported;
};
static struct jc_record* jc_recs = NULL;
static long jc_n = 0, jc_cap = 0;
static long jc_push(void) {
  if (jc_n == jc_cap) {
    long nc = jc_cap ? 2 * jc_cap : 1024;
    struct jc_record* p = realloc(jc_recs, (size_t)nc * sizeof(struct jc_record));
    if (p == NULL) return -1;
    jc_recs = p; jc_cap = nc;
  }
  memset(&jc_recs[jc_n], 0, sizeof(struct jc_record));
  return jc_n++;
}
static int get_m3_tamper(void);
void judge_copy_write_outputs(char output_dir_name[]) {
  if (!get_judge_copy() && !get_false_report_smart() && !get_m3_tamper()) return;
  char fn[512];
  snprintf(fn, sizeof fn, "%sjudge_copy_attacks.csv", output_dir_name);
  FILE* f = fopen(fn, "w");
  if (f == NULL) return;
  fprintf(f, "payment_id,holder,degree,extra_ms,evaluated,hold_true_ms,hold_meas_ms,hidden_in_ms,hidden_out_ms,judge_delivered,fav_test,reported\n");
  for (long k = 0; k < jc_n; k++) {
    struct jc_record* r = &jc_recs[k];
    fprintf(f, "%ld,%ld,%ld,%.0f,%d,%.0f,%.0f,%.0f,%.0f,%d,%d,%d\n", r->pid, r->holder, r->degree, r->extra,
            r->evaluated, r->hold_true, r->hold_meas, r->hidden_in, r->hidden_out, r->delivered, r->fav_test, r->reported);
  }
  fclose(f);
}

/* === method3 (judging_strategy=3): 判定ノードを使わない分散型の検知 ===
 * preimage を送り返すとき各ノードが自分の時刻を書き込み、記録は送金者まで渡る。時刻に署名はつけない前提なので、
 * 途中のノードは自分より下流の記録を書き換えられる (正直な判定者は届いた記録をそのまま信じる)。
 * いまは誰も時刻を偽らない (書き換えの嘘はまだ入れていない) ので、署名の有無で結果は変わらない。
 * 経路上のノードは、自分より下流のノードの記録を見られる。そこで、対象ノード q の保持 (相互証明と同じく両隣の記録から
 * 出す) を、q より上流にいる各ノード (送金者を含む) が「自分が見た分だけで学んだ q の普段の値」で検定する
 * (判定者 × 対象ごとに検定の状態を持つ。検定の中身は method2 と同じ on_hold_hypothesis_test)。
 * 異常なら判定者が q を告発し、告発はゴシップで全員に届く (遅れ 0 とみなす)。違う告発者が
 * CLOTH_M3_ACCUSERS (既定 1) 人以上そろったら q を確定し、それまでの告発を method2 と同じ報告 (評判の罰) に流す。
 * 確定後の異常はその都度報告する (1 決済 1 回)。悪意ノードは判定者になっても告発しない。
 * 判定ノードの観測の集約 (share_judge_information) と fail 検知器の報告は使わない。
 * 嘘のパターン (CLOTH_M3_FALSE_ACCUSE=1, 既定 0): その決済で実際に保持した攻撃者が、自分に preimage を渡した
 * 下流の隣 (受取人のこともある) を告発する (なすりつけ)。時刻の記録は正直に書く。告発者は攻撃者 1 人なので、
 * k=2 なら確定には別の告発者が要る。
 * 嘘の告発への対策 (CLOTH_M3_DISTRUST_CONFIRMED, 既定 2。0 = 使わない):
 *   1 = 確定した (攻撃者と判断された) 告発者の新しい告発は数えない。
 *   2 = 1 に加えて、告発者が確定したら、それまでの告発も数えない (報告は取り消して評判を戻す)。
 *       告発者の確定が外れたら、その告発はまた数える。
 *   嘘の告発は、その決済の正直な判定者の検定が終わってから処理する (同じ決済で確定した嘘つきの告発を捨てられる)。
 * 既定を k=1 + 対策 2 にした理由: 嘘をつくのは保持した本人なので、同じ決済の正直な判定者が 1 人でも異常と見れば
 * その場で嘘つきが確定し、嘘は全部捨てられる (3 シード × 9 取引数で、嘘ありの結果が嘘なしと同じになった)。
 * k=1 では対策 1 と 2 の結果は同じ。保持せずに嘘だけをつく悪意ノードは想定しない (それには k=1 が一番弱い)。
 * 記録の書き換え (CLOTH_M3_TAMPER=1, 既定 0。method3 のときだけ): 時刻に署名がないので、保持した攻撃者が
 * 下流の隣 B (受取人のこともある) の「自分に preimage を渡した時刻」を足した遅れの分だけ遅く書き換え、
 * 自分の受け取り時刻も同じだけ遅く書く。記録は食い違わず、B が保持したように見える (B が受取人なら遅れは消える)。
 * CLOTH_M3_TAMPER=2: 付け替え先を下流のどこか (すぐ隣から受取人まで) にする。決済 ID と攻撃者の ID のハッシュで選ぶ
 * (乱数は使わない)。付け替え先 C の送出時刻、A と C の間のノードの受領・送出時刻、A の受領時刻を同じだけ遅くするので、
 * 記録は食い違わず C が保持したように見える (間のノードの保持は変わらない)。すぐ隣を選んだときは 1 と同じ。 */
static int get_m3_false_accuse(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_FALSE_ACCUSE");
  return (v = (e != NULL && e[0] != '\0' && strcmp(e, "0") != 0) ? 1 : 0);
}
static int get_m3_accusers_required(void) {
  static int v = -1;
  if (v >= 1) return v;
  const char* e = getenv("CLOTH_M3_ACCUSERS");
  v = 1;
  if (e != NULL && e[0] != '\0') { int t = atoi(e); if (t >= 1) v = t; }
  return v;
}
static int get_m3_distrust(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_DISTRUST_CONFIRMED");
  v = (e != NULL && e[0] != '\0') ? atoi(e) : 2;
  if (v < 0 || v > 2) v = 2;
  return v;
}
static int get_m3_tamper(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_TAMPER");
  v = (e != NULL && e[0] != '\0') ? atoi(e) : 0;
  if (v < 0 || v > 2) v = 0;
  return v;
}
static long m3_tamper_count = 0;   /* 書き換えた決済の数 */
static long m3_tamper_recv = 0;    /* そのうち受取人に付け替えた数 */
static long m3_tamper_dist_sum = 0;   /* 付け替え先までのホップ数の合計 */
/* 申し立て (CLOTH_M3_APPEAL, 既定 0 = 使わない (10/26 から。10/17〜10/26 の既定は 3)。対策 2 のときだけ効く):
 *   確定したノード x は 1 回だけ「冤罪だ」と申し立てられる (本物の攻撃者も申し立てる)。相手は x が確定した決済で
 *   x の上流の隣 u (x の記録を書き換えられる位置)。申し立てると x と u のチャンネルを閉じ、x の罰を止めて
 *   (報告を取り消して評判を戻す)、x と u の両方を監視する。
 *   証拠 = 正直な判定者が異常と見た保持。本人の保持の異常に加えて、本人が中継した決済での下流の隣 (中継) の異常も
 *   本人の分とし、そのときは下流の隣を告発しない (書き換えでは遅れが下流の隣に出るため)。受取人の保持は検定しない。
 *   先に証拠が出たほうが負け。x が負けたら確定し直す (罰を戻す)。u が負けたら u を有罪として確定し、u を相手にした
 *   申し立ては全部申し立てた側の勝ち (それまでの告発を数えなくし、チャンネルを開け直す)。有罪のノードは以後も
 *   下流の隣の異常を本人の分とする。決着がつくまで監視を続け、決着の後の申し立ては受け付けない
 *   (相手として有罪になったノードも申し立てられない)。
 *   2 = 1 と同じだが、下流の隣がすでに確定している (自分の遅れとして説明がつく) ときは本人の分にしない。
 *   3 = 割合で比べる: 監視中に中継した決済の数 r と証拠の数 e (本人の異常 + 中継した決済での下流の隣の異常) を数え、
 *       割合 (e + θ·m) / (r + m) の高いほうが負け (負ける側の e が CLOTH_M3_APPEAL_MIN_EVIDENCE (既定 2) 以上の
 *       ときだけ。同じなら監視を続ける)。θ = CLOTH_M3_APPEAL_PRIOR_RATE (既定 0.2)・m = CLOTH_M3_APPEAL_PRIOR_WEIGHT
 *       (既定 5) は前もっての割合とその重み (中継しない相手 (送金者など) は θ のまま)。下流の隣の異常は数えるだけで、
 *       その隣はふつうどおり告発する (有罪のノードの下流の隣の異常だけは、1・2 と同じく有罪のノードの分にする)。
 *       扱う決済が多いハブは、下流の隣で別の攻撃者が攻撃しても割合は小さい (嘘なしの seed 7・n=12800 で中央 2%・
 *       最大 12%。攻撃者自身は中継の 86% で攻撃する)。
 *   既定を 3 にした理由 (金額 100・p 0.001・3 シード、n=12800、申し立てなし → 3): 記録の書き換え (CLOTH_M3_TAMPER) では
 *   +43.7% (防御なしより悪い) → -49.4%。代わりに嘘なしは -81.3% → -78.1%、自分の受け取り時刻を偽る嘘は -76.5% → -70.9%
 *   (申し立てた攻撃者は、監視中に罰が止まる間に 1〜2 回攻撃できる)。
 *   10/26 に既定を 0 に戻した理由: ハッシュチェーンと送金者だけの告発 (CLOTH_M3_SENDER_ONLY) が入ると、正直なノードが
 *   申し立てる場面がほぼなくなり (n=12800 の嘘なしで 0 回)、申し立てるのは攻撃者だけで罰が止まる (終わった時点で 382 人)。
 *   送金者だけの告発と一緒に外すと、検出率 (終わった時点) は嘘なしで 49.7% → 93.4%、送金成功率は 98.21% → 99.14%。 */
static int get_m3_appeal(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_APPEAL");
  int given = (e != NULL && e[0] != '\0');
  v = given ? atoi(e) : 0;
  if (v < 0 || v > 3) v = 0;
  if (v > 0 && get_m3_distrust() != 2) {   /* 対策 2 でないときは使わない (明示したときだけ知らせる) */
    if (given) fprintf(stderr, "[method3] CLOTH_M3_APPEAL は CLOTH_M3_DISTRUST_CONFIRMED=2 のときだけ効く (使わない)\n");
    v = 0;
  }
  return v;
}
static long get_m3_appeal_long(const char* name, long def) {
  const char* e = getenv(name);
  if (e == NULL || e[0] == '\0') return def;
  long t = atol(e);
  return (t >= 1) ? t : def;
}
/* 申し立ての相手を、確定した決済で対象より上流にいた中継の全部にする (CLOTH_M3_APPEAL_ALL_UPSTREAM=1、既定 0。割合で比べる 3 のときだけ)。
 * 送金者は相手にしない (記録を書き換えるのは保持した中継だけ)。上流に中継がいないときは申し立てない。
 * チャンネルを閉じるのはすぐ上流の隣とだけ (つながっているのはそこだけ)。決着は、相手のうち割合 (e+θm)/(r+m) が
 * 一番高いノードと比べて決め、相手のどれかが有罪になれば申し立てた側の勝ち。相手が 1 人なら 0 と同じ。 */
static int get_m3_appeal_all(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_APPEAL_ALL_UPSTREAM");
  return (v = (get_m3_appeal() == 3 && e != NULL && e[0] != '\0' && strcmp(e, "0") != 0) ? 1 : 0);
}
/* 監視中の証拠を、本人が中継した決済で本人より下流 (2 つ以上先も) で起きた異常まで広げる
 * (CLOTH_M3_APPEAL_EVIDENCE_DOWNSTREAM=1、既定 0。割合で比べる 3 のときだけ)。すぐ下流の隣は 0 でも数えるので、
 * 足すのは 2 つ以上先の分 (同じ決済では 1 回だけ)。有罪のノードの分にして告発をつけかえるのは、今までどおりすぐ上流の隣だけ。 */
static int get_m3_appeal_ev_down(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_APPEAL_EVIDENCE_DOWNSTREAM");
  return (v = (get_m3_appeal() == 3 && e != NULL && e[0] != '\0' && strcmp(e, "0") != 0) ? 1 : 0);
}
/* 受取人の保持も検定する (CLOTH_M3_RECEIVER_TEST、既定 1。0 = 使わない。method3 のときだけ)。受取人は自分の支払いを遅らせない前提なので、
 * 受取人の保持 (HTLC を受け取ってから preimage を返したと記録された時刻まで) が異常なら、受取人のすぐ上流の中継を告発する
 * (監視中なら、その中継の証拠にも数える)。検定するのは受取人より上流の正直なノード (送金者を含み、告発される中継は除く)。
 * 受取人としての基準は、中継としての基準とは別に学ぶ。
 * 既定にした理由 (金額 100・p 0.001・3 シード、n=12800): 案 1〜3 (受取人の検定・受取人の記録を直接・絞り込み) の組み合わせを
 * 比べ、書き換え 2 条件の削減の平均が一番大きく、嘘なしを悪くしないのが受取人の検定だけだった (すぐ隣 -49.4% -> -66.1%、
 * 下流のどこか -31.2% -> -51.8%、嘘なしは 27 セルとも出力が同じ)。絞り込みを足すと書き換えにはもっと効くが嘘なしが 0.9 pt 悪くなり、
 * 受取人の記録を直接届けると受取人の保持が異常に見えなくなって、この検定の効き目が消える。 */
static int get_m3_rcv_test(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_RECEIVER_TEST");
  return (v = (e != NULL && e[0] != '\0') ? (strcmp(e, "0") != 0) : 1);
}
static long m3_rcv_tests = 0, m3_rcv_anom = 0;
/* 受取人の検定で見つかった異常は、すぐ罰せず割合で決める (CLOTH_M3_RCV_WATCH、既定 1。0 ですぐ告発する前の作り)。受取人のすぐ上流の中継 L について、
 * warmup 後に中継した決済の数 r と、受取人の異常が出た決済の数 e を数え、(e + θm) / (r + m) が CLOTH_M3_RCV_WATCH_RATE
 * (既定 0.3) 以上かつ e が CLOTH_M3_RCV_WATCH_MIN (既定 2) 以上になってから L を告発する。θ・m は申し立ての前もっての割合と重み。 */
static int get_m3_rcv_watch(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_RCV_WATCH");
  return (v = (e != NULL && e[0] != '\0') ? (strcmp(e, "0") != 0) : 1);
}
static double get_m3_rcv_watch_rate(void) {
  static double v = -1.0;
  if (v >= 0.0) return v;
  const char* e = getenv("CLOTH_M3_RCV_WATCH_RATE");
  v = 0.3; if (e != NULL && e[0] != '\0') { double t = atof(e); if (t > 0.0 && t <= 1.0) v = t; }
  return v;
}
static long get_m3_rcv_watch_min(void) {
  static long v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_RCV_WATCH_MIN");
  v = 2; if (e != NULL && e[0] != '\0') { long t = atol(e); if (t >= 1) v = t; }
  return v;
}
static long m3_rcv_held = 0;   /* 受取人の異常のうち、割合が低くて告発を見送った回数 */
/* 受取人の記録を経路を通さずに送金者へ届ける (CLOTH_M3_RECEIVER_DIRECT=1、既定 0。method3 のときだけ)。
 * 受取人と送金者は請求書のやりとりで直接つながっているので、受取人の時刻はこの道で届き、途中の中継には書き換えられない。
 * 記録の書き換え (CLOTH_M3_TAMPER) が受取人の記録に及ばなくなるだけで、ほかの処理 (受取人の記録を信じる突き合わせ) はそのまま。 */
static int get_m3_rcv_direct(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_RECEIVER_DIRECT");
  return (v = (e != NULL && e[0] != '\0' && strcmp(e, "0") != 0) ? 1 : 0);
}
static long m3_rcv_direct_kept = 0;
/* 誰が上流にいたときに異常が出たかで絞る (CLOTH_M3_TOMOGRAPHY=1、既定 0。method3 のときだけ)。
 * 各中継について、warmup 後に中継した決済の数 r と、そのうち下流のどこかの中継が異常と見られた決済の数 c を数え、
 * 割合 (c + θm) / (r + m) が CLOTH_M3_TOMO_THRESHOLD (既定 0.3) 以上で c が CLOTH_M3_TOMO_MIN (既定 3) 以上なら、
 * その決済で異常を見た正直な判定者がその中継も告発する (1 決済 1 回)。θ・m は申し立ての前もっての割合と重み。 */
static int get_m3_tomo(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_TOMOGRAPHY");
  return (v = (e != NULL && e[0] != '\0' && strcmp(e, "0") != 0) ? 1 : 0);
}
static double get_m3_tomo_threshold(void) {
  static double v = -1.0;
  if (v >= 0.0) return v;
  const char* e = getenv("CLOTH_M3_TOMO_THRESHOLD");
  v = 0.3;
  if (e != NULL && e[0] != '\0') { double t = atof(e); if (t > 0.0 && t <= 1.0) v = t; }
  return v;
}
static long get_m3_tomo_min(void) {
  static long v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_TOMO_MIN");
  v = 3;
  if (e != NULL && e[0] != '\0') { long t = atol(e); if (t >= 1) v = t; }
  return v;
}
static long m3_tomo_acc = 0, m3_tomo_acc_h = 0;   /* 絞って告発した回数・そのうち正直なノード */   /* 受取人の記録が書き換えられずに届いた (書き換えの対象が受取人だった) 回数 */
/* 申し立てを受け付ける条件 (CLOTH_M3_APPEAL_CONC=1、既定 0。割合で比べる 3 のときだけ)。確定してもすぐには申し立てず、
 * 数える告発の記録が CLOTH_M3_APPEAL_CONC_MIN (既定 2) 件以上たまり、そのうち CLOTH_M3_APPEAL_CONC_FRAC (既定 0.8) 以上が
 * 同じ上流の隣の決済だったときだけ、その隣を相手に申し立てる (濡れ衣は罪を被せた上流の隣の下に集中する)。
 * 条件を満たさない間は確定したまま (罰は止めない)。 */
static int get_m3_appeal_conc(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_APPEAL_CONC");
  return (v = (get_m3_appeal() == 3 && e != NULL && e[0] != '\0' && strcmp(e, "0") != 0) ? 1 : 0);
}
static long get_m3_appeal_conc_min(void) {
  static long v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_APPEAL_CONC_MIN");
  v = 2; if (e != NULL && e[0] != '\0') { long t = atol(e); if (t >= 1) v = t; }
  return v;
}
static double get_m3_appeal_conc_frac(void) {
  static double v = -1.0;
  if (v >= 0.0) return v;
  const char* e = getenv("CLOTH_M3_APPEAL_CONC_FRAC");
  v = 0.8; if (e != NULL && e[0] != '\0') { double t = atof(e); if (t > 0.0 && t <= 1.0) v = t; }
  return v;
}
/* 申し立ての相手を有罪にするのは、相手の割合が申し立てた側の CLOTH_M3_APPEAL_OPP_FACTOR 倍 (既定 2。1 で前の作り) を
 * 超えたときだけにする (割合で比べる 3 のとき)。申し立てた側が負ける決め方は変えない。 */
static double get_m3_appeal_opp_factor(void) {
  static double v = -1.0;
  if (v >= 0.0) return v;
  const char* e = getenv("CLOTH_M3_APPEAL_OPP_FACTOR");
  v = 2.0; if (e != NULL && e[0] != '\0') { double t = atof(e); if (t >= 1.0) v = t; }
  return v;
}
/* 申し立てに勝った (冤罪と認められた) ノードが、あとで別の相手のせいでまた確定したら、もう 1 回だけ申し立てられる
 * (CLOTH_M3_APPEAL_TWICE、既定 1。0 で 1 回だけの前の作り。割合で比べる 3 のとき)。負けたノードと相手として有罪になったノードは申し立てられない。 */
static int get_m3_appeal_twice(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_APPEAL_TWICE");
  return (v = (get_m3_appeal() == 3 && ((e != NULL && e[0] != '\0') ? (strcmp(e, "0") != 0) : 1)) ? 1 : 0);
}
static int m3_cmp_long(const void* a, const void* b) { long x = *(const long*)a, y = *(const long*)b; return (x > y) - (x < y); }
static long get_m3_appeal_prior_weight(void) {
  static long v = -1;
  return (v >= 0) ? v : (v = get_m3_appeal_long("CLOTH_M3_APPEAL_PRIOR_WEIGHT", 5));
}
static double get_m3_appeal_prior_rate(void) {
  static double v = -1.0;
  if (v >= 0.0) return v;
  const char* e = getenv("CLOTH_M3_APPEAL_PRIOR_RATE");
  v = 0.2;
  if (e != NULL && e[0] != '\0') { double t = atof(e); if (t >= 0.0 && t <= 1.0) v = t; }
  return v;
}
static long get_m3_appeal_min_evidence(void) {
  static long v = -1;
  return (v >= 0) ? v : (v = get_m3_appeal_long("CLOTH_M3_APPEAL_MIN_EVIDENCE", 2));
}
struct m3_ev {                /* 対策 2 用: 決済ごとの告発 (告発者つき) */
  long pid;
  int reported;
  long* acc; int n_acc, cap_acc;
  long up;                    /* 申し立て用: この決済で対象の上流の隣 */
  long* ups; int n_ups;       /* 申し立て用 (全部の上流): この決済で対象より上流にいた中継 */
};
struct m3_target {            /* 対象ノードごとの告発の状態 (ゴシップで全員が同じものを見る) */
  long* accusers; int n_acc, cap_acc;
  int confirmed;
  long n_pend, cap_pend;      /* 確定前の告発 (決済ごと) */
  long* pend_pid; long* pend_reporter; uint64_t* pend_time;
  uint64_t first_accuse_time, confirm_time;
  long tests, anomalies, reports;
  long false_accusations;     /* 嘘の告発を受けた回数 */
  long ignored;               /* 対策: 確定した告発者の分として数えなかった告発 */
  long revoked, unconfirms;   /* 対策 2: 取り消した報告・確定が外れた回数 */
  struct m3_ev* ev; long n_ev, cap_ev;   /* 対策 2: この対象への告発 (決済ごと) */
  long* tg; int n_tg, cap_tg;            /* 対策 2: このノードが告発した相手 */
  int ap;                     /* 申し立て: 0 = まだ, 1 = 監視中, 2 = 決着 (もう申し立てられない) */
  int ap_won;                 /* 1 = 勝った (冤罪), 2 = 負けた */
  int guilty;                 /* 申し立ての相手として有罪になった */
  long ap_opp, named, blamed; /* 申し立ての相手・自分を相手にした監視中の申し立ての数・下流の隣の異常を自分の分にした回数 */
  uint64_t ap_start, ap_end;
  long void_from;             /* 申し立てに勝った: これより前の告発 (ev の番号) は数えない */
  long cl_e[8]; int n_cl;     /* 申し立てで閉じたチャンネル (辺の id) */
  long a_r, a_e;              /* 割合で比べる (3): 監視中に中継した決済の数・証拠の数 */
  long a_last_pid;            /* 2 つ以上先の異常を数えた最後の決済 (id+1)。同じ決済で 2 回数えない */
  long rv_r, rv_e;            /* 受取人の検定の監視: 中継した決済・受取人の異常が出た決済 */
  long tm_r, tm_c, tm_last_pid, tm_acc_pid;   /* 絞り込み: 中継した決済・下流で異常が出た決済・最後に数えた決済・最後に告発した決済 (id+1) */
  long* by; int n_by, cap_by; /* 自分を相手に申し立てたノード */
  long* opps; int n_opps;     /* 申し立ての相手 (全部の上流のとき) */
  int n_appeals;              /* 申し立てた回数 */
};
static struct m3_target* m3_t = NULL;
static long m3_nn = 0;
static int m3_names(long i, long u) {   /* i の監視中の申し立ての相手に u が入っているか */
  struct m3_target* t = &m3_t[i];
  if (t->n_opps == 0) return t->ap_opp == u;
  for (int k = 0; k < t->n_opps; k++) if (t->opps[k] == u) return 1;
  return 0;
}
/* 判定者 × 対象 の検定の状態。on_hold_hypothesis_test に渡す影のノード (settle_* だけを使い、次数は対象のものを見る) */
static uint64_t* m3_keys = NULL;
static struct node** m3_vals = NULL;
static long m3_cap = 0, m3_used = 0;
static uint64_t m3_hash(uint64_t x) {
  x += 0x9E3779B97F4A7C15ULL; x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ULL;
  x = (x ^ (x >> 27)) * 0x94D049BB133111EBULL; return x ^ (x >> 31);
}
static void m3_insert(uint64_t key, struct node* v) {
  uint64_t i = m3_hash(key) & (uint64_t)(m3_cap - 1);
  while (m3_keys[i] != 0) i = (i + 1) & (uint64_t)(m3_cap - 1);
  m3_keys[i] = key; m3_vals[i] = v; m3_used++;
}
static struct node* m3_shadow(long observer, struct node* target) {
  uint64_t key = (((uint64_t)observer + 1) << 32) | (uint64_t)(target->id + 1);
  if (m3_cap == 0 || (m3_used + 1) * 2 > m3_cap) {   /* 表を広げて入れ直す */
    long oc = m3_cap; uint64_t* ok = m3_keys; struct node** ov = m3_vals;
    m3_cap = oc ? oc * 2 : 1 << 16;
    m3_keys = calloc((size_t)m3_cap, sizeof(uint64_t)); m3_vals = calloc((size_t)m3_cap, sizeof(struct node*));
    m3_used = 0;
    for (long k = 0; k < oc; k++) if (ok[k] != 0) m3_insert(ok[k], ov[k]);
    free(ok); free(ov);
  }
  uint64_t i = m3_hash(key) & (uint64_t)(m3_cap - 1);
  while (m3_keys[i] != 0) {
    if (m3_keys[i] == key) return m3_vals[i];
    i = (i + 1) & (uint64_t)(m3_cap - 1);
  }
  struct node* sh = calloc(1, sizeof(struct node));
  sh->id = target->id;
  sh->open_edges = target->open_edges;   /* 次数 (σ の膨張) は対象のものを使う。共有するだけで解放しない */
  m3_insert(key, sh);
  return sh;
}
/* 照らし合わせ用: 送金者がこれまで確かめた記録の全部のホップの保持をまとめて学ぶ状態 (対象ごとではない) */
static struct node* m3_shadow_pool(long observer) {
  struct node tmp; memset(&tmp, 0, sizeof tmp);
  tmp.id = 0x3FFFFFFF;   /* どのノードの id とも重ならないキー (open_edges は NULL = 次数 0) */
  return m3_shadow(observer, &tmp);
}
/* 受取人としての検定の状態 (中継としての状態とは別のキー) */
static struct node* m3_shadow_rcv(long observer, struct node* target) {
  uint64_t key = (((uint64_t)observer + 1) << 32) | ((uint64_t)(target->id + 1) | 0x80000000ULL);
  if (m3_cap == 0 || (m3_used + 1) * 2 > m3_cap) {
    long oc = m3_cap; uint64_t* ok = m3_keys; struct node** ov = m3_vals;
    m3_cap = oc ? oc * 2 : 1 << 16;
    m3_keys = calloc((size_t)m3_cap, sizeof(uint64_t)); m3_vals = calloc((size_t)m3_cap, sizeof(struct node*));
    m3_used = 0;
    for (long k = 0; k < oc; k++) if (ok[k] != 0) m3_insert(ok[k], ov[k]);
    free(ok); free(ov);
  }
  uint64_t i = m3_hash(key) & (uint64_t)(m3_cap - 1);
  while (m3_keys[i] != 0) {
    if (m3_keys[i] == key) return m3_vals[i];
    i = (i + 1) & (uint64_t)(m3_cap - 1);
  }
  struct node* sh = calloc(1, sizeof(struct node));
  sh->id = target->id;
  sh->open_edges = target->open_edges;
  m3_insert(key, sh);
  return sh;
}
static struct m3_target* m3_target_of(struct network* network, long id) {
  if (m3_t == NULL) {
    m3_nn = array_len(network->nodes);
    m3_t = calloc((size_t)m3_nn, sizeof(struct m3_target));
  }
  return (id >= 0 && id < m3_nn) ? &m3_t[id] : NULL;
}
static void m3_add_accuser(struct m3_target* t, long who) {
  for (int k = 0; k < t->n_acc; k++) if (t->accusers[k] == who) return;
  if (t->n_acc == t->cap_acc) {
    t->cap_acc = t->cap_acc ? 2 * t->cap_acc : 4;
    t->accusers = realloc(t->accusers, (size_t)t->cap_acc * sizeof(long));
  }
  t->accusers[t->n_acc++] = who;
}
static void m3_report(struct network* network, struct m3_target* t, struct node* target, long reporter, long pid,
                      uint64_t now, struct network_params net_params) {
  report_attacked_node_to_judges(network, reporter, target->id, (uint64_t)pid, now, net_params);
  target->hold_reports_main++;
  t->reports++;
}
/* 対象への告発 1 件 (この決済の分) を処理する: 確定済みなら報告、未確定ならためて、告発者がそろえば確定して流す。 */
static int m3_accuse_event(struct network* network, struct simulation* simulation, struct payment* payment,
                           struct network_params net_params, struct m3_target* t, struct node* target, long reporter) {
  if (t->first_accuse_time == 0) t->first_accuse_time = simulation->current_time;
  if (t->confirmed) {
    if (has_attack_reporter(payment, target->id)) return 0;
    register_attack_reporter(payment, target->id);
    m3_report(network, t, target, reporter, payment->id, simulation->current_time, net_params);
    return 1;
  }
  /* 同じ決済の告発は 1 件だけためる (嘘の告発と正直な告発が同じ決済で重なったとき、確定で 2 回報告しない)。
   * ためるのは決済の順なので、重なるなら直前の 1 件 */
  int same_payment = (t->n_pend > 0 && t->pend_pid[t->n_pend - 1] == payment->id);
  if (!same_payment) {
    if (t->n_pend == t->cap_pend) {
      t->cap_pend = t->cap_pend ? 2 * t->cap_pend : 4;
      t->pend_pid = realloc(t->pend_pid, (size_t)t->cap_pend * sizeof(long));
      t->pend_reporter = realloc(t->pend_reporter, (size_t)t->cap_pend * sizeof(long));
      t->pend_time = realloc(t->pend_time, (size_t)t->cap_pend * sizeof(uint64_t));
    }
    t->pend_pid[t->n_pend] = payment->id; t->pend_reporter[t->n_pend] = reporter;
    t->pend_time[t->n_pend] = simulation->current_time; t->n_pend++;
  }
  if (t->n_acc < get_m3_accusers_required()) return 0;
  /* 違う告発者がそろった: 確定して、ためていた告発を報告に流す */
  t->confirmed = 1;
  t->confirm_time = simulation->current_time;
  register_attack_reporter(payment, target->id);
  for (long k = 0; k < t->n_pend; k++)
    m3_report(network, t, target, t->pend_reporter[k], t->pend_pid[k], simulation->current_time, net_params);
  return 1;
}
/* 告発者 a の告発を数えるか (対策: 確定した告発者の告発は数えない) */
static int m3_counts(long a) {
  return !(a >= 0 && a < m3_nn && m3_t[a].confirmed);
}
static void m3_add_id(long** arr, int* n, int* cap, long v) {
  for (int k = 0; k < *n; k++) if ((*arr)[k] == v) return;
  if (*n == *cap) { *cap = *cap ? 2 * *cap : 4; *arr = realloc(*arr, (size_t)*cap * sizeof(long)); }
  (*arr)[(*n)++] = v;
}
/* 申し立てを始める: x と u のチャンネル (両向き) を閉じ、両方を監視する */
static void m3_appeal_start(struct network* network, struct simulation* simulation, long x, long u) {
  struct m3_target* t = &m3_t[x];
  t->ap = 1; t->ap_opp = u; t->ap_start = simulation->current_time;
  t->n_appeals++;
  m3_t[u].named++;
  m3_add_id(&m3_t[u].by, &m3_t[u].n_by, &m3_t[u].cap_by, x);
  struct node* nx = (struct node*)array_get(network->nodes, x);
  t->n_cl = 0;
  for (long k = 0; nx != NULL && nx->open_edges != NULL && k < array_len(nx->open_edges) && t->n_cl < 8; k++) {
    struct edge* ed = (struct edge*)array_get(nx->open_edges, k);
    if (ed == NULL || ed->to_node_id != u) continue;
    struct edge* ce = (struct edge*)array_get(network->edges, ed->counter_edge_id);
    ed->is_closed = 1;
    if (ce != NULL) ce->is_closed = 1;
    t->cl_e[t->n_cl++] = ed->id;
  }
}
/* 対策 2: 対象 x の確定と報告を「いま数える告発」だけで決め直す。確定が変わったら 1 を返す。
 * 確定する = 数える告発者が k 人以上。報告する決済 = 確定していて、数える告発者が 1 人以上いる決済。
 * 報告が要らなくなった決済は取り消して評判を戻し (revoke_reports_from_judges)、また要るようになった決済は報告し直す。 */
static int m3_hc_no_appeal(long x);   /* ハッシュチェーン: 判定ノードの測定で決まった犯人は申し立てられない (CLOTH_M3_HASHCHAIN_CULPRIT=3) */
static int m3_sync(struct network* network, struct simulation* simulation, struct payment* payment,
                   struct network_params net_params, long x) {
  struct m3_target* t = &m3_t[x];
  struct node* nd = (struct node*)array_get(network->nodes, x);
  if (nd == NULL) return 0;
  int eff = 0;
  if (t->void_from > 0) {   /* 申し立てに勝った: 残りの告発だけで違う告発者を数え直す */
    long* seen = NULL; int ns = 0, cs = 0;
    for (long j = t->void_from; j < t->n_ev; j++)
      for (int k = 0; k < t->ev[j].n_acc; k++)
        if (t->ev[j].acc[k] != x && m3_counts(t->ev[j].acc[k])) m3_add_id(&seen, &ns, &cs, t->ev[j].acc[k]);
    eff = ns; free(seen);
  } else {
    for (int k = 0; k < t->n_acc; k++) if (t->accusers[k] != x && m3_counts(t->accusers[k])) eff++;
  }
  int want = (eff >= get_m3_accusers_required());
  if (get_m3_appeal()) {
    if (t->guilty) want = 1;
    /* 2 回目の申し立てができる: 1 回目に勝っていて、まだ 2 回目を使っていない (CLOTH_M3_APPEAL_TWICE) */
    int again = get_m3_appeal_twice() && t->ap == 2 && t->ap_won == 1 && !t->guilty && t->n_appeals < 2;
    int no_ap = m3_hc_no_appeal(x);
    if (get_m3_appeal_conc() && !get_m3_appeal_all()) {
      if (want && (t->ap == 0 || again) && !t->guilty && !no_ap) {   /* 告発の記録が同じ上流の隣の下に集中しているときだけ申し立てる */
        long* us = malloc((size_t)(t->n_ev > 0 ? t->n_ev : 1) * sizeof(long)); long nc = 0;
        for (long j = t->void_from; j < t->n_ev; j++) {
          int cnt_ok = 0;
          for (int k = 0; k < t->ev[j].n_acc; k++) if (t->ev[j].acc[k] != x && m3_counts(t->ev[j].acc[k])) { cnt_ok = 1; break; }
          if (cnt_ok && t->ev[j].up >= 0) us[nc++] = t->ev[j].up;
        }
        long best = -1, bestc = 0;
        if (nc > 0) {
          qsort(us, (size_t)nc, sizeof(long), m3_cmp_long);
          for (long i = 0, j; i < nc; i = j) {
            for (j = i; j < nc && us[j] == us[i]; j++) ;
            if (j - i > bestc) { bestc = j - i; best = us[i]; }
          }
        }
        free(us);
        if (nc >= get_m3_appeal_conc_min() && (double)bestc >= get_m3_appeal_conc_frac() * (double)nc &&
            best >= 0 && best < m3_nn && best != x && !(again && best == t->ap_opp)) {
          if (again) t->ap_won = 0;
          m3_appeal_start(network, simulation, x, best);
        }
      }
    } else if (want && !t->confirmed && t->ap == 0 && !no_ap) {   /* 確定する: 1 回だけ申し立てる (相手 = いま数える最後の告発の上流の隣) */
      long opp = -1; struct m3_ev* eo = NULL;
      for (long j = t->n_ev - 1; j >= t->void_from && opp < 0; j--)
        for (int k = 0; k < t->ev[j].n_acc; k++)
          if (t->ev[j].acc[k] != x && m3_counts(t->ev[j].acc[k])) { opp = t->ev[j].up; eo = &t->ev[j]; break; }
      if (get_m3_appeal_all()) {   /* 相手 = その決済で上流にいた中継の全部 (いなければ申し立てない) */
        if (eo != NULL && eo->n_ups > 0) {
          m3_appeal_start(network, simulation, x, eo->ups[eo->n_ups - 1]);
          t->opps = malloc((size_t)eo->n_ups * sizeof(long)); t->n_opps = 0;
          for (int k = 0; k < eo->n_ups; k++) {
            long u = eo->ups[k];
            if (u < 0 || u >= m3_nn || u == x) continue;
            t->opps[t->n_opps++] = u;
            if (u != eo->ups[eo->n_ups - 1]) { m3_t[u].named++; m3_add_id(&m3_t[u].by, &m3_t[u].n_by, &m3_t[u].cap_by, x); }
          }
        }
      } else if (opp >= 0 && opp < m3_nn && opp != x) m3_appeal_start(network, simulation, x, opp);
    } else if (want && !t->confirmed && again && !no_ap) {
      /* 申し立てに勝ったあと、別の相手のせいでまた確定した: 2 回目の申し立て (相手が前回と違うときだけ) */
      long opp = -1;
      for (long j = t->n_ev - 1; j >= t->void_from && opp < 0; j--)
        for (int k = 0; k < t->ev[j].n_acc; k++)
          if (t->ev[j].acc[k] != x && m3_counts(t->ev[j].acc[k])) { opp = t->ev[j].up; break; }
      if (opp >= 0 && opp < m3_nn && opp != x && opp != t->ap_opp) { t->ap_won = 0; m3_appeal_start(network, simulation, x, opp); }
    }
    if (t->ap == 1) want = 0;   /* 監視中は罰を止める */
  }
  long to_revoke = 0;
  for (long j = 0; j < t->n_ev; j++) {
    struct m3_ev* e = &t->ev[j];
    long rep = -1;
    if (j >= t->void_from)
      for (int k = 0; k < e->n_acc && rep < 0; k++) if (e->acc[k] != x && m3_counts(e->acc[k])) rep = e->acc[k];
    int wr = want && rep >= 0;
    if (wr && !e->reported) {
      m3_report(network, t, nd, rep, e->pid, simulation->current_time, net_params);
      if (e->pid == payment->id) register_attack_reporter(payment, x);
      e->reported = 1;
    } else if (!wr && e->reported) {
      e->reported = 0;
      to_revoke++;
    }
  }
  if (to_revoke > 0) {
    revoke_reports_from_judges(network, x, to_revoke, net_params);
    nd->hold_reports_main -= to_revoke;
    t->reports -= to_revoke;
    t->revoked += to_revoke;
  }
  if (want == t->confirmed) return 0;
  if (want) {
    if (t->confirm_time == 0) {   /* 最初の確定: そのとき流した報告の数を残す (出力の pending_at_confirm) */
      t->confirm_time = simulation->current_time;
      t->n_pend = 0;
      for (long j = 0; j < t->n_ev; j++) t->n_pend += t->ev[j].reported;
    }
  }
  else t->unconfirms++;
  t->confirmed = want;
  return 1;
}
/* 対策 2: 対象への告発 1 件 (この決済の分、告発者は acc[0..n-1]) を記録し、確定の変化を告発した相手へ順に伝える。 */
static void m3_propagate(struct network* network, struct simulation* simulation, struct payment* payment,
                         struct network_params net_params, long start);
static void m3_accuse_v2(struct network* network, struct simulation* simulation, struct payment* payment,
                         struct network_params net_params, struct m3_target* t, struct node* target,
                         const long* acc, int n, long up) {
  if (t->first_accuse_time == 0) t->first_accuse_time = simulation->current_time;
  struct m3_ev* e = (t->n_ev > 0 && t->ev[t->n_ev - 1].pid == payment->id) ? &t->ev[t->n_ev - 1] : NULL;
  if (e == NULL) {   /* 決済の順にためるので、同じ決済なら直前の 1 件 */
    if (t->n_ev == t->cap_ev) {
      t->cap_ev = t->cap_ev ? 2 * t->cap_ev : 4;
      t->ev = realloc(t->ev, (size_t)t->cap_ev * sizeof(struct m3_ev));
    }
    e = &t->ev[t->n_ev++];
    memset(e, 0, sizeof *e);
    e->pid = payment->id;
    e->up = up;
    if (get_m3_appeal_all() && payment->route != NULL && payment->route->route_hops != NULL) {
      int nh = array_len(payment->route->route_hops), q = -1;
      for (int k = 1; k < nh && q < 0; k++) {
        struct route_hop* rh = (struct route_hop*)array_get(payment->route->route_hops, k);
        if (rh != NULL && rh->from_node_id == target->id) q = k;
      }
      if (q > 1) {
        e->ups = malloc((size_t)(q - 1) * sizeof(long));
        for (int k = 1; k < q; k++) {
          struct route_hop* rh = (struct route_hop*)array_get(payment->route->route_hops, k);
          e->ups[e->n_ups++] = (rh != NULL) ? rh->from_node_id : -1;
        }
      }
    }
  }
  for (int k = 0; k < n; k++) {
    if (!m3_counts(acc[k])) t->ignored++;
    m3_add_id(&e->acc, &e->n_acc, &e->cap_acc, acc[k]);
    m3_add_accuser(t, acc[k]);
    struct m3_target* ta = m3_target_of(network, acc[k]);
    if (ta != NULL) m3_add_id(&ta->tg, &ta->n_tg, &ta->cap_tg, target->id);
  }
  m3_propagate(network, simulation, payment, net_params, target->id);
}
/* x から決め直し、確定が変わったノードがいれば、そのノードが告発した相手も決め直す (いつまでも揺れないように回数に上限) */
static void m3_propagate(struct network* network, struct simulation* simulation, struct payment* payment,
                         struct network_params net_params, long start) {
  static long* wl = NULL; static long wl_cap = 0;
  long wl_n = 0, steps = 0;
  if (wl_cap == 0) { wl_cap = 64; wl = malloc((size_t)wl_cap * sizeof(long)); }
  wl[wl_n++] = start;
  while (wl_n > 0) {
    long x = wl[--wl_n];
    if (++steps > 1000000) { fprintf(stderr, "[method3] 確定の決め直しが収束しない (打ち切り)\n"); break; }
    if (!m3_sync(network, simulation, payment, net_params, x)) continue;
    struct m3_target* tx = &m3_t[x];
    for (int k = 0; k < tx->n_tg; k++) {
      if (wl_n == wl_cap) { wl_cap *= 2; wl = realloc(wl, (size_t)wl_cap * sizeof(long)); }
      wl[wl_n++] = tx->tg[k];
    }
  }
}
/* 申し立ての決着。won = 1 なら申し立てた x の勝ち (それまでの告発を数えなくし、チャンネルを開け直す)。決め直しは呼ぶ側で */
static void m3_appeal_end(struct network* network, struct simulation* simulation, long x, int won) {
  struct m3_target* t = &m3_t[x];
  if (t->ap != 1) return;
  t->ap = 2; t->ap_won = won ? 1 : 2; t->ap_end = simulation->current_time;
  if (t->n_opps > 0) { for (int k = 0; k < t->n_opps; k++) m3_t[t->opps[k]].named--; }
  else if (t->ap_opp >= 0 && t->ap_opp < m3_nn) m3_t[t->ap_opp].named--;
  if (!won) return;
  t->void_from = t->n_ev;
  for (int k = 0; k < t->n_cl; k++) {
    struct edge* ed = (struct edge*)array_get(network->edges, t->cl_e[k]);
    if (ed == NULL) continue;
    struct edge* ce = (struct edge*)array_get(network->edges, ed->counter_edge_id);
    ed->is_closed = 0;
    if (ce != NULL) ce->is_closed = 0;
  }
}
/* 申し立ての相手 u を有罪にする: u を相手にした監視中の申し立ては全部申し立てた側の勝ち。u 自身はもう申し立てられない */
static void m3_convict(struct network* network, struct simulation* simulation, struct payment* payment,
                       struct network_params net_params, long u) {
  struct m3_target* tu = &m3_t[u];
  if (tu->ap == 1) m3_appeal_end(network, simulation, u, 0);
  tu->ap = 2; tu->guilty = 1;
  for (long i = 0; i < m3_nn && tu->named > 0; i++) {
    if (m3_t[i].ap != 1 || !m3_names(i, u)) continue;
    m3_appeal_end(network, simulation, i, 1);
    m3_propagate(network, simulation, payment, net_params, i);
  }
  m3_propagate(network, simulation, payment, net_params, u);
}
/* 申し立ての証拠: 位置 q の対象 y を正直な判定者 flg[0..nf-1] が異常と見た。
 * 監視中・有罪の上流の隣 w の分にしたら (y は告発しない) 1 を返す。 */
static int m3_appeal_evidence(struct network* network, struct simulation* simulation, struct payment* payment,
                              struct network_params net_params, int q, struct node* target, const long* flg, int nf) {
  long y = target->id;
  struct m3_target* ty = &m3_t[y];
  long w = -1, uw = -1;
  if (q >= 2) {   /* 上流の隣が中継のときだけ */
    struct route_hop* r1 = (struct route_hop*)array_get(payment->route->route_hops, q - 1);
    struct route_hop* r2 = (struct route_hop*)array_get(payment->route->route_hops, q - 2);
    if (r1 != NULL) w = r1->from_node_id;
    if (r2 != NULL) uw = r2->from_node_id;
  }
  int blame = 0, self = 0;
  if (w >= 0 && w < m3_nn) {
    struct m3_target* tw = &m3_t[w];
    if ((tw->ap == 1 || tw->named > 0 || tw->guilty) &&
        !(get_m3_appeal() == 2 && (ty->confirmed || ty->guilty))) blame = 1;
  }
  if (ty->ap == 1) { m3_appeal_end(network, simulation, y, 0); self = 1; }      /* 申し立てた本人に遅れ: 本人の負け */
  if (ty->named > 0) { m3_convict(network, simulation, payment, net_params, y); self = 1; }   /* 相手に遅れ: 相手の負け */
  if (blame) {
    struct m3_target* tw = &m3_t[w];
    struct node* wn = (struct node*)array_get(network->nodes, w);
    if (tw->ap == 1) m3_appeal_end(network, simulation, w, 0);
    if (tw->named > 0) m3_convict(network, simulation, payment, net_params, w);
    tw->blamed++;
    if (wn != NULL) m3_accuse_v2(network, simulation, payment, net_params, tw, wn, flg, nf, uw);
  }
  return blame && !self;
}
/* 割合で比べる (3) */
static int m3_watched(long v) { return v >= 0 && v < m3_nn && (m3_t[v].ap == 1 || m3_t[v].named > 0); }
static void m3_ratio_pair(struct network* network, struct simulation* simulation, struct payment* payment,
                          struct network_params net_params, long x, long u) {
  struct m3_target* tx = &m3_t[x];
  struct m3_target* tu = &m3_t[u];
  if (tx->ap != 1 || tx->ap_opp != u || tu->guilty) return;
  double m = (double)get_m3_appeal_prior_weight(), th = get_m3_appeal_prior_rate();
  long E = get_m3_appeal_min_evidence();
  double rx = ((double)tx->a_e + th * m) / ((double)tx->a_r + m);
  double ru = ((double)tu->a_e + th * m) / ((double)tu->a_r + m);
  if (rx > ru && tx->a_e >= E) {          /* 申し立てた側の負け */
    m3_appeal_end(network, simulation, x, 0);
    m3_propagate(network, simulation, payment, net_params, x);
  } else if (ru > rx * get_m3_appeal_opp_factor() && tu->a_e >= E) {   /* 相手の負け */
    m3_convict(network, simulation, payment, net_params, u);
  }
}
static void m3_ratio_appeal(struct network* network, struct simulation* simulation, struct payment* payment,
                            struct network_params net_params, long x) {
  struct m3_target* tx = &m3_t[x];
  if (tx->ap != 1 || tx->n_opps == 0) return;
  double m = (double)get_m3_appeal_prior_weight(), th = get_m3_appeal_prior_rate();
  long E = get_m3_appeal_min_evidence();
  double rx = ((double)tx->a_e + th * m) / ((double)tx->a_r + m);
  long ub = -1; double rb = -1.0;
  for (int k = 0; k < tx->n_opps; k++) {
    struct m3_target* tu = &m3_t[tx->opps[k]];
    double ru = ((double)tu->a_e + th * m) / ((double)tu->a_r + m);
    if (ru > rb) { rb = ru; ub = tx->opps[k]; }
  }
  if (ub < 0) return;
  if (rx > rb && tx->a_e >= E) {                       /* 申し立てた側の負け */
    m3_appeal_end(network, simulation, x, 0);
    m3_propagate(network, simulation, payment, net_params, x);
  } else if (rb > rx * get_m3_appeal_opp_factor() && m3_t[ub].a_e >= E) {           /* 一番疑わしい相手の負け */
    m3_convict(network, simulation, payment, net_params, ub);
  }
}
static void m3_ratio_check(struct network* network, struct simulation* simulation, struct payment* payment,
                           struct network_params net_params, long v) {
  if (v < 0 || v >= m3_nn) return;
  if (get_m3_appeal_all()) {
    if (m3_t[v].ap == 1) m3_ratio_appeal(network, simulation, payment, net_params, v);
    if (m3_t[v].named > 0 && m3_t[v].n_by > 0) {
      int n = m3_t[v].n_by;
      long* cp = malloc((size_t)n * sizeof(long));
      memcpy(cp, m3_t[v].by, (size_t)n * sizeof(long));
      for (int k = 0; k < n; k++) if (m3_t[cp[k]].ap == 1 && m3_names(cp[k], v)) m3_ratio_appeal(network, simulation, payment, net_params, cp[k]);
      free(cp);
    }
    return;
  }
  if (m3_t[v].ap == 1) m3_ratio_pair(network, simulation, payment, net_params, v, m3_t[v].ap_opp);
  if (m3_t[v].named > 0 && m3_t[v].n_by > 0) {
    int n = m3_t[v].n_by;
    long* cp = malloc((size_t)n * sizeof(long));
    memcpy(cp, m3_t[v].by, (size_t)n * sizeof(long));
    for (int k = 0; k < n; k++) m3_ratio_pair(network, simulation, payment, net_params, cp[k], v);
    free(cp);
  }
}
/* 位置 q の対象 y を正直な判定者 flg[0..nf-1] が異常と見た: 監視中なら証拠に数える。有罪の上流の隣の分にしたら 1 を返す */
static int m3_ratio_evidence(struct network* network, struct simulation* simulation, struct payment* payment,
                             struct network_params net_params, int q, struct node* target, const long* flg, int nf) {
  long y = target->id, w = -1, uw = -1;
  if (q >= 2) {   /* 上流の隣が中継のときだけ */
    struct route_hop* r1 = (struct route_hop*)array_get(payment->route->route_hops, q - 1);
    struct route_hop* r2 = (struct route_hop*)array_get(payment->route->route_hops, q - 2);
    if (r1 != NULL) w = r1->from_node_id;
    if (r2 != NULL) uw = r2->from_node_id;
  }
  if (w >= m3_nn) w = -1;
  if (m3_watched(y)) m3_t[y].a_e++;
  if (w >= 0 && m3_watched(w)) m3_t[w].a_e++;
  int blame = (w >= 0 && m3_t[w].guilty);
  if (blame) {
    struct node* wn = (struct node*)array_get(network->nodes, w);
    m3_t[w].blamed++;
    if (wn != NULL) m3_accuse_v2(network, simulation, payment, net_params, &m3_t[w], wn, flg, nf, uw);
  }
  m3_ratio_check(network, simulation, payment, net_params, y);
  if (w >= 0) m3_ratio_check(network, simulation, payment, net_params, w);
  if (get_m3_appeal_ev_down()) {   /* 2 つ以上上流の、監視中の中継の証拠にも数える */
    long seen[64]; int ns = 0;
    for (int k = 1; k + 1 < q && ns < 64; k++) {
      struct route_hop* rk = (struct route_hop*)array_get(payment->route->route_hops, k);
      long v = (rk != NULL) ? rk->from_node_id : -1;
      if (v < 0 || v >= m3_nn || v == y || v == w || !m3_watched(v)) continue;
      if (m3_t[v].a_last_pid == payment->id + 1) continue;
      m3_t[v].a_last_pid = payment->id + 1;
      m3_t[v].a_e++;
      seen[ns++] = v;
    }
    for (int k = 0; k < ns; k++) m3_ratio_check(network, simulation, payment, net_params, seen[k]);
  }
  return blame;
}
/* 受取人の保持を検定し、異常なら受取人のすぐ上流の中継を告発する (CLOTH_M3_RECEIVER_TEST) */

/* === method3 のハッシュチェーン (CLOTH_M3_HASHCHAIN、既定 1。0 で使わない = 10/22 昼までの既定) ===
 * preimage を返すとき、各ノード (中継と受取人) は自分の記録 (受け取った時刻・上流へ渡した時刻。受取人は HTLC が届いた時刻も) と
 * 下流から届いた印をまとめて、送金者と自分だけが知る鍵で HMAC-SHA256 の印を付ける (鍵は送金・試行・位置・ノードごと)。
 * 送金者は最後に全部の印を確かめる。途中のノードが下流の記録を書き換えると、書き換えられた記録の印が合わなくなる。
 * 送金者に一番近い側で印が合わない位置を j とすると、j より下流の記録 (j-1 の保持の検定も j の記録を使う) は検定に使わず、
 * ペア (j-1, j) を判定ノードに知らせる (j-1 が送金者なら j だけ)。印からはペアのどちらかまでしか分からない。
 * 判定ノードはそのペアを監視し、以後その 2 人が中継する決済では、2 人それぞれの保持を判定ノードの時計で測る
 * (判定ノード経由の受け渡し、CLOTH_JUDGE_COPY と同じ作り: 保持 = 本人の写しの時刻 − 本人の受領書の時刻。どちらも本人の
 *  ものなので、相手の数字は動かせない。攻撃者は受領書を遅らせる手と写しを先に送る手で、それぞれ T まで隠す。T = CLOTH_JUDGE_COPY_T_MS)。
 * 測った保持は、経路の上流の正直な判定者が自分の基準値 (warmup で学んだもの。監視中の値では学び直さない) で検定する。
 * 異常が出たノードをそのペアの犯人として普段どおり告発し、相手は監視から外す。犯人は監視を続ける。決まらないペアは監視を続ける。
 * 判定ノード (CLOTH_M3_HASHCHAIN_JUDGES 個、既定 10) は受け持ちを数えるだけで、判定ノードまでの遅れは 0 とみなす。
 * 鍵は乱数を使わずに作る (ほかの乱数の列を変えない)。印を付ける・確かめる時間は実際に測って出力する。 */
static int get_m3_hashchain(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_HASHCHAIN");
  v = (e != NULL && e[0] != '\0') ? (strcmp(e, "0") != 0) : 1;
  if (v && !m3_hmac_selftest()) { fprintf(stderr, "ERROR: HMAC-SHA256 の自己テスト (FIPS 180・RFC 4231) が合わない\n"); exit(1); }
  return v;
}
static int get_m3_hc_judges(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_HASHCHAIN_JUDGES");
  v = 10; if (e != NULL && e[0] != '\0') { int t = atoi(e); if (t >= 1) v = t; }
  return v;
}
/* 送金者が印を確かめる時間 (1 ホップあたり ms、既定 0)。0 より大きいと、確かめてから検定・告発するまでを t × ホップ数 遅らせる
 * (送金の完了は遅らせない) */
static double get_m3_hc_verify_ms(void) {
  static double v = -1.0;
  if (v >= 0.0) return v;
  const char* e = getenv("CLOTH_M3_HASHCHAIN_VERIFY_MS");
  v = 0.0; if (e != NULL && e[0] != '\0') { double t = atof(e); if (t > 0.0) v = t; }
  return v;
}
/* 印に鍵を使うか (CLOTH_M3_HASHCHAIN_KEYED、既定 1)。0 = 鍵なし (対照用): 印は SHA-256 (記録と下流の印) で、だれでも計算できる。
 * 記録を書き換えた攻撃者は、書き換えた位置の印を下流から順に作り直すので、送金者が確かめても全部合う。
 * 対照 (10/26、金額 100・p 0.001・3 シード、n=12800、防御なしに対する遅延の変化): 書き換え すぐ隣 −79.8% → −37.9%、
 * 下流のどこか −79.8% → −43.8%、罰を受けた正直 0 → 408 / 318。書き換えのない条件は鍵つきと出力が同じ */
static int get_m3_hc_keyed(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_HASHCHAIN_KEYED");
  return (v = (e != NULL && e[0] != '\0') ? (strcmp(e, "0") != 0) : 1);
}
static long m3_hc_forged = 0;   /* 鍵なしで攻撃者が作り直した印の数 */
static long m3_hc_deferred = 0;   /* 遅らせて検定した決済 */
static long m3_hc_tag_n = 0, m3_hc_ver_n = 0;            /* 付けた印・確かめた印の数 */
static double m3_hc_tag_ns = 0.0, m3_hc_ver_ns = 0.0;    /* そのためにかかった時間 (実際の計算) */
static long m3_hc_checked = 0, m3_hc_fail = 0, m3_hc_fail_match = 0, m3_hc_fail_explained = 0;
static long m3_hc_meas = 0, m3_hc_meas_att = 0, m3_hc_cmp = 0, m3_hc_same = 0;
static double m3_hc_hidden = 0.0, m3_hc_extra = 0.0;
struct m3_hc_pair { long a, b; int judge; uint64_t t0, t1; long fails; int resolved; long culprit; };
static struct m3_hc_pair* m3_hc_pairs = NULL;
static long m3_hc_np = 0, m3_hc_pcap = 0, m3_hc_nn = 0;
static int* m3_hc_mon = NULL;     /* ノードごと: 決まっていない監視中のペアの数 */
static char* m3_hc_culp = NULL;   /* ノードごと: 監視で犯人と決まった */
static int* m3_hc_jof = NULL;     /* ノードごと: 受け持つ判定ノード */
static uint64_t* m3_hc_since = NULL;   /* ノードごと: 監視を始めた時刻 (これより後の受け渡しだけ判定ノードが測れる) */
static long* m3_hc_load = NULL;   /* 判定ノードごと: 測った回数 */
static void m3_hc_init(struct network* network) {
  if (m3_hc_mon != NULL) return;
  m3_hc_nn = array_len(network->nodes);
  m3_hc_mon = calloc((size_t)m3_hc_nn, sizeof(int));
  m3_hc_culp = calloc((size_t)m3_hc_nn, sizeof(char));
  m3_hc_jof = calloc((size_t)m3_hc_nn, sizeof(int));
  m3_hc_since = calloc((size_t)m3_hc_nn, sizeof(uint64_t));
  m3_hc_load = calloc((size_t)get_m3_hc_judges(), sizeof(long));
}
/* 監視で犯人と決まったノードの扱い (CLOTH_M3_HASHCHAIN_CULPRIT): 0 = 監視を続ける (10/22 夕方の既定)、
 * 1 = 罰を受けている (確定している) 間は監視しない (申し立て中などで罰が止まると監視に戻る)、2 = もう監視しない
 * (申し立てで罰が止まったまま証拠がたまらず、罰を受けなくなる)、3 = 申し立てられず監視もしない (既定) */
static long m3_hc_judge_target = -1;   /* いま判定ノードの測定で検定しているノード */
static int get_m3_hc_culprit(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_HASHCHAIN_CULPRIT");
  v = 3; if (e != NULL && e[0] != '\0') { int t = atoi(e); if (t >= 0 && t <= 3) v = t; }
  return v;
}
/* 3 = 判定ノードの測定で決まった犯人は申し立てられず (申し立て中なら負け)、監視もしない。
 * 判定ノードの時計で測った保持は本人のものなので、冤罪の申し立ても、異常を上流の隣の証拠に付け替える処理も要らない。
 * 犯人がまた書き換えて印が合わなくなったら、正直な送金者が犯人を告発する (m3_hc_flag。報告が重ならないと評判が下がらないため) */
static int m3_hc_no_appeal(long x) {
  if (!get_m3_hashchain() || get_m3_hc_culprit() != 3 || m3_hc_culp == NULL || x < 0 || x >= m3_hc_nn) return 0;
  return m3_hc_culp[x] || x == m3_hc_judge_target;
}
static int m3_hc_culp_watched(long v) {
  if (!m3_hc_culp[v]) return 0;
  int mode = get_m3_hc_culprit();
  if (mode == 0) return 1;
  if (mode >= 2) return 0;
  return !(m3_t != NULL && v < m3_nn && m3_t[v].confirmed);
}
static int m3_hc_monitored(long v) {
  return m3_hc_mon != NULL && v >= 0 && v < m3_hc_nn && (m3_hc_mon[v] > 0 || m3_hc_culp_watched(v));
}
/* 位置 q の受け渡しを判定ノードが見ていたか: 監視中で、本人が受け取ったのが監視を始めたあと */
static int m3_hc_watched_here(struct payment* pm, int q, int nh, long v) {
  if (!m3_hc_monitored(v) || pm->m3_true_recv == NULL || q >= pm->m3_hc_cap) return 0;
  uint64_t t_in = (q < nh) ? pm->m3_true_recv[q] : pm->m3_rcv_arrive;
  return t_in != 0 && t_in >= m3_hc_since[v];
}
static long m3_hc_node_at(struct payment* pm, int pos, int nh) {   /* 位置 pos のノード (0 = 送金者、nh = 受取人) */
  if (pos == nh) return pm->receiver;
  struct route_hop* rh = (struct route_hop*)array_get(pm->route->route_hops, pos);
  return (rh != NULL) ? rh->from_node_id : -1;
}
static double m3_hc_ns(struct timespec a, struct timespec b) {
  return (double)(b.tv_sec - a.tv_sec) * 1e9 + (double)(b.tv_nsec - a.tv_nsec);
}
static void m3_hc_put(uint8_t* buf, size_t* n, uint64_t v, int bytes) {
  for (int k = bytes - 1; k >= 0; k--) buf[(*n)++] = (uint8_t)(v >> (8 * k));
}
/* 送金者と位置 pos のノードだけが知る鍵 (本物の LN ではオニオンの鍵共有で作る。ここでは送金・試行・位置・ノードから SHA-256 で作る) */
static void m3_hc_key(const struct payment* pm, int pos, long node_id, uint8_t key[32]) {
  static const char lbl[] = "CLoTH-Gossip method3 hashchain";
  uint8_t buf[64]; size_t n = 0;
  memcpy(buf, lbl, sizeof lbl - 1); n = sizeof lbl - 1;
  m3_hc_put(buf, &n, (uint64_t)pm->id, 8); m3_hc_put(buf, &n, (uint64_t)pm->attempts, 4);
  m3_hc_put(buf, &n, (uint64_t)pos, 4); m3_hc_put(buf, &n, (uint64_t)node_id, 8);
  m3_sha256(buf, n, key);
}
/* 位置 pos の印 = HMAC(鍵, 送金・試行・位置・ノード・受け取った時刻・渡した時刻・HTLC が届いた時刻 (受取人)・下流の印) */
static void m3_hc_mac(const struct payment* pm, int pos, int nh, long node_id, uint8_t out[32]) {
  uint8_t key[32], msg[96]; size_t n = 0;
  static const uint8_t zero[32] = {0};
  m3_hc_key(pm, pos, node_id, key);
  m3_hc_put(msg, &n, (uint64_t)pm->id, 8); m3_hc_put(msg, &n, (uint64_t)pm->attempts, 4);
  m3_hc_put(msg, &n, (uint64_t)pos, 4); m3_hc_put(msg, &n, (uint64_t)node_id, 8);
  m3_hc_put(msg, &n, (pos < nh) ? pm->hop_settle_recv_times[pos] : 0, 8);
  m3_hc_put(msg, &n, pm->hop_settle_send_times[pos], 8);
  m3_hc_put(msg, &n, (pos == nh) ? pm->m3_rcv_arrive : 0, 8);
  memcpy(msg + n, (pos < nh) ? pm->m3_tags + 32 * (pos + 1) : zero, 32); n += 32;
  if (get_m3_hc_keyed()) m3_hmac_sha256(key, 32, msg, n, out);
  else m3_sha256(msg, n, out);
}
/* 位置 pos のノードが自分の記録に印を付ける (自分の記録を書いたあと・下流の印が届いたあと) */
static void m3_hc_sign(struct payment* pm, int pos, long node_id) {
  if (pm->m3_tags == NULL || pm->route == NULL) return;
  int nh = array_len(pm->route->route_hops);
  if (pos < 1 || pos > nh || nh >= pm->m3_hc_cap || nh > pm->hop_settle_recv_capacity) return;
  struct timespec a, b;
  clock_gettime(CLOCK_MONOTONIC, &a);
  m3_hc_mac(pm, pos, nh, node_id, pm->m3_tags + 32 * pos);
  clock_gettime(CLOCK_MONOTONIC, &b);
  m3_hc_tag_ns += m3_hc_ns(a, b); m3_hc_tag_n++;
}
/* 送金者が全部の印を確かめる。送金者に一番近い側で合わなかった位置を返す (全部合えば 0) */
static int m3_hc_verify(struct payment* pm, int nh) {
  int j = 0;
  for (int p = nh; p >= 1; p--) {
    uint8_t exp[32];
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    m3_hc_mac(pm, p, nh, m3_hc_node_at(pm, p, nh), exp);
    clock_gettime(CLOCK_MONOTONIC, &b);
    m3_hc_ver_ns += m3_hc_ns(a, b); m3_hc_ver_n++;
    if (memcmp(exp, pm->m3_tags + 32 * p, 32) != 0) j = p;
  }
  return j;
}
/* 印が位置 j で合わなかった: ペア (j-1, j) を判定ノードに知らせる。すでに監視で犯人と決まったノードを含むなら説明済み */
static long m3_hc_reaccuse = 0;   /* 犯人がまた書き換え、送金者が告発した回数 (CLOTH_M3_HASHCHAIN_CULPRIT=3) */
static void m3_hc_add_pair(struct simulation* simulation, long a, long b);
static void m3_hc_flag(struct network* network, struct simulation* simulation, struct payment* pm,
                       struct network_params net_params, int j, int nh) {
  m3_hc_init(network);
  long b = m3_hc_node_at(pm, j, nh);
  long a = (j - 1 >= 1) ? m3_hc_node_at(pm, j - 1, nh) : -1;   /* j-1 が送金者なら j だけ */
  if (b < 0 || b >= m3_hc_nn || a >= m3_hc_nn) return;
  if ((a >= 0 && m3_hc_culp[a]) || m3_hc_culp[b]) {
    m3_hc_fail_explained++;
    if (get_m3_hc_culprit() == 3) {   /* 犯人がまた書き換えた: 判定ノードを使わず、送金者が犯人を告発する (正直な送金者だけ) */
      long cv = (a >= 0 && m3_hc_culp[a]) ? a : b;
      int pc = (cv == a) ? j - 1 : j;
      struct node* sn = (struct node*)array_get(network->nodes, pm->sender);
      struct node* cn = (struct node*)array_get(network->nodes, cv);
      struct m3_target* ct = m3_target_of(network, cv);
      if (sn != NULL && !sn->is_malicious && cn != NULL && ct != NULL) {
        long acc = pm->sender;
        long up = (pc >= 1) ? m3_hc_node_at(pm, pc - 1, nh) : -1;
        m3_accuse_v2(network, simulation, pm, net_params, ct, cn, &acc, 1, up);
        m3_hc_reaccuse++;
      }
    }
    return;
  }
  m3_hc_add_pair(simulation, a, b);
}
/* ペア (a, b) を判定ノードの監視に回す (a = -1 なら b だけ)。同じペアがまだ決まっていなければ回数を数えるだけ */
static void m3_hc_add_pair(struct simulation* simulation, long a, long b) {
  for (long k = 0; k < m3_hc_np; k++) {
    struct m3_hc_pair* q = &m3_hc_pairs[k];
    if (!q->resolved && q->a == a && q->b == b) { q->fails++; return; }
  }
  if (m3_hc_np == m3_hc_pcap) {
    m3_hc_pcap = m3_hc_pcap ? 2 * m3_hc_pcap : 256;
    m3_hc_pairs = realloc(m3_hc_pairs, (size_t)m3_hc_pcap * sizeof(struct m3_hc_pair));
  }
  struct m3_hc_pair* q = &m3_hc_pairs[m3_hc_np];
  q->a = a; q->b = b; q->judge = (int)(m3_hc_np % get_m3_hc_judges());
  q->t0 = simulation->current_time; q->t1 = 0; q->fails = 1; q->resolved = 0; q->culprit = -1;
  m3_hc_np++;
  if (a >= 0) { if (!m3_hc_monitored(a)) m3_hc_since[a] = q->t0; m3_hc_mon[a]++; m3_hc_jof[a] = q->judge; }
  if (!m3_hc_monitored(b)) m3_hc_since[b] = q->t0;
  m3_hc_mon[b]++; m3_hc_jof[b] = q->judge;
}
/* 監視で v に異常が出た: v を含む決まっていないペアの犯人を v にし、相手を監視から外す。v は監視を続ける */
static void m3_hc_resolve(long v, uint64_t now) {
  if (v < 0 || v >= m3_hc_nn) return;
  m3_hc_culp[v] = 1;
  for (long k = 0; k < m3_hc_np; k++) {
    struct m3_hc_pair* q = &m3_hc_pairs[k];
    if (q->resolved || (q->a != v && q->b != v)) continue;
    q->resolved = 1; q->culprit = v; q->t1 = now;
    if (q->a >= 0) m3_hc_mon[q->a]--;
    m3_hc_mon[q->b]--;
  }
}
/* === 告発の照らし合わせ (CLOTH_M3_ACCUSE_CHECK、既定 1。0 で照らし合わせない。ハッシュチェーンを使うときだけ) ===
 * 告発は「この送金で位置 q のノードの保持が異常だった」という主張なので、その送金の送金者が、印を確かめた記録で
 * 位置 q の保持 (両隣の記録から: recv[q-1] − send[q+1]) を計算し直す。送金者がこれまで確かめた全部のホップの保持で学んだ
 * まとめた基準値に対して z が CLOTH_M3_ACCUSE_CHECK_Z (既定 1.0) より小さい (はっきり正常) なら、告発は記録と食い違う。
 * 1 = 食い違う告発は捨てる、2 = 捨てたうえで、告発した本人を送金者が告発し返す。正直な判定者の告発にも同じ決まりを当てる。
 * 照らし合わせるのは正直な送金者だけ。印が合わない記録を使う告発と、判定ノードの測定の告発は照らし合わせない */
static int get_m3_xcheck(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_ACCUSE_CHECK");
  v = 1; if (e != NULL && e[0] != '\0') { int t = atoi(e); if (t >= 0 && t <= 2) v = t; }
  return v;
}
static double get_m3_xcheck_z(void) {
  static double v = -1e9;
  if (v > -1e8) return v;
  const char* e = getenv("CLOTH_M3_ACCUSE_CHECK_Z");
  v = 1.0; if (e != NULL && e[0] != '\0') v = atof(e);
  return v;
}
static int m3_xc_on = 0, m3_xc_fail = 0;   /* この送金で照らし合わせるか・印が合わない位置 */
static long m3_xc_checked = 0, m3_xc_ref_obs = 0, m3_xc_ref_obs_mal = 0, m3_xc_ref_false = 0, m3_xc_counter = 0;
static long m3_xc_skip_fail = 0, m3_xc_skip_sender = 0, m3_xc_skip_rec = 0;   /* 照らし合わせられなかった: 印が合わない・送金者が悪意・記録がない */
static int m3_xc_refutes(struct network* network, struct payment* pm, int q, int nh, double avg_iv) {
  if (!m3_xc_on || q < 1 || q > nh) return 0;
  if (m3_xc_fail > 0 && (q == nh ? q : q + 1) >= m3_xc_fail) { m3_xc_skip_fail++; return 0; }   /* 印が合わない記録は使えない */
  struct node* sn = (struct node*)array_get(network->nodes, pm->sender);
  if (sn == NULL || sn->is_malicious) { m3_xc_skip_sender++; return 0; }   /* 照らし合わせるのは正直な送金者だけ */
  if (pm->hop_settle_send_times == NULL || nh > pm->hop_settle_recv_capacity) { m3_xc_skip_rec++; return 0; }
  /* 中継は両隣の記録から (recv[q-1] − send[q+1])、受取人は本人の記録から (preimage を返した時刻 − HTLC が届いた時刻) */
  uint64_t ru = (q < nh) ? pm->hop_settle_recv_times[q - 1] : pm->hop_settle_send_times[nh];
  uint64_t sb = (q < nh) ? pm->hop_settle_send_times[q + 1] : pm->m3_rcv_arrive;
  if (ru == 0 || sb == 0) { m3_xc_skip_rec++; return 0; }
  m3_xc_checked++;
  if (ru <= sb) return 1;   /* 記録の上では保持がない */
  hold_set_sample_var(0.0);
  on_hold_hypothesis_test_nolearn(m3_shadow_pool(pm->sender), (double)(ru - sb), 0, avg_iv, nh);
  return hold_last_z() < get_m3_xcheck_z();
}
/* 記録と食い違う告発をしたノード acc を、送金者が告発し返す */
static void m3_xc_counter_accuse(struct network* network, struct simulation* simulation, struct payment* pm,
                                 struct network_params net_params, long acc, int nh) {
  struct node* an = (struct node*)array_get(network->nodes, acc);
  struct m3_target* at = m3_target_of(network, acc);
  if (an == NULL || at == NULL || acc == pm->sender) return;
  long up = -1;
  for (int p = 1; p <= nh; p++) if (m3_hc_node_at(pm, p, nh) == acc) { up = m3_hc_node_at(pm, p - 1, nh); break; }
  long s = pm->sender;
  m3_accuse_v2(network, simulation, pm, net_params, at, an, &s, 1, up);
  m3_xc_counter++;
}
/* === 送金者だけの告発 (CLOTH_M3_SENDER_ONLY、既定 1 (10/26 から)。0 で使わない。ハッシュチェーンを使うときだけ) ===
 * その決済で対象を異常と見た正直な判定者が送金者 1 人だけなら、送金者の記録を照らし合わせられる人がいない。
 * 1 = 対象が送金者のすぐ隣 (位置 1) なら (送金者, 対象) をペアとして判定ノードの監視に回し、いまは告発しない。
 *     位置 2 以降なら、間の中継が誰も異常と見ていないので嘘の告発とみなして捨てる。
 * 2 = 位置 2 以降も捨てずに、(送金者, 対象) をペアとして判定ノードの監視に回す。
 * 判定ノードの測定の検定 (m3_hc_judge_target) と、判定ノードの測定で犯人と決まったノードへの告発には当てない (そのまま告発する)。
 * 判定ノードの測定で犯人と決まった送金者の告発は捨てる
 * 既定を 1 にした理由 (金額 100・p 0.001・3 シード、n=12800、申し立てなしと一緒に): 悪意の送金者による嘘の告発
 * (CLOTH_M3_SENDER_FALSE_ACCUSE) で -72.7% (罰を受けた正直 125) → -80.8% (0)。全条件・全 n で罰を受けた正直は 0。
 * 嘘なしは -81.5% → -80.7% と少し小さくなるが、検出率 (終わった時点) は 49.7% → 93.4%・誤検知 2 → 0。
 * 2 は 1 とほぼ同じで判定ノードの測定が多い。CLOTH_M3_SENDER_ONLY=0 と CLOTH_M3_APPEAL=3 で 4354a0f と同じ */
static int get_m3_sender_only(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_SENDER_ONLY");
  v = 1; if (e != NULL && e[0] != '\0') { int t = atoi(e); if (t >= 0 && t <= 2) v = t; }
  return v;
}
static long m3_so_pair = 0, m3_so_pair_true = 0, m3_so_disc = 0, m3_so_disc_true = 0, m3_so_disc_culp = 0;   /* 正直な判定者の告発: ペアに回した (本当に保持していた)・捨てた (本当に保持していた)・犯人の送金者の告発を捨てた */
static long m3_so_lie_pair = 0, m3_so_lie_disc = 0;   /* 悪意の送金者の嘘の告発: ペアに回した・捨てた */
/* 戻り値 1 = この告発は扱った (ペアに回したか捨てた)。is_lie は数えるのを分けるだけ */
static int m3_so_rule(struct network* network, struct simulation* simulation, struct payment* pm, int q, long target,
                      const long* acc, int n, int is_lie) {
  if (!get_m3_sender_only() || !get_m3_hashchain() || n != 1 || acc[0] != pm->sender || q < 1) return 0;
  if (target == m3_hc_judge_target) return 0;
  m3_hc_init(network);
  if (target < 0 || target >= m3_hc_nn || pm->sender < 0 || pm->sender >= m3_hc_nn) return 0;
  if (m3_hc_culp[target]) return 0;   /* 判定ノードの測定で決まった犯人への告発はそのまま */
  if (m3_hc_culp[pm->sender]) { m3_so_disc_culp++; return 1; }
  int held = (target == pm->grief_hold_node_id && pm->grief_hold_extra_ms > 0);
  if (q == 1 || get_m3_sender_only() == 2) {
    m3_hc_add_pair(simulation, pm->sender, target);
    if (is_lie) m3_so_lie_pair++; else { m3_so_pair++; m3_so_pair_true += held; }
  } else {
    if (is_lie) m3_so_lie_disc++; else { m3_so_disc++; m3_so_disc_true += held; }
  }
  return 1;
}
/* 判定ノードの時計で測った位置 q の保持 (本人の写しの時刻 − 本人の受領書の時刻)。判定ノードまでの遅れ 0 では本当の時刻になり、
 * ずれるのは本人の手口の分だけ: その決済の保持者 (悪意) は受領書を遅らせて min(足した遅れ, T)、残りを写しを先に送って
 * min(残り, T) 隠す (判定ノードが受け渡しを代わりにする前に)。戻り値 <= 0 は測れない */
static double m3_hc_judge_hold(struct network* network, struct payment* pm, int q, int nh, struct jc_eval* ev) {
  ev->hidden_in = ev->hidden_out = 0.0; ev->delivered = 0;
  if (q < 1 || q > nh || pm->m3_true_send == NULL || q >= pm->m3_hc_cap) return 0.0;
  uint64_t t_in = (q < nh) ? pm->m3_true_recv[q] : pm->m3_rcv_arrive;
  uint64_t t_out = pm->m3_true_send[q];
  if (t_in == 0 || t_out <= t_in) return 0.0;
  long id = m3_hc_node_at(pm, q, nh);
  struct node* nd = (id >= 0) ? (struct node*)array_get(network->nodes, id) : NULL;
  if (nd != NULL && nd->is_malicious && id == pm->grief_hold_node_id && pm->grief_hold_extra_ms > 0) {
    double T = get_judge_copy_t_ms(), x = (double)pm->grief_hold_extra_ms;
    ev->hidden_in = (x < T) ? x : T;
    ev->delivered = (x > T);
    double r = x - ev->hidden_in;
    ev->hidden_out = (r < T) ? r : T;
  }
  return (double)(t_out - t_in) - ev->hidden_in - ev->hidden_out;
}
static void method3_receiver_test(struct network* network, struct simulation* simulation, struct payment* payment,
                                  struct network_params net_params, int nh, double avg_iv, double lat_judge) {
  if (nh < 2 || payment->m3_rcv_arrive == 0 || payment->hop_settle_send_times == NULL) return;
  if (nh > payment->hop_settle_recv_capacity) return;
  uint64_t sb = payment->hop_settle_send_times[nh];   /* 受取人が preimage を返したと記録された時刻 */
  if (sb == 0 || sb <= payment->m3_rcv_arrive) return;
  double lat = (lat_judge > 0.0) ? lat_judge : (double)(sb - payment->m3_rcv_arrive);   /* 監視中の受取人は判定ノードの時計で測った値 */
  struct node* rcv = (struct node*)array_get(network->nodes, payment->receiver);
  struct route_hop* rl = (struct route_hop*)array_get(payment->route->route_hops, nh - 1);
  if (rcv == NULL || rl == NULL) return;
  long last = rl->from_node_id;   /* 受取人のすぐ上流の中継 */
  if (last == payment->sender || last < 0 || last >= m3_nn) return;
  int warm = detector_in_warmup(payment, (long)simulation->processed_payments);
  long flg[nh]; int nf = 0, tested = 0;
  for (int u = 0; u < nh; u++) {
    struct route_hop* rh = (struct route_hop*)array_get(payment->route->route_hops, u);
    if (rh == NULL) continue;
    struct node* obs = (struct node*)array_get(network->nodes, rh->from_node_id);
    if (obs == NULL || obs->is_malicious || obs->id == last) continue;
    struct node* sh = m3_shadow_rcv(obs->id, rcv);
    hold_set_sample_var(0.0);
    int r = on_hold_hypothesis_test(sh, lat, warm, avg_iv, nh);
    if (!warm) tested = 1;
    if (r) flg[nf++] = obs->id;
  }
  if (tested) m3_rcv_tests++;
  if (nf == 0) return;
  m3_rcv_anom++;
  if (!warm && m3_so_rule(network, simulation, payment, nh - 1, last, flg, nf, 0)) return;   /* 送金者だけの告発 */
  struct node* ln = (struct node*)array_get(network->nodes, last);
  struct m3_target* t = m3_target_of(network, last);
  if (ln == NULL || t == NULL) return;
  long up = -1;
  if (nh >= 2) { struct route_hop* r2 = (struct route_hop*)array_get(payment->route->route_hops, nh - 2); if (r2 != NULL) up = r2->from_node_id; }
  if (get_m3_appeal() == 3 && m3_watched(last)) m3_t[last].a_e++;   /* 監視中なら本人の証拠に */
  if (get_m3_rcv_watch()) {   /* すぐ罰せず、受取人の異常が出た割合が高くなってから告発する */
    double m = (double)get_m3_appeal_prior_weight(), th = get_m3_appeal_prior_rate();
    t->rv_e++;
    double rho = ((double)t->rv_e + th * m) / ((double)t->rv_r + m);
    if (t->rv_e < get_m3_rcv_watch_min() || rho < get_m3_rcv_watch_rate()) {
      m3_rcv_held++;
      if (get_m3_appeal() == 3) m3_ratio_check(network, simulation, payment, net_params, last);
      return;
    }
  }
  if (get_m3_distrust() == 2) {
    m3_accuse_v2(network, simulation, payment, net_params, t, ln, flg, nf, up);
  } else {
    for (int k = 0; k < nf; k++) m3_add_accuser(t, flg[k]);
    m3_accuse_event(network, simulation, payment, net_params, t, ln, flg[0]);
  }
  if (get_m3_appeal() == 3) m3_ratio_check(network, simulation, payment, net_params, last);
}
/* 嘘のパターン: この決済の保持者が、自分に preimage を渡した下流の隣を告発する (warmup 後に実際に遅れを足したときだけ)。 */
static void method3_false_accuse(struct network* network, struct simulation* simulation, struct payment* payment,
                                 struct network_params net_params) {
  if (!get_m3_false_accuse() || payment->grief_hold_node_id < 0 || payment->grief_hold_extra_ms == 0) return;
  if (detector_in_warmup(payment, (long)simulation->processed_payments)) return;
  int nh = array_len(payment->route->route_hops);
  for (int a = 1; a < nh; a++) {
    struct route_hop* rh = (struct route_hop*)array_get(payment->route->route_hops, a);
    if (rh == NULL || rh->from_node_id != payment->grief_hold_node_id) continue;
    struct node* att = (struct node*)array_get(network->nodes, rh->from_node_id);
    struct node* prev = (struct node*)array_get(network->nodes, rh->to_node_id);   /* preimage を渡してきた隣 */
    if (att == NULL || !att->is_malicious || prev == NULL) return;
    struct m3_target* t = m3_target_of(network, prev->id);
    if (t == NULL) return;
    t->false_accusations++;
    if (m3_xc_refutes(network, payment, a + 1, nh, (double)net_params.average_payment_forward_interval)) {   /* 照らし合わせ: 記録と食い違う */
      m3_xc_ref_false++;
      if (get_m3_xcheck() == 2) m3_xc_counter_accuse(network, simulation, payment, net_params, att->id, nh);
      return;
    }
    int lv = get_m3_distrust();
    if (lv == 2) {
      long a1 = att->id;
      m3_accuse_v2(network, simulation, payment, net_params, t, prev, &a1, 1, att->id);
      return;
    }
    if (lv == 1 && !m3_counts(att->id)) { t->ignored++; return; }   /* 確定した嘘つきの告発は数えない */
    m3_add_accuser(t, att->id);
    m3_accuse_event(network, simulation, payment, net_params, t, prev, att->id);
    return;
  }
}
/* 嘘のパターン (悪意の送金者, CLOTH_M3_SENDER_FALSE_ACCUSE=1, 既定 0。CLOTH_MAL_SENDER_SEND=1 のときだけ効く):
 * 悪意の送金者が、warmup 後に成功した自分の送金のうち割合 CLOTH_M3_SENDER_FALSE_ACCUSE_RATE (既定 0.5) で、
 * 経路上の正直な中継 1 人 (仲間の悪意ノードは選ばない・受取人は選ばない) を「保持が異常だった」と告発する。時刻の記録は正直に書く。
 * 嘘をつく送金と告発する中継は、決済 ID と送金者の ID のハッシュで選ぶ (乱数は使わない)。
 * 照らし合わせは送金者がするので、この嘘は照らし合わせられない (m3_xc_refutes は悪意の送金者では照らし合わせない)。 */
static int get_m3_sender_false_accuse(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_M3_SENDER_FALSE_ACCUSE");
  return (v = (e != NULL && e[0] != '\0' && strcmp(e, "0") != 0) ? 1 : 0);
}
static double get_m3_sender_false_accuse_rate(void) {
  static double v = -1.0;
  if (v >= 0.0) return v;
  const char* e = getenv("CLOTH_M3_SENDER_FALSE_ACCUSE_RATE");
  v = 0.5;
  if (e != NULL && e[0] != '\0') { double t = atof(e); if (t >= 0.0 && t <= 1.0) v = t; }
  return v;
}
static long m3_sfa_payments = 0, m3_sfa_lies = 0, m3_sfa_counted = 0, m3_sfa_nocand = 0;   /* 悪意の送金者の成功した送金 (warmup 後)・嘘の告発・そのとき送金者が確定していなかった・告発できる中継がいない */
static void method3_sender_false_accuse(struct network* network, struct simulation* simulation, struct payment* payment,
                                        struct network_params net_params) {
  if (!get_m3_sender_false_accuse() || !get_mal_sender_send()) return;
  struct node* sn = (struct node*)array_get(network->nodes, payment->sender);
  if (sn == NULL || !sn->is_malicious) return;
  if (detector_in_warmup(payment, (long)simulation->processed_payments)) return;
  m3_sfa_payments++;
  uint64_t h = m3_hash(((uint64_t)payment->id << 20) ^ (uint64_t)(payment->sender + 1) ^ 0x5E4DE2FA15EULL);
  if ((double)(h >> 11) * 0x1.0p-53 >= get_m3_sender_false_accuse_rate()) return;
  int nh = array_len(payment->route->route_hops);
  int cand[nh > 0 ? nh : 1], nc = 0;
  for (int q = 1; q < nh; q++) {
    long id = m3_hc_node_at(payment, q, nh);
    struct node* nd = (id >= 0) ? (struct node*)array_get(network->nodes, id) : NULL;
    if (nd != NULL && !nd->is_malicious) cand[nc++] = q;
  }
  if (nc == 0) { m3_sfa_nocand++; return; }
  int q = cand[m3_hash(h) % (uint64_t)nc];
  struct node* tn = (struct node*)array_get(network->nodes, m3_hc_node_at(payment, q, nh));
  struct m3_target* t = (tn != NULL) ? m3_target_of(network, tn->id) : NULL;
  if (t == NULL) return;
  t->false_accusations++;
  m3_sfa_lies++;
  if (m3_counts(sn->id)) m3_sfa_counted++;
  long up = m3_hc_node_at(payment, q - 1, nh);   /* 申し立ての相手になる上流の隣 (q = 1 なら送金者本人) */
  if (m3_xc_refutes(network, payment, q, nh, (double)net_params.average_payment_forward_interval)) {   /* 悪意の送金者なので食い違いは出ない */
    m3_xc_ref_false++;
    if (get_m3_xcheck() == 2) m3_xc_counter_accuse(network, simulation, payment, net_params, sn->id, nh);
    return;
  }
  {   /* 送金者だけの告発 (同じ決済で正直な判定者も対象を告発していれば当てない) */
    struct m3_ev* ev = (t->n_ev > 0 && t->ev[t->n_ev - 1].pid == payment->id) ? &t->ev[t->n_ev - 1] : NULL;
    long a0 = sn->id;
    if (!(ev != NULL && ev->n_acc > 0) && m3_so_rule(network, simulation, payment, q, tn->id, &a0, 1, 1)) return;
  }
  int lv = get_m3_distrust();
  if (lv == 2) {
    long a1 = sn->id;
    m3_accuse_v2(network, simulation, payment, net_params, t, tn, &a1, 1, up);
    return;
  }
  if (lv == 1 && !m3_counts(sn->id)) { t->ignored++; return; }   /* 確定した嘘つきの告発は数えない */
  m3_add_accuser(t, sn->id);
  m3_accuse_event(network, simulation, payment, net_params, t, tn, sn->id);
}
/* 絞り込み: 位置 q の対象を正直な判定者 flg[] が異常と見た。q より上流の中継の「下流で異常が出た決済」を数え、
 * 割合がしきい値を超えた中継を同じ判定者が告発する */
static void method3_tomo(struct network* network, struct simulation* simulation, struct payment* payment,
                         struct network_params net_params, int q, struct node* target, const long* flg, int nf) {
  double m = (double)get_m3_appeal_prior_weight(), th = get_m3_appeal_prior_rate();
  for (int k = 1; k < q; k++) {
    struct route_hop* rk = (struct route_hop*)array_get(payment->route->route_hops, k);
    long u = (rk != NULL) ? rk->from_node_id : -1;
    if (u < 0 || u >= m3_nn || u == target->id || u == payment->sender) continue;
    struct m3_target* tu = &m3_t[u];
    if (tu->tm_last_pid == payment->id + 1) continue;
    tu->tm_last_pid = payment->id + 1;
    tu->tm_c++;
    double rho = ((double)tu->tm_c + th * m) / ((double)tu->tm_r + m);
    if (tu->tm_c < get_m3_tomo_min() || rho < get_m3_tomo_threshold() || tu->tm_acc_pid == payment->id + 1) continue;
    tu->tm_acc_pid = payment->id + 1;
    struct node* un = (struct node*)array_get(network->nodes, u);
    if (un == NULL) continue;
    m3_tomo_acc++; if (!un->is_malicious) m3_tomo_acc_h++;
    long up = -1;
    if (k >= 1) { struct route_hop* r2 = (struct route_hop*)array_get(payment->route->route_hops, k - 1); if (r2 != NULL) up = r2->from_node_id; }
    if (get_m3_distrust() == 2) m3_accuse_v2(network, simulation, payment, net_params, tu, un, flg, nf, up);
    else { for (int j = 0; j < nf; j++) m3_add_accuser(tu, flg[j]); m3_accuse_event(network, simulation, payment, net_params, tu, un, flg[0]); }
  }
}
/* 位置 q の対象ノードの保持 settle_lat を、q より上流の各判定者が検定する。報告したら 1 を返す。 */
static int method3_observe(struct network* network, struct simulation* simulation, struct payment* payment,
                           struct network_params net_params, int q, struct node* target, double settle_lat,
                           int fav_test, double avg_iv, int nh, double legs_var) {
  struct m3_target* t = m3_target_of(network, target->id);
  if (t == NULL) return 0;
  int warm = detector_in_warmup(payment, (long)simulation->processed_payments);
  int tested = 0;
  long flg[q > 0 ? q : 1];   /* 異常と見た判定者 (経路の上流から順) */
  int nf = 0;
  for (int u = 0; u < q; u++) {
    struct route_hop* rh = (struct route_hop*)array_get(payment->route->route_hops, u);
    if (rh == NULL) continue;
    struct node* obs = (struct node*)array_get(network->nodes, rh->from_node_id);
    if (obs == NULL || obs->is_malicious) continue;   /* 悪意ノードは告発しない */
    struct node* sh = m3_shadow(obs->id, target);
    hold_set_sample_var(legs_var);
    int r = fav_test ? on_hold_hypothesis_test_nolearn(sh, settle_lat, warm, avg_iv, nh)
                     : on_hold_hypothesis_test(sh, settle_lat, warm, avg_iv, nh);
    if (!warm) tested = 1;
    if (r) flg[nf++] = obs->id;
  }
  if (tested) { t->tests++; target->settle_test_count++; }
  if (get_m3_appeal() == 3 && !warm && m3_watched(target->id) &&
      target->id != payment->sender && target->id != payment->receiver) {   /* 監視中に中継した決済を数える */
    m3_t[target->id].a_r++;
    m3_ratio_check(network, simulation, payment, net_params, target->id);
  }
  if (get_m3_rcv_watch() && !warm && target->id != payment->sender && target->id != payment->receiver)
    t->rv_r++;   /* 受取人の検定の監視: 中継した決済を数える */
  if (get_m3_tomo() && !warm && target->id != payment->sender && target->id != payment->receiver)
    t->tm_r++;   /* 絞り込み: 中継した決済を数える */
  if (nf == 0) return 0;
  if (!warm && target->id != m3_hc_judge_target && m3_xc_refutes(network, payment, q, nh, avg_iv)) {   /* 照らし合わせ: 記録と食い違う告発は捨てる */
    m3_xc_ref_obs += nf;
    if (target->is_malicious) m3_xc_ref_obs_mal += nf;
    if (get_m3_xcheck() == 2) for (int k = 0; k < nf; k++) m3_xc_counter_accuse(network, simulation, payment, net_params, flg[k], nh);
    return 0;
  }
  if (!warm && m3_so_rule(network, simulation, payment, q, target->id, flg, nf, 0)) return 0;   /* 送金者だけの告発 */
  t->anomalies++; target->settle_anomaly_count++;
  int lv = get_m3_distrust();
  if (target->id == payment->sender || target->id == payment->receiver) {
    for (int k = 0; k < nf; k++) m3_add_accuser(t, flg[k]);
    if (t->first_accuse_time == 0) t->first_accuse_time = simulation->current_time;
    return 0;
  }
  if (get_m3_tomo() && !warm) method3_tomo(network, simulation, payment, net_params, q, target, flg, nf);
  if (lv == 2) {
    if (get_m3_appeal() == 3) {
      if (!m3_hc_no_appeal(target->id) && m3_ratio_evidence(network, simulation, payment, net_params, q, target, flg, nf)) return 0;
    } else if (get_m3_appeal() && m3_appeal_evidence(network, simulation, payment, net_params, q, target, flg, nf)) return 0;
    long up = -1;
    if (q >= 1) {
      struct route_hop* ru = (struct route_hop*)array_get(payment->route->route_hops, q - 1);
      if (ru != NULL) up = ru->from_node_id;
    }
    m3_accuse_v2(network, simulation, payment, net_params, t, target, flg, nf, up);
    return has_attack_reporter(payment, target->id);
  }
  long reporter = -1;
  for (int k = 0; k < nf; k++) {
    if (lv == 1 && !m3_counts(flg[k])) { t->ignored++; continue; }   /* 確定した告発者の告発は数えない */
    m3_add_accuser(t, flg[k]);
    if (reporter < 0) reporter = flg[k];
  }
  if (reporter < 0) return 0;
  return m3_accuse_event(network, simulation, payment, net_params, t, target, reporter);
}
void method3_write_outputs(struct network* network, char output_dir_name[]) {
  if (m3_t == NULL) return;
  char fn[512];
  snprintf(fn, sizeof fn, "%smethod3_accusations.csv", output_dir_name);
  FILE* f = fopen(fn, "w");
  if (f == NULL) return;
  fprintf(f, "node_id,is_malicious,degree,first_attack_time,tests,anomalies,distinct_accusers,confirmed,first_accuse_time,confirm_time,pending_at_confirm,reports,false_accusations,malicious_accusers,ignored_accusations,revoked_reports,unconfirms%s\n",
          get_m3_appeal() ? (get_m3_appeal_all() ? ",appeal_state,appeal_won,appeal_opponent,appeal_start,appeal_end,convicted,blamed,watch_relays,watch_evidence,appeal_opponents"
                                                : ",appeal_state,appeal_won,appeal_opponent,appeal_start,appeal_end,convicted,blamed,watch_relays,watch_evidence") : "");
  long n_ap = 0, n_won = 0, n_lost = 0, n_conv = 0, n_won_h = 0, n_won_m = 0, n_conv_h = 0;
  for (long i = 0; i < m3_nn; i++) {
    struct m3_target* t = &m3_t[i];
    if (t->tests == 0 && t->anomalies == 0 && t->false_accusations == 0 && t->ap == 0 && !t->guilty) continue;
    struct node* nd = (struct node*)array_get(network->nodes, i);
    long deg = (nd != NULL && nd->open_edges != NULL) ? array_len(nd->open_edges) : 0;
    int mal_acc = 0;
    for (int k = 0; k < t->n_acc; k++) {
      struct node* an = (struct node*)array_get(network->nodes, t->accusers[k]);
      if (an != NULL && an->is_malicious) mal_acc++;
    }
    fprintf(f, "%ld,%d,%ld,%llu,%ld,%ld,%d,%d,%llu,%llu,%ld,%ld,%ld,%d,%ld,%ld,%ld", i, (nd != NULL && nd->is_malicious) ? 1 : 0, deg,
            (unsigned long long)((nd != NULL) ? nd->first_attack_time : 0), t->tests, t->anomalies, t->n_acc, t->confirmed,
            (unsigned long long)t->first_accuse_time, (unsigned long long)t->confirm_time, t->confirmed ? t->n_pend : 0, t->reports,
            t->false_accusations, mal_acc, t->ignored, t->revoked, t->unconfirms);
    if (get_m3_appeal()) {
      int mal = (nd != NULL && nd->is_malicious);
      fprintf(f, ",%d,%d,%ld,%llu,%llu,%d,%ld,%ld,%ld", t->ap, t->ap_won, t->ap ? t->ap_opp : -1L,
              (unsigned long long)t->ap_start, (unsigned long long)t->ap_end, t->guilty, t->blamed, t->a_r, t->a_e);
      if (get_m3_appeal_all()) fprintf(f, ",%d", t->n_opps);
      if (t->ap == 1 || t->ap_won != 0) n_ap++;   /* 申し立てたノード (相手として有罪になっただけのノードは除く) */
      if (t->ap_won == 1) { n_won++; if (mal) n_won_m++; else n_won_h++; }
      if (t->ap_won == 2) n_lost++;
      if (t->guilty) { n_conv++; if (!mal) n_conv_h++; }
    }
    fprintf(f, "\n");
  }
  fclose(f);
  if (get_m3_appeal())
    printf("[method3] 申し立て (方式 %d%s、割合で比べるときの前もっての割合 %.2f・重み %ld・最小の証拠 %ld) %ld 件 (勝ち %ld = 正直 %ld・悪意 %ld / 負け %ld / 監視中 %ld)・相手として有罪 %ld (うち正直 %ld)\n",
           get_m3_appeal(), get_m3_appeal_all() ? (get_m3_appeal_ev_down() ? "・相手は上流の中継の全部・証拠は下流の全部" : "・相手は上流の中継の全部")
                                    : (get_m3_appeal_ev_down() ? "・証拠は下流の全部" : ""), get_m3_appeal_prior_rate(), get_m3_appeal_prior_weight(), get_m3_appeal_min_evidence(),
           n_ap, n_won, n_won_h, n_won_m, n_lost, n_ap - n_won - n_lost, n_conv, n_conv_h);
  printf("[method3] 判定者×対象の検定の状態 %ld 組・告発の記録 %s\n", m3_used, fn);
  if (get_m3_tomo()) printf("[method3] 絞り込み (しきい値 %.2f・最小 %ld) で告発 %ld 回 (うち正直なノード %ld 回)\n",
                           get_m3_tomo_threshold(), get_m3_tomo_min(), m3_tomo_acc, m3_tomo_acc_h);
  if (get_m3_rcv_direct()) printf("[method3] 受取人の記録を直接届けた: 書き換えが受取人の記録に及ばなかった回数 %ld\n", m3_rcv_direct_kept);
  if (get_m3_rcv_test()) printf("[method3] 受取人の検定 %ld 回・異常 %ld 回 (受取人のすぐ上流の中継を告発%s %ld 回)\n", m3_rcv_tests, m3_rcv_anom,
                               get_m3_rcv_watch() ? "・割合が低くて見送った" : "", m3_rcv_held);
  if (get_m3_sender_false_accuse() && get_mal_sender_send())
    printf("[method3] 悪意の送金者の嘘の告発 (割合 %.2f): 成功した悪意の送金者の送金 %ld 件 (warmup 後)・嘘の告発 %ld 件 (そのとき送金者が確定していなかった %ld 件)・告発できる中継がいない %ld 件\n",
           get_m3_sender_false_accuse_rate(), m3_sfa_payments, m3_sfa_lies, m3_sfa_counted, m3_sfa_nocand);
  if (get_m3_tamper()) printf("[method3] 記録を書き換えた決済 %ld 件 (方式 %d・受取人に付け替え %ld 件・付け替え先までの平均ホップ %.2f)\n",
                             m3_tamper_count, get_m3_tamper(), m3_tamper_recv,
                             m3_tamper_count ? (double)m3_tamper_dist_sum / (double)m3_tamper_count : 0.0);
  if (get_m3_hashchain()) {
    long np_res = 0, np_mal = 0, np_hon = 0, np_mal_any = 0, mon_now = 0;
    for (long k = 0; k < m3_hc_np; k++) {
      struct m3_hc_pair* q = &m3_hc_pairs[k];
      struct node* na = (q->a >= 0) ? (struct node*)array_get(network->nodes, q->a) : NULL;
      struct node* nb = (struct node*)array_get(network->nodes, q->b);
      if ((na != NULL && na->is_malicious) || (nb != NULL && nb->is_malicious)) np_mal_any++;
      if (!q->resolved) continue;
      np_res++;
      struct node* nc = (struct node*)array_get(network->nodes, q->culprit);
      if (nc != NULL && nc->is_malicious) np_mal++; else np_hon++;
    }
    for (long v = 0; v < m3_hc_nn; v++) if (m3_hc_monitored(v)) mon_now++;
    printf("[method3] ハッシュチェーン (%s): 印 %ld 個 (1 個 %.2f µs)・確かめた印 %ld 個 (1 個 %.2f µs)・確かめた決済 %ld 件・印が合わない決済 %ld 件 (書き換えた保持者のすぐ下流で合わない %ld 件・犯人が決まっていて説明済み %ld 件)・攻撃者が作り直した印 %ld 個\n",
           get_m3_hc_keyed() ? "鍵つき" : "鍵なし",
           m3_hc_tag_n, m3_hc_tag_n ? m3_hc_tag_ns / 1e3 / (double)m3_hc_tag_n : 0.0,
           m3_hc_ver_n, m3_hc_ver_n ? m3_hc_ver_ns / 1e3 / (double)m3_hc_ver_n : 0.0, m3_hc_checked, m3_hc_fail, m3_hc_fail_match, m3_hc_fail_explained,
           m3_hc_forged);
    printf("[method3] ハッシュチェーンの監視 (判定ノード %d 個・T %.0f ms): ペア %ld 組 (悪意を含む %ld 組)・犯人が決まった %ld 組 (悪意 %ld・正直 %ld)・終わった時点で監視中のノード %ld・判定ノードで測った回数 %ld (攻撃した決済 %ld 回、足した遅れ %.0f ms のうち隠した %.0f ms)・記録と判定ノードの保持が同じ検定 %ld / %ld\n",
           get_m3_hc_judges(), get_judge_copy_t_ms(), m3_hc_np, np_mal_any, np_res, np_mal, np_hon, mon_now, m3_hc_meas, m3_hc_meas_att, m3_hc_extra, m3_hc_hidden, m3_hc_same, m3_hc_cmp);
    char fp2[512];
    snprintf(fp2, sizeof fp2, "%smethod3_hashchain_pairs.csv", output_dir_name);
    FILE* g = fopen(fp2, "w");
    if (g != NULL) {
      fprintf(g, "a,b,a_malicious,b_malicious,judge,flag_time,fails,resolved,culprit,culprit_malicious,resolve_time\n");
      for (long k = 0; k < m3_hc_np; k++) {
        struct m3_hc_pair* q = &m3_hc_pairs[k];
        struct node* na = (q->a >= 0) ? (struct node*)array_get(network->nodes, q->a) : NULL;
        struct node* nb = (struct node*)array_get(network->nodes, q->b);
        struct node* nc = (q->culprit >= 0) ? (struct node*)array_get(network->nodes, q->culprit) : NULL;
        fprintf(g, "%ld,%ld,%d,%d,%d,%llu,%ld,%d,%ld,%d,%llu\n", q->a, q->b, na != NULL ? na->is_malicious : -1,
                nb != NULL ? nb->is_malicious : -1, q->judge, (unsigned long long)q->t0, q->fails, q->resolved, q->culprit,
                nc != NULL ? nc->is_malicious : -1, (unsigned long long)q->t1);
      }
      fclose(g);
    }
    printf("[method3] ハッシュチェーンの検証時間 %.1f ms/ホップ・遅らせて検定した決済 %ld 件・犯人の扱い %d (また書き換えた犯人を送金者が告発 %ld 回)\n",
           get_m3_hc_verify_ms(), m3_hc_deferred, get_m3_hc_culprit(), m3_hc_reaccuse);
    if (get_m3_xcheck())
      printf("[method3] 告発の照らし合わせ (方式 %d・z < %.2f で食い違い): 照らし合わせた告発 %ld 件・捨てた判定者の告発 %ld 件 (対象が悪意 %ld)・捨てた嘘の告発 %ld 件・告発し返した %ld 回・照らし合わせられなかった (印が合わない %ld・送金者が悪意 %ld・記録がない %ld)\n",
             get_m3_xcheck(), get_m3_xcheck_z(), m3_xc_checked, m3_xc_ref_obs, m3_xc_ref_obs_mal, m3_xc_ref_false, m3_xc_counter,
             m3_xc_skip_fail, m3_xc_skip_sender, m3_xc_skip_rec);
    if (get_m3_sender_only())
      printf("[method3] 送金者だけの告発 (方式 %d): 正直な判定者の告発をペアに回した %ld 回 (本当に保持していた %ld)・捨てた %ld 回 (本当に保持していた %ld)・犯人と決まった送金者の告発を捨てた %ld 回・悪意の送金者の嘘をペアに回した %ld 回・捨てた %ld 回\n",
             get_m3_sender_only(), m3_so_pair, m3_so_pair_true, m3_so_disc, m3_so_disc_true, m3_so_disc_culp, m3_so_lie_pair, m3_so_lie_disc);
    printf("[method3] 判定ノードごとの測った回数:");
    for (int k = 0; k < get_m3_hc_judges(); k++) printf(" %ld", m3_hc_load != NULL ? m3_hc_load[k] : 0L);
    printf("\n");
  }
}

/* ノードが申告する時刻 = 真の時刻 + 時計オフセット + (嘘をつくなら嘘の分)。
 * dir: +1 = 「遅く受け取った」方向に盛る, -1 = 「早く送った」方向に盛る。
 * 保持者は「遅く受け取って、すぐ送った」と偽ることで見かけの保持時間を 2X 縮める。
 * pm == NULL を渡すと嘘は乗らない(時計オフセットのみ)。 */
static uint64_t reported_time(struct node* nd, struct payment* pm, uint64_t true_time, int dir) {
  long adj = node_clock_offset(nd != NULL ? nd->id : 0);
  if (lies_on_this_payment(nd, pm) && get_escrow()) {
    /* エスクロー方式: 隠せるのは受け取り側だけ、量は期限とエスカレーションで決まる */
    long off = -1;
    if (dir > 0 && escrow_offerer_of(pm, nd->id, &off)) {
      struct escrow_link L;
      int via = 0;
      escrow_link_eval(nd->id, off, pm->id, 1, &L);
      adj += (long)(escrow_hide(&L, &via) + 0.5);
    }
  } else if (lies_on_this_payment(nd, pm) && !get_judge_copy()) {   /* 判定ノード経由では申告を使わないので嘘を乗せない */
    int side = get_false_report_side();
    long amount = get_false_report_smart() ? (long)pm->grief_hold_extra_ms : get_false_report_ms();
    if (side == FALSE_REPORT_SIDE_BOTH ||
        (side == FALSE_REPORT_SIDE_RECV && dir > 0) ||
        (side == FALSE_REPORT_SIDE_SEND && dir < 0))
      adj += dir * amount;
  }
  long t = (long)true_time + adj;
  return (t < 0) ? 0 : (uint64_t)t;
}

/* === 攻撃手法セレクタ (CLOTH_ATTACK_MODE) ===
 * 悪意ノードが行う攻撃の種別をスクリプトから選択する:
 *   1 = fail 型のみ        (forward leg で遅延させ HTLC を失敗させる; hold 割合 0.0)
 *   2 = hold 型のみ        (settlement=backward レグでの preimage 保持グリーフィング単独; 割合 1.0)
 *   3 = 混在 (fail + hold) (hold 割合は CLOTH_GRIEF_HOLD_RATIO、既定 0.5)
 * 未設定/範囲外のときは 0 を返し、get_grief_hold_ratio() は後方互換のため
 * CLOTH_GRIEF_HOLD_RATIO を直接参照する (既定 0.0 = 従来どおり全て fail 型)。 */
/* === hold-to-timeout 型を warmup 決済にも発動させるか (CLOTH_FAIL_ATTACK_IN_WARMUP, 既定 0) ===
 * 既定 0: warmup 決済 (payment->is_warmup) では失敗させず通常転送する。hold 型は遅延注入が
 *   is_warmup で止まるため warmup 中は実質攻撃が無いのに、hold-to-timeout 型だけは warmup 中も
 *   失敗させていた非対称を解消する。これで全攻撃型で「warmup = 攻撃の無い学習期間」が成り立ち、
 *   検知器 (monitoring.c::detector_in_warmup) の warmup 学習に攻撃サンプルが混入しない。
 *   (旧挙動では warmup 決済の 4 割強が攻撃を受けていた。2026-10-08 実測)
 * 1: 旧挙動 (2026-10-08 以前)。過去 run の再現用。
 * 乱数: attack_roll / mode_roll は従来どおり引くので、hold 型 (mode 2) の乱数列・結果は不変。 */
static int fail_attack_in_warmup(void) {
  static int v = -1;
  if (v < 0) {
    const char* e = getenv("CLOTH_FAIL_ATTACK_IN_WARMUP");
    v = (e != NULL && e[0] != '\0' && strcmp(e, "0") != 0) ? 1 : 0;
  }
  return v;
}

/* === fail 検知器: 失敗ホップ(fallthrough)の検定対象 (CLOTH_FAIL_FALLTHROUGH_ALL_ERRORS, 既定 0) ===
 * 失敗したホップは次ノードが転送しないので、区間の終わりを「送信者が失敗を受けた時刻」で代用する
 * (fallthrough)。この区間には失敗が送信者へ戻る往復 (k ホップ × 転送間隔) が丸ごと入る。
 * 既定 0: 攻撃による失敗 (error.type == OFFLINENODE) のときだけ検定する。hold-to-timeout 型は
 *   ここで保持時間 (攻撃遅延 + OFFLINELATENCY) が現れるので検出の本体になる。残高不足などの
 *   普通の失敗 (NORESPONSE) では失敗ホップのノードは転送していないので測るべき遅延が無く、
 *   戻りの往復を遅延と誤認して異常判定していた (k≥4 で p<0.01、k≥5 で p<0.001 を超える)。
 *   error.type は実網の失敗コード (unknown_next_peer / temporary_channel_failure) に相当し観測可能。
 * 1: 旧挙動 (エラー種別によらず検定)。過去 run の再現用。 */
static int fail_fallthrough_all_errors(void) {
  static int v = -1;
  if (v < 0) {
    const char* e = getenv("CLOTH_FAIL_FALLTHROUGH_ALL_ERRORS");
    v = (e != NULL && e[0] != '\0' && strcmp(e, "0") != 0) ? 1 : 0;
  }
  return v;
}

/* === fail 検知器: Phase 2 フォールバック (CLOTH_FAIL_PHASE2_FALLBACK, 既定 0) ===
 * 案D で攻撃者が決まらない (異常ホップの送り先が送信者/受信者だけ) とき、「経路上で最初に報告して
 * いない中継ノード」を攻撃者とする旧ロジック。異常の位置と無関係なノードを選ぶため、本物の攻撃の
 * 帰属には一度も使われず (mode1 で使用 0 回)、誤検知だけを生んでいた (mode2 の FP の約半数)。
 * 既定 0: 使わない (案D で決まらなければ報告しない)。1: 旧挙動。過去 run の再現用。 */
static int fail_phase2_fallback(void) {
  static int v = -1;
  if (v < 0) {
    const char* e = getenv("CLOTH_FAIL_PHASE2_FALLBACK");
    v = (e != NULL && e[0] != '\0' && strcmp(e, "0") != 0) ? 1 : 0;
  }
  return v;
}

static int get_attack_mode(void) {
  char* e = getenv("CLOTH_ATTACK_MODE");
  if (e == NULL || e[0] == '\0') return 0;
  int m = atoi(e);
  if (m < 1 || m > 3) return 0;
  return m;
}

/* === hold 型攻撃 (settlement=backward レグでの preimage 保持遅延) ===
 * 悪意ノードが行う攻撃のうち「保持(hold)型」にする割合 [0,1] を返す。
 * CLOTH_ATTACK_MODE が設定されていればそれを優先 (1→0.0, 2→1.0, 3→混在割合)、
 * 未設定なら後方互換のため env CLOTH_GRIEF_HOLD_RATIO を直接参照する (既定 0.0)。
 * hold 型に当たった攻撃は、forward leg では失敗させず通常転送し、settlement レグで
 * そのノードが preimage の release を遅延させる(失敗なし=支払いは成功)。よって
 * fail 検知器には映らず hold 検知器だけが拾える (monitoring.h の用語ブロック参照)。 */
static double get_grief_hold_ratio(void) {
  int mode = get_attack_mode();
  if (mode == 1) return 0.0;   /* fail 型のみ */
  if (mode == 2) return 1.0;   /* hold 型のみ */
  if (mode == 3) {             /* 混在: 割合は CLOTH_GRIEF_HOLD_RATIO (既定 0.5) */
    char* e = getenv("CLOTH_GRIEF_HOLD_RATIO");
    double v = (e == NULL || e[0] == '\0') ? 0.5 : atof(e);
    if (v < 0.0) v = 0.0;
    if (v > 1.0) v = 1.0;
    return v;
  }
  /* mode 未指定 (後方互換): 従来どおり CLOTH_GRIEF_HOLD_RATIO を直接参照 */
  char* e = getenv("CLOTH_GRIEF_HOLD_RATIO");
  if (e == NULL) return 0.0;
  double v = atof(e);
  if (v < 0.0) v = 0.0;
  if (v > 1.0) v = 1.0;
  return v;
}

/* シャドウ計測(報告はせず CSV 出力のみ)の有効化。CLOTH_GRIEF_SHADOW_LOG が
 * 設定されているときだけ /tmp/cloth_grief_shadow.csv に settlement レグの転送
 * レイテンシを記録。 */
static int hold_shadow_log_enabled(void) {
  return getenv("CLOTH_GRIEF_SHADOW_LOG") != NULL;
}

/* hold 検知器 (B) の有効化。CLOTH_DETECT_GRIEF が設定されていて、かつ案A が無効
 * (CLOTH_HOLD_ROUNDTRIP=0) のときだけ、forward_success() で各ノードの settlement レグ転送
 * レイテンシを仮説検定し、保持攻撃者を直接特定して report_attacked_node_to_judges() に報告する。
 * 既定の案A (receive_success) はこの env に関係なく、評判システムが有効なら常に走る。
 * (env 名の "GRIEF" は過去 run の再現性のため旧称のまま = hold 検知器のこと) */
static int get_detect_hold(void) {
  return getenv("CLOTH_DETECT_GRIEF") != NULL;
}

/* hold 検出 案A (round-trip + 隣接差分)。各ノードの往復時間 (HTLC送出→preimage返送受信)
 * を receive_success で走査し、各ノードの保持時間を settle 検定にかけ、異常なノードを報告する
 * (同じ決済で同じノードは1回)。検定値は既定 (CLOTH_REPORT_ATTEST=1) では相互証明の
 * hold[p]=recv[p-1]-send_back[p+1]。ATTEST=0 のときは隣接差 Δ[i]=RT[i]-RT[i+1] の resid を使う。
 * 有効時は forward_success の (B) settle 直接検定を無効化(二重報告防止)。
 * **既定 ON = (A) に切替済み(2026-07-24)**。従来の (B) per-node settle 直接帰属に戻すには
 * env CLOTH_HOLD_ROUNDTRIP=0 を設定する。 */
static int get_hold_roundtrip(void) {
  const char* e = getenv("CLOTH_HOLD_ROUNDTRIP");
  if (e != NULL) return atoi(e) != 0;   /* 明示指定を尊重 (0=(B)へ, 非0=(A)) */
  return 1;                             /* 既定=(A)差分版 */
}

/* hold検出を hold-to-timeout型と完全対称にする観測条件 (CLOTH_HOLD_RT_SELFTIME)。
 * ⚠️ 既定の相互証明 (CLOTH_REPORT_ATTEST=1) では検定値は相互証明の式で上書きされるので、
 *    ここで計算する resid は「resid<=0 の標本を落とす」フィルタとしてだけ効く。
 * 各ノードが「自ノードだけで観測できる」往復時間 RT[i]=recv[i]-send[i] を測り、隣接差
 * Δ=RT[i]-RT[i+1] から平均インターバルを引いた resid(≈下流 i+1 の保持時間) を検定する。
 * 旧版(=0)は recv[i]-recv[i+1] 直接(下流=保持者本人の受領時刻を要する)。selftime版は
 * hold-to-timeout型 send[i+1]-send[i] と同じ観測条件で、保持者本人の時刻に依存しないより自然な形。
 * **既定 ON (2026-08-01)**: seed{7,42,123}×n{3200,6400} で検出率+0.86〜1.48pp・precision
 * 100%不変を確証(劣化なし)。旧 recv差分に戻すには env CLOTH_HOLD_RT_SELFTIME=0。 */
static int get_hold_rt_selftime(void) {
  const char* e = getenv("CLOTH_HOLD_RT_SELFTIME");
  if (e != NULL) return atoi(e) != 0;   /* 明示指定を尊重 (0=旧 recv[i]-recv[i+1] へ) */
  return 1;                             /* 既定=fail対称の自己観測RT */
}

/* check whether there is sufficient balance in an edge for forwarding the payment; check also that the policies in the edge are respected */
unsigned int check_balance_and_policy(struct edge* edge, struct edge* prev_edge, struct route_hop* prev_hop, struct route_hop* next_hop) {
  uint64_t expected_fee;

  if(next_hop->amount_to_forward > edge->balance)
    return 0;

  if(next_hop->amount_to_forward < edge->policy.min_htlc){
    fprintf(stderr, "ERROR: policy.min_htlc not respected\n");
    exit(-1);
  }

  expected_fee = compute_fee(next_hop->amount_to_forward, edge->policy);
  if(prev_hop->amount_to_forward != next_hop->amount_to_forward + expected_fee){
    fprintf(stderr, "ERROR: policy.fee not respected\n");
    exit(-1);
  }

  if(prev_hop->timelock != next_hop->timelock + prev_edge->policy.timelock){
    fprintf(stderr, "ERROR: policy.timelock not respected\n");
    exit(-1);
  }

  return 1;
}

/* retrieve a hop from a payment route */
struct route_hop *get_route_hop(long node_id, struct array *route_hops, int is_sender) {
  struct route_hop *route_hop;
  long i, index = -1;

  for (i = 0; i < array_len(route_hops); i++) {
    route_hop = array_get(route_hops, i);
    if (is_sender && route_hop->from_node_id == node_id) {
      index = i;
      break;
    }
    if (!is_sender && route_hop->to_node_id == node_id) {
      index = i;
      break;
    }
  }

  if (index == -1)
    return NULL;

  return array_get(route_hops, index);
}


/* FUNCTIONS MANAGING NODE PAIR RESULTS */

/* set the result of a node pair as success: it means that a payment was successfully forwarded in an edge connecting the two nodes of the node pair.
 This information is used by the sender node to find a route that maximizes the possibilities of successfully sending a payment */
void set_node_pair_result_success(struct element** results, long from_node_id, long to_node_id, uint64_t success_amount, uint64_t success_time){
  struct node_pair_result* result;

  result = get_by_key(results[from_node_id], to_node_id, is_equal_key_result);

  if(result == NULL){
    result = malloc(sizeof(struct node_pair_result));
    result->to_node_id = to_node_id;
    result->fail_time = 0;
    result->fail_amount = 0;
    result->success_time = 0;
    result->success_amount = 0;
    results[from_node_id] = push(results[from_node_id], result);
  }

  result->success_time = success_time;
  if(success_amount > result->success_amount)
    result->success_amount = success_amount;
  if(result->fail_time != 0 && result->success_amount > result->fail_amount)
    result->fail_amount = success_amount + 1;
}

/* set the result of a node pair as success: it means that a payment failed when passing through  an edge connecting the two nodes of the node pair.
   This information is used by the sender node to find a route that maximizes the possibilities of successfully sending a payment */
void set_node_pair_result_fail(struct element** results, long from_node_id, long to_node_id, uint64_t fail_amount, uint64_t fail_time){
  struct node_pair_result* result;

  result = get_by_key(results[from_node_id], to_node_id, is_equal_key_result);

  if(result != NULL)
    if(fail_amount > result->fail_amount && fail_time - result->fail_time < 60000)
      return;

  if(result == NULL){
    result = malloc(sizeof(struct node_pair_result));
    result->to_node_id = to_node_id;
    result->fail_time = 0;
    result->fail_amount = 0;
    result->success_time = 0;
    results[from_node_id] = push(results[from_node_id], result);
  }

  result->fail_amount = fail_amount;
  result->fail_time = fail_time;
  if(fail_amount == 0)
    result->success_amount = 0;
  else if(fail_amount != 0 && fail_amount <= result->success_amount)
    result->success_amount = fail_amount - 1;
}

/* process a payment which succeeded */
void process_success_result(struct node* node, struct payment *payment, uint64_t current_time){
  struct route_hop* hop;
  int i;
  struct array* route_hops;
  route_hops = payment->route->route_hops;
  for(i=0; i<array_len(route_hops); i++){
    hop = array_get(route_hops, i);
    set_node_pair_result_success(node->results, hop->from_node_id, hop->to_node_id, hop->amount_to_forward, current_time);
  }
}

/* process a payment which failed (different processments depending on the error type) */
void process_fail_result(struct node* node, struct payment *payment, uint64_t current_time){
  struct route_hop* hop, *error_hop;
  int i;
  struct array* route_hops;

  error_hop = payment->error.hop;

  if(error_hop->from_node_id == payment->sender) //do nothing if the error was originated by the sender (see `processPaymentOutcomeSelf` in lnd)
    return;

  if(payment->error.type == OFFLINENODE) {
    set_node_pair_result_fail(node->results, error_hop->from_node_id, error_hop->to_node_id, 0, current_time);
    set_node_pair_result_fail(node->results, error_hop->to_node_id, error_hop->from_node_id, 0, current_time);
  }
  else if(payment->error.type == NOBALANCE || payment->error.type == NORESPONSE) {
    route_hops = payment->route->route_hops;
    for(i=0; i<array_len(route_hops); i++){
      hop = array_get(route_hops, i);
      if(hop->edge_id == error_hop->edge_id) {
        set_node_pair_result_fail(node->results, hop->from_node_id, hop->to_node_id, hop->amount_to_forward, current_time);
        break;
      }
      set_node_pair_result_success(node->results, hop->from_node_id, hop->to_node_id, hop->amount_to_forward, current_time);
    }
  }
}


void generate_send_payment_event(struct payment* payment, struct array* path, struct simulation* simulation, struct network* network){
  struct route* route;
  uint64_t next_event_time;
  struct event* send_payment_event;
  route = transform_path_into_route(path, payment->amount, network, simulation->current_time);
  payment->route = route;
  // execute send_payment event immediately
  next_event_time = simulation->current_time;
  send_payment_event = new_event(next_event_time, SENDPAYMENT, payment->sender, payment );
  simulation->events = heap_insert(simulation->events, send_payment_event, compare_event);
}


struct payment* create_payment_shard(long shard_id, uint64_t shard_amount, struct payment* payment){
  struct payment* shard;
  shard = new_payment(shard_id, payment->sender, payment->receiver, shard_amount, payment->start_time, payment->max_fee_limit);
  shard->attempts = 1;
  shard->is_shard = 1;
  shard->is_warmup = payment->is_warmup;
  return shard;
}

/*HTLC FUNCTIONS*/

/* find a path for a payment (a modified version of dijkstra is used: see `routing.c`) */
void find_path(struct event *event, struct simulation* simulation, struct network* network, struct array** payments, unsigned int mpp, enum routing_method routing_method, struct network_params net_params) {
  struct payment *payment, *shard1, *shard2;
  struct array *path, *shard1_path, *shard2_path;
  uint64_t shard1_amount, shard2_amount;
  enum pathfind_error error;
  long shard1_id, shard2_id;
  
  payment = event->payment;

  ++(payment->attempts);

  if(net_params.payment_timeout != -1 && simulation->current_time > payment->start_time + net_params.payment_timeout) {
    payment->end_time = simulation->current_time;
    payment->is_timeout = 1;
    payment->error.type = NORESPONSE;
    return;
  }

  // find path
  if(routing_method == CLOTH_ORIGINAL) {
      if (payment->attempts == 1) {
          if (net_params.enable_rbr) {
              // === Stage ④ RBR: Use reputation-based path finding with reconstruction ===
              path = find_reputation_based_route(payment->sender, payment->receiver, payment->amount,
                                                 network, simulation->current_time, 0, &error,
                                                 net_params.routing_method, NULL, payment->max_fee_limit,
                                                 net_params);
          } else {
              /* warmup 中は攻撃が発動しない(apply_attack_delay_if_needed の is_warmup ゲート)ため、
               * 旧 dijkstra_avoid_malicious_nodes(ground-truth is_malicious 回避)は撤去。
               * warmup/post-warmup とも事前計算経路を使い、正解ラベルに依存しない。 */
              path = paths[payment->id];
          }
      }else {
          if (net_params.enable_rbr) {
              // === Retry: Use RBR for subsequent attempts ===
              path = find_reputation_based_route(payment->sender, payment->receiver, payment->amount,
                                                 network, simulation->current_time, 0, &error,
                                                 net_params.routing_method, NULL, payment->max_fee_limit,
                                                 net_params);
          } else if (net_params.judging_strategy > 0 && net_params.enable_reputation_system) {
              // === Retry: Use reputation-weighted dijkstra when judging is active ===
              path = dijkstra_with_reputation(payment->sender, payment->receiver, payment->amount,
                                             network, simulation->current_time, 0, &error,
                                             net_params.routing_method, net_params.rbr_reputation_weight);
          } else {
              path = dijkstra(payment->sender, payment->receiver, payment->amount, network, simulation->current_time, 0, &error, net_params.routing_method, NULL, payment->max_fee_limit);
          }
      }
  } else {

      if (payment->attempts == 1) {
          path = paths[payment->id];
          if (path != NULL) {

              // calc path capacity
              uint64_t path_cap = INT64_MAX;
              for (int i = 0; i < array_len(path); i++) {
                  struct route_hop *hop = array_get(path, i);
                  struct edge *edge = array_get(network->edges, hop->edge_id);
                  uint64_t estimated_cap;
                  if (i == 0) {
                      // if first edge of the path (directory connected edge to source node)
                      estimated_cap = edge->balance;
                  } else {
                      estimated_cap = estimate_capacity(edge, network, routing_method);
                  }
                  if (estimated_cap < path_cap) path_cap = estimated_cap;
              }

              // calc total fee
              struct route *route = transform_path_into_route(path, payment->amount, network, simulation->current_time);
              uint64_t fee = route->total_fee;
              free_route(route);

              // if path capacity is not enough to send the payment, find new path
              if (path_cap < payment->amount + fee) {
                  path = dijkstra(payment->sender, payment->receiver, payment->amount, network, simulation->current_time, 0, &error, net_params.routing_method, NULL, payment->max_fee_limit);
              }
          } else {
              path = dijkstra(payment->sender, payment->receiver, payment->amount, network, simulation->current_time, 0, &error, net_params.routing_method, NULL, payment->max_fee_limit);
          }
      } else {

          // exclude edges
          struct element* exclude_edges = NULL;
          for(struct element* iterator = payment->history; iterator != NULL; iterator = iterator->next) {
            struct attempt* a = iterator->data;
            struct edge* exclude_edge = array_get(network->edges, a->error_edge_id);
            exclude_edges = push(exclude_edges, exclude_edge);
          }

          if (net_params.enable_rbr) {
              path = find_reputation_based_route(payment->sender, payment->receiver, payment->amount,
                                                 network, simulation->current_time, 0, &error,
                                                 net_params.routing_method, exclude_edges, payment->max_fee_limit,
                                                 net_params);
          } else {
              path = dijkstra(payment->sender, payment->receiver, payment->amount, network, simulation->current_time, 0, &error, net_params.routing_method, exclude_edges, payment->max_fee_limit);
          }
      }
  }

  if (path != NULL) {
    generate_send_payment_event(payment, path, simulation, network);
    return;
  }

  //  if a path is not found, try to split the payment in two shards (multi-path payment)
  if(mpp && path == NULL && !(payment->is_shard) && payment->attempts == 1 ){
    shard1_amount = payment->amount/2;
    shard2_amount = payment->amount - shard1_amount;
    
    if (net_params.enable_rbr) {
        shard1_path = find_reputation_based_route(payment->sender, payment->receiver, shard1_amount,
                                                  network, simulation->current_time, 0, &error,
                                                  net_params.routing_method, NULL, payment->max_fee_limit / 2,
                                                  net_params);
    } else {
        shard1_path = dijkstra(payment->sender, payment->receiver, shard1_amount, network, simulation->current_time, 0, &error, net_params.routing_method, NULL, payment->max_fee_limit / 2);
    }
    
    if(shard1_path == NULL){
      payment->end_time = simulation->current_time;
      payment->error.type = NORESPONSE;
      payment->is_timeout = 1;
      return;
    }
    
    if (net_params.enable_rbr) {
        shard2_path = find_reputation_based_route(payment->sender, payment->receiver, shard2_amount,
                                                  network, simulation->current_time, 0, &error,
                                                  net_params.routing_method, NULL, payment->max_fee_limit / 2,
                                                  net_params);
    } else {
        shard2_path = dijkstra(payment->sender, payment->receiver, shard2_amount, network, simulation->current_time, 0, &error, net_params.routing_method, NULL, payment->max_fee_limit / 2);
    }
    
    if(shard2_path == NULL){
      payment->end_time = simulation->current_time;
      payment->error.type = NORESPONSE;
      payment->is_timeout = 1;
      return;
    }
    // if shard1_path and shard2_path is same route, return
    if(routing_method != CLOTH_ORIGINAL) {
        long shard1_path_len = array_len(shard1_path);
        long shard2_path_len = array_len(shard2_path);
        if (shard1_path_len == shard2_path_len) {
            int duplicated = 0;
            for (int i = 0; i < shard1_path_len; i++) {
                struct route_hop *shard1_hop = array_get(shard1_path, i);
                for (int j = 0; j < shard2_path_len; j++) {
                    struct route_hop *shard2_hop = array_get(shard2_path, j);
                    if (shard1_hop->edge_id == shard2_hop->edge_id) duplicated++;
                }
            }
            // all hop of shade1_path is same as shade2_path's, return
            if (duplicated == shard1_path_len && duplicated == shard2_path_len) {
                payment->end_time = simulation->current_time;
                payment->error.type = NORESPONSE;
                payment->is_timeout = 1;
                return;
            }
        }
    }
    shard1_id = array_len(*payments);
    shard2_id = array_len(*payments) + 1;
    shard1 = create_payment_shard(shard1_id, shard1_amount, payment);
    shard2 = create_payment_shard(shard2_id, shard2_amount, payment);
    *payments = array_insert(*payments, shard1);
    *payments = array_insert(*payments, shard2);
    payment->is_shard = 1;
    payment->shards_id[0] = shard1_id;
    payment->shards_id[1] = shard2_id;
    generate_send_payment_event(shard1, shard1_path, simulation, network);
    generate_send_payment_event(shard2, shard2_path, simulation, network);
    return;
  }

  // no path
  payment->end_time = simulation->current_time;
  payment->error.type = NORESPONSE;
  payment->is_timeout = 1;
}

/* send an HTLC for the payment (behavior of the payment sender) */
/* 悪意ノードもふつうに送金する (CLOTH_MAL_SENDER_SEND=1、既定 0)。中継は送金者が誰か知らない (オニオン経路) ので、
 * 攻撃者は仲間の送金でもほかと同じように保持する。成功率と遅延の集計からは悪意の送金者の送金を外す (cloth.c) */
int get_mal_sender_send(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_MAL_SENDER_SEND");
  return (v = (e != NULL && e[0] != '\0' && strcmp(e, "0") != 0) ? 1 : 0);
}
void send_payment(struct event* event, struct simulation* simulation, struct network* network, struct network_params net_params){
  struct payment* payment;
  uint64_t next_event_time;
  struct route* route;
  struct route_hop* first_route_hop;
  struct edge* next_edge;
  struct event* next_event;
  enum event_type event_type;
  unsigned long is_next_node_offline;
  struct node* node;

  payment = event->payment;
  route = payment->route;
  node = array_get(network->nodes, event->node_id);
  first_route_hop = array_get(route->route_hops, 0);
  next_edge = array_get(network->edges, first_route_hop->edge_id);

  /* If the sender itself is malicious, abort immediately without reporting.
   * This models a sender-side attack that never puts the HTLC on the wire.
   * CLOTH_MAL_SENDER_SEND=1 のときは悪意の送金者もふつうに送金する (悪意の送金者による嘘の告発を測るため)。 */
  if (node->is_malicious && !get_mal_sender_send()) {
    payment->error.type = OFFLINENODE;
    payment->error.hop = first_route_hop;
    payment->offline_node_count += 1;
    payment->end_time = simulation->current_time;
    add_attempt_history(payment, network, simulation->current_time, 0);
    simulation->processed_payments++;
    return;
  }

  /* Stage ②: record incoming observation at the current node if it is a judge. */
  if (detect_and_record_htlc_observation(network, payment->id, payment->amount, node->id, 0, simulation->current_time, route)) {
    payment->is_observed = 1;
  }
  
  /* === Stage ② Payment Information Judging (Sender) ===
   * If sender is a judge, record the initial HTLC.
   */
  if (node->is_judge) {
      record_htlc_observation(
          network,
          payment->id,
          payment->sender,                    // prev_node = sender itself
          first_route_hop->to_node_id,        // next_node = first hop receiver
          first_route_hop->amount_to_forward, // amount
          simulation->current_time,
          first_route_hop->timelock,
          node->id,
          node->judge_id,
          0.0,    // channel_balance_before (not applicable for sender)
          0.0,    // channel_balance_after (not applicable for sender)
          0       // is_balance_adjustment (false)
      );
  }

  if(!is_present(next_edge->id, node->open_edges)) {
    printf("ERROR (send_payment): edge %ld is not an edge of node %ld \n", next_edge->id, node->id);
    exit(-1);
  }

  first_route_hop->edges_lock_start_time = simulation->current_time;

  /* simulate the case that the next node in the route is offline */
  is_next_node_offline = gsl_ran_discrete(simulation->random_generator, network->faulty_node_prob);
  if(is_next_node_offline){
    payment->offline_node_count += 1;
    payment->error.type = OFFLINENODE;
    payment->error.hop = first_route_hop;
    /* NOTE: do NOT report the offline node here. Being offline is not the same
     * as being a malicious attacker, and this used the ground-truth offline flag
     * (an oracle) to flag a legitimate node — a false positive. Detection is left
     * to the observation-based attribution in receive_fail(). */
    next_event_time = simulation->current_time + OFFLINELATENCY;
    next_event = new_event(next_event_time, RECEIVEFAIL, event->node_id, event->payment);
    simulation->events = heap_insert(simulation->events, next_event, compare_event);
    return;
  }

  // fail no balance
  if (cloth_debug_enabled()) fprintf(stderr, "[FORWARD_CHECK][SEND] payment=%ld edge=%ld required=%llu balance=%llu min_htlc=%llu fee_base=%llu fee_prop=%llu\n", payment->id, next_edge->id, (unsigned long long)first_route_hop->amount_to_forward, (unsigned long long)next_edge->balance, (unsigned long long)next_edge->policy.min_htlc, (unsigned long long)next_edge->policy.fee_base, (unsigned long long)next_edge->policy.fee_proportional);
  if(first_route_hop->amount_to_forward > next_edge->balance) {
    mark_no_response_failure(payment, first_route_hop);
    payment->no_balance_count += 1;
    next_event_time = simulation->current_time;
    next_event = new_event(next_event_time, RECEIVEFAIL, event->node_id, event->payment);
    simulation->events = heap_insert(simulation->events, next_event, compare_event);
    return;
  }

  // update balance
  uint64_t prev_balance = next_edge->balance;
  next_edge->balance -= first_route_hop->amount_to_forward;

  next_edge->tot_flows += 1;
  
  /* === Stage ④ Hypothesis Testing: Record first hop HTLC send time ===
   * リトライのたびに send_payment が呼ばれるため、前の試行の時刻をゼロクリアしてから記録する。 */
  if (route->route_hops != NULL) {
      int num_hops = route->route_hops->size;
      /* リトライで経路が初回より長くなる場合への対応。旧実装は容量を「初回経路
       * 長」に固定していたため、より長い再経路では境界 index (capacity-1) の
       * t_end が範囲外参照で 0 になり current_time にフォールスルー → 正常ノードを
       * 攻撃者と誤特定していた (FP の根因)。現試行の経路長が容量を超えたら再確保
       * して容量を現経路長まで拡張する。 */
      if (!payment->hop_send_times_initialized) {
          payment->hop_send_times = (uint64_t*)malloc(num_hops * sizeof(uint64_t));
          payment->hop_send_times_capacity = num_hops;
          payment->hop_send_times_initialized = 1;
      } else if (num_hops > payment->hop_send_times_capacity) {
          free(payment->hop_send_times);
          payment->hop_send_times = (uint64_t*)malloc(num_hops * sizeof(uint64_t));
          payment->hop_send_times_capacity = num_hops;
      }
  }
  if (payment->hop_send_times != NULL) {
      /* 各試行の先頭でゼロクリア: 前試行の残留値が新経路の検定を汚染しないようにする */
      for (int i = 0; i < payment->hop_send_times_capacity; i++)
          payment->hop_send_times[i] = 0;
      payment->hop_send_times[0] = simulation->current_time;
      /* hold round-trip(案A)用: preimage 受信/送出 時刻配列を hop_send_times と同容量で
       * 確保・ゼロ化。⚠️ 2本の配列は必ず同じ容量変数 hop_settle_recv_capacity で
       * 管理し、容量が伸びるときは**両方**作り直すこと。片方だけ据え置くと、より長い
       * 経路の試行で領域外書き込みになる(過去の hop_send_times 容量固定バグと同根)。 */
      if (payment->hop_settle_recv_capacity < payment->hop_send_times_capacity ||
          payment->hop_settle_send_times == NULL) {
          int cap = payment->hop_send_times_capacity;
          if (cap < payment->hop_settle_recv_capacity) cap = payment->hop_settle_recv_capacity;
          if (payment->hop_settle_recv_capacity < cap || payment->hop_settle_recv_times == NULL) {
              if (payment->hop_settle_recv_times != NULL) free(payment->hop_settle_recv_times);
              payment->hop_settle_recv_times = (uint64_t*)malloc(cap * sizeof(uint64_t));
          }
          /* 送出申告は nh+1 スロット確保する。末尾(index=nh)は**受信者**が
           * 「最終中継ノードへ preimage を送った」と申告する枠。これが無いと
           * 最終中継ノード(p=nh-1)は下流の証明が存在せず永久に判定できない。 */
          if (payment->hop_settle_send_times != NULL) free(payment->hop_settle_send_times);
          payment->hop_settle_send_times = (uint64_t*)malloc((cap + 1) * sizeof(uint64_t));
          payment->hop_settle_recv_capacity = cap;
      }
      if (payment->hop_settle_recv_times != NULL)
          for (int i = 0; i < payment->hop_settle_recv_capacity; i++)
              payment->hop_settle_recv_times[i] = 0;
      if (payment->hop_settle_send_times != NULL)
          for (int i = 0; i <= payment->hop_settle_recv_capacity; i++)
              payment->hop_settle_send_times[i] = 0;
  }
  payment->grief_hold_extra_ms = 0;   /* 保持者が足した遅れも試行ごとに消す */
  payment->m3_rcv_arrive = 0;
  if (net_params.judging_strategy == 3 && get_m3_hashchain() && payment->hop_settle_send_times != NULL) {   /* ハッシュチェーン: 位置ごとの印と本当の時刻 */
      int need = payment->hop_settle_recv_capacity + 1;
      if (payment->m3_hc_cap < need) {
          free(payment->m3_tags); free(payment->m3_true_recv); free(payment->m3_true_send);
          payment->m3_tags = (unsigned char*)malloc((size_t)need * 32);
          payment->m3_true_recv = (uint64_t*)malloc((size_t)need * sizeof(uint64_t));
          payment->m3_true_send = (uint64_t*)malloc((size_t)need * sizeof(uint64_t));
          payment->m3_hc_cap = need;
      }
      memset(payment->m3_tags, 0, (size_t)payment->m3_hc_cap * 32);
      memset(payment->m3_true_recv, 0, (size_t)payment->m3_hc_cap * sizeof(uint64_t));
      memset(payment->m3_true_send, 0, (size_t)payment->m3_hc_cap * sizeof(uint64_t));
  }

  /* === Stage ① Malicious Node Attack Injection (最初のホップ) ===
   * 送信者の最初のホップ先が悪意ノードの場合も、中継 (forward_payment) と同様に
   * 攻撃を注入する。send_payment にこの判定が無かったため、送信者に隣接する
   * 攻撃ハブ(特に高次数ノード)は攻撃せず転送成功し、成功時の評判ブースト
   * (htlc.c の Success Path) で reputation が回復して RBR 回避を免れていた。
   * 受信者が悪意の場合は攻撃しない (forward_payment の !is_last_hop と対称)。
   * hop_send_times[0] 設定後に置くことで、receive_fail() の案D attribution が
   * 攻撃者(hop[0].to_node)を正しく特定できる。
   * fail/hold の分岐は forward_payment (Stage ①) と同一: hold_ratio>0 のときだけ
   * mode_roll を引き、hold 型なら失敗させず grief_hold_node_id を予約して通常転送
   * (遅延注入と first_attack_time は forward_success 側)。従来はここが hold-to-timeout 型固定で、
   * mode 2/3 でも送信者隣接の悪意ハブだけ fail する非対称があった。 */
  {
    struct node* first_hop_node = array_get(network->nodes, first_route_hop->to_node_id);
    if (first_hop_node != NULL && first_hop_node->is_malicious &&
        first_route_hop->to_node_id != payment->receiver) {
      double attack_roll = gsl_rng_uniform(simulation->random_generator);
      if (attack_roll < first_hop_node->attack_probability) {
        double hold_ratio = get_grief_hold_ratio();
        double mode_roll = (hold_ratio > 0.0)
            ? gsl_rng_uniform(simulation->random_generator) : 1.0;
        if (mode_roll < hold_ratio) {
          /* === HOLD 型: 失敗させない。決済経路での遅延注入を予約して通常転送 ===
           * 残高減算(この関数の前半)はそのまま = HTLC は実際に転送される。
           * fall through して下の通常送信処理 (success sending) に進む。 */
          payment->grief_hold_node_id = first_hop_node->id;
        } else if (payment->is_warmup && !fail_attack_in_warmup()) {
          /* warmup 決済には hold-to-timeout 型を発動しない (fail_attack_in_warmup 参照)。
           * hold 型と同じく fall through して下の通常送信処理に進む。 */
        } else {
        uint64_t base_delay = sample_base_forward_delay(simulation, net_params);
        uint64_t forward_delay = apply_attack_delay_if_needed(
          simulation, net_params, payment, base_delay, 1
        );
        uint64_t attack_event_time = simulation->current_time + forward_delay;

        /* 分母正常化: 検知が報告可能になる post-warmup の攻撃のみ first_attack_time を立てる。
         * (既定では warmup 決済にはそもそも攻撃が発動しない=fail_attack_in_warmup。以下は
         *  CLOTH_FAIL_ATTACK_IN_WARMUP=1 の旧挙動向けの保護として残している)
         * warmup 中の hold-to-timeout 攻撃は仮説検定が抑制され報告できないため、recall 分母
         * (observable_attacked=観測×攻撃)に数えると検知器を不当に減点する(測定アーティファクト)。
         * ゲートは is_warmup(injection ゲートと同根: 完了数基準は小 n で分母が過小/0 になる)。 */
        if (first_hop_node->first_attack_time == 0 && !payment->is_warmup) {
          first_hop_node->first_attack_time = attack_event_time;
        }

        /* この関数の前半で減算した最初のホップの残高/フロー計上を取り消す
         * (攻撃で HTLC は転送されない)。receive_fail() は error が最初のホップの
         * とき残高を復元しない前提のため、ここで戻しておく。 */
        next_edge->balance += first_route_hop->amount_to_forward;
        next_edge->tot_flows -= 1;

        /* HTLC fails due to malicious node attack. 攻撃者の特定は receive_fail() の
         * 観測ベース attribution に委ねる (悪意ノードの hop_send_times は 0 のまま)。 */
        payment->error.type = OFFLINENODE;
        payment->error.hop = first_route_hop;
        payment->offline_node_count += 1;

        next_event_time = attack_event_time + OFFLINELATENCY;
        next_event = new_event(next_event_time, RECEIVEFAIL, event->node_id, event->payment);
        simulation->events = heap_insert(simulation->events, next_event, compare_event);
        return;
        }
      }
    }
  }

  // success sending
  event_type = first_route_hop->to_node_id == payment->receiver ? RECEIVEPAYMENT : FORWARDPAYMENT;
  next_event_time = simulation->current_time + net_params.average_payment_forward_interval + (long)(fabs(net_params.variance_payment_forward_interval * gsl_ran_ugaussian(simulation->random_generator)));
  next_event = new_event(next_event_time, event_type, first_route_hop->to_node_id, event->payment);
  simulation->events = heap_insert(simulation->events, next_event, compare_event);
}

/* forward an HTLC for the payment (behavior of an intermediate hop node in a route) */
void forward_payment(struct event* event, struct simulation* simulation, struct network* network, struct network_params net_params){
  struct payment* payment;
  struct route* route;
  struct route_hop* next_route_hop, *previous_route_hop;
  long  prev_node_id;
  enum event_type event_type;
  struct event* next_event;
  uint64_t next_event_time;
  unsigned long is_next_node_offline;
  struct node* node;
  unsigned int is_last_hop;
  struct edge *next_edge = NULL, *prev_edge;
  struct node* next_node;

  payment = event->payment;
  node = array_get(network->nodes, event->node_id);
  route = payment->route;
  next_route_hop=get_route_hop(node->id, route->route_hops, 1);
  previous_route_hop = get_route_hop(node->id, route->route_hops, 0);
  is_last_hop = next_route_hop->to_node_id == payment->receiver;
    next_route_hop->edges_lock_start_time = simulation->current_time;

  /* === Stage ④ Hypothesis Testing: 自ノードの処理開始時刻を記録 ===
   * 攻撃チェックより前に記録することで、悪意ノードが攻撃で途中 return しても
   * 直前の正直ノードの hop_send_times[i] は確実に設定される。
   * セマンティクス: hop_send_times[i] = hop[i].from_node が処理を開始した時刻 */
  if (!payment->hop_send_times_initialized && route->route_hops != NULL) {
      int num_hops = route->route_hops->size;
      payment->hop_send_times = (uint64_t*)malloc(num_hops * sizeof(uint64_t));
      payment->hop_send_times_capacity = num_hops;
      payment->hop_send_times_initialized = 1;
      for (int k = 0; k < num_hops; k++) payment->hop_send_times[k] = 0;
  }
  if (payment->hop_send_times != NULL && route->route_hops != NULL) {
      for (int i = 0; i < route->route_hops->size; i++) {
          struct route_hop* rh = (struct route_hop*)array_get(route->route_hops, i);
          if (rh != NULL && rh->from_node_id == node->id) {
              if (i < payment->hop_send_times_capacity)
                  payment->hop_send_times[i] = reported_time(node, NULL, simulation->current_time, -1);
              break;
          }
      }
  }

  /* Stage ②: record incoming observation at this hop if it is a judge. */
  if (detect_and_record_htlc_observation(network, payment->id, payment->amount, node->id, 0, simulation->current_time, route)) {
    payment->is_observed = 1;
  }
  
  /* === Stage ② Payment Information Judging ===
   * If current node is a judge, record detailed HTLC observation
   * for later information integration and payment tracking. */
  if (node->is_judge) {
      record_htlc_observation(
          network,
          payment->id,                    // payment_id
          previous_route_hop->from_node_id,  // prev_node (information before this hop)
          next_route_hop->to_node_id,     // next_node (information after this hop)
          next_route_hop->amount_to_forward,  // amount
          simulation->current_time,       // timestamp
          next_route_hop->timelock,       // timelock
          node->id,                       // current_node (this judge)
          node->judge_id,               // judge_id
          0.0,    // channel_balance_before (not currently tracked)
          0.0,    // channel_balance_after (not currently tracked)
          0       // is_balance_adjustment (false for normal payments)
      );
  }

  if(!is_present(next_route_hop->edge_id, node->open_edges)) {
    printf("ERROR (forward_payment): edge %ld is not an edge of node %ld \n", next_route_hop->edge_id, node->id);
    exit(-1);
  }

  next_node = array_get(network->nodes, next_route_hop->to_node_id);

  /* simulate the case that the next node in the route is offline */
  is_next_node_offline = gsl_ran_discrete(simulation->random_generator, network->faulty_node_prob);
  if(is_next_node_offline && !is_last_hop){ //assume that the receiver node is always online
    uint64_t base_delay = sample_base_forward_delay(simulation, net_params);
    uint64_t network_delay = apply_attack_delay_if_needed(
      simulation, net_params, payment, base_delay, next_node->is_malicious && !is_last_hop
    );
    payment->offline_node_count += 1;
    payment->error.type = OFFLINENODE;
    payment->error.hop = next_route_hop;
    prev_node_id = previous_route_hop->from_node_id;
    event_type = prev_node_id == payment->sender ? RECEIVEFAIL : FORWARDFAIL;
    next_event_time = simulation->current_time + network_delay + OFFLINELATENCY;
    next_event = new_event(next_event_time, event_type, prev_node_id, event->payment);
    simulation->events = heap_insert(simulation->events, next_event, compare_event);
    return;
  }

  /* === Stage ① Malicious Node Attack Injection ===
   * If the next node is malicious, inject HTLC failure with attack_probability */
  if (next_node->is_malicious && !is_last_hop) {
    double attack_roll = gsl_rng_uniform(simulation->random_generator);
    if (attack_roll < next_node->attack_probability) {
      /* === 混在モード: 攻撃のうち一部を「保持(hold)型グリーフィング」にする ===
       * env CLOTH_GRIEF_HOLD_RATIO の確率で hold 型 (失敗させず通常転送し、
       * backward 経路でこのノードが preimage を保持して遅延)、残りは hold-to-timeout 型。
       * hold_ratio=0 のときは mode_roll を引かないので RNG ストリーム・挙動は不変。 */
      double hold_ratio = get_grief_hold_ratio();
      double mode_roll = (hold_ratio > 0.0)
          ? gsl_rng_uniform(simulation->random_generator) : 1.0;

      if (mode_roll < hold_ratio) {
        /* === HOLD 型: 失敗させない。決済経路での遅延注入を予約して通常転送 ===
         * first_attack_time は実際に保持遅延を注入する forward_success() で設定する
         * (途中で別要因により決済に到達しなかった場合はこのノードは「攻撃せず」)。
         * fall through (return しない) して下の通常転送処理に進む。 */
        payment->grief_hold_node_id = next_node->id;
      } else if (payment->is_warmup && !fail_attack_in_warmup()) {
        /* warmup 決済には hold-to-timeout 型を発動しない (fail_attack_in_warmup 参照)。
         * fall through して下の通常転送処理に進む。 */
      } else {
        /* === hold-to-timeout 型 (HTLC を保持してタイムアウト失敗させる; 旧称 fail型/forward型) === */
        uint64_t base_delay = sample_base_forward_delay(simulation, net_params);
        uint64_t forward_delay = apply_attack_delay_if_needed(
          simulation, net_params, payment, base_delay, 1
        );
        uint64_t attack_event_time = simulation->current_time + forward_delay;

        /* 分母正常化: post-warmup の攻撃のみ first_attack_time を計上
         * (理由・ゲート選択は send_payment 側の同種コメント参照; payment->is_warmup で判定)。 */
        if (next_node->first_attack_time == 0 && !payment->is_warmup) {
          next_node->first_attack_time = attack_event_time;
        }

        // HTLC fails due to malicious node attack
        payment->error.type = OFFLINENODE;  // Simulate as node failure
        payment->error.hop = next_route_hop;
        payment->offline_node_count += 1;

        /* NOTE: Detection must NOT use the ground-truth is_malicious label.
         * Because the malicious node fails the HTLC instead of forwarding, its
         * hop_send_times entry stays 0. 案D in receive_fail() blames the to_node of the
         * anomalous hop (= this node); the Phase 2 path-walk fallback is off by default. */

        prev_node_id = previous_route_hop->from_node_id;
        event_type = prev_node_id == payment->sender ? RECEIVEFAIL : FORWARDFAIL;
        next_event_time = attack_event_time + OFFLINELATENCY;
        next_event = new_event(next_event_time, event_type, prev_node_id, event->payment);
        simulation->events = heap_insert(simulation->events, next_event, compare_event);
        return;
      }
    }
  }

  // BEGIN -- NON-STRICT FORWARDING (cannot simulate it because the current blokchain height is needed)
  /* can_send_htlc = 0; */
  /* prev_edge = array_get(network->edges,previous_route_hop->edge_id); */
  /* for(i=0; i<array_len(node->open_edges); i++) { */
  /*   next_edge = array_get(node->open_edges, i); */
  /*   if(next_edge->to_node_id != next_route_hop->to_node_id) continue; */
  /*   can_send_htlc = check_balance_and_policy(next_edge, prev_edge, previous_route_hop, next_route_hop, is_last_hop); */
  /*   if(can_send_htlc) break; */
  /* } */

  /* if(!can_send_htlc){ */
  /*   next_edge = array_get(network->edges,next_route_hop->edge_id); */
  /*   printf("no balance: %ld < %ld\n", next_edge->balance, next_route_hop->amount_to_forward ); */
  /*   printf("prev_hop->timelock, next_hop->timelock: %d, %d + %d\n", previous_route_hop->timelock, next_route_hop->timelock, next_edge->policy.timelock ); */
  /*   payment->error.type = NOBALANCE; */
  /*   payment->error.hop = next_route_hop; */
  /*   payment->no_balance_count += 1; */
  /*   prev_node_id = previous_route_hop->from_node_id; */
  /*   event_type = prev_node_id == payment->sender ? RECEIVEFAIL : FORWARDFAIL; */
  /*   next_event_time = simulation->current_time + 100 + gsl_ran_ugaussian(simulation->random_generator);//prev_channel->latency; */
  /*   next_event = new_event(next_event_time, event_type, prev_node_id, event->payment); */
  /*   simulation->events = heap_insert(simulation->events, next_event, compare_event); */
  /*   return; */
  /* } */

  /* next_route_hop->edge_id = next_edge->id; */
  //END -- NON-STRICT FORWARDING

  // STRICT FORWARDING
  prev_edge = array_get(network->edges,previous_route_hop->edge_id);
  next_edge = array_get(network->edges, next_route_hop->edge_id);

  // fail no balance
  {
    uint64_t expected_fee = compute_fee(next_route_hop->amount_to_forward, next_edge->policy);
    if (cloth_debug_enabled()) fprintf(stderr, "[FORWARD_CHECK][FORWARD] payment=%ld edge=%ld required=%llu prev_amount=%llu expected_fee=%llu balance=%llu min_htlc=%llu\n", payment->id, next_route_hop->edge_id, (unsigned long long)next_route_hop->amount_to_forward, (unsigned long long)previous_route_hop->amount_to_forward, (unsigned long long)expected_fee, (unsigned long long)next_edge->balance, (unsigned long long)next_edge->policy.min_htlc);
  }
  if(!check_balance_and_policy(next_edge, prev_edge, previous_route_hop, next_route_hop)){
    uint64_t base_delay = sample_base_forward_delay(simulation, net_params);
    uint64_t network_delay = apply_attack_delay_if_needed(
      simulation, net_params, payment, base_delay, next_node->is_malicious && !is_last_hop
    );
    mark_no_response_failure(payment, next_route_hop);
    payment->no_balance_count += 1;
    prev_node_id = previous_route_hop->from_node_id;
    event_type = prev_node_id == payment->sender ? RECEIVEFAIL : FORWARDFAIL;
    next_event_time = simulation->current_time + network_delay;
    next_event = new_event(next_event_time, event_type, prev_node_id, event->payment);
    simulation->events = heap_insert(simulation->events, next_event, compare_event);
    return;
  }

  // update balance
  uint64_t prev_balance = next_edge->balance;
  next_edge->balance -= next_route_hop->amount_to_forward;

  next_edge->tot_flows += 1;

  // success forwarding
  event_type = is_last_hop  ? RECEIVEPAYMENT : FORWARDPAYMENT;
  // interval for forwarding payment
  {
    uint64_t base_delay = sample_base_forward_delay(simulation, net_params);
    uint64_t network_delay = apply_attack_delay_if_needed(
      simulation, net_params, payment, base_delay, next_node->is_malicious && !is_last_hop
    );
    next_event_time = simulation->current_time + network_delay;
  }
  next_event = new_event(next_event_time, event_type, next_route_hop->to_node_id, event->payment);
  simulation->events = heap_insert(simulation->events, next_event, compare_event);
}

/* receive a payment (behavior of the payment receiver node) */
void receive_payment(struct event* event, struct simulation* simulation, struct network* network, struct network_params net_params){
  long  prev_node_id;
  struct route* route;
  struct payment* payment;
  struct route_hop* last_route_hop;
  struct edge* forward_edge,*backward_edge;
  struct event* next_event;
  enum event_type event_type;
  uint64_t next_event_time;
  struct node* node;

  payment = event->payment;
  route = payment->route;
  node = array_get(network->nodes, event->node_id);
  payment->m3_rcv_arrive = simulation->current_time;   /* method3 の受取人の検定用 (受取人が HTLC を受け取った時刻) */

  last_route_hop = array_get(route->route_hops, array_len(route->route_hops) - 1);
  forward_edge = array_get(network->edges, last_route_hop->edge_id);
  backward_edge = array_get(network->edges, forward_edge->counter_edge_id);

  last_route_hop->edges_lock_end_time = simulation->current_time;

  if(!is_present(backward_edge->id, node->open_edges)) {
    printf("ERROR (receive_payment): edge %ld is not an edge of node %ld \n", backward_edge->id, node->id);
    exit(-1);
  }

  // update balance
  backward_edge->balance += last_route_hop->amount_to_forward;

  payment->is_success = 1;

  prev_node_id = last_route_hop->from_node_id;
  event_type = prev_node_id == payment->sender ? RECEIVESUCCESS : FORWARDSUCCESS;
  next_event_time = simulation->current_time + net_params.average_payment_forward_interval + (long)(fabs(net_params.variance_payment_forward_interval * gsl_ran_ugaussian(simulation->random_generator)));//channel->latency;
  /* 相互証明: 受信者が「最終中継ノードへ preimage を送った」と申告する時刻を
   * 末尾スロット(index=nh)に記録する。これで p=nh-1 も両隣の証明が揃い判定可能になる。
   * 受信者は送金の受け手であり保持攻撃者ではないので嘘モデルの対象外。 */
  if (payment->hop_settle_send_times != NULL && payment->route != NULL) {
      int nh_rcv = array_len(payment->route->route_hops);
      if (nh_rcv <= payment->hop_settle_recv_capacity)
          payment->hop_settle_send_times[nh_rcv] =
              reported_time(array_get(network->nodes, payment->receiver), payment, next_event_time, -1);
  }
  if (get_m3_hashchain() && net_params.judging_strategy == 3 && payment->m3_tags != NULL && payment->route != NULL) {
      int nh_rcv = array_len(payment->route->route_hops);
      if (nh_rcv < payment->m3_hc_cap) {
          payment->m3_true_send[nh_rcv] = next_event_time;
          m3_hc_sign(payment, nh_rcv, payment->receiver);
      }
  }
  next_event = new_event(next_event_time, event_type, prev_node_id, event->payment);
  simulation->events = heap_insert(simulation->events, next_event, compare_event);
}

/* forward an HTLC success back to the payment sender (behavior of a intermediate hop node in the route) */

void forward_success(struct event* event, struct simulation* simulation, struct network* network, struct network_params net_params){
  if (get_escrow() || escrow_params()->hold_legs > 0) escrow_bind(network);
  struct route_hop* prev_hop;
  struct payment* payment;
  struct edge* forward_edge, * backward_edge;
  long prev_node_id;
  struct event* next_event;
  enum event_type event_type;
  struct node* node;
  uint64_t next_event_time;

  payment = event->payment;
  prev_hop = get_route_hop(event->node_id, payment->route->route_hops, 0);
  forward_edge = array_get(network->edges, prev_hop->edge_id);
  backward_edge = array_get(network->edges, forward_edge->counter_edge_id);
  node = array_get(network->nodes, event->node_id);
  prev_hop->edges_lock_end_time = simulation->current_time;

  /* hold round-trip(案A): このノードが preimage を受け取った時刻(=このイベント発火時刻)を
   * from_node==node->id のホップ index に記録。往復時間 = recv - hop_send_times[idx]。 */
  if (get_hold_roundtrip() && payment->hop_settle_recv_times != NULL &&
      payment->route != NULL && payment->route->route_hops != NULL) {
      int nh_r = array_len(payment->route->route_hops);
      for (int hi = 0; hi < nh_r && hi < payment->hop_settle_recv_capacity; hi++) {
          struct route_hop* rh = (struct route_hop*)array_get(payment->route->route_hops, hi);
          if (rh != NULL && rh->from_node_id == node->id) {
              if (stays_silent_on_payment(node, payment)) { node->silence_count++; }
              else payment->hop_settle_recv_times[hi] = reported_time(node, payment, simulation->current_time, +1);
              break;
          }
      }
  }

  if(!is_present(backward_edge->id, node->open_edges)) {
    printf("ERROR (forward_success): edge %ld is not an edge of node %ld \n", backward_edge->id, node->id);
    exit(-1);
  }

  // update balance
  backward_edge->balance += prev_hop->amount_to_forward;

  prev_node_id = prev_hop->from_node_id;
  event_type = prev_node_id == payment->sender ? RECEIVESUCCESS : FORWARDSUCCESS;

  /* === settlement (backward) レグの保持時間 ===
   * 通常はランダムな転送インターバル。このノードが hold 型攻撃者として予約
   * (payment->grief_hold_node_id) されている場合は、forward leg の攻撃遅延
   * モデル(×attack_delay_intensity)を流用して preimage の release を遅延させる。
   * 失敗はさせない (= 支払いは成功する)。保持しない場合は従来と同一値。
   * この settle_base は forward leg のレイテンシとは独立にサンプリングされるので、
   * forward leg 側の遅延は hold 検知器の入力には一切入らない。 */
  uint64_t settle_base = net_params.average_payment_forward_interval +
      (long)(fabs(net_params.variance_payment_forward_interval * gsl_ran_ugaussian(simulation->random_generator)));
  uint64_t settle_delay = settle_base;
  int grief_held = 0;
  if (payment->grief_hold_node_id == node->id) {
    settle_delay = apply_attack_delay_if_needed(simulation, net_params, payment, settle_base, 1);
    grief_held = 1;
    /* 分母正常化: 実際に保持遅延が注入された (settle_delay>settle_base) ときのみ
     * first_attack_time を立てる。warmup 中や遅延無効時は注入されず検知可能な信号が
     * 出ない=「攻撃せず」なので recall の分母に数えない。これは first_attack_time の当初の設計意図
     * (「実際に保持遅延を注入する forward_success で設定」) を予約だけで立てていた
     * 実装に対して厳密化したもの。 */
    if (node->first_attack_time == 0 && settle_delay > settle_base)
      node->first_attack_time = simulation->current_time;
    payment->grief_hold_extra_ms = (settle_delay > settle_base) ? settle_delay - settle_base : 0;
    /* 賢い嘘: 嘘の量 (足した遅れ) はここで決まるので、上で記録した受領の申告を記録し直す (乱数は使わない) */
    if (get_false_report_smart() && get_hold_roundtrip() && payment->hop_settle_recv_times != NULL &&
        payment->route != NULL && payment->route->route_hops != NULL && !stays_silent_on_payment(node, payment)) {
      int nh_r = array_len(payment->route->route_hops);
      for (int hi = 0; hi < nh_r && hi < payment->hop_settle_recv_capacity; hi++) {
        struct route_hop* rh = (struct route_hop*)array_get(payment->route->route_hops, hi);
        if (rh != NULL && rh->from_node_id == node->id) {
          payment->hop_settle_recv_times[hi] = reported_time(node, payment, simulation->current_time, +1);
          break;
        }
      }
    }
    /* method3 の記録の書き換え: 付け替え先 (1 = 下流の隣、2 = 下流のどこか) までの記録を、足した遅れの分だけ遅くする */
    if (get_m3_tamper() && net_params.judging_strategy == 3 && node->is_malicious &&
        payment->grief_hold_extra_ms > 0 && get_hold_roundtrip() &&
        payment->hop_settle_recv_times != NULL && payment->hop_settle_send_times != NULL &&
        payment->route != NULL && payment->route->route_hops != NULL) {
      int nh_r = array_len(payment->route->route_hops);
      for (int hi = 0; hi < nh_r && hi < payment->hop_settle_recv_capacity; hi++) {   /* 送出の記録は容量+1 枠 */
        struct route_hop* rh = (struct route_hop*)array_get(payment->route->route_hops, hi);
        if (rh != NULL && rh->from_node_id == node->id) {
          int tgt = hi + 1;   /* 付け替え先の位置 (nh_r は受取人) */
          if (get_m3_tamper() == 2 && nh_r > hi + 1) {
            unsigned long h = ((unsigned long)payment->id * 2654435761UL) ^ ((unsigned long)node->id * 40503UL + 0x9E37UL);
            h ^= (h >> 15); h *= 2246822519UL; h ^= (h >> 13);
            tgt = hi + 1 + (int)(h % (unsigned long)(nh_r - hi));
          }
          if (tgt > payment->hop_settle_recv_capacity) tgt = payment->hop_settle_recv_capacity;
          int ok = (payment->hop_settle_send_times[tgt] != 0 && payment->hop_settle_recv_times[hi] != 0);
          for (int k = hi + 1; k < tgt && ok; k++)
            ok = (payment->hop_settle_recv_times[k] != 0 && payment->hop_settle_send_times[k] != 0);
          if (ok) {
            uint64_t X = payment->grief_hold_extra_ms;
            if (tgt == nh_r && get_m3_rcv_direct()) m3_rcv_direct_kept++;   /* 受取人の記録は直接届くので書き換えられない */
            else payment->hop_settle_send_times[tgt] += X;   /* 付け替え先 (tgt == nh は受取人) */
            for (int k = hi + 1; k < tgt; k++) { payment->hop_settle_recv_times[k] += X; payment->hop_settle_send_times[k] += X; }
            payment->hop_settle_recv_times[hi] += X;
            /* 鍵なしのハッシュチェーン: 書き換えた位置 (付け替え先からすぐ下流まで) の印を下流から順に作り直す。
             * 自分の印はこのあと作り直した印の上に付ける */
            if (get_m3_hashchain() && !get_m3_hc_keyed() && payment->m3_tags != NULL &&
                nh_r < payment->m3_hc_cap && nh_r <= payment->hop_settle_recv_capacity) {
              for (int k = tgt; k > hi; k--) {
                m3_hc_mac(payment, k, nh_r, m3_hc_node_at(payment, k, nh_r), payment->m3_tags + 32 * k);
                m3_hc_forged++;
              }
            }
            m3_tamper_count++;
            m3_tamper_dist_sum += tgt - hi;
            if (tgt == nh_r) m3_tamper_recv++;
          }
          break;
        }
      }
    }
  }
  next_event_time = simulation->current_time + settle_delay;
  /* 相互証明用: このノードが「上流へ preimage を送った」と申告する時刻。
   * 上流の hop_settle_recv_times[自分の1つ上] と同一イベントの二者申告になる。 */
  if (payment->hop_settle_send_times != NULL && payment->route != NULL) {
      int nh_s = array_len(payment->route->route_hops);
      for (int hi = 0; hi < nh_s && hi < payment->hop_settle_recv_capacity; hi++) {
          struct route_hop* rh = (struct route_hop*)array_get(payment->route->route_hops, hi);
          if (rh != NULL && rh->from_node_id == node->id) {
              if (!stays_silent_on_payment(node, payment))
                  payment->hop_settle_send_times[hi] = reported_time(node, payment, next_event_time, -1);
              break;
          }
      }
  }
  if (get_m3_hashchain() && net_params.judging_strategy == 3 && payment->m3_tags != NULL && payment->route != NULL) {
      int nh_s = array_len(payment->route->route_hops);
      for (int hi = 1; hi < nh_s && hi < payment->m3_hc_cap; hi++) {
          struct route_hop* rh = (struct route_hop*)array_get(payment->route->route_hops, hi);
          if (rh != NULL && rh->from_node_id == node->id) {
              payment->m3_true_recv[hi] = simulation->current_time;
              payment->m3_true_send[hi] = next_event_time;
              m3_hc_sign(payment, hi, node->id);
              break;
          }
      }
  }

  /* === シャドウ計測 (Phase 0): 報告はしない。各ノードの決済転送レイテンシを記録し、
   * 攻撃者(保持) vs 正常ノードの分離度(SNR) を実測する。CLOTH_GRIEF_SHADOW_LOG 時のみ。
   * 列: pid,node_id,is_malicious,degree,settle_delay_ms,settle_base_ms,held === */
  if (hold_shadow_log_enabled()) {
    long deg = (node->open_edges != NULL) ? array_len(node->open_edges) : 0;
    FILE* fh = fopen("/tmp/cloth_grief_shadow.csv", "a");
    if (fh) {
      fprintf(fh, "%llu,%ld,%d,%ld,%llu,%llu,%d\n",
              (unsigned long long)payment->id, node->id,
              node->is_malicious ? 1 : 0, deg,
              (unsigned long long)settle_delay, (unsigned long long)settle_base, grief_held);
      fclose(fh);
    }
  }

  /* === hold 検知器 (Phase 1): settlement レグの直接検定 (案B) ===
   * 各ノードの settlement レグ転送レイテンシ settle_delay を per-node 仮説検定し、
   * 異常(=保持)を出したノード本人を攻撃者として報告する。保持ノードは自分で release を
   * 転送するので直接帰属でよい(下流帰属トリック不要)。計測・報告者は上流ノード(prev_node_id)。
   * 観測ゲート(method1/method2)は fail 検知器と共通。既定 OFF (CLOTH_DETECT_GRIEF)。
   * 検知器に渡すのは (ノード, 観測レイテンシ, warmup 判定, seed) だけで、grief_hold_node_id
   * や is_malicious は渡さない = 攻撃型の事前ラベルなしで判定する。
   * ※ 案A(CLOTH_HOLD_ROUNDTRIP, 既定ON)有効時はこの直接検定を無効化し、receive_success の
   *    往復走査に一本化する(同一ノードを二重報告しないため)。 */
  if (net_params.enable_reputation_system && get_detect_hold() && !get_hold_roundtrip()) {
    int nh_b = (payment->route != NULL) ? array_len(payment->route->route_hops) : 0;
    int should_report = on_hold_hypothesis_test(
        node, (double)settle_delay,
        detector_in_warmup(payment, (long)simulation->processed_payments),
        (double)net_params.average_payment_forward_interval, nh_b);
    if (should_report && is_node_observed_by_judges(network, node->id)) {
      report_attacked_node_to_judges(
          network,
          prev_node_id,   /* reporter = 決済を受け取る上流ノード(保持を観測) */
          node->id,       /* attacker = 保持したノード本人(直接帰属) */
          payment->id,
          simulation->current_time,
          net_params);
    }
  }

  next_event = new_event(next_event_time, event_type, prev_node_id, event->payment);
  simulation->events = heap_insert(simulation->events, next_event, compare_event);
}

/* receive an HTLC success (behavior of the payment sender node) */
/* 送金者が preimage を受け取ったあとの保持の検定 (method2・method3。method3 のハッシュチェーンの検証と監視を含む)。
 * ハッシュチェーンの検証時間があるときは M3VERIFY のイベントで遅らせて呼ぶ */
static void hold_tests_on_success(struct payment* payment, struct simulation* simulation,
                                  struct network* network, struct network_params net_params) {
      int nh = array_len(payment->route->route_hops);
      double avg_iv = (double)net_params.average_payment_forward_interval;
      /* fail(receive_fail) は順方向 per-hop レイテンシ send[i+1]-send[i] を各ホップで検定し
       * 異常ホップの攻撃者を報告する。hold もこれに対称に、決済(backward)経路の per-hop
       * レイテンシ recv[i]-recv[i+1] (=下流ノード i+1 が決済を受領してから上流 i へ転送する
       * までの時間 = i+1 自身の保持時間 = (B)の settle_delay と同量) を各ペアで検定する。
       * 往復差分と違い順方向ホップのばらつきが混入しないためベースライン分散が膨らまず、
       * 保持者の取りこぼしが起きない。各異常ノード(=保持者)を報告(1決済1ノード dedup)。 */
      int anom_pos = -1;   /* この決済で直前に異常と判定した経路位置 (ペア検定の「説明済み」判定用) */
      /* 判定ノード経由の受け渡し・賢い嘘の検証用の記録 (warmup 後に保持者が実際に遅れを足した決済だけ) */
      long jc_rec = -1;
      if ((get_judge_copy() || get_false_report_smart() || get_m3_tamper()) && payment->grief_hold_node_id >= 0 &&
          payment->grief_hold_extra_ms > 0 && !detector_in_warmup(payment, (long)simulation->processed_payments)) {
          jc_rec = jc_push();
          if (jc_rec >= 0) {
              struct node* hn = (struct node*)array_get(network->nodes, payment->grief_hold_node_id);
              jc_recs[jc_rec].pid = payment->id;
              jc_recs[jc_rec].holder = payment->grief_hold_node_id;
              jc_recs[jc_rec].degree = (hn != NULL && hn->open_edges != NULL) ? array_len(hn->open_edges) : 0;
              jc_recs[jc_rec].extra = (double)payment->grief_hold_extra_ms;
          }
      }
      /* method3 のハッシュチェーン: 全部の印を確かめ、合わない位置 hc_fail より下流の記録は使わない */
      int hc_on = (net_params.judging_strategy == 3 && get_m3_hashchain() && payment->m3_tags != NULL && nh < payment->m3_hc_cap);
      int hc_fail = 0;
      if (hc_on) {
          m3_hc_init(network);
          hc_fail = m3_hc_verify(payment, nh);
          m3_hc_checked++;
          m3_xc_on = (get_m3_xcheck() > 0);
          m3_xc_fail = hc_fail;
          if (hc_fail > 0) {
              m3_hc_fail++;
              if (hc_fail >= 2 && m3_hc_node_at(payment, hc_fail - 1, nh) == payment->grief_hold_node_id) m3_hc_fail_match++;
              m3_hc_flag(network, simulation, payment, net_params, hc_fail, nh);
          }
      }
      for (int i = 0; i + 1 < nh; i++) {
          if (i + 1 >= payment->hop_settle_recv_capacity) break;
          if (hc_on) {
              int q = i + 1;
              long vq = m3_hc_node_at(payment, q, nh);
              if (m3_hc_watched_here(payment, q, nh, vq)) {   /* 監視中: 判定ノードの時計で測った保持を検定する */
                  struct jc_eval hev;
                  double lat = m3_hc_judge_hold(network, payment, q, nh, &hev);
                  struct node* qn = (struct node*)array_get(network->nodes, vq);
                  struct m3_target* tq = m3_target_of(network, vq);
                  if (lat > 0.0 && qn != NULL && tq != NULL) {
                      long an0 = tq->anomalies;
                      m3_hc_judge_target = vq;
                      int m3r = method3_observe(network, simulation, payment, net_params, q, qn, lat, 1, avg_iv, nh, 0.0);
                      m3_hc_judge_target = -1;
                      if (tq->anomalies > an0) {
                          m3_hc_resolve(vq, simulation->current_time);
                          if (get_m3_hc_culprit() == 3 && tq->ap == 1) {   /* 申し立て中の犯人: 負けで終わらせて罰を戻す */
                              m3_appeal_end(network, simulation, vq, 0);
                              m3_propagate(network, simulation, payment, net_params, vq);
                          }
                      }
                      m3_hc_meas++; m3_hc_load[m3_hc_jof[vq]]++;
                      if (vq == payment->grief_hold_node_id && payment->grief_hold_extra_ms > 0) {
                          m3_hc_meas_att++; m3_hc_hidden += hev.hidden_in + hev.hidden_out; m3_hc_extra += (double)payment->grief_hold_extra_ms;
                      }
                      if (jc_rec >= 0 && vq == payment->grief_hold_node_id) {
                          struct jc_record* r = &jc_recs[jc_rec];
                          r->evaluated = 1; r->hold_true = lat + hev.hidden_in + hev.hidden_out; r->hold_meas = lat;
                          r->hidden_in = hev.hidden_in; r->hidden_out = hev.hidden_out; r->delivered = hev.delivered;
                          r->fav_test = 1; r->reported = m3r;
                      }
                  }
                  continue;
              }
              if (hc_fail > 0 && q >= hc_fail - 1) continue;   /* 印が合わない記録を使う検定はしない */
          }
          uint64_t ru = payment->hop_settle_recv_times[i];      /* node i が決済を受領した時刻 */
          uint64_t rd = payment->hop_settle_recv_times[i + 1];  /* node i+1 が決済を受領した時刻 */
          /* 入れ子制約: 区間[send[i],recv[i]] は [send[i+1],recv[i+1]] を厳密に含むので
           * 物理的に必ず ru > rd。破れている = どちらかの申告が嘘(または欠測)。
           * 従来は黙って捨てていたが、嘘の痕跡として下流ノードに計上する。 */
          if (ru != 0 && rd != 0 && ru <= rd) {
              struct route_hop* hv = (struct route_hop*)array_get(payment->route->route_hops, i + 1);
              if (hv != NULL) {
                  struct node* vn = (struct node*)array_get(network->nodes, hv->from_node_id);
                  if (vn != NULL) vn->nesting_violation_count++;
              }
          }
          /* 欠測(黙秘)の扱い。被疑者(i+1)が記録を出していない場合、旧方式 (ATTEST=0) は
           * Δ の計算に本人の記録が要るので成立せず逃がすしかない。相互証明モードは
           * 帰属式が本人の記録を使わないので、ポリシー1なら帰属を続行できる。 */
          /* 被疑者本人の記録が使えないケースを一括で扱う:
           *   (a) 欠測(黙秘)       rd == 0
           *   (b) 入れ子制約違反   ru <= rd  (本人が受領時刻を盛ると発生)
           * どちらも「本人の申告が信用できない」だけであって、相互証明の帰属式
           * hold[p]=recv[p-1]-send_back[p+1] は本人の申告を使わないので成立する。
           * 従来はここで一律 continue して、**依存していない帰属まで捨てていた**。 */
          int accused_unusable = (rd == 0) || (ru <= rd);
          int bypass_ok = (get_report_attest() && get_attest_silence_policy());
          if (ru == 0) continue;
          if (accused_unusable && !bypass_ok) continue;
          double settle_lat = 0.0;
          if (accused_unusable) {
              /* 本人の記録は使えない。相互証明の両隣帰属に委ねる。 */
          } else if (get_hold_rt_selftime()) {
              /* fail対称版: 各ノードの自己観測 RT=recv-send の隣接差から resid を復元。
               * RT[i]-RT[i+1] = (recv[i]-recv[i+1]) + (send[i+1]-send[i]) なので、順方向
               * ホップ分を平均インターバルで差し引いて下流 i+1 の保持時間を推定する。 */
              uint64_t su  = payment->hop_send_times[i];
              uint64_t sdn = payment->hop_send_times[i + 1];
              if (su == 0 || sdn == 0) continue;
              double rti = (double)ru - (double)su;    /* node i の往復時間(自己観測) */
              double rtd = (double)rd - (double)sdn;   /* node i+1 の往復時間 */
              settle_lat = (rti - rtd) - avg_iv;       /* resid ≈ 下流 i+1 の保持時間 */
              if (settle_lat <= 0.0) continue;
          } else {
              settle_lat = (double)(ru - rd);          /* SELFTIME=0 のとき: recv[i]-recv[i+1] 直接 */
          }
          struct route_hop* hop_dn = (struct route_hop*)array_get(payment->route->route_hops, i + 1);
          struct route_hop* hop_up = (struct route_hop*)array_get(payment->route->route_hops, i);
          if (hop_dn == NULL || hop_up == NULL) continue;
          struct node* dn_node = (struct node*)array_get(network->nodes, hop_dn->from_node_id);
          if (dn_node == NULL) continue;
          long cand = hop_dn->from_node_id;   /* 攻撃者候補 = 下流ノード本人(保持者) */
          int fav_test = 0;                   /* (4a) 片側の食い違いを被疑者に有利な時刻で検定した */
          int dispute_up = 0, dispute_dn = 0; /* (4a) のとき食い違ったリンク */
          uint64_t sb_dn_anchor = 0;          /* 下流の送出申告 (ペア検定の下側の基準点) */
          struct node* up_node_p = NULL;
          int diag_p_silent = 0;              /* 診断ログ用: 本人の記録を使えない扱いにした */
          long esc_d1 = 0;                    /* 上側リンク (i, i+1) の食い違いの大きさ (エスカレーション) */

          /* === 相互証明モード (CLOTH_REPORT_ATTEST=1) ===========================
           * 被疑ノード p(=位置 i+1) 自身の申告を一切使わず、両隣の申告だけで
           * 保持時間を構成する:
           *     hold[p] = recv[p-1] (上流が「p から受け取った」と申告)
           *             - send_back[p+1] (下流が「p へ送った」と申告)
           * これにより p は自分の数字を盛って自己免罪することができない。
           * さらに、同一イベントを二者が申告している2本のリンクを突き合わせ、
           * 許容差を超えたら両端点に不一致を計上する。扱いはポリシーで決める:
           *   端のリンク (送金者・受取人と接する) → 端点の記録を信頼し、p の記録を使わずに続行
           *   2本とも食い違う → 共通点の p が原因と断定して続行 (DISPUTE_POLICY)
           *   1本だけ食い違う → (4a) p に一番有利な時刻で検定 (SINGLE_DISPUTE, 0 のときだけ破棄)
           * (単独の嘘はここで「冤罪」ではなく「不一致」に変換される)。 */
          struct jc_eval jce = {0.0, 0.0, 0};
          double hold_true = 0.0;              /* 検証用の記録: 両隣の本当の時刻から出した保持 */
          if (get_report_attest() && get_judge_copy()) {
              /* 判定ノード経由の受け渡し: 判定ノードの時計だけで保持を測る (食い違いの処理は使わない) */
              settle_lat = judge_copy_hold(network, payment, i + 1, &jce);
              if (settle_lat <= 0.0) continue;
              hold_true = settle_lat + jce.hidden_in + jce.hidden_out;
          } else if (get_report_attest()) {
              /* i+2 == nh は受信者の送出申告スロット。受信者証明が無い(0)なら従来どおり判定不能。 */
              if (i + 2 > nh || i + 2 > payment->hop_settle_recv_capacity) continue;
              if (payment->hop_settle_send_times == NULL) continue;
              uint64_t sb_p  = payment->hop_settle_send_times[i + 1]; /* p 自身の送信申告 */
              uint64_t sb_dn = payment->hop_settle_send_times[i + 2]; /* 下流の送信申告 */
              uint64_t rd2   = payment->hop_settle_recv_times[i + 1]; /* p 自身の受領申告 */
              if (sb_dn == 0) continue;            /* 隣人(下流)の記録が無ければ帰属不能 */
              hold_true = (ru > sb_dn) ? (double)(ru - sb_dn) : 0.0;   /* 嘘をつくのは保持者だけなので両隣は本当 */
              int p_silent = (sb_p == 0 || rd2 == 0 || accused_unusable);
              int sd_pol = get_attest_single_dispute();
              /* 因果違反: 本人の申告が「受け取る前に送った」になっている = 本人の記録は使えない。
               * 送出時刻だけを早く偽る嘘は入れ子制約(受領側)に掛からないので、ここで受ける。 */
              if (sd_pol >= 1 && !p_silent && sb_p <= rd2) {
                  p_silent = 1;
                  dn_node->causality_violation_count++;
              }
              /* 本人の記録が無い/入れ子違反で信用できない = 突き合わせはできないが帰属は成立する */
              if (p_silent && !get_attest_silence_policy()) continue;  /* 旧実装: 逃がす */
              long tol = get_attest_tolerance_ms();
              struct node* up_node = (struct node*)array_get(network->nodes, hop_up->from_node_id);
              struct route_hop* hop_dn2 = (struct route_hop*)array_get(payment->route->route_hops, i + 2);
              struct node* dn2_node = (hop_dn2 != NULL)
                  ? (struct node*)array_get(network->nodes, hop_dn2->from_node_id) : NULL;
              up_node_p = up_node;
              sb_dn_anchor = sb_dn;
              /* リンク(p-1,p): 上流の受領申告 vs p の送信申告 (同一イベント) */
              long d1 = (long)ru - (long)sb_p;  if (d1 < 0) d1 = -d1;
              /* リンク(p,p+1): p の受領申告 vs 下流の送信申告 (同一イベント) */
              long d2 = (long)rd2 - (long)sb_dn; if (d2 < 0) d2 = -d2;
              if (d1 > tol) esc_d1 = d1;
              /* 送金者(i==0 の上流)は判定をする本人なので自分の受領時刻を信頼する。
               * 食い違えば p の送信申告が嘘と決まるので、p の記録を使えない扱いにして帰属を続ける。 */
              if (!p_silent && i == 0 && d1 > tol && get_attest_trust_sender()) {
                  if (up_node) up_node->attest_dispute_count++;
                  dn_node->attest_dispute_count++;
                  p_silent = 1;
              }
              /* 受取人(i+2 == nh の下流)も同様に信頼すると、p の受領申告の嘘が決まる。 */
              if (!p_silent && i + 2 == nh && d2 > tol && get_attest_trust_receiver()) {
                  dn_node->attest_dispute_count++;
                  if (dn2_node) dn2_node->attest_dispute_count++;
                  p_silent = 1;
              }
              diag_p_silent = p_silent;
              if (p_silent) {
                  /* 突き合わせはできないが、両隣の記録だけで帰属は成立する。
                   * 黙秘そのものを証拠として計上し、帰属は続行する。 */
              } else if (d1 > tol && d2 > tol && get_attest_dispute_policy()) {
                  /* 2本とも食い違う = 共通点である被疑者本人の申告が原因と断定できる。
                   * 帰属式は本人の申告を使わないので、そのまま帰属を続行する。
                   * (痕跡としては両端点に計上しておく) */
                  if (up_node) up_node->attest_dispute_count++;
                  dn_node->attest_dispute_count++;
                  if (dn2_node) dn2_node->attest_dispute_count++;
              } else if (d1 > tol || d2 > tol) {
                  if (d1 > tol) { if (up_node) up_node->attest_dispute_count++;
                                  dn_node->attest_dispute_count++; }
                  if (d2 > tol) { dn_node->attest_dispute_count++;
                                  if (dn2_node) dn2_node->attest_dispute_count++; }
                  if (sd_pol == 0) continue;   /* 従来: 不一致リンクからは帰属しない */
                  /* (4a) 食い違ったリンクの時刻は p に一番有利なほうを採る:
                   *   上端(p が上流へ渡した時刻) = 早いほう, 下端(p が受け取った時刻) = 遅いほう。
                   * 正直な p なら自分の正しい申告が選ばれるので隣人の嘘では膨らまない。 */
                  dispute_up = (d1 > tol);
                  dispute_dn = (d2 > tol);
                  uint64_t upper = (ru < sb_p) ? ru : sb_p;
                  uint64_t lower = (sb_dn > rd2) ? sb_dn : rd2;
                  if (upper <= lower) continue;
                  settle_lat = (double)(upper - lower);
                  fav_test = 1;
              }
              if (!fav_test) {
                  if (ru <= sb_dn) continue;
                  settle_lat = (double)(ru - sb_dn);   /* 両隣の申告のみで構成 */
              }
          }
          if (getenv("CLOTH_HOLD_RT_DEBUG") && payment->grief_hold_node_id >= 0) {
              FILE* _f = fopen("/tmp/holdrt_debug.csv", "a");
              if (_f) { fprintf(_f, "%llu,%d,%ld,%ld,%ld,%d,%.0f\n",
                  (unsigned long long)payment->id, i, hop_up->from_node_id, cand,
                  payment->grief_hold_node_id, (cand == payment->grief_hold_node_id) ? 1 : 0, settle_lat);
                  fclose(_f); }
          }
          if (get_escrow() && !escrow_params()->excuse) {
              struct escrow_link L;
              escrow_link_eval(cand, hop_dn->to_node_id, payment->id, dn_node->is_malicious, &L);
              if (L.r > L.D) settle_lat += L.D + L.e - L.er;
          }
          double legs_var = 0.0;   /* この標本の片道のばらつき (標本ごとの標準化に渡す) */
          if (escrow_params()->hold_legs > 0) {
              /* 測る保持に含まれる片道の遅れ: 1本目 = 下流 (送り手) → 本人、2本目 = 本人 → 上流 */
              struct escrow_link L;
              int norm = escrow_params()->legs_norm;
              escrow_link_eval(cand, hop_dn->to_node_id, payment->id, 0, &L);
              settle_lat += L.leg - (norm ? L.leg_mean : 0.0);
              legs_var += L.leg_var;
              if (escrow_params()->hold_legs >= 2) {
                  escrow_link_eval(hop_up->from_node_id, cand, payment->id, 0, &L);
                  settle_lat += L.leg - (norm ? L.leg_mean : 0.0);
                  legs_var += L.leg_var;
              }
              if (settle_lat < 1.0) settle_lat = 1.0;
          }
          if (get_escrow() && escrow_params()->jitter_in_hold && !escrow_params()->anchor_key &&
              !lies_on_this_payment(dn_node, payment)) {
              /* 起点 = オファー時刻 + 予想往復 なので、期限内の往復のぶれ (r - E[r]) は保持に混ざる */
              struct escrow_link L;
              escrow_link_eval(cand, hop_dn->to_node_id, payment->id, dn_node->is_malicious, &L);
              if (L.r <= L.D) {
                  settle_lat += L.r - L.er;
                  if (settle_lat < 1.0) settle_lat = 1.0;
              }
          }
          /* method3: 判定ノードの共通の基準値ではなく、経路上の各判定者が自分の基準値で検定して告発する。
           * ペア検定・従来の報告は使わない */
          if (net_params.judging_strategy == 3) {
              if (m3_xc_on && !fav_test) {   /* 照らし合わせのまとめた基準値を学ぶ (送金者が確かめた記録の全部のホップ) */
                  hold_set_sample_var(0.0);
                  (void)on_hold_hypothesis_test(m3_shadow_pool(payment->sender), settle_lat,
                                                detector_in_warmup(payment, (long)simulation->processed_payments), avg_iv, nh);
              }
              if (hc_on && !fav_test) {   /* 測り方の確認: 記録の保持と判定ノードの時計の保持 (隠す手口なし) が同じか */
                  struct jc_eval cev;
                  double jl = m3_hc_judge_hold(network, payment, i + 1, nh, &cev);
                  if (jl > 0.0 && cev.hidden_in + cev.hidden_out == 0.0) { m3_hc_cmp++; if (fabs(jl - settle_lat) < 0.5) m3_hc_same++; }
              }
              int m3r = method3_observe(network, simulation, payment, net_params, i + 1, dn_node, settle_lat,
                                        fav_test, avg_iv, nh, legs_var);
              if (jc_rec >= 0 && cand == payment->grief_hold_node_id) {   /* 攻撃ごとの記録 (検証用) */
                  struct jc_record* r = &jc_recs[jc_rec];
                  r->evaluated = 1; r->hold_true = hold_true; r->hold_meas = settle_lat;
                  r->fav_test = fav_test; r->reported = m3r;
              }
              continue;
          }
          /* fail と同じく per-hop で検定(保持ノード本人の backward レイテンシを直接)。
           * (4a) の標本は片方が嘘なので学習しない版で検定する。 */
          hold_set_sample_var(legs_var);
          int should_report = fav_test
              ? on_hold_hypothesis_test_nolearn(
                    dn_node, settle_lat,
                    detector_in_warmup(payment, (long)simulation->processed_payments), avg_iv, nh)
              : on_hold_hypothesis_test(
                    dn_node, settle_lat,
                    detector_in_warmup(payment, (long)simulation->processed_payments), avg_iv, nh);
          {
              /* 診断 (env CLOTH_SETTLE_ZLOG): warmup 後の検定ごとの z を書き出す
               * 決済,ノード,次数,悪意,この決済の保持者か,(4a)か,そのノードの検定回数,z,σ,報告したか */
              static FILE* zf = NULL; static int zinit = 0;
              if (!zinit) { zinit = 1; const char* zp = getenv("CLOTH_SETTLE_ZLOG");
                            if (zp != NULL && zp[0] != '\0') zf = fopen(zp, "w"); }
              if (zf != NULL && !detector_in_warmup(payment, (long)simulation->processed_payments))
                  fprintf(zf, "%ld,%ld,%ld,%d,%d,%d,%ld,%.4f,%.5f,%d\n", payment->id, cand,
                          (dn_node->open_edges != NULL) ? array_len(dn_node->open_edges) : 0L,
                          dn_node->is_malicious ? 1 : 0, (payment->grief_hold_node_id == cand) ? 1 : 0,
                          fav_test, dn_node->settle_test_count, hold_last_z(), hold_last_sd(), should_report);
          }
          if (jc_rec >= 0 && cand == payment->grief_hold_node_id) {
              struct jc_record* r = &jc_recs[jc_rec];
              r->evaluated = 1; r->hold_true = hold_true; r->hold_meas = settle_lat;
              r->hidden_in = jce.hidden_in; r->hidden_out = jce.hidden_out; r->delivered = jce.delivered;
              r->fav_test = fav_test; r->reported = should_report;
          }
          if (should_report && cand != payment->sender && cand != payment->receiver &&
              is_node_observed_by_judges(network, cand) &&
              !has_attack_reporter(payment, cand)) {   /* dedup: 同一決済で同一ノードは1回 */
              register_attack_reporter(payment, cand); /* dedup キーとして保持者を記録 */
              report_attacked_node_to_judges(network, hop_up->from_node_id, cand,
                  payment->id, simulation->current_time, net_params);
              int newly_confirmed = (dn_node->hold_reports_main + dn_node->hold_reports_fav == 0);
              if (fav_test) dn_node->hold_reports_fav++; else dn_node->hold_reports_main++;
              /* このノードが初めて個別の検定で確定した: これとペアになったノードの集計の報告を見直す */
              if (newly_confirmed && get_attest_pair_revoke()) {
                  for (int j = 0; j < dn_node->pair_partner_count; j++)
                      pair_recheck(network,
                          (struct node*)array_get(network->nodes, dn_node->pair_partners[j]), net_params);
              }
          }
          if (should_report) anom_pos = i + 1;

          /* 診断ログ (env CLOTH_ATTEST_DIAG_LOG=<path>): warmup 後に実際に保持遅延が入った決済で、
           * 被疑者か上流が保持者である評価を1行ずつ書く。位置別・端点別の内訳を出すため。 */
          {
              const char* dlog = getenv("CLOTH_ATTEST_DIAG_LOG");
              long holder = payment->grief_hold_node_id;
              if (dlog != NULL && dlog[0] != '\0' && holder >= 0 &&
                  payment->attack_delay_event_count > 0 &&
                  !detector_in_warmup(payment, (long)simulation->processed_payments) &&
                  (cand == holder || hop_up->from_node_id == holder)) {
                  FILE* df = fopen(dlog, "a");
                  if (df != NULL) {
                      fprintf(df, "%ld,%d,%d,%ld,%ld,%ld,%ld,%d,%d,%d,%d,%.0f,%d\n",
                          payment->id, nh, i + 1, cand, hop_up->from_node_id, holder,
                          (dn_node->open_edges != NULL) ? array_len(dn_node->open_edges) : 0,
                          diag_p_silent, fav_test, dispute_up, dispute_dn, settle_lat, should_report);
                      fclose(df);
                  }
              }
          }

          /* (4b) 有利な時刻でも正常に見えた = 嘘が保持時間のほとんどを隣へ付け替えた可能性。
           * 食い違ったリンクの両端 {i, i+1} の合計保持を、2人の外側の記録
           * (i-1 の受領申告と i+2 の送出申告) だけで測って検定する。合計は2人の間の
           * 付け替えでは動かないので、異常なら「2人のどちらか」が保持したと確定する。
           * 下側リンク(p, p+1)の食い違いは次の反復で p+1 の上側リンクとして扱う。 */
          /* 食い違いの記録 (エスクロー方式): 上側リンク (i, i+1) が食い違っていれば、その2人をペアとして
           * 記録する。送金者とのリンク (i == 0) は送金者の信頼で決着済み、受取人とのリンクは被疑者の
           * 下側なのでここには来ない。warmup 中は記録しない (warmup でも予約された保持者は嘘をつくが
           * 割合の分母は warmup 後の検定数なので)。この決済で既に報告されたノードを含むなら説明済み。 */
          if (get_attest_dispute_flags() && !get_escrow() && esc_d1 > 0 && i >= 1 && up_node_p != NULL &&
              !should_report && anom_pos != i &&
              !detector_in_warmup(payment, (long)simulation->processed_payments)) {
              handle_pair_flag(network, simulation, payment, net_params, up_node_p, dn_node, (double)esc_d1);
          }
          if (fav_test && !should_report && get_attest_single_dispute() >= 2 && !get_attest_dispute_flags() && !get_escrow()) {
              if (dispute_up && anom_pos != i) {   /* 上流 i が既に異常判定なら説明済み */
                  if (i == 0 || up_node_p == NULL) {
                      dn_node->pair_endpoint_skips++;   /* 相手が送金者: 外側の基準点が無い */
                  } else {
                      uint64_t anchor_up = payment->hop_settle_recv_times[i - 1];
                      if (anchor_up > sb_dn_anchor &&
                          on_hold_pair_test(up_node_p, dn_node, (double)(anchor_up - sb_dn_anchor),
                              detector_in_warmup(payment, (long)simulation->processed_payments),
                              avg_iv, nh)) {
                          handle_pair_flag(network, simulation, payment, net_params,
                                           up_node_p, dn_node, (double)(anchor_up - sb_dn_anchor));
                      }
                  }
              }
              if (dispute_dn && i + 2 == nh)
                  dn_node->pair_endpoint_skips++;       /* 相手が受取人: 外側の基準点が無い */
          }
      }

      /* method3 の嘘のパターン (CLOTH_M3_FALSE_ACCUSE): 保持者が下流の隣を告発する。
       * この決済の正直な判定者の検定のあとに処理する (同じ決済で確定した嘘つきの告発を対策で捨てられるように) */
      if (net_params.judging_strategy == 3 && get_m3_rcv_test()) {   /* 受取人の保持も検定する */
          double lat_j = 0.0;
          if (hc_on && m3_hc_watched_here(payment, nh, nh, payment->receiver)) {   /* 監視中の受取人は判定ノードの時計で測る */
              struct jc_eval rev;
              lat_j = m3_hc_judge_hold(network, payment, nh, nh, &rev);
          }
          if (!hc_on || lat_j > 0.0 || hc_fail == 0)   /* 印が合わない (受取人の記録を使えない) ときはしない */
              method3_receiver_test(network, simulation, payment, net_params, nh, avg_iv, lat_j);
      }
      if (net_params.judging_strategy == 3) method3_false_accuse(network, simulation, payment, net_params);
      if (net_params.judging_strategy == 3) method3_sender_false_accuse(network, simulation, payment, net_params);
      m3_xc_on = 0; m3_xc_fail = 0;

      /* エスクロー方式: 受け渡しごとのタイムアウト (判定ノードへのエスカレーション) を記録する。
       * 受け手 = hop k の from (中継), 送り手 = hop k の to。送金者が受け手の k=0 は除く。
       * タイムアウトした受け渡しの2人をペアとして (5) の集計に回す (この決済で既に報告済みなら説明済み)。
       * 統計ログ (env CLOTH_ESCROW_STATS_LOG): P,決済,受け渡し数,鍵待ちの合計,正直なタイムアウト,攻撃者のタイムアウト
       *                                       ,Tor の受け渡し数,そのうち正直なタイムアウト,遅い処理の受け手の受け渡し数,そのうち正直なタイムアウト,受け手が攻撃者の受け渡し数
       *                                       H,決済,保持者,隠した量,タイムアウトの手口か
       *                                       K,受け手,送り手,タイムアウトしたか,嘘をついたか (受け渡しごと) */
      if (get_escrow() && !detector_in_warmup(payment, (long)simulation->processed_payments)) {
          const char* slog = getenv("CLOTH_ESCROW_STATS_LOG");
          FILE* sf = (slog != NULL && slog[0] != '\0') ? fopen(slog, "a") : NULL;
          double sum_wait = 0.0;
          int n_to_honest = 0, n_to_att = 0, n_hand = 0;
          int n_hand_tor = 0, n_to_h_tor = 0, n_hand_slow = 0, n_to_h_slow = 0, n_mal_recv = 0;
          for (int k = 1; k < nh; k++) {
              struct route_hop* rh = (struct route_hop*)array_get(payment->route->route_hops, k);
              if (rh == NULL) continue;
              struct node* rn = (struct node*)array_get(network->nodes, rh->from_node_id);
              struct node* on = (struct node*)array_get(network->nodes, rh->to_node_id);
              if (rn == NULL || on == NULL) continue;
              struct escrow_link L;
              escrow_link_eval(rn->id, on->id, payment->id, rn->is_malicious, &L);
              int lying = lies_on_this_payment(rn, payment);
              int via = 0;
              double H = lying ? escrow_hide(&L, &via) : 0.0;
              int timed_out = lying ? via : (L.r > L.D);
              sum_wait += timed_out ? (L.D + L.e) : L.r;
              n_hand++;
              if (timed_out) { if (lying) n_to_att++; else n_to_honest++; }
              int slow = escrow_proc_of(rn->id) > 0.0;
              if (L.tor) { n_hand_tor++; if (timed_out && !lying) n_to_h_tor++; }
              if (slow) { n_hand_slow++; if (timed_out && !lying) n_to_h_slow++; }
              if (rn->is_malicious) n_mal_recv++;
              if (timed_out && !has_attack_reporter(payment, rn->id) && !has_attack_reporter(payment, on->id))
                  handle_pair_flag(network, simulation, payment, net_params, rn, on,
                                   timed_out ? (L.D + L.e) : L.r);
              if (lying && sf != NULL)
                  fprintf(sf, "H,%ld,%ld,%.1f,%d\n", payment->id, rn->id, H, via);
              if (sf != NULL)
                  fprintf(sf, "K,%ld,%ld,%d,%d\n", rn->id, on->id, timed_out, lying);
          }
          if (sf != NULL) {
              fprintf(sf, "P,%ld,%d,%.1f,%d,%d,%d,%d,%d,%d,%d\n", payment->id, n_hand, sum_wait, n_to_honest, n_to_att,
                      n_hand_tor, n_to_h_tor, n_hand_slow, n_to_h_slow, n_mal_recv);
              fclose(sf);
          }
      }
}
void method3_verify_event(struct event* event, struct simulation* simulation, struct network* network, struct network_params net_params) {
  struct payment* payment = event->payment;
  long saved = simulation->processed_payments;   /* warmup の旧判定は受け取った時点の数で */
  simulation->processed_payments = payment->m3_proc_at;
  hold_tests_on_success(payment, simulation, network, net_params);
  simulation->processed_payments = saved;
  m3_hc_deferred++;
}

void receive_success(struct event* event, struct simulation* simulation, struct network* network, struct network_params net_params){
  if (get_escrow() || escrow_params()->hold_legs > 0) escrow_bind(network);
  struct node* node;
  struct payment* payment;
  payment = event->payment;
  node = array_get(network->nodes, event->node_id);
  event->payment->end_time = simulation->current_time;
  {
    static int jc_printed = 0;
    if (!jc_printed && (get_judge_copy() || get_false_report_smart())) {
      jc_printed = 1;
      printf("[JudgeCopy] 判定ノード経由=%d T=%.0fms 賢い嘘=%d 嘘のスイッチ=%ldms 側=%s\n",
             get_judge_copy(), get_judge_copy_t_ms(), get_false_report_smart(), get_false_report_ms(),
             get_false_report_side() == FALSE_REPORT_SIDE_RECV ? "recv" :
             get_false_report_side() == FALSE_REPORT_SIDE_SEND ? "send" : "both");
    }
  }

  add_attempt_history(payment, network, simulation->current_time, 1);

  /* === Stage ④ Hypothesis Testing: Increment global payment counter === */
  simulation->processed_payments++;

  /* === hold round-trip 検出 (案A, CLOTH_HOLD_ROUNDTRIP)：隣接差分版 ===
   * 各ノードの往復時間 RT[i] = recv[i] - send[i] は自ノードだけで観測可能。経路上の隣接
   * ノードの差 Δ[i] = RT[i] - RT[i+1] は導出上「下流ノード(i+1)の決済転送遅延 settle_delay
   * ＋1本の順方向ホップ」に等しい。よって resid = Δ[i] - 平均インターバル ≈ 下流ノード
   * (i+1)の settle_delay を、観測可能な往復量だけから復元できる(希釈なし=(B)と同じ信号)。
   * この resid を下流ノードの settle 検定にかけ、異常なノードを報告する(報告者=上流ノード、
   * 同じ決済で同じノードは1回)。**既定 ON**。既定の相互証明 (CLOTH_REPORT_ATTEST=1) では
   * 検定値を下の相互証明モードの hold[p]=recv[p-1]-send_back[p+1] に置き換える。 */
  if (get_hold_roundtrip() && net_params.enable_reputation_system &&
      payment->route != NULL && payment->hop_send_times != NULL &&
      payment->hop_settle_recv_times != NULL) {
      int nh = array_len(payment->route->route_hops);
      /* 送信者(=このノード)の preimage 受信時刻を記録 */
      for (int i = 0; i < nh && i < payment->hop_settle_recv_capacity; i++) {
          struct route_hop* rh = (struct route_hop*)array_get(payment->route->route_hops, i);
          if (rh != NULL && rh->from_node_id == node->id) {
              payment->hop_settle_recv_times[i] = reported_time(node, payment, simulation->current_time, +1); break;
          }
      }
      payment->num_attack_reporters = 0;   /* 試行ごとに初期化(dedup キー兼用) */
      uint64_t hc_dly = 0;
      if (net_params.judging_strategy == 3 && get_m3_hashchain() && get_m3_hc_verify_ms() > 0.0)
          hc_dly = (uint64_t)(get_m3_hc_verify_ms() * (double)nh + 0.5);
      if (hc_dly > 0) {   /* ハッシュチェーンの検証時間: 印を確かめ終えてから検定・告発する */
          payment->m3_proc_at = (long)simulation->processed_payments;
          struct event* ve = new_event(simulation->current_time + hc_dly, M3VERIFY, node->id, payment);
          simulation->events = heap_insert(simulation->events, ve, compare_event);
      } else {
          hold_tests_on_success(payment, simulation, network, net_params);
      }
  }

  /* === Stage ④ fail 検知器: forward leg のホップ間レイテンシで各ノードを個別検定 ===
   * hop_send_times[i]     : ホップ i の送信時刻
   * hop_send_times[i+1]   : ホップ i+1 の送信時刻（= ホップ i の処理+転送完了時刻）
   * 最終ホップは result_time（= receive_success の現在時刻）を終端とする。
   * これにより判定ノードの有無に関係なく各ノードの処理遅延を独立に検定できる。
   * ここは成功経路なので is_fail=0 で呼ぶ = 報告はしない (下のコメント参照)。 */
  if (net_params.enable_reputation_system && payment->route != NULL && payment->hop_send_times != NULL) {
      int n_hops = array_len(payment->route->route_hops);
      for (int hop_idx = 0; hop_idx < n_hops; hop_idx++) {
          struct route_hop* hop = (struct route_hop*)array_get(
                                      payment->route->route_hops, hop_idx);
          if (hop == NULL) continue;

          struct node* hop_node = (struct node*)array_get(
                                      network->nodes, hop->from_node_id);
          if (hop_node == NULL) continue;

          uint64_t t_start = (hop_idx < payment->hop_send_times_capacity)
                             ? payment->hop_send_times[hop_idx] : 0;
          if (t_start == 0) continue;

          /* ホップ i の終端時刻:
           *   中間ホップ → 次ホップの送信時刻
           *   最終ホップ → result_time */
          uint64_t t_end;
          if (hop_idx + 1 < n_hops &&
              hop_idx + 1 < payment->hop_send_times_capacity &&
              payment->hop_send_times[hop_idx + 1] > t_start) {
              t_end = payment->hop_send_times[hop_idx + 1];
          } else {
              t_end = simulation->current_time;
          }
          if (t_end <= t_start) continue;

          /* 成功経路の検定はベースライン更新と Axis-2 用カウンタ
           * (hyp_test_count/hyp_anomaly_count) の蓄積のみが目的。
           * on_fail_hypothesis_test (fail 検知器) は is_fail=1 のときしか
           * should_report を立てない (monitoring.c の k-of-m / 1-strike 両分岐)
           * ため、ここでの報告は構造的に発生しない。以前ここにあった報告ブロックは
           * 到達不能なデッドコードだったので除去した。fail 型の報告は receive_fail 側、
           * hold 型の報告は receive_success の hold 検知器 (案A・相互証明, 既定) が担う。
           * ⚠️ したがって「forward leg で遅延させるが失敗させない」攻撃 (slow-forward)
           *    はどちらの検知器も報告しない。異常自体は上の hyp_anomaly_count に
           *    載るので、拾えるのは Axis-2 BH-FDR モード (CLOTH_FLAG_MODE=bh) のみ。 */
          (void) on_fail_hypothesis_test(
              hop_node,
              t_start,
              t_end,
              detector_in_warmup(payment, (long)simulation->processed_payments),
              0           /* is_fail = 0 */
          );
      }
  }

  // === Dynamic Reputation Update: Success Path ===
  // When payment succeeds, increase reputation of nodes in successful path
  if (net_params.judging_strategy > 0 && net_params.enable_reputation_system && payment->route != NULL) {
    double reputation_boost = 0.05;  // Increase reputation by 5% on success
    for (int i = 0; i < array_len(payment->route->route_hops); i++) {
      struct route_hop* hop = (struct route_hop*)array_get(payment->route->route_hops, i);
      if (hop != NULL) {
        struct node* hop_node = (struct node*)array_get(network->nodes, hop->from_node_id);
        /* boost抑制(env-gated): 報告のあるノードは成功転送boostで評判回復させない */
        if (hop_node != NULL && hop_node->reputation_score < 1.0 && !boost_suppressed_for(hop_node)) {
          hop_node->reputation_score += reputation_boost;
          if (hop_node->reputation_score > 1.0) {
            hop_node->reputation_score = 1.0;
          }
        }
      }
    }
  }

    // next event
    uint64_t next_event_time = simulation->current_time + net_params.group_broadcast_delay;

    // request_group_update event
    if (net_params.routing_method == GROUP_ROUTING) {
        struct event *next_event = new_event(next_event_time, UPDATEGROUP, event->node_id, event->payment);
        simulation->events = heap_insert(simulation->events, next_event, compare_event);
    }

    // channel update broadcast event
    struct event *channel_update_event = new_event(next_event_time, CHANNELUPDATESUCCESS, node->id, payment);
    simulation->events = heap_insert(simulation->events, channel_update_event, compare_event);
}

/* forward an HTLC fail back to the payment sender (behavior of a intermediate hop node in the route) */
void forward_fail(struct event* event, struct simulation* simulation, struct network* network, struct network_params net_params){
  struct payment* payment;
  struct route_hop* next_hop, *prev_hop;
  struct edge* next_edge;
  long prev_node_id;
  struct event* next_event;
  enum event_type event_type;
  struct node* node;
  uint64_t next_event_time;

  node = array_get(network->nodes, event->node_id);
  payment = event->payment;
  next_hop = get_route_hop(event->node_id, payment->route->route_hops, 1);
  next_edge = array_get(network->edges, next_hop->edge_id);

  if(!is_present(next_edge->id, node->open_edges)) {
    printf("ERROR (forward_fail): edge %ld is not an edge of node %ld \n", next_edge->id, node->id);
    exit(-1);
  }

  next_hop->edges_lock_end_time = simulation->current_time;

  /* since the payment failed, the balance must be brought back to the state before the payment occurred */
  uint64_t prev_balance = next_edge->balance;
  next_edge->balance += next_hop->amount_to_forward;

  prev_hop = get_route_hop(event->node_id, payment->route->route_hops, 0);
  prev_node_id = prev_hop->from_node_id;
  event_type = prev_node_id == payment->sender ? RECEIVEFAIL : FORWARDFAIL;
  next_event_time = simulation->current_time + net_params.average_payment_forward_interval + (long)(fabs(net_params.variance_payment_forward_interval * gsl_ran_ugaussian(simulation->random_generator)));//prev_channel->latency;
  next_event = new_event(next_event_time, event_type, prev_node_id, event->payment);
  simulation->events = heap_insert(simulation->events, next_event, compare_event);
}

/* receive an HTLC fail (behavior of the payment sender node) */
void receive_fail(struct event* event, struct simulation* simulation, struct network* network, struct network_params net_params){
  struct payment* payment;
  struct route_hop* first_hop, *error_hop;
  struct edge* next_edge, *error_edge;
  struct event* next_event;
  struct node* node;
  uint64_t next_event_time;

  payment = event->payment;
  node = array_get(network->nodes, event->node_id);

  error_hop = payment->error.hop;
  error_edge = array_get(network->edges, error_hop->edge_id);
  if(error_hop->from_node_id != payment->sender){ // if the error occurred in the first hop, the balance hasn't to be updated, since it was not decreased
    first_hop = array_get(payment->route->route_hops, 0);
    next_edge = array_get(network->edges, first_hop->edge_id);
    if(!is_present(next_edge->id, node->open_edges)) {
      printf("ERROR (receive_fail): edge %ld is not an edge of node %ld \n", next_edge->id, node->id);
      exit(-1);
    }

    uint64_t prev_balance = next_edge->balance;
    next_edge->balance += first_hop->amount_to_forward;
  }

/* print FAIL_NO_BALANCE error
    struct channel* channel = array_get(network->channels, error_edge->channel_id);
    printf("\n\tERROR : RECEIVE_FAIL on sending payment(id=%ld, amount=%lu) at edge(id=%ld, balance=%lu, htlc_max_msat=%lu, channel_capacity=%lu) ", payment->id, payment->amount, error_edge->id, error_edge->balance, ((struct channel_update*)(error_edge->channel_updates->data))->htlc_maximum_msat, channel->capacity);
    printf("\n\tPATH  : ");
    for(int i = 0; i < array_len(payment->route->route_hops); i++){
        struct route_hop* hop = array_get(payment->route->route_hops, i);
        struct edge* edge = array_get(network->edges, hop->edge_id);
        printf("(edge_id=%ld,edge_balance=%lu,", edge->id, edge->balance);
        if(edge->group != NULL) {
            printf("group_id=%ld,group_cap=%lu)", edge->group->id, edge->group->group_cap);
        }else{
            printf("group_id=NULL,group_cap=NULL)");
        }
        if (i != array_len(payment->route->route_hops) - 1) printf("-");
    }
    printf("\n");
*/


    // record channel_update
    struct channel_update *channel_update = malloc(sizeof(struct channel_update));
    channel_update->htlc_maximum_msat = payment->amount;
    channel_update->edge_id = error_edge->id;
    channel_update->time = simulation->current_time;
    error_edge->channel_updates = push(error_edge->channel_updates, channel_update);

  add_attempt_history(payment, network, simulation->current_time, 0);

  /* === Stage ④ Hypothesis Testing: Increment global payment counter === */
  simulation->processed_payments++;

  /* === Stage ④ Hypothesis Testing + 案D Attacker Attribution (失敗時) ===
   * Phase 1: 各ホップで仮説検定を走らせ、異常を検出したノードを payment の
   *          計測・報告者リスト (attack_reporters) に登録する。
   *          攻撃者は HTLC を転送しないため hop_send_times が 0 となり検定がスキップされ、
   *          自然に計測・報告者リストに入らない。
   * Phase 2: (既定 OFF, CLOTH_FAIL_PHASE2_FALLBACK=1 で旧挙動) 経路を送信者→受信者方向に
   *          走査し、最初に報告していないノードを攻撃者と判定する。
   * 帰属は下の「案D」(異常ホップの送り先) が本体。失敗ホップの区間は攻撃による失敗
   * (OFFLINENODE) のときだけ検定する (CLOTH_FAIL_FALLTHROUGH_ALL_ERRORS=1 で旧挙動)。 */
  if (net_params.enable_reputation_system && payment->route != NULL && payment->hop_send_times != NULL) {
      int n_hops = array_len(payment->route->route_hops);

      /* リトライをまたいで reporters が残らないよう今回の試行分だけを使う */
      payment->num_attack_reporters = 0;

      /* === 案D (immediate-downstream attribution) ===
       * 各ホップで仮説検定を行い、異常レイテンシを観測したホップの「送り先 (to_node)」
       * を攻撃者とする。攻撃遅延は攻撃者の直前ノードが攻撃者へ HTLC を送信する区間
       * (hop_send_times[i+1]-hop_send_times[i]) のレイテンシに現れ、攻撃者自身は
       * HTLC を転送しない (hop_send_times が 0 のまま) ため計測・報告者にならない。よって
       * 「異常を報告したホップの直後のノード」が攻撃者である。従来の Phase 2
       * 「最初の未報告ノード」走査は攻撃者手前の正常ノード (特に高次数ハブ) を
       * 誤特定し大量の false positive を生んでいたが、これを構造的に解消する。 */
      long attacker_id = -1;
      long reporter_id = payment->sender;
      double attacker_latency = 0; /* DEBUG: 報告を誘発したホップのレイテンシ */
      int attacker_hopidx = -1;    /* DEBUG: 攻撃者を確定したホップ index */
      int attacker_tend_fallthrough = 0; /* DEBUG: t_end が current_time に落ちたか(=to_node未転送) */
      /* Phase 1: 各ホップで検定 → 計測・報告者登録 + 攻撃者候補(直後ノード)を記録 */
      for (int hop_idx = 0; hop_idx < n_hops; hop_idx++) {
          struct route_hop* hop = (struct route_hop*)array_get(
                                      payment->route->route_hops, hop_idx);
          if (hop == NULL) continue;

          struct node* hop_node = (struct node*)array_get(
                                      network->nodes, hop->from_node_id);
          if (hop_node == NULL) continue;

          uint64_t t_start = (hop_idx < payment->hop_send_times_capacity)
                             ? payment->hop_send_times[hop_idx] : 0;
          if (t_start == 0) continue;

          uint64_t t_end;
          int tend_fallthrough = 0;
          if (hop_idx + 1 < n_hops &&
              hop_idx + 1 < payment->hop_send_times_capacity &&
              payment->hop_send_times[hop_idx + 1] > t_start) {
              t_end = payment->hop_send_times[hop_idx + 1];
          } else {
              t_end = simulation->current_time;
              tend_fallthrough = 1;
          }
          if (t_end <= t_start) continue;
          /* 失敗ホップ(fallthrough)は攻撃による失敗のときだけ検定する (fail_fallthrough_all_errors)。
           * 普通の失敗では区間が「失敗の戻り往復」でしかなく、検定も学習もしない。 */
          if (tend_fallthrough && payment->error.type != OFFLINENODE &&
              !fail_fallthrough_all_errors()) continue;

          int should_report = on_fail_hypothesis_test(
              hop_node,
              t_start,
              t_end,
              detector_in_warmup(payment, (long)simulation->processed_payments),
              1  /* is_fail = 1 */
          );

          if (should_report) {
              register_attack_reporter(payment, hop_node->id);

              /* 案D: 異常ホップの送り先 (直後のノード) を攻撃者候補とする。送信者・
               * 受信者は攻撃者になり得ないため除外。hop_idx 昇順ループなので、最後に
               * 条件を満たした最下流の異常ホップの送り先が attacker_id に残る。 */
              long downstream = hop->to_node_id;
              if (downstream != payment->receiver &&
                  downstream != payment->sender) {
                  attacker_id = downstream;
                  reporter_id = hop->from_node_id;
                  attacker_latency = (double)(t_end - t_start);
                  attacker_hopidx = hop_idx;
                  attacker_tend_fallthrough = tend_fallthrough;
              }
          }
      }

      /* Phase 2 (フォールバック, 既定 OFF = fail_phase2_fallback): 案D で攻撃者が確定しなかった
       * 場合 (報告ホップの送り先が送信者/受信者のみ等) に限り、旧来の「経路上で最初に報告して
       * いないノード」を攻撃者とする。異常の位置と無関係なノードを選ぶため既定では使わない。 */
      for (int i = 0; fail_phase2_fallback() && i < n_hops; i++) {
          struct route_hop* hop = (struct route_hop*)array_get(
                                      payment->route->route_hops, i);
          if (hop == NULL) continue;
          long node_id = hop->from_node_id;
          if (node_id == payment->sender) continue; /* 送信者は攻撃者になり得ない */
          if (attacker_id < 0 && !has_attack_reporter(payment, node_id)) {
              attacker_id = node_id;
              /* 直前ホップの from_node を計測・報告者とする */
              if (i > 0) {
                  struct route_hop* prev = (struct route_hop*)array_get(
                                              payment->route->route_hops, i - 1);
                  if (prev != NULL) reporter_id = prev->from_node_id;
              }
              break;
          }
      }

      /* Two gates before flagging an attacker:
       *  (1) Anomaly evidence must exist: at least one node on the path observed
       *      an abnormal hop latency (num_attack_reporters > 0). Without it the
       *      failure is an ordinary one (no balance, timeout, route exhaustion)
       *      and blaming the first intermediary would be a false positive.
       *  (2) A judge must actually be able to observe the attacker. This is
       *      the gate that differentiates method1 (co-located only) from method2
       *      (watches its assigned nodes; all nodes by default, degree floor via
       *      CLOTH_OBSERVE_DEGREE_MIN). */
      if (attacker_id >= 0 && payment->num_attack_reporters > 0 &&
          net_params.judging_strategy != 3 &&   /* method3 は fail 検知器の報告を使わない (共通の基準値なので) */
          is_node_observed_by_judges(network, attacker_id)) {
          /* 診断計装: 報告された攻撃者の TP/FP 内訳を /tmp/cloth_attribution.csv に記録。
           * 専用 env CLOTH_ATTRIBUTION_LOG 設定時のみ有効 (cloth_debug_enabled() の重い
           * ログ群とは独立)。本番では env 未設定でこのブロック全体 (経路文脈ループ +
           * ファイル出力) を完全スキップしゼロコスト。analyze_attribution.py で集計。
           * 列: pid,attacker,is_mal,degree,reporter,n_rep,latency,route_mal,
           *     attacker_pos,nearest_mal_pos,attempts,rn,capacity,hopidx,fallthrough */
          if (getenv("CLOTH_ATTRIBUTION_LOG") != NULL) {
              struct node* an = (struct node*)array_get(network->nodes, attacker_id);
              long adeg = (an != NULL && an->open_edges != NULL) ? array_len(an->open_edges) : 0;
              /* 経路文脈: この経路に悪性ノードが乗っているか / 攻撃者と最寄り悪性の位置 */
              int route_mal = 0;          /* 経路上の悪性ノード数 */
              int attacker_pos = -1;      /* 攻撃者の経路上 from_node 位置 */
              int nearest_mal_pos = -1;   /* 最寄り悪性ノードの位置 */
              int rn = (payment->route != NULL) ? array_len(payment->route->route_hops) : 0;
              for (int ri = 0; ri < rn; ri++) {
                  struct route_hop* rh = (struct route_hop*)array_get(payment->route->route_hops, ri);
                  if (rh == NULL) continue;
                  struct node* fn = (struct node*)array_get(network->nodes, rh->from_node_id);
                  if (fn != NULL && fn->is_malicious) { route_mal++; if (nearest_mal_pos < 0) nearest_mal_pos = ri; }
                  if (rh->from_node_id == attacker_id) attacker_pos = ri;
                  /* 受信者側(最後のto_node)の悪性も確認 */
                  if (ri == rn - 1) {
                      struct node* tn = (struct node*)array_get(network->nodes, rh->to_node_id);
                      if (tn != NULL && tn->is_malicious) route_mal++;
                  }
              }
              FILE* fh = fopen("/tmp/cloth_attribution.csv", "a");
              if (fh) {
                  fprintf(fh, "%llu,%ld,%d,%ld,%ld,%d,%.0f,%d,%d,%d,%d,%d,%d,%d,%d\n",
                          (unsigned long long)payment->id, attacker_id,
                          (an != NULL) ? (int)an->is_malicious : -1, adeg,
                          reporter_id, payment->num_attack_reporters, attacker_latency,
                          route_mal, attacker_pos, nearest_mal_pos,
                          payment->attempts, rn, payment->hop_send_times_capacity,
                          attacker_hopidx, attacker_tend_fallthrough);
                  fclose(fh);
              }
          }
          report_attacked_node_to_judges(
              network,
              reporter_id,
              attacker_id,
              payment->id,
              simulation->current_time,
              net_params
          );
      }
  }

  /* === Stage ④ PRT: Path Reconstruction Threshold Check ===
   * If threshold-based reconstruction is enabled, check if we've exceeded max attempts
   */
  if (net_params.enable_prt) {
    payment->reconstruction_count++;
    payment->last_reconstruction_time = simulation->current_time;

    if (payment->reconstruction_count > net_params.prt_threshold) {
      // Threshold exceeded - abort this payment
      payment->prt_abort_triggered = 1;
      payment->prt_abort_time = simulation->current_time;

      // Mark as failed
      payment->is_success = 0;
      payment->end_time = simulation->current_time;

      // Don't retry - payment is aborted
      return;
    }
  }

  next_event_time = simulation->current_time;
  next_event = new_event(next_event_time, FINDPATH, payment->sender, payment);
  simulation->events = heap_insert(simulation->events, next_event, compare_event);

    // channel update broadcast event
    struct event *channel_update_event = new_event(simulation->current_time + net_params.group_broadcast_delay, CHANNELUPDATEFAIL, node->id, payment);
    simulation->events = heap_insert(simulation->events, channel_update_event, compare_event);
}

// 送金に使用された全てのedgeのグループ更新を行う
struct element* request_group_update(struct event* event, struct simulation* simulation, struct network* network, struct network_params net_params, struct element* group_add_queue){

    for(long i = 0; i < array_len(event->payment->route->route_hops); i++){
        struct route_hop* hop = array_get(event->payment->route->route_hops, i);
        struct edge* edge = array_get(network->edges, hop->edge_id);
        struct edge* counter_edge = array_get(network->edges, edge->counter_edge_id);

        if(edge->group != NULL) {
            struct group* group = edge->group;
            int close_flg = update_group(edge->group, net_params, simulation->current_time, simulation->random_generator, net_params.enable_fake_balance_update, edge);

            if(close_flg){
                group->is_closed = simulation->current_time;

                // add edges to queue
                for(long j = 0; j < array_len(group->edges); j++){
                    struct edge* edge_in_group = array_get(group->edges, j);
                    edge_in_group->group = NULL;
                    group_add_queue = list_insert_sorted_position(group_add_queue, edge_in_group, (long (*)(void *)) get_edge_balance);
                }

                // construct_groups event
                uint64_t next_event_time = simulation->current_time;
                struct event* next_event = new_event(next_event_time, CONSTRUCTGROUPS, event->node_id, event->payment);
                simulation->events = heap_insert(simulation->events, next_event, compare_event);
            }
        }

        if(counter_edge->group != NULL) {
            struct group* group = counter_edge->group;
            int close_flg = update_group(counter_edge->group, net_params, simulation->current_time, simulation->random_generator, net_params.enable_fake_balance_update, counter_edge);

            if(close_flg){
                group->is_closed = simulation->current_time;

                // add edges to queue
                for(long j = 0; j < array_len(group->edges); j++){
                    struct edge* edge_in_group = array_get(group->edges, j);
                    edge_in_group->group = NULL;
                    group_add_queue = list_insert_sorted_position(group_add_queue, edge_in_group, (long (*)(void *)) get_edge_balance);
                }

                // construct_groups event
                uint64_t next_event_time = simulation->current_time;
                struct event* next_event = new_event(next_event_time, CONSTRUCTGROUPS, event->node_id, event->payment);
                simulation->events = heap_insert(simulation->events, next_event, compare_event);
            }
        }
    }

    return group_add_queue;
}

int can_join_group(struct group* group, struct edge* edge, enum routing_method routing_method){

    if(routing_method == GROUP_ROUTING){
        if(edge->balance < group->min_cap_limit || edge->balance > group->max_cap_limit){
            return 0;
        }

        for(int i = 0; i < array_len(group->edges); i++) {
            struct edge *e = array_get(group->edges, i);
            if (edge == e) return 0;
            if (edge->to_node_id == e->to_node_id ||
                edge->to_node_id == e->from_node_id ||
                edge->from_node_id == e->to_node_id ||
                edge->from_node_id == e->from_node_id) {
                return 0;
            }
        }

        return 1;
    }
    else if(routing_method == GROUP_ROUTING_CUL){

        if(group->group_cap < edge->balance - (uint64_t)((double)edge->balance * edge->policy.cul_threshold)) return 0;
        if(group->group_cap > edge->balance) return 0;

        for(int i = 0; i < array_len(group->edges); i++) {
            struct edge *e = array_get(group->edges, i);
            if (edge == e) return 0;
            if (edge->to_node_id == e->to_node_id ||
                edge->to_node_id == e->from_node_id ||
                edge->from_node_id == e->to_node_id ||
                edge->from_node_id == e->from_node_id) {
                return 0;
            }
        }

        return 1;
    }
    else{
        fprintf(stderr, "ERROR: can_join_group called with unsupported routing method %d\n", routing_method);
        exit(1);
    }
}

struct element* construct_groups(struct simulation* simulation, struct element* group_add_queue, struct network *network, struct network_params net_params){

    if(group_add_queue == NULL) return group_add_queue;

    for(struct element* iterator = group_add_queue; iterator != NULL; iterator = iterator->next){

        struct edge* requesting_edge = iterator->data;

        if(net_params.routing_method == GROUP_ROUTING) {

            // new group
            struct group* group = malloc(sizeof(struct group));
            group->edges = array_initialize(net_params.group_size);
            group->edges = array_insert(group->edges, requesting_edge);
            if(net_params.group_limit_rate != -1) {
                group->max_cap_limit = requesting_edge->balance + (uint64_t)((float)requesting_edge->balance * net_params.group_limit_rate);
                group->min_cap_limit = requesting_edge->balance - (uint64_t)((float)requesting_edge->balance * net_params.group_limit_rate);
                if(group->max_cap_limit < requesting_edge->balance) group->max_cap_limit = UINT64_MAX;
                if(group->min_cap_limit > requesting_edge->balance) group->min_cap_limit = 0;
            }else {
                group->max_cap_limit = UINT64_MAX;
                group->min_cap_limit = 0;
            }
            group->id = array_len(network->groups);
            group->is_closed = 0;
            group->constructed_time = simulation->current_time;
            group->history = NULL;

            // search the closest balance edge from neighbors
            struct element* bottom = iterator;
            struct element* top = iterator;
            while(bottom != NULL || top != NULL){

                // both edge are out of group limit, skip this group
                if(top != NULL && bottom != NULL){
                    struct edge* bottom_edge = bottom->data;
                    struct edge* top_edge = top->data;
                    if(bottom_edge->balance < group->min_cap_limit && top_edge->balance > group->max_cap_limit){
                        break;
                    }
                }

                // join bottom and top edge to group
                if(bottom != NULL){
                    struct edge* bottom_edge = bottom->data;
                    if(can_join_group(group, bottom_edge, net_params.routing_method)){
                        group->edges = array_insert(group->edges, bottom_edge);
                        if(array_len(group->edges) == net_params.group_size) break;
                    }
                    bottom = bottom->prev;
                }
                if(top != NULL){
                    struct edge* top_edge = top->data;
                    if(can_join_group(group, top_edge, net_params.routing_method)){
                        group->edges = array_insert(group->edges, top_edge);
                        if(array_len(group->edges) == net_params.group_size) break;
                    }
                    top = top->next;
                }
            }

            // register group
            if(array_len(group->edges) == net_params.group_size){
                // init group_cap
                update_group(group, net_params, simulation->current_time, simulation->random_generator, net_params.enable_fake_balance_update, NULL);
                network->groups = array_insert(network->groups, group);
                for(int i = 0; i < array_len(group->edges); i++){
                    struct edge* group_member_edge = array_get(group->edges, i);
                    group_add_queue = list_delete(group_add_queue, &iterator, group_member_edge, (int (*)(void *, void *)) is_equal_edge);
                    group_member_edge->group = group;
                }
                if(iterator == NULL) break;
            }else{
                array_free(group->edges);
                free(group);
            }
        }
        else if (net_params.routing_method == GROUP_ROUTING_CUL) {
            struct group* group = malloc(sizeof(struct group));
            group->edges = array_initialize(net_params.group_size);
            group->edges = array_insert(group->edges, requesting_edge);
            group->min_cap_limit = 0;
            group->max_cap_limit = 0;
            group->id = array_len(network->groups);
            group->is_closed = 0;
            group->constructed_time = simulation->current_time;
            group->history = NULL;

            // グループ構築次のみ、requesting_edgeの容量秘匿のため、一時的にgroup_capを以下の値に設定する
            group->group_cap = requesting_edge->balance - (uint64_t)((double)requesting_edge->balance * requesting_edge->policy.cul_threshold);

            // search the closest balance edge from neighbors
            struct element* i_bottom = iterator;
            struct element* i_top = iterator;
            while(i_bottom != NULL || i_top != NULL){

                // both edge are out of group limit, skip this group
                if(i_top != NULL && i_bottom != NULL){
                    struct edge* bottom_edge = i_bottom->data;
                    struct edge* top_edge = i_top->data;

                    // group_reqブロードキャストメッセージを受け取ったedgeが範囲外でグループに所属できない場合の判定
                    // https://www.notion.so/cul-230d4e598f3480d5882ef98559d5caaa?source=copy_link
                    if(group->group_cap > top_edge->balance) break;
                    if(group->group_cap < top_edge->balance - (uint64_t)((double)top_edge->balance * top_edge->policy.cul_threshold)) break;
                    if(group->group_cap > bottom_edge->balance) break;
                    if(group->group_cap < bottom_edge->balance - (uint64_t)((double)bottom_edge->balance * bottom_edge->policy.cul_threshold)) break;
                }

                // join i_bottom and i_top edge to group
                if(i_bottom != NULL){
                    struct edge* bottom_edge = i_bottom->data;
                    if(can_join_group(group, bottom_edge, net_params.routing_method)){
                        group->edges = array_insert(group->edges, bottom_edge);
                        if(array_len(group->edges) == net_params.group_size) break;
                    }
                    i_bottom = i_bottom->prev;
                }
                if(i_top != NULL){
                    struct edge* top_edge = i_top->data;
                    if(can_join_group(group, top_edge, net_params.routing_method)){
                        group->edges = array_insert(group->edges, top_edge);
                        if(array_len(group->edges) == net_params.group_size) break;
                    }
                    i_top = i_top->next;
                }
            }

            // register group
            if(array_len(group->edges) == net_params.group_size){
                // init group_cap
                update_group(group, net_params, simulation->current_time, simulation->random_generator, net_params.enable_fake_balance_update, NULL);
                network->groups = array_insert(network->groups, group);
                for(int i = 0; i < array_len(group->edges); i++){
                    struct edge* group_member_edge = array_get(group->edges, i);
                    group_add_queue = list_delete(group_add_queue, &iterator, group_member_edge, (int (*)(void *, void *)) is_equal_edge);
                    group_member_edge->group = group;
                }
                if(iterator == NULL) break;
            }else{
                array_free(group->edges);
                free(group);
            }
        }
    }
    return group_add_queue;
}

void channel_update_success(struct event* event, struct simulation* simulation, struct network* network){
    struct node* node = array_get(network->nodes, event->node_id);
    process_success_result(node, event->payment, simulation->current_time);
}

void channel_update_fail(struct event* event, struct simulation* simulation, struct network* network){
    struct node* node = array_get(network->nodes, event->node_id);
    process_fail_result(node, event->payment, simulation->current_time);
}