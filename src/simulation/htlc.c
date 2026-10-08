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
 *   (a) 真のタイムアウト (elapsed > payment_timeout, 行343)
 *   (b) 経路なし NOPATH (空経路, 行466/482/502/524)
 *   (c) 残高不足 NOBALANCE (この関数経由, 呼び出し元 608/911)
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
 * ⚠️ 注入点は apply_attack_delay_if_needed の全呼び出し箇所 (hold-to-timeout型のフォワード遅延と
 *    hold型の settle 保持、および悪意ノード経由時のフォワード遅延) で共通。hold モードでは
 *    1決済あたりフォワード側と settle 側で独立に2回サンプルされる。 */
#define ATTACK_DELAY_DIST_FIXED       0
#define ATTACK_DELAY_DIST_LOGNORMAL   1
#define ATTACK_DELAY_DIST_EXPONENTIAL 2
#define ATTACK_DELAY_DIST_PARETO      3
#define ATTACK_DELAY_DIST_UNIFORM     4

static int get_attack_delay_dist(void) {
  static int cached = -1;
  if (cached >= 0) return cached;
  const char* e = getenv("CLOTH_ATTACK_DELAY_DIST");
  if (e == NULL || e[0] == '\0' || strcmp(e, "fixed") == 0)        cached = ATTACK_DELAY_DIST_FIXED;
  else if (strcmp(e, "lognormal") == 0)                            cached = ATTACK_DELAY_DIST_LOGNORMAL;
  else if (strcmp(e, "exponential") == 0 || strcmp(e, "exp") == 0) cached = ATTACK_DELAY_DIST_EXPONENTIAL;
  else if (strcmp(e, "pareto") == 0)                               cached = ATTACK_DELAY_DIST_PARETO;
  else if (strcmp(e, "uniform") == 0)                              cached = ATTACK_DELAY_DIST_UNIFORM;
  else {
    fprintf(stderr, "WARNING: unknown CLOTH_ATTACK_DELAY_DIST='%s' -> fixed\n", e);
    cached = ATTACK_DELAY_DIST_FIXED;
  }
  if (cached != ATTACK_DELAY_DIST_FIXED)
    printf("[Config] 攻撃遅延分布 CLOTH_ATTACK_DELAY_DIST=%s (平均保持は fixed と同一・分散のみ変化)\n", e);
  return cached;
}

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

  uint64_t adjusted_delay = (uint64_t)llround((double)base_delay * multiplier);
  if (adjusted_delay < base_delay) adjusted_delay = base_delay;

  if (payment != NULL && adjusted_delay > base_delay) {
    payment->attack_delay_added_total += (adjusted_delay - base_delay);
    payment->attack_delay_event_count += 1;
  }

  return adjusted_delay;
}

/* ============================================================================
 * === 偽報告(嘘の報告)の検証ハーネス ==========================================
 * 悪意ノードは報告者にもなれるので、自分の観測時刻を偽って隣接ノードを陥れたり
 * 自分の保持を隠したりできる。これを定量するための実験用ノブ群。すべて既定 0 =
 * 無効で、無効時は乱数も引かず従来と完全に同一の挙動になる。
 *
 *  CLOTH_FALSE_REPORT_MS = X : 悪意ノードが自分の申告を X[ms] 水増しする。
 *      申告 RT = recv - send を膨らませる方向(recv を +X, send を -X)に偽る。
 *      現行の帰属 Δ[i]=RT[i]-RT[i+1] では、これは同時に
 *        (a) 自分への嫌疑 Δ[i-1] を縮める = 自己免罪
 *        (b) 下流への嫌疑 Δ[i]   を膨らませる = 下流の冤罪
 *      の両方を達成する。preimage を上流へ送った申告時刻も -X して、相互証明側も偽る。
 *  CLOTH_CLOCK_SKEW_MS = E : 各ノードに固定の時計オフセット(-E..+E)を与える。
 *      ノード ID から決定論的に作るので乱数ストリームは動かない。
 *      自ノード内の差分(RT)では相殺されるが、ノードをまたぐ突き合わせには効く。
 *  CLOTH_REPORT_ATTEST = 1 : 帰属を「隣接ノードの申告のみ」で行う方式に切替。
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
/* 報告の帰属方式。0 = 現行(被疑ノード自身の申告を使う), 1 = 隣接ノードの申告のみ(相互証明)。 */
/* 報告の帰属方式。**2026-10-06 に既定を 1(相互証明) へ変更**。
 * 0 にすると旧来の「被疑者自身の申告 RT を使う」方式に戻る。
 * 旧方式は悪意ノードが報告者になれる前提の下では成立しない:
 *   嘘100ms/毎回 → 冤罪152件・precision 42.4%、黙秘100% → recall 16.1%。
 * 相互証明は hold[p]=recv[p-1]-send_back[p+1] と被疑者の申告を使わないので、
 * 嘘にも黙秘にも不感 (seed{7,42,123} で recall 90.5-93.7%・冤罪0・precision100%)。
 * ⚠️ 挙動変更: この既定変更以前の検知結果とは直接比較できない。 */
static int get_report_attest(void) {
  static int v = -1;
  if (v >= 0) return v;
  const char* e = getenv("CLOTH_REPORT_ATTEST");
  if (e != NULL && e[0] != '\0') return (v = (strcmp(e, "0") != 0) ? 1 : 0);
  return (v = 1);   /* 既定 = 相互証明 */
}
/* 食い違い(dispute)が起きたときの扱い (CLOTH_ATTEST_DISPUTE_POLICY, 既定 0)。
 *   0 = 従来: どちらか一方でも食い違えば帰属を破棄する。
 *       → 被疑者が自分の2つの申告を偽ると d1,d2 が両方跳ね、**自分に不利な帰属を自分で消せる**。
 *   1 = 共通点による特定: 被疑者 p の2本のリンクが**両方**食い違うなら、2本の共通ノードは
 *       p しかいないので原因は p の申告だと断定できる。帰属式
 *       hold[p]=recv[p-1]-send_back[p+1] は p の申告を使わないので、そのまま帰属してよい。
 *       片方だけの食い違いはどちらが嘘か決められないので従来どおり破棄する(冤罪防止)。
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
 * 嘘をつくより簡単な回避策: 現行の帰属は Δ=RT[i]−RT[i+1] に被疑者本人の記録を必要とするので、
 * 記録を出さないだけで検定が成立しなくなる。嘘と同じく「その決済の保持者本人」に限定し、
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

/* ノードが申告する時刻 = 真の時刻 + 時計オフセット + (嘘をつくなら嘘の分)。
 * dir: +1 = 「遅く受け取った」方向に盛る, -1 = 「早く送った」方向に盛る。
 * 保持者は「遅く受け取って、すぐ送った」と偽ることで見かけの保持時間を 2X 縮める。
 * pm == NULL を渡すと嘘は乗らない(時計オフセットのみ)。 */
static uint64_t reported_time(struct node* nd, struct payment* pm, uint64_t true_time, int dir) {
  long adj = node_clock_offset(nd != NULL ? nd->id : 0);
  if (lies_on_this_payment(nd, pm)) adj += dir * get_false_report_ms();
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

/* hold 検知器 (Phase 1) の有効化。CLOTH_DETECT_GRIEF が設定されているとき、
 * forward_success() で各ノードの settlement レグ転送レイテンシを仮説検定し、保持
 * 攻撃者を直接特定して report_attacked_node_to_judges() に報告する。既定 OFF。
 * (env 名の "GRIEF" は過去 run の再現性のため旧称のまま = hold 検知器のこと) */
static int get_detect_hold(void) {
  return getenv("CLOTH_DETECT_GRIEF") != NULL;
}

/* hold 検出 案A (round-trip + 隣接差分)。各ノードの往復時間 (HTLC送出→preimage返送受信)
 * を receive_success で走査し、隣接差 Δ[i]=RT[i]-RT[i+1] から resid≈下流ノードの settle_delay
 * を復元→settle検定→異常最大区間の下流ノードを攻撃者として1決済1回報告(観測可能な量のみ使用)。
 * 有効時は forward_success の (B) settle 直接検定を無効化(二重報告防止)。
 * **既定 ON = (A) に切替済み(2026-07-24)**。従来の (B) per-node settle 直接帰属に戻すには
 * env CLOTH_HOLD_ROUNDTRIP=0 を設定する。 */
static int get_hold_roundtrip(void) {
  const char* e = getenv("CLOTH_HOLD_ROUNDTRIP");
  if (e != NULL) return atoi(e) != 0;   /* 明示指定を尊重 (0=(B)へ, 非0=(A)) */
  return 1;                             /* 既定=(A)差分版 */
}

/* hold検出を hold-to-timeout型と完全対称にする観測条件 (CLOTH_HOLD_RT_SELFTIME)。
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
   * This models a sender-side attack that never puts the HTLC on the wire. */
  if (node->is_malicious) {
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
           * 残高減算(上の 617-620)はそのまま = HTLC は実際に転送される。
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

        /* 上の 562-566 で減算した最初のホップの残高/フロー計上を取り消す
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
         * hop_send_times entry stays 0, so the path-walk attribution in
         * receive_fail() (Phase 2) flags it as the first non-reporting node. */

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
  next_event = new_event(next_event_time, event_type, prev_node_id, event->payment);
  simulation->events = heap_insert(simulation->events, next_event, compare_event);
}

/* forward an HTLC success back to the payment sender (behavior of a intermediate hop node in the route) */

void forward_success(struct event* event, struct simulation* simulation, struct network* network, struct network_params net_params){
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
     * 出ない=「攻撃せず」なので recall の分母に数えない。これは行 808-810 の設計意図
     * (「実際に保持遅延を注入する forward_success で設定」) を予約だけで立てていた
     * 実装に対して厳密化したもの。 */
    if (node->first_attack_time == 0 && settle_delay > settle_base)
      node->first_attack_time = simulation->current_time;
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
void receive_success(struct event* event, struct simulation* simulation, struct network* network, struct network_params net_params){
  struct node* node;
  struct payment* payment;
  payment = event->payment;
  node = array_get(network->nodes, event->node_id);
  event->payment->end_time = simulation->current_time;

  add_attempt_history(payment, network, simulation->current_time, 1);

  /* === Stage ④ Hypothesis Testing: Increment global payment counter === */
  simulation->processed_payments++;

  /* === hold round-trip 検出 (案A, CLOTH_HOLD_ROUNDTRIP)：隣接差分版 ===
   * 各ノードの往復時間 RT[i] = recv[i] - send[i] は自ノードだけで観測可能。経路上の隣接
   * ノードの差 Δ[i] = RT[i] - RT[i+1] は導出上「下流ノード(i+1)の決済転送遅延 settle_delay
   * ＋1本の順方向ホップ」に等しい。よって resid = Δ[i] - 平均インターバル ≈ 下流ノード
   * (i+1)の settle_delay を、観測可能な往復量だけから復元できる(希釈なし=(B)と同じ信号)。
   * この resid を下流ノードの settle 検定にかけ、異常が最大の区間の下流ノードを攻撃者と
   * して1決済1回だけ報告する(報告者=上流ノード)。既定 OFF。 */
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
      double avg_iv = (double)net_params.average_payment_forward_interval;
      /* fail(receive_fail) は順方向 per-hop レイテンシ send[i+1]-send[i] を各ホップで検定し
       * 異常ホップの攻撃者を報告する。hold もこれに対称に、決済(backward)経路の per-hop
       * レイテンシ recv[i]-recv[i+1] (=下流ノード i+1 が決済を受領してから上流 i へ転送する
       * までの時間 = i+1 自身の保持時間 = (B)の settle_delay と同量) を各ペアで検定する。
       * 往復差分と違い順方向ホップのばらつきが混入しないためベースライン分散が膨らまず、
       * 保持者の取りこぼしが起きない。各異常ノード(=保持者)を報告(1決済1ノード dedup)。 */
      for (int i = 0; i + 1 < nh; i++) {
          if (i + 1 >= payment->hop_settle_recv_capacity) break;
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
          /* 欠測(黙秘)の扱い。被疑者(i+1)が記録を出していない場合、現行方式は
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
              settle_lat = (double)(ru - rd);          /* 既定: recv[i]-recv[i+1] 直接 */
          }
          struct route_hop* hop_dn = (struct route_hop*)array_get(payment->route->route_hops, i + 1);
          struct route_hop* hop_up = (struct route_hop*)array_get(payment->route->route_hops, i);
          if (hop_dn == NULL || hop_up == NULL) continue;
          struct node* dn_node = (struct node*)array_get(network->nodes, hop_dn->from_node_id);
          if (dn_node == NULL) continue;
          long cand = hop_dn->from_node_id;   /* 攻撃者候補 = 下流ノード本人(保持者) */

          /* === 相互証明モード (CLOTH_REPORT_ATTEST=1) ===========================
           * 被疑ノード p(=位置 i+1) 自身の申告を一切使わず、両隣の申告だけで
           * 保持時間を構成する:
           *     hold[p] = recv[p-1] (上流が「p から受け取った」と申告)
           *             - send_back[p+1] (下流が「p へ送った」と申告)
           * これにより p は自分の数字を盛って自己免罪することができない。
           * さらに、同一イベントを二者が申告している2本のリンクを突き合わせ、
           * 許容差を超えたらそのリンクからの帰属を破棄し、両端点に不一致を計上する
           * (単独の嘘はここで「冤罪」ではなく「不一致」に変換される)。 */
          if (get_report_attest()) {
              /* i+2 == nh は受信者の送出申告スロット。受信者証明が無い(0)なら従来どおり判定不能。 */
              if (i + 2 > nh || i + 2 > payment->hop_settle_recv_capacity) continue;
              if (payment->hop_settle_send_times == NULL) continue;
              uint64_t sb_p  = payment->hop_settle_send_times[i + 1]; /* p 自身の送信申告 */
              uint64_t sb_dn = payment->hop_settle_send_times[i + 2]; /* 下流の送信申告 */
              uint64_t rd2   = payment->hop_settle_recv_times[i + 1]; /* p 自身の受領申告 */
              if (sb_dn == 0) continue;            /* 隣人(下流)の記録が無ければ帰属不能 */
              int p_silent = (sb_p == 0 || rd2 == 0 || accused_unusable);
              /* 本人の記録が無い/入れ子違反で信用できない = 突き合わせはできないが帰属は成立する */
              if (p_silent && !get_attest_silence_policy()) continue;  /* 旧実装: 逃がす */
              long tol = get_attest_tolerance_ms();
              struct node* up_node = (struct node*)array_get(network->nodes, hop_up->from_node_id);
              struct route_hop* hop_dn2 = (struct route_hop*)array_get(payment->route->route_hops, i + 2);
              struct node* dn2_node = (hop_dn2 != NULL)
                  ? (struct node*)array_get(network->nodes, hop_dn2->from_node_id) : NULL;
              /* リンク(p-1,p): 上流の受領申告 vs p の送信申告 (同一イベント) */
              long d1 = (long)ru - (long)sb_p;  if (d1 < 0) d1 = -d1;
              /* リンク(p,p+1): p の受領申告 vs 下流の送信申告 (同一イベント) */
              long d2 = (long)rd2 - (long)sb_dn; if (d2 < 0) d2 = -d2;
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
                  continue;   /* 不一致リンクからは帰属しない */
              }
              if (ru <= sb_dn) continue;
              settle_lat = (double)(ru - sb_dn);   /* 両隣の申告のみで構成 */
          }
          if (getenv("CLOTH_HOLD_RT_DEBUG") && payment->grief_hold_node_id >= 0) {
              FILE* _f = fopen("/tmp/holdrt_debug.csv", "a");
              if (_f) { fprintf(_f, "%llu,%d,%ld,%ld,%ld,%d,%.0f\n",
                  (unsigned long long)payment->id, i, hop_up->from_node_id, cand,
                  payment->grief_hold_node_id, (cand == payment->grief_hold_node_id) ? 1 : 0, settle_lat);
                  fclose(_f); }
          }
          /* fail と同じく per-hop で検定(保持ノード本人の backward レイテンシを直接)。 */
          int should_report = on_hold_hypothesis_test(
              dn_node, settle_lat,
              detector_in_warmup(payment, (long)simulation->processed_payments), avg_iv, nh);
          if (should_report && cand != payment->sender && cand != payment->receiver &&
              is_node_observed_by_judges(network, cand) &&
              !has_attack_reporter(payment, cand)) {   /* dedup: 同一決済で同一ノードは1回 */
              register_attack_reporter(payment, cand); /* dedup キーとして保持者を記録 */
              report_attacked_node_to_judges(network, hop_up->from_node_id, cand,
                  payment->id, simulation->current_time, net_params);
          }
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
           * hold 型の報告は forward_success の hold 検知器 (CLOTH_DETECT_GRIEF) が担う。
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

  /* === Stage ④ Hypothesis Testing + Path-Walk Attacker Attribution (失敗時) ===
   * Phase 1: 各ホップで仮説検定を走らせ、異常を検出したノードを payment の
   *          計測・報告者リスト (attack_reporters) に登録する。
   *          攻撃者は HTLC を転送しないため hop_send_times が 0 となり検定がスキップされ、
   *          自然に計測・報告者リストに入らない。
   * Phase 2: 経路を送信者→受信者方向に走査し、最初に報告していないノードを
   *          攻撃者と判定してペナルティを与える。 */
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

      /* Phase 2 (フォールバック): 案D で攻撃者が確定しなかった場合 (報告ホップの
       * 送り先が送信者/受信者のみ等) に限り、従来の「経路上で最初に報告していない
       * ノード」を攻撃者とする。 */
      for (int i = 0; i < n_hops; i++) {
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
       *      (also watches its assigned high-degree nodes). */
      if (attacker_id >= 0 && payment->num_attack_reporters > 0 &&
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