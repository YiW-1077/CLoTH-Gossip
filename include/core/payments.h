#ifndef PAYMENTS_H
#define PAYMENTS_H

#include <stdint.h>
#include <gsl/gsl_rng.h>
#include "data_structures/array.h"
#include "data_structures/heap.h"
#include "core/cloth.h"
#include "network/network.h"
#include "network/routing.h"

enum payment_error_type{
  NOERROR,
  NOBALANCE,
  OFFLINENODE, //it corresponds to `FailUnknownNextPeer` in lnd
  NORESPONSE,
};

/* register an eventual error occurred when the payment traversed a hop */
struct payment_error{
  enum payment_error_type type;
  struct route_hop* hop;
};

struct payment {
  long id;
  long sender;
  long receiver;
  uint64_t amount; //millisatoshis
  uint64_t max_fee_limit; //millisatoshis
  struct route* route;
  uint64_t start_time;
  uint64_t end_time;
  int attempts;
  struct payment_error error;
  /* attributes for multi-path-payment (mpp)*/
  unsigned int is_shard;
  long shards_id[2];
  /* attributes used for computing stats */
  unsigned int is_success;
  int offline_node_count;
  int no_balance_count;
  unsigned int is_timeout;
  uint64_t attack_delay_added_total; // cumulative delay added by attack-delay model [ms]
  unsigned int attack_delay_event_count; // number of hops where extra delay was injected
  struct element* history; // list of `struct attempt`
  
  /* === Stage ④ PRT: Path Reconstruction Tracking === */
  int reconstruction_count;              // Number of path reconstruction attempts
  long last_reconstruction_time;         // Timestamp of last reconstruction
  unsigned int prt_abort_triggered;      // 1 if threshold exceeded and aborted
  uint64_t prt_abort_time;               // When abort was triggered
  
  /* === Stage ④ Research: Hypothesis Testing (p-value) Tracking === */
  uint64_t* hop_send_times;         // array of HTLC send timestamps per hop (malloc'd size = route length)
  int hop_send_times_capacity;      // allocated size for hop_send_times
  int hop_send_times_initialized;   // flag: 1 if malloc'd, 0 if not
  /* === hold round-trip 検出(案A, env CLOTH_HOLD_ROUNDTRIP) ===
   * hop_settle_recv_times[i] = hop[i].from_node が preimage(鍵) を受け取った時刻。
   * 往復時間 = hop_settle_recv_times[i] - hop_send_times[i]。forward_success /
   * receive_success の冒頭で current_time を記録する。0 = 未記録。 */
  uint64_t* hop_settle_recv_times;  // array of preimage-return receive timestamps per hop
  int hop_settle_recv_capacity;     // allocated size (= hop_send_times_capacity)
  /* === 偽報告対策の検証用: 隣接ノードによる相互証明 (CLOTH_REPORT_ATTEST) ===
   * hop_settle_send_times[i] = hop[i].from_node が preimage を「上流へ送った」と
   * 申告する時刻。hop_settle_recv_times[i-1] (上流が受け取ったと申告する時刻) と
   * 同一イベントの二者申告になるので、突き合わせると片側の嘘を検出できる。 */
  uint64_t* hop_settle_send_times;  // array of preimage-forward send timestamps per hop

  /* === hold 型攻撃 (settlement レグでの保持遅延。支払いは失敗させない) ===
   * 混在モードで、ある悪意ノードが「forward leg では失敗させず、settlement
   * (backward) レグで preimage を保持して遅延させる」と決めた場合、そのノード id を
   * 記録する(-1=なし)。この値は攻撃注入側の内部状態で、検知器には渡らない。
   * 1経路につき1ノード(最後に hold を選んだノード)を保持。計測フェーズには十分。 */
  long grief_hold_node_id;
  
  /* === Warm-up phase tracking === */
  unsigned int is_warmup;           // 1 if payment is part of the first 500 generated payments
  
  /* === Judging: Observation tracking === */
  unsigned int is_observed;         // 1 if at least one judge observed this payment

  /* === Attack Report Tracking (per payment) === */
  long* attack_reporters;          // node IDs that filed an attack report for this payment
  int   num_attack_reporters;
  int   attack_reporters_capacity;
};

struct attempt {
  int attempts;
  uint64_t end_time;
  long error_edge_id;
  enum payment_error_type error_type;
  struct array* route; // array of `struct edge_snapshot`
  short is_succeeded;
};

struct payment* new_payment(long id, long sender, long receiver, uint64_t amount, uint64_t start_time, uint64_t max_fee_limit);
struct array* initialize_payments(struct payments_params pay_params, long n_nodes, gsl_rng* random_generator);
void add_attempt_history(struct payment* pmt, struct network* network, uint64_t time, short is_succeeded);

#endif
