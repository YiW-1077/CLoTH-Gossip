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
 * 検知器側の warmup 保護は monitoring.c::get_warmup_payments が別途担う。 */

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

/* === 攻撃手法セレクタ (CLOTH_ATTACK_MODE) ===
 * 悪意ノードが行う攻撃の種別をスクリプトから選択する:
 *   1 = fail 型のみ        (従来の HTLC 失敗攻撃; hold 割合 0.0)
 *   2 = hold 型のみ        (決済 backward 経路での preimage 保持グリーフィング単独; 割合 1.0)
 *   3 = 混在 (fail + hold) (hold 割合は CLOTH_GRIEF_HOLD_RATIO、既定 0.5)
 * 未設定/範囲外のときは 0 を返し、get_grief_hold_ratio() は後方互換のため
 * CLOTH_GRIEF_HOLD_RATIO を直接参照する (既定 0.0 = 従来どおり全て fail 型)。 */
static int get_attack_mode(void) {
  char* e = getenv("CLOTH_ATTACK_MODE");
  if (e == NULL || e[0] == '\0') return 0;
  int m = atoi(e);
  if (m < 1 || m > 3) return 0;
  return m;
}

/* === Grief-hold 攻撃 (決済=backward 経路での preimage 保持遅延) ===
 * 悪意ノードが行う攻撃のうち「保持(hold)型」にする割合 [0,1] を返す。
 * CLOTH_ATTACK_MODE が設定されていればそれを優先 (1→0.0, 2→1.0, 3→混在割合)、
 * 未設定なら後方互換のため env CLOTH_GRIEF_HOLD_RATIO を直接参照する (既定 0.0)。
 * hold 型に当たった攻撃は、フォワードで失敗させず通常転送し、backward 経路で
 * そのノードが preimage の release を遅延させる(失敗なし=支払いは成功)。 */
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
 * 設定されているときだけ /tmp/cloth_grief_shadow.csv に決済転送レイテンシを記録。 */
static int grief_shadow_log_enabled(void) {
  return getenv("CLOTH_GRIEF_SHADOW_LOG") != NULL;
}

/* Grief-hold 検知器 (Phase 1) の有効化。CLOTH_DETECT_GRIEF が設定されているとき、
 * forward_success() で各ノードの決済転送レイテンシを仮説検定し、保持攻撃者を
 * 直接特定して report_attacked_node_to_monitors() に報告する。既定 OFF。 */
static int get_detect_grief(void) {
  return getenv("CLOTH_DETECT_GRIEF") != NULL;
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
            } else if (payment->is_warmup) {
                // === Stage ④ Warm-up: Avoid malicious nodes during baseline learning ===
                path = dijkstra_avoid_malicious_nodes(payment->sender, payment->receiver, payment->amount,
                                                     network, simulation->current_time,
                                                     0, &error,
                                                     net_params.routing_method,
                                                     payment->max_fee_limit);
          } else {
              path = paths[payment->id];
          }
      }else {
          if (net_params.enable_rbr) {
              // === Retry: Use RBR for subsequent attempts ===
              path = find_reputation_based_route(payment->sender, payment->receiver, payment->amount,
                                                 network, simulation->current_time, 0, &error,
                                                 net_params.routing_method, NULL, payment->max_fee_limit,
                                                 net_params);
            } else if (payment->is_warmup) {
                // === Warm-up retry: Still avoid malicious nodes ===
                path = dijkstra_avoid_malicious_nodes(payment->sender, payment->receiver, payment->amount,
                                                     network, simulation->current_time,
                                                     0, &error,
                                                     net_params.routing_method,
                                                   payment->max_fee_limit);
          } else if (net_params.monitoring_strategy > 0 && net_params.enable_reputation_system) {
              // === Retry: Use reputation-weighted dijkstra when monitoring is active ===
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

  /* Stage ②: record incoming observation at the current node if it is a monitor. */
  if (detect_and_record_htlc_observation(network, payment->id, payment->amount, node->id, 0, simulation->current_time, route)) {
    payment->is_observed = 1;
  }
  
  /* === Stage ② Payment Information Monitoring (Sender) ===
   * If sender is a monitor, record the initial HTLC.
   */
  if (node->is_monitor) {
      record_htlc_observation(
          network,
          payment->id,
          payment->sender,                    // prev_node = sender itself
          first_route_hop->to_node_id,        // next_node = first hop receiver
          first_route_hop->amount_to_forward, // amount
          simulation->current_time,
          first_route_hop->timelock,
          node->id,
          node->monitor_id,
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
   * (遅延注入と first_attack_time は forward_success 側)。従来はここが fail 型固定で、
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
        } else {
        uint64_t base_delay = sample_base_forward_delay(simulation, net_params);
        uint64_t forward_delay = apply_attack_delay_if_needed(
          simulation, net_params, payment, base_delay, 1
        );
        uint64_t attack_event_time = simulation->current_time + forward_delay;

        /* 分母正常化: 検知が報告可能になる post-warmup の攻撃のみ first_attack_time を立てる。
         * warmup 中の失敗攻撃は仮説検定が抑制され報告できないため、recall 分母
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
                  payment->hop_send_times[i] = simulation->current_time;
              break;
          }
      }
  }

  /* Stage ②: record incoming observation at this hop if it is a monitor. */
  if (detect_and_record_htlc_observation(network, payment->id, payment->amount, node->id, 0, simulation->current_time, route)) {
    payment->is_observed = 1;
  }
  
  /* === Stage ② Payment Information Monitoring ===
   * If current node is a monitor, record detailed HTLC observation
   * for later information integration and payment tracking. */
  if (node->is_monitor) {
      record_htlc_observation(
          network,
          payment->id,                    // payment_id
          previous_route_hop->from_node_id,  // prev_node (information before this hop)
          next_route_hop->to_node_id,     // next_node (information after this hop)
          next_route_hop->amount_to_forward,  // amount
          simulation->current_time,       // timestamp
          next_route_hop->timelock,       // timelock
          node->id,                       // current_node (this monitor)
          node->monitor_id,               // monitor_id
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
       * backward 経路でこのノードが preimage を保持して遅延)、残りは従来の fail 型。
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
      } else {
        /* === FAIL 型 (従来の攻撃挙動) === */
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

  if(!is_present(backward_edge->id, node->open_edges)) {
    printf("ERROR (forward_success): edge %ld is not an edge of node %ld \n", backward_edge->id, node->id);
    exit(-1);
  }

  // update balance
  backward_edge->balance += prev_hop->amount_to_forward;

  prev_node_id = prev_hop->from_node_id;
  event_type = prev_node_id == payment->sender ? RECEIVESUCCESS : FORWARDSUCCESS;

  /* === backward(決済)経路の保持時間 ===
   * 通常はランダムな転送インターバル。このノードが grief-hold 攻撃者として
   * 予約 (payment->grief_hold_node_id) されている場合は、フォワードの攻撃遅延
   * モデル(×attack_delay_intensity)を流用して preimage の release を遅延させる。
   * 失敗はさせない (= 支払いは成功する)。保持しない場合は従来と同一値。 */
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

  /* === シャドウ計測 (Phase 0): 報告はしない。各ノードの決済転送レイテンシを記録し、
   * 攻撃者(保持) vs 正常ノードの分離度(SNR) を実測する。CLOTH_GRIEF_SHADOW_LOG 時のみ。
   * 列: pid,node_id,is_malicious,degree,settle_delay_ms,settle_base_ms,held === */
  if (grief_shadow_log_enabled()) {
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

  /* === Grief-hold 検知 (Phase 1) ===
   * 各ノードの決済転送レイテンシ settle_delay を per-node 仮説検定し、異常(=保持)を
   * 出したノード本人を攻撃者として報告する。保持ノードは自分で release を転送するので
   * 直接帰属でよい(下流帰属トリック不要)。報告者は上流ノード(prev_node_id)。
   * 観測ゲート(method1/method2)はフォワード検知と共通。既定 OFF (CLOTH_DETECT_GRIEF)。 */
  if (net_params.enable_reputation_system && get_detect_grief()) {
    int should_report = on_settlement_result_hypothesis_test(
        node, (double)settle_delay, (long)simulation->processed_payments,
        (double)net_params.average_payment_forward_interval);
    if (should_report && is_node_observed_by_monitors(network, node->id)) {
      report_attacked_node_to_monitors(
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

  /* === Stage ④ Hypothesis Testing: ホップ間レイテンシで各ノードを個別検定 ===
   * hop_send_times[i]     : ホップ i の送信時刻
   * hop_send_times[i+1]   : ホップ i+1 の送信時刻（= ホップ i の処理+転送完了時刻）
   * 最終ホップは result_time（= receive_success の現在時刻）を終端とする。
   * これにより監視ノードの有無に関係なく各ノードの処理遅延を独立に検定できる。 */
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
           * on_payment_result_hypothesis_test は is_fail=1 のときしか
           * should_report を立てない (monitoring.c の k-of-m / 1-strike 両分岐)
           * ため、ここでの報告は構造的に発生しない。以前ここにあった報告ブロックは
           * 到達不能なデッドコードだったので除去した。フォワード方向の報告は
           * receive_fail 側、hold 型の報告は forward_success の settle 検定
           * (CLOTH_DETECT_GRIEF) が担う。 */
          (void) on_payment_result_hypothesis_test(
              hop_node,
              t_start,
              t_end,
              simulation->processed_payments,
              0           /* is_fail = 0 */
          );
      }
  }

  // === Dynamic Reputation Update: Success Path ===
  // When payment succeeds, increase reputation of nodes in successful path
  if (net_params.monitoring_strategy > 0 && net_params.enable_reputation_system && payment->route != NULL) {
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
   *          報告者リスト (attack_reporters) に登録する。
   *          攻撃者は HTLC を転送しないため hop_send_times が 0 となり検定がスキップされ、
   *          自然に報告者リストに入らない。
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
       * HTLC を転送しない (hop_send_times が 0 のまま) ため報告者にならない。よって
       * 「異常を報告したホップの直後のノード」が攻撃者である。従来の Phase 2
       * 「最初の未報告ノード」走査は攻撃者手前の正常ノード (特に高次数ハブ) を
       * 誤特定し大量の false positive を生んでいたが、これを構造的に解消する。 */
      long attacker_id = -1;
      long reporter_id = payment->sender;
      double attacker_latency = 0; /* DEBUG: 報告を誘発したホップのレイテンシ */
      int attacker_hopidx = -1;    /* DEBUG: 攻撃者を確定したホップ index */
      int attacker_tend_fallthrough = 0; /* DEBUG: t_end が current_time に落ちたか(=to_node未転送) */
      /* Phase 1: 各ホップで検定 → 報告者登録 + 攻撃者候補(直後ノード)を記録 */
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

          int should_report = on_payment_result_hypothesis_test(
              hop_node,
              t_start,
              t_end,
              simulation->processed_payments,
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
              /* 直前ホップの from_node を報告者とする */
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
       *  (2) A monitor must actually be able to observe the attacker. This is
       *      the gate that differentiates method1 (co-located only) from method2
       *      (also watches its assigned high-degree nodes). */
      if (attacker_id >= 0 && payment->num_attack_reporters > 0 &&
          is_node_observed_by_monitors(network, attacker_id)) {
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
          report_attacked_node_to_monitors(
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