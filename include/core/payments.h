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
