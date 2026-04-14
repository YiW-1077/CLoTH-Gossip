#ifndef ROUTING_H
#define ROUTING_H

#include <stdint.h>
#include "data_structures/array.h"
#include "data_structures/heap.h"
#include <pthread.h>
#include "data_structures/array.h"
#include "data_structures/list.h"
#include "network/network.h"

#define N_THREADS 12
#define FINALTIMELOCK 40

extern pthread_mutex_t data_mutex;
extern pthread_mutex_t jobs_mutex;
extern struct array** paths;
extern struct element* jobs;

/* === Stage ④: Global RBR Parameters === */
extern struct network_params* global_net_params;

struct thread_args{
  struct network* network;
  struct array* payments;
  uint64_t current_time;
  long data_index;
  enum routing_method routing_method;
};

struct distance{
  long node;
  uint64_t distance;
  uint64_t amt_to_receive;
  uint64_t fee;
  double probability;
  uint32_t timelock;
  double weight;
  long next_edge;
};

struct dijkstra_hop {
  long node;
  long edge;
};

struct path_hop{
  long sender;
  long receiver;
  long edge;
};

struct route_hop {
  long from_node_id;
  long to_node_id;
  long edge_id;
  uint64_t amount_to_forward;
  uint32_t timelock;
  uint64_t edges_lock_start_time;
  uint64_t edges_lock_end_time;
  uint64_t group_cap;
};


struct route {
  uint64_t total_amount;
  uint64_t total_fee;
  uint64_t total_timelock;
  struct array *route_hops;
};

/* === Stage ④ PRA: Path Reconstruction Attempt === */
struct pra_context {
    long* failed_nodes;           // Nodes that caused failures
    int num_failed_nodes;
    int max_failed_nodes;
    
    int reconstruction_attempts;  // Count of path reconstructions
    long first_attempt_time;
    long last_reconstruction_time;
};

enum pathfind_error{
  NOLOCALBALANCE,
  NOPATH,
  PATHFAILURE_THRESHOLD_EXCEEDED
};

void initialize_dijkstra(long n_nodes, long n_edges, struct array* payments);

uint64_t estimate_capacity(struct edge* edge, struct network* network, enum routing_method routing_method);

void run_dijkstra_threads(struct network* network, struct array* payments, uint64_t current_time, enum routing_method routing_method);

struct array* dijkstra(long source, long destination, uint64_t amount, struct network* network, uint64_t current_time, long p, enum pathfind_error *error, enum routing_method routing_method, struct element* exclude_edges, uint64_t max_fee_limit);

/* === Stage ④ PRA Functions === */
struct array* dijkstra_exclude_nodes(long source, long destination, uint64_t amount,
                                      struct network* network, uint64_t current_time,
                                      long* excluded_node_ids, int num_excluded,
                                      long p, enum pathfind_error *error);

struct pra_context* pra_context_new();
void pra_context_add_failed_node(struct pra_context* ctx, long node_id);
void pra_context_free(struct pra_context* ctx);

struct route* transform_path_into_route(struct array* path_hops, uint64_t amount_to_send, struct network* network, uint64_t time);

int compare_distance(struct distance* a, struct distance* b);

void free_route(struct route* route);


#endif
