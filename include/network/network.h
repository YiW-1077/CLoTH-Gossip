#ifndef NETWORK_H
#define NETWORK_H

#include <stdio.h>
#include <stdint.h>
#include "core/cloth.h"
#include "data_structures/list.h"

#define MAXMSATOSHI 5E17 //5 millions  bitcoin
#define MAXTIMELOCK 100
#define MINTIMELOCK 10
#define MAXFEEBASE 5000
#define MINFEEBASE 1000
#define MAXFEEPROP 10
#define MINFEEPROP 1
#define MAXLATENCY 100
#define MINLATENCY 10
#define MINBALANCE 1E2
#define MAXBALANCE 1E11

/* a policy that must be respected when forwarding a payment through an edge (see edge below) */
struct policy {
  uint64_t fee_base;
  uint64_t fee_proportional;
  uint64_t min_htlc;
  uint32_t timelock;
  double cul_threshold;
};

/* a node of the payment-channel network */
struct node {
  long id;
  struct array* open_edges;
  struct element **results;
  unsigned int explored;
  /* === Stage ① Research: Malicious Node Fields === */
  unsigned int is_malicious;        // 1 if this node is a malicious DoS attacker
  double attack_probability;        // probability of HTLC failure when forwarding
  /* === Stage ② Research: Monitor Node Fields === */
  unsigned int is_monitor;          // 1 if this node hosts a monitoring agent
  int monitor_id;                   // ID of the monitor agent on this node
  /* === Stage ③ Research: Reputation System Fields === */
  double reputation_score;          // [0.0, 1.0] - 1.0=trusted, 0.0=malicious
  int malicious_reports;            // count of detection incidents
  long last_movement_time;          // last time this monitor relocated (for movement tracking)
  uint64_t first_attack_time;       // first simulation time this malicious node triggered attack
  uint64_t first_detection_time;    // first simulation time this node was detected
};

/* a bidirectional payment channel of the payment-channel network open between two nodes */
struct channel {
  long id;
  long node1;
  long node2;
  long edge1;
  long edge2;
  uint64_t capacity;
  unsigned int is_closed;
};

/* an edge represents one of the two direction of a payment channel */
struct edge {
  long id;
  long channel_id;
  long from_node_id;
  long to_node_id;
  long counter_edge_id;
  struct policy policy;
  uint64_t balance;
  unsigned int is_closed;
  uint64_t tot_flows;
  struct group* group;
  struct element* channel_updates;
};


struct edge_snapshot {
  long id;
  uint64_t balance;
  short is_in_group;
  uint64_t group_cap;
  short does_channel_update_exist;
  uint64_t last_channle_update_value;
  uint64_t sent_amt;
};


struct channel_update {
    long edge_id;
    uint64_t time;
    uint64_t htlc_maximum_msat;
};


struct group_update {
    uint64_t time;
    uint64_t group_cap;
    uint64_t* edge_balances;
    long fake_balance_updated_edge_id; // if not -1, it means that the group cap is updated with a fake value and this is the edge id that triggered the update
    uint64_t fake_balance_updated_edge_actual_balance;

    /**
     * triggered_edge_id is the edge that triggered this group update.
     * Payments that are forwarded through this edge will be recorded in the group history.
     * if -1, it means that this group update is not triggered by an edge update, but by a group construction
     */
    long triggered_edge_id;
};


struct group {
    long id;
    struct array* edges;
    uint64_t max_cap_limit;
    uint64_t min_cap_limit;
    uint64_t group_cap;
    uint64_t is_closed; // if not zero, it describes closed time
    uint64_t constructed_time;
    struct element* history; // list of `struct group_update`
};


struct graph_channel {
  long node1_id;
  long node2_id;
};

/* === Stage ② Monitor Agent Definition === */
typedef struct {
    int monitor_id;                    // Global monitor ID (0..num_monitors-1)
    int node_id;                       // Physical node ID where this monitor is deployed
    int deployed_at_stage;             // 1=method1, 2=method2
    
    // Method 1 specific
    int watching_hub_id;               // Hub this monitor is watching
    
    // Method 2 specific  
    int* direct_hub_connections;       // Array of hub IDs for direct connections
    int num_direct_hubs;               // Count of direct hubs
    
    // Observation statistics
    long total_htlcs_observed;
    long htlcs_with_correlated_pairs;
    long payments_captured;
} MonitorAgent;

/* === Stage ② Hub Information Structure === */
typedef struct {
    int hub_id;                        // Node ID of this hub
    int degree;                        // Number of connections (next order)
    int* neighbor_ids;                 // Array of adjacent node IDs
    int num_neighbors;
    
    // Leaf node analysis
    int* leaf_neighbor_ids;            // Node IDs with degree <= threshold
    int num_leaf_neighbors;
} HubInfo;

/* === Stage ② Payment Observability Tracking === */
typedef struct {
    long payment_id;
    int num_monitors_on_path;          // Count of monitors observing this payment
    int* observers;                    // Array of monitor IDs
    int num_observers;
    
    // Correlation metadata
    uint64_t amount_observed;
    int sender_proximity;              // -1=unknown, 0=direct, 1=1hop, etc
    int receiver_proximity;
} PaymentObservability;

#define MONITOR_NODE_LIMIT 10
#define MONITOR_SWITCH_INTERVAL_PAYMENTS 100


struct network {
  struct array* nodes;
  struct array* channels;
  struct array* edges;
  struct array* groups;
  gsl_ran_discrete_t* faulty_node_prob;
  
  /* === Stage ② Monitor Tracking === */
  MonitorAgent* monitors;              // Array of deployed monitors
  int num_monitors;
  long cumulative_monitor_assignments; // sum of active monitor slots over all placements
  long cumulative_monitor_relocations; // number of monitor moves that changed node
  int monitor_rotation_epoch;          // incremented each relocation cycle
  HubInfo* hubs;                       // Array of hub information
  int num_hubs;
};


struct node* new_node(long id);

struct channel* new_channel(long id, long direction1, long direction2, long node1, long node2, uint64_t capacity);

struct edge* new_edge(long id, long channel_id, long counter_edge_id, long from_node_id, long to_node_id, uint64_t balance, struct policy policy, uint64_t channel_capacity);

void open_channel(struct network* network, gsl_rng* random_generator, struct network_params net_params);

struct network* initialize_network(struct network_params net_params, gsl_rng* random_generator);

/* === Stage ① Malicious Node Initialization === */
void initialize_malicious_nodes(struct network* network, 
                                 double malicious_ratio, 
                                 double failure_prob,
                                 gsl_rng* rng);

/* === Stage ② Monitor Placement Functions === */
void initialize_hub_info(struct network* network, int hub_threshold);
void analyze_leaf_neighbors(struct network* network, int leaf_threshold);
int deploy_monitors_method1(struct network* network, int hub_threshold, int leaf_threshold);
int deploy_monitors_method2_enhanced(struct network* network, int hub_threshold, int leaf_threshold, int top_hub_count);
void detect_and_record_htlc_observation(struct network* network, long payment_id, uint64_t amount, int node_id, int direction);

/* === Stage ③ Reputation System Functions === */
void initialize_reputation_scores(struct network* network);
void update_node_reputation_on_detection(struct node* node, double penalty, uint64_t detection_time);
void apply_reputation_decay_all_nodes(struct network* network, double decay_rate);
int suggest_monitor_movement(struct network* network, struct network_params params, uint64_t current_time);

int update_group(struct group* group, struct network_params net_params, uint64_t current_time, gsl_rng* random_generator, int enable_fake_balance_update, struct edge* triggered_edge);

long get_edge_balance(struct edge* e);

void free_network(struct network* network);

struct edge_snapshot* take_edge_snapshot(struct edge* e, uint64_t sent_amt, short is_in_group, uint64_t group_cap);

#endif
