#ifndef MONITORING_H
#define MONITORING_H

#include <stdint.h>
#include "data_structures/array.h"
#include "network/network.h"

struct payment; /* forward declaration */

/* === Stage ② Monitoring: HTLC Information Observation ===
 * 
 * Monitors deployed on the network observe HTLC forwarding events.
 * By integrating observations from multiple monitors, the complete
 * payment path and amount can be estimated (onion routing attack).
 */

/* === HTLC Observation: Information captured by monitor nodes === */
struct htlc_observation {
    uint64_t payment_id;       // Payment identifier
    long prev_node_id;         // Previous hop node (source side)
    long next_node_id;         // Next hop node (destination side)
    uint64_t amount;           // Amount being forwarded
    uint64_t timestamp;        // When observation was made
    uint32_t timelock;         // HTLC timelock value
    long monitor_id;           // ID of monitor recording this observation
    long current_node_id;      // Node where this observation occurred
    
    /* === Balance Adjustment Tracking === */
    double channel_balance_before;  // Monitor's channel balance before HTLC forward
    double channel_balance_after;   // Monitor's channel balance after HTLC forward
    int is_balance_adjustment;      // 1 if this is a balance adjustment payment
};

/* === Estimated Payment: Result of information integration === */
struct estimated_payment {
    long* complete_path;       // Reconstructed complete path
    int path_length;           // Number of hops in path
    uint64_t amount;           // Estimated payment amount (observed at first monitor)
    uint64_t upstream_amount;  // Amount observed upstream (closest to sender)
    uint64_t downstream_amount;// Amount observed downstream (closest to receiver)
    int num_observations;      // Number of observations used
    char success_status[16];   // "success" or "failure"
    float confidence_level;    // 0.0 to 1.0
};

/* === Balance Adjustment Payment Structure === */
struct balance_adjustment_payment {
    uint64_t payment_id;          // Unique payment identifier
    long src_monitor_id;          // Source monitor node ID
    long dst_monitor_id;          // Destination monitor node ID
    uint64_t amount;              // Amount to transfer
    uint64_t timestamp;           // When generated
    int is_internal;              // 1 if internal monitor-to-monitor payment
};

/* === Global observation storage === */
extern struct array* g_htlc_observations;
extern int g_monitoring_enabled;

/* === Monitor Recording Functions === */

/**
 * Initialize global observation storage
 */
void initialize_observation_storage();

/**
 * Record an HTLC observation when monitor node processes a forwarding HTLC
 * Called from forward_payment() if current node is a monitor
 */
void record_htlc_observation(
    struct network* network,
    uint64_t payment_id,
    long prev_node_id,
    long next_node_id,
    uint64_t amount,
    uint64_t timestamp,
    uint32_t timelock,
    long current_node_id,
    long monitor_id,
    double channel_balance_before,
    double channel_balance_after,
    int is_balance_adjustment
);

/* === Balance Adjustment Payment Generation === */

/**
 * Generate balance adjustment payments for monitor nodes
 * Ensures monitors have balanced channels to relay normal payments
 * Called during initialization before normal payments
 */
struct array* generate_balance_adjustment_payments(
    struct network* network,
    uint64_t start_time,
    gsl_rng* rng
);

/* === Information Integration Functions === */

/**
 * Integrate observations from all monitors to reconstruct payment paths
 * Called at end of simulation
 * Returns array of estimated_payment structures
 */
struct array* integrate_observations_from_monitors(struct network* network, struct array* payments);

/**
 * Share monitor observations across monitors and update global reputation scores
 * Called during simulation after HTLC observations are recorded
 * Updates network->nodes[*]->reputation_score based on integrated information
 */
void share_monitor_information_and_update_reputation(
    struct network* network,
    struct network_params net_params
);

/**
 * Report an attacked node from the one-hop upstream node to the monitoring layer.
 * This is invoked at the node that first observes the failure.
 */
void report_attacked_node_to_monitors(
    struct network* network,
    long reporter_node_id,
    long attacked_node_id,
    uint64_t payment_id,
    uint64_t timestamp,
    struct network_params net_params
);

/**
 * Reconstruct path from observation chains
 * Used internally by integrate_observations_from_monitors
 */
long* reconstruct_payment_path_from_chain(
    struct array* observation_chain,
    int* path_length
);

/**
 * Check if two observations belong to same payment based on:
 * - Amount matching
 * - Timelock matching
 * - Temporal proximity
 */
int observations_match(
    struct htlc_observation* obs1,
    struct htlc_observation* obs2,
    uint64_t time_window_ms
);

/* === Output Functions === */

/**
 * Free estimated payment structure
 */
void free_estimated_payment(struct estimated_payment* est);

/**
 * Free all observations
 */
void free_all_observations();

/**
 * Monitor trust score management
 */
struct monitor_trust_score {
    long monitor_id;
    double trust_score;  // [0.0, 1.0]
    int correct_observations;
    int contradicted_observations;
};

/**
 * Initialize monitor trust scores (all monitors start at 0.8)
 */
void initialize_monitor_trust_scores(struct network* network);

/**
 * Update monitor trust score based on observation accuracy
 */
void update_monitor_trust_score(long monitor_id, int is_correct);

/**
 * Register node_id as having filed an attack report for payment.
 * Called when hypothesis test fires (should_report=1) on a failed payment.
 */
void register_attack_reporter(struct payment* payment, long node_id);

/**
 * Return 1 if node_id has already filed an attack report for payment, 0 otherwise.
 */
int has_attack_reporter(struct payment* payment, long node_id);

/**
 * Calculate p-value using log-normal distribution hypothesis test
 * H0: latency is normal network congestion
 * H1: latency is intentional attack (too high)
 * Uses Z-test on log-transformed latency: Z = (ln(latency + 1) - μ) / σ
 * Returns p-value [0.0, 1.0]; p < 0.01 indicates likely attack
 */
double calculate_p_value_log_normal(double observed_latency_ms, double baseline_mean, double baseline_std);

/**
 * Update node's baseline latency statistics using exponential moving average (EMA)
 * μ_new = μ_old × 0.99 + ln(latency + 1) × 0.01
 * σ_new updated to match observed variance around new μ
 */
void update_baseline_lognormal(struct node* node, double observed_latency_ms);

/**
 * Process payment completion/failure result: compute latency, check for attacks via p-value
 * Called when HTLC result is received (Fulfill or Fail event)
 * Returns 1 if node should be reported (p < 0.01 and suspicion_score >= 3), 0 otherwise
 */
int on_payment_result_hypothesis_test(
    struct node* forwarding_node,
    uint64_t htlc_send_time,
    uint64_t result_time,
    long payment_count_global,
    int is_fail
);

#endif
