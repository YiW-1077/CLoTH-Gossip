#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <math.h>
#include "network/monitoring.h"
#include "data_structures/array.h"
#include "network/network.h"
#include "core/payments.h"

/* Runtime-configurable detection parameters (via env vars):
 * CLOTH_PVALUE_THRESHOLD - p-value threshold for anomaly (default 0.005)
 * CLOTH_TIME_WINDOW_MS  - time window for chaining observations in ms (default 10000)
 */
static double get_pvalue_threshold() {
    char *env = getenv("CLOTH_PVALUE_THRESHOLD");
    if (env == NULL) return 0.005;
    double v = atof(env);
    if (v <= 0.0) return 0.005;
    return v;
}

static uint64_t get_time_window_ms() {
    char *env = getenv("CLOTH_TIME_WINDOW_MS");
    if (env == NULL) return 10000;
    uint64_t v = strtoull(env, NULL, 10);
    if (v == 0) return 10000;
    return v;
}

/* === Global observation storage === */
struct array* g_htlc_observations = NULL;
int g_monitoring_enabled = 1;



/* === Global monitor trust scores === */
static struct monitor_trust_score* g_monitor_trust_scores = NULL;
static int g_num_monitors_with_scores = 0;

/* === Helper function to compare observation pointers by timestamp === */
static int obs_compare_by_timestamp(const void* a, const void* b) {
    const struct htlc_observation* obs_a = *(const struct htlc_observation* const*)a;
    const struct htlc_observation* obs_b = *(const struct htlc_observation* const*)b;

    if (obs_a->timestamp < obs_b->timestamp) return -1;
    if (obs_a->timestamp > obs_b->timestamp) return 1;
    return 0;
}

/* === Initialize observation storage === */
void initialize_observation_storage() {
    if (g_htlc_observations == NULL) {
        g_htlc_observations = array_initialize(1000);
    }
}

/* === Record HTLC Observation === */
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
) {
    if (!g_monitoring_enabled) {
        return;
    }

    if (g_htlc_observations == NULL) {
        initialize_observation_storage();
    }

    struct htlc_observation* obs = (struct htlc_observation*)malloc(sizeof(struct htlc_observation));
    if (obs == NULL) {
        fprintf(stderr, "ERROR: Failed to allocate HTLC observation\n");
        return;
    }

    obs->payment_id = payment_id;
    obs->prev_node_id = prev_node_id;
    obs->next_node_id = next_node_id;
    obs->amount = amount;
    obs->timestamp = timestamp;
    obs->timelock = timelock;
    obs->monitor_id = monitor_id;
    obs->current_node_id = current_node_id;
    obs->channel_balance_before = channel_balance_before;
    obs->channel_balance_after = channel_balance_after;
    obs->is_balance_adjustment = is_balance_adjustment;

    g_htlc_observations = array_insert(g_htlc_observations, obs);
}

/* === Check if observations match === */
int observations_match(
    struct htlc_observation* obs1,
    struct htlc_observation* obs2,
    uint64_t time_window_ms
) {
    if (obs1 == NULL || obs2 == NULL) {
        return 0;
    }

    // Timelock must match
    if (obs1->timelock != obs2->timelock) {
        return 0;
    }

    // Enforce temporal ordering: obs1 should be earlier (upstream) and obs2 later (downstream)
    if (obs2->timestamp < obs1->timestamp) {
        return 0;
    }

    // Check if timestamps are within window (obs2.timestamp - obs1.timestamp)
    uint64_t time_diff = obs2->timestamp - obs1->timestamp;
    if (time_diff > time_window_ms) {
        return 0;
    }

    // Amounts along a payment path should be non-increasing due to fees.
    // Require upstream amount >= downstream amount.
    if (obs1->amount < obs2->amount) {
        return 0;
    }

    return 1;
}

/* === Reconstruct payment path from chain of observations === */
long* reconstruct_payment_path_from_chain(
    struct array* observation_chain,
    int* path_length
) {
    if (observation_chain == NULL || array_len(observation_chain) == 0) {
        *path_length = 0;
        return NULL;
    }

    int chain_len = array_len(observation_chain);
    long* path = (long*)malloc((chain_len + 2) * sizeof(long));

    if (path == NULL) {
        *path_length = 0;
        return NULL;
    }

    // Get first observation to find sender
    struct htlc_observation* first_obs = (struct htlc_observation*)array_get(observation_chain, 0);
    path[0] = first_obs->prev_node_id;

    // Chain the observations
    int path_idx = 1;
    for (int i = 0; i < chain_len; i++) {
        struct htlc_observation* obs = (struct htlc_observation*)array_get(observation_chain, i);
        path[path_idx++] = obs->next_node_id;
    }

    *path_length = path_idx;
    return path;
}

/* === Integrate observations to estimate payment paths === */
struct array* integrate_observations_from_monitors(struct network* network, struct array* payments) {
    struct array* estimated_payments = array_initialize(100);

    if (g_htlc_observations == NULL || array_len(g_htlc_observations) == 0) {
        if (cloth_debug_enabled()) printf("[Monitoring] No observations recorded\n");
        return estimated_payments;
    }

    // Ensure trust scores are initialized
    if (g_num_monitors_with_scores == 0) {
        initialize_monitor_trust_scores(network);
    }

    int num_obs = array_len(g_htlc_observations);
    if (cloth_debug_enabled()) printf("[Monitoring] Processing %d observations\n", num_obs);

    // Group observations by payment_id
    struct array** observation_groups = (struct array**)malloc(num_obs * sizeof(struct array*));
    uint64_t* group_ids = (uint64_t*)malloc(num_obs * sizeof(uint64_t));
    int num_groups = 0;

    for (int i = 0; i < num_obs; i++) {
        struct htlc_observation* obs_i = (struct htlc_observation*)array_get(g_htlc_observations, i);

        int target_group = -1;
        for (int g = 0; g < num_groups; g++) {
            if (group_ids[g] == obs_i->payment_id) {
                target_group = g;
                break;
            }
        }

        if (target_group == -1) {
            target_group = num_groups;
            observation_groups[target_group] = array_initialize(20);
            group_ids[target_group] = obs_i->payment_id;
            num_groups++;
        }

        observation_groups[target_group] = array_insert(observation_groups[target_group], obs_i);
    }

    if (cloth_debug_enabled()) printf("[Monitoring] Formed %d observation groups\n", num_groups);

    // Convert groups to estimated payments
    // Use route-consistent chaining within each payment_id group.
    uint64_t time_window = get_time_window_ms();  // time window for matching observations (ms), configurable via CLOTH_TIME_WINDOW_MS
    for (int g = 0; g < num_groups; g++) {
        long group_len = array_len(observation_groups[g]);
        if (group_len <= 0) {
            continue;
        }

        // Sort observations by time first.
        if (group_len > 1) {
            qsort(observation_groups[g]->element, group_len, sizeof(void*), obs_compare_by_timestamp);
        }

        // Require route consistency only for payments that changed route (reconstruction/retry).
        int require_route_consistency = 0;
        if (payments != NULL) {
            uint64_t payment_id = group_ids[g];
            if (payment_id < (uint64_t)array_len(payments)) {
                struct payment* p = (struct payment*)array_get(payments, (long)payment_id);
                if (p != NULL && (p->reconstruction_count > 0 || p->attempts > 1)) {
                    require_route_consistency = 1;
                }
            }
        }

        // Split same-payment observations into chains.
        struct array** chains = (struct array**)malloc(group_len * sizeof(struct array*));
        int num_chains = 0;
        if (chains == NULL) {
            continue;
        }

        for (long i = 0; i < group_len; i++) {
            struct htlc_observation* obs = (struct htlc_observation*)array_get(observation_groups[g], i);
            int target_chain = -1;

            if (require_route_consistency) {
                for (int c = 0; c < num_chains; c++) {
                    struct htlc_observation* last_obs = (struct htlc_observation*)array_get(chains[c], array_len(chains[c]) - 1);
                    if (last_obs != NULL &&
                        last_obs->next_node_id == obs->prev_node_id &&
                        observations_match(last_obs, obs, time_window)) {
                        target_chain = c;
                        break;
                    }
                }
            }

            if (target_chain == -1) {
                target_chain = num_chains;
                chains[target_chain] = array_initialize(8);
                num_chains++;
            }

            chains[target_chain] = array_insert(chains[target_chain], obs);
        }

        for (int c = 0; c < num_chains; c++) {
            struct estimated_payment* est = (struct estimated_payment*)malloc(sizeof(struct estimated_payment));
            if (est == NULL) {
                continue;
            }

            long chain_len = array_len(chains[c]);
            struct htlc_observation* first_obs = (struct htlc_observation*)array_get(chains[c], 0);
            struct htlc_observation* last_obs = (struct htlc_observation*)array_get(chains[c], chain_len - 1);

            // Reconstruct path
            int path_len = 0;
            est->complete_path = reconstruct_payment_path_from_chain(chains[c], &path_len);
            est->path_length = path_len;
            est->amount = first_obs->amount;
            est->upstream_amount = first_obs->amount;
            est->downstream_amount = last_obs->amount;
            est->num_observations = chain_len;

            // Estimate success and confidence
            strcpy(est->success_status, "estimated");
            est->confidence_level = (float)est->num_observations / 10.0f;  // Simple heuristic
            if (est->confidence_level > 1.0f) est->confidence_level = 1.0f;

            estimated_payments = array_insert(estimated_payments, est);
        }

        for (int c = 0; c < num_chains; c++) {
            array_free(chains[c]);
        }
        free(chains);
    }

    // Cleanup
    for (int g = 0; g < num_groups; g++) {
        // Don't free observation_groups[g] contents - they reference g_htlc_observations
        array_free(observation_groups[g]);
    }
    free(observation_groups);
    free(group_ids);

    return estimated_payments;
}

/* === Free estimated payment === */
void free_estimated_payment(struct estimated_payment* est) {
    if (est == NULL) return;
    if (est->complete_path != NULL) {
        free(est->complete_path);
    }
    free(est);
}

/* === Free all observations === */
void free_all_observations() {
    if (g_htlc_observations == NULL) {
        return;
    }

    for (int i = 0; i < array_len(g_htlc_observations); i++) {
        struct htlc_observation* obs = (struct htlc_observation*)array_get(g_htlc_observations, i);
        if (obs != NULL) {
            free(obs);
        }
    }

    array_free(g_htlc_observations);
    g_htlc_observations = NULL;
}

/* === Initialize monitor trust scores === */
void initialize_monitor_trust_scores(struct network* network) {
    if (network == NULL || network->num_monitors == 0) {
        return;
    }

    g_monitor_trust_scores = (struct monitor_trust_score*)malloc(
        network->num_monitors * sizeof(struct monitor_trust_score));

    for (int i = 0; i < network->num_monitors; i++) {
        g_monitor_trust_scores[i].monitor_id = i;
        g_monitor_trust_scores[i].trust_score = 0.8;  // Initial trust
        g_monitor_trust_scores[i].correct_observations = 0;
        g_monitor_trust_scores[i].contradicted_observations = 0;
    }

    g_num_monitors_with_scores = network->num_monitors;
}

/* === Update monitor trust score === */
void update_monitor_trust_score(long monitor_id, int is_correct) {
    if (monitor_id < 0 || monitor_id >= g_num_monitors_with_scores) {
        return;
    }

    struct monitor_trust_score* score = &g_monitor_trust_scores[monitor_id];

    if (is_correct) {
        score->trust_score += 0.1;
        score->correct_observations++;
    } else {
        score->trust_score -= 0.2;
        score->contradicted_observations++;
    }

    // Clamp to [0.1, 1.0]
    if (score->trust_score > 1.0) {
        score->trust_score = 1.0;
    } else if (score->trust_score < 0.1) {
        score->trust_score = 0.1;
    }
}

/* === Generate balance adjustment payments === */
struct array* generate_balance_adjustment_payments(
    struct network* network,
    uint64_t start_time,
    gsl_rng* rng
) {
    struct array* balance_payments = array_initialize(100);

    if (network == NULL || network->num_monitors == 0) {
        return balance_payments;
    }

    uint64_t payment_id_base = 1000000;  // High base to avoid collision with normal payments
    uint64_t current_time = start_time;

    // For each monitor, generate balance adjustment payments to other monitors
    // Strategy: Create payments to equalize balances across monitor network
    for (int src = 0; src < network->num_monitors; src++) {
        MonitorAgent* src_monitor = &network->monitors[src];
        struct node* src_node = (struct node*)array_get(network->nodes, src_monitor->node_id);

        if (src_node == NULL) {
            continue;
        }

        // Find nearby monitors to send balance adjustments
        // For simplicity, pair monitors sequentially
        int dst = (src + 1) % network->num_monitors;
        if (dst == src) {
            continue;  // Only 1 monitor, no need for adjustment
        }

        MonitorAgent* dst_monitor = &network->monitors[dst];
        struct node* dst_node = (struct node*)array_get(network->nodes, dst_monitor->node_id);

        if (dst_node == NULL) {
            continue;
        }

        // Generate small balance adjustment payment
        // Amount: 50% of average channel balance
        uint64_t adjustment_amount = 50000000;  // 0.5 BTC in millisatoshis as base

        struct balance_adjustment_payment* ba_payment =
            (struct balance_adjustment_payment*)malloc(sizeof(struct balance_adjustment_payment));

        ba_payment->payment_id = payment_id_base + array_len(balance_payments);
        ba_payment->src_monitor_id = src_monitor->node_id;
        ba_payment->dst_monitor_id = dst_monitor->node_id;
        ba_payment->amount = adjustment_amount;
        ba_payment->timestamp = current_time;
        ba_payment->is_internal = 1;

        balance_payments = array_insert(balance_payments, ba_payment);

        current_time += 100;  // Stagger payments 100ms apart
    }

    return balance_payments;
}

/**
 * ==================================================================================
 * Monitor Information Sharing & Dynamic Reputation System
 * ==================================================================================
 */

/**
 * Share monitor observations across monitors and update global reputation scores
 * This function:
 * 1. Integrates observations from all monitors
 * 2. Identifies suspected malicious nodes from payment paths
 * 3. Updates global reputation scores for all nodes
 * 4. Makes reputation data available to routing algorithms
 */
void share_monitor_information_and_update_reputation(
    struct network* network,
    struct network_params net_params
) {
    if (network == NULL || g_htlc_observations == NULL) {
        return;
    }

    int num_observations = array_len(g_htlc_observations);

    if (num_observations == 0) {
        return;
    }

    if (cloth_debug_enabled()) printf("[Monitoring] Sharing information across monitors...\n");
    if (cloth_debug_enabled()) printf("[Monitoring] Total observations: %d\n", num_observations);

    // Integrate observations to get estimated payment paths
    struct array* estimated_payments = integrate_observations_from_monitors(network, NULL);

    if (estimated_payments == NULL) {
        return;
    }

    // Analyze estimated payments to identify suspicious nodes
    int num_estimated = array_len(estimated_payments);
    if (cloth_debug_enabled()) printf("[Monitoring] Estimated payments from integration: %d\n", num_estimated);

    // Initialize node suspicion scores (0.0 = trusted, 1.0 = malicious)
    double* node_suspicion = (double*)calloc(array_len(network->nodes), sizeof(double));
    int* node_suspicion_count = (int*)calloc(array_len(network->nodes), sizeof(int));

    // Analyze each estimated payment path
    for (int i = 0; i < num_estimated; i++) {
        struct estimated_payment* est_pmt = (struct estimated_payment*)array_get(estimated_payments, i);

        if (est_pmt == NULL || est_pmt->complete_path == NULL) {
            continue;
        }

        // If payment failed and has high confidence, identify the failing node
        if (strcmp(est_pmt->success_status, "failure") == 0 && est_pmt->confidence_level > 0.5) {
            // Heuristic: Identify the most likely failing node
            // Primary strategy: Check for amount discrepancy (upstream vs downstream)
            // This indicates which node(s) handled the payment before failure

            long suspected_node_id = -1;
            double suspicion_strength = 0.2;  // Conservative: 0.2 for low confidence

            // If upstream_amount != downstream_amount, a node on the path modified it
            // The downstream node (closest to receiver) is most likely the culprit
            if (est_pmt->downstream_amount > 0 && est_pmt->path_length > 1) {
                suspected_node_id = est_pmt->complete_path[est_pmt->path_length - 2];
                suspicion_strength = 0.15;  // Gradual penalization
            }

            // Fallback: if path_length >= 3, suspect the last intermediate node (hop before receiver)
            if (suspected_node_id < 0 && est_pmt->path_length > 2) {
                suspected_node_id = est_pmt->complete_path[est_pmt->path_length - 2];
                suspicion_strength = 0.1;  // Very conservative
            }

            // Apply suspicion only to the suspected node (not all path nodes)
            if (suspected_node_id >= 0 && suspected_node_id < (long)array_len(network->nodes)) {
                node_suspicion[suspected_node_id] += suspicion_strength;
                node_suspicion_count[suspected_node_id]++;
            }
        }
    }

    // Update global reputation scores based on integrated information
    if (cloth_debug_enabled()) printf("[Monitoring] Updating reputation scores...\n");

    int nodes_updated = 0;
    int num_nodes = array_len(network->nodes);

    for (int i = 0; i < num_nodes; i++) {
        struct node* node = (struct node*)array_get(network->nodes, i);

        if (node == NULL) {
            continue;
        }

        /* Fix 1 (non-destructive batch update): if this sweep has no suspicion
         * evidence against the node, leave its reputation untouched. Recomputing
         * from a 1.0 baseline here would wipe out penalties already accumulated by
         * the realtime detection path (report_attacked_node_to_monitors ->
         * update_node_reputation_on_detection), which is currently the only path
         * that actually lowers reputation. */
        if (node_suspicion_count[i] == 0) {
            continue;
        }

        // Base reputation: 1.0 (trusted)
        double reputation = 1.0;

        // Adjust based on number of malicious reports (not suspicion score)
        // Using a linear + diminishing decay model: each report reduces reputation
        // Strong initial penalty for first few reports, then slower diminishing
        if (node_suspicion_count[i] > 0) {
            int report_count = node_suspicion_count[i];

            /* Hub protection: high-degree nodes appear on more paths and
             * accumulate suspicion reports faster than low-degree nodes,
             * so scale down the penalty proportionally to degree.
             * degree=0: scale=1.0, degree=200: scale=0.5, degree=1000: scale=0.17
             * Consistent with the scaling in report_attacked_node_to_monitors. */
            long degree = 0;
            if (node->open_edges != NULL) degree = array_len(node->open_edges);
            double degree_scale = 1.0 / (1.0 + (double)degree / 200.0);
            if (degree_scale < 0.1) degree_scale = 0.1;

            double penalty = 0.0;

            if (report_count <= 12) {
                penalty = report_count * 0.08;
            } else {
                penalty = 12 * 0.08 + log(report_count - 11.0) * 0.05;
            }

            penalty *= degree_scale;

            // Cap maximum penalty at 0.95
            if (penalty > 0.95) {
                penalty = 0.95;
            }

            reputation -= penalty;
        }

        // Clamp reputation to [0.0, 1.0]
        if (reputation < 0.0) reputation = 0.0;
        if (reputation > 1.0) reputation = 1.0;

        // Update node reputation
        double old_rep = node->reputation_score;
        node->reputation_score = reputation;

        if (fabs(reputation - old_rep) > 1e-6) {  // Only count if significantly changed
            nodes_updated++;
        }
    }

    if (cloth_debug_enabled()) printf("[Monitoring] Updated reputation for %d nodes\n", nodes_updated);

    // Identify and report suspected malicious nodes
    int suspect_count = 0;
    for (int i = 0; i < num_nodes; i++) {
        struct node* node = (struct node*)array_get(network->nodes, i);
        if (node != NULL && node->reputation_score < 0.5) {
            suspect_count++;
        }
    }

    if (cloth_debug_enabled()) printf("[Monitoring] Nodes with low reputation (<0.5): %d\n", suspect_count);
    if (cloth_debug_enabled()) printf("[Monitoring] Information sharing complete - Routing can now use reputation scores\n");

    // Clean up
    free(node_suspicion);
    free(node_suspicion_count);

    // Free estimated payments
    if (estimated_payments != NULL) {
        for (int i = 0; i < array_len(estimated_payments); i++) {
            struct estimated_payment* est = (struct estimated_payment*)array_get(estimated_payments, i);
            if (est != NULL) {
                free_estimated_payment(est);
            }
        }
        array_free(estimated_payments);
    }
}

void report_attacked_node_to_monitors(
    struct network* network,
    long reporter_node_id,
    long attacked_node_id,
    uint64_t payment_id,
    uint64_t timestamp,
    struct network_params net_params
) {
    if (network == NULL || !net_params.monitoring_strategy || !net_params.enable_reputation_system) {
        return;
    }

    if (attacked_node_id < 0 || attacked_node_id >= array_len(network->nodes)) {
        return;
    }

    struct node* attacked_node = (struct node*)array_get(network->nodes, attacked_node_id);
    if (attacked_node == NULL) {
        return;
    }

    if (cloth_debug_enabled())
        printf("[Monitoring] reporter=%ld reported attack on node=%ld for payment=%" PRIu64 "\n",
               reporter_node_id,
               attacked_node_id,
               payment_id);

    /* Require multiple independent reports before applying reputation penalty */
    const int REPORTS_REQUIRED = 2; /* configurable constant: require 2 reports */

    /* Increment the report counter (represents independent reports received) */
    attacked_node->malicious_reports++;

    /* Apply penalty only when enough reports accumulated; apply per-batch: every REPORTS_REQUIRED reports */
    if (attacked_node->malicious_reports % REPORTS_REQUIRED == 0) {
        /* Hub protection: scale penalty down for high-degree (hub) nodes to avoid over-penalizing central nodes */
        long degree = 0;
        if (attacked_node->open_edges != NULL) degree = array_len(attacked_node->open_edges);
        double degree_scale = 1.0 / (1.0 + ((double)degree) / 500.0); /* degree 500 -> 0.5, 1000 -> 0.333 */
        if (degree_scale < 0.1) degree_scale = 0.1; /* floor to avoid zeroing out penalty */

        double scaled_penalty = net_params.reputation_penalty_on_detection * degree_scale;

        if (cloth_debug_enabled())
            printf("[Monitoring] applying scaled penalty to node=%ld degree=%ld scale=%.4f base_penalty=%.4f scaled_penalty=%.4f\n",
                   attacked_node_id, degree, degree_scale, net_params.reputation_penalty_on_detection, scaled_penalty);

        update_node_reputation_on_detection(
            attacked_node,
            scaled_penalty,
            timestamp
        );
    }
}

/**
 * === Hypothesis Testing: Log-Normal p-value Calculation ===
 *
 * Model: Latency under H0 (normal congestion) follows log-normal distribution
 * H0: ln(latency + 1) ~ N(μ, σ²)
 * H1: ln(latency + 1) is significantly higher (one-tailed test)
 *
 * Z-score: Z = (ln(latency + 1) - μ) / σ
 * p-value: P(Z > observed_z) [cumulative normal distribution]
 */

/**
 * Cumulative normal distribution (standard normal CDF)
 * Using error function approximation
 * Returns P(X ≤ x) for X ~ N(0, 1)
 */
static double normal_cdf(double z) {
    // Approximation using error function (erf)
    // CDF(z) = 0.5 * (1 + erf(z / sqrt(2)))
    return 0.5 * (1.0 + erf(z / sqrt(2.0)));
}

/**
 * Calculate p-value from Z-score (one-tailed test for high values)
 * p = 1 - CDF(z) = P(Z > z)
 */
static double p_value_from_z(double z) {
    return 1.0 - normal_cdf(z);
}

double calculate_p_value_log_normal(double observed_latency_ms, double baseline_mean, double baseline_std) {
    // Prevent division by zero
    if (baseline_std < 1e-6) {
        return 0.5; // No baseline yet, neutral p-value
    }

    // Log-transform: offset by 1ms to avoid log(0)
    double log_latency = log(observed_latency_ms + 1.0);

    // Compute Z-score
    double z_score = (log_latency - baseline_mean) / baseline_std;

    // Get p-value (one-tailed: delay in high direction)
    double p = p_value_from_z(z_score);

    return p;
}

/**
 * Update baseline using exponential moving average (EMA)
 * EMA weight: 0.99 old, 0.01 new (slow adaptation)
 */
void update_baseline_lognormal(struct node* node, double observed_latency_ms) {
    if (node == NULL) return;

    double log_latency = log(observed_latency_ms + 1.0);

    // First observation: initialize baseline
    if (node->baseline_std < 1e-6) {
        node->baseline_mean = log_latency;
        node->baseline_std = 0.5; // Start with small variance estimate
        return;
    }

    // EMA update for mean
    double new_mean = 0.99 * node->baseline_mean + 0.01 * log_latency;

    // Update variance estimate (simplified: use deviation from new mean)
    double deviation = fabs(log_latency - new_mean);
    double new_std = 0.99 * node->baseline_std + 0.01 * deviation;

    // Ensure minimum std to avoid numerical issues
    if (new_std < 0.1) new_std = 0.1;

    node->baseline_mean = new_mean;
    node->baseline_std = new_std;
}

/**
 * Process HTLC result and apply hypothesis testing
 *
 * Returns: 1 if attack should be reported (suspicion_score >= 2), 0 otherwise
 *
 * Logic:
 * 1. Compute p-value from observed latency
 * 2. During warm-up (payment_count < 500): learn baseline, update score but don't report
 * 3. After warm-up:
 *    - If p < 0.005: increment suspicion_score
 *    - If p >= 0.005: decrement suspicion_score (if > 0)
 *    - If suspicion_score >= 2: return 1 (report attack)
 * 4. Always update baseline for next iteration
 */
/**
 * on_payment_result_hypothesis_test  ― ホップ間レイテンシ仮説検定版
 *
 * htlc.c 側で hop_send_times[i] → hop_send_times[i+1]（または result_time）を
 * 1 ホップ分の区間レイテンシとして渡すため、ここでは 1 ホップ単体を検定する。
 * 監視ノードの有無に関係なく、各ノードを独立に評価できる。
 *
 * 引数:
 *   forwarding_node     : 検定対象のノード
 *   htlc_send_time      : そのホップの送信開始時刻
 *   result_time         : そのホップの処理完了時刻（次ホップ送信 or 最終結果時刻）
 *   payment_count_global: グローバル支払いカウント（ウォームアップ判定用）
 *   is_fail             : 1=forward_fail, 0=forward_success
 *
 * 戻り値: 1=報告すべき異常検知, 0=正常 or ウォームアップ中
 */
int on_payment_result_hypothesis_test(
    struct node* forwarding_node,
    uint64_t htlc_send_time,
    uint64_t result_time,
    long payment_count_global,
    int is_fail
) {
    if (forwarding_node == NULL || htlc_send_time >= result_time) return 0;

    forwarding_node->payment_count++;
    int should_report = 0;
    int old_suspicion = forwarding_node->suspicion_score;

    double latency_ms = (double)(result_time - htlc_send_time);

    /* ============================================================
     * ウォームアップ（最初の 500 支払い）: ベースライン学習のみ
     * ============================================================ */
    if (payment_count_global < 500) {
        update_baseline_lognormal(forwarding_node, latency_ms);
        return 0;
    }

    /* ============================================================
     * 検定本体: 1 ホップ分のレイテンシを対数正規分布で検定
     * ============================================================ */
    double p_threshold = get_pvalue_threshold();
    double p_value = calculate_p_value_log_normal(
                         latency_ms,
                         forwarding_node->baseline_mean,
                         forwarding_node->baseline_std);

    if (p_value < p_threshold) {
        /* 異常: suspicion を上げ、forward_fail 時のみ報告 */
        forwarding_node->suspicion_score++;
        if (is_fail && forwarding_node->suspicion_score >= 2)
            should_report = 1;
    } else {
        /* 正常: suspicion を回復してベースラインを更新 */
        if (forwarding_node->suspicion_score > 0)
            forwarding_node->suspicion_score--;
        update_baseline_lognormal(forwarding_node, latency_ms);
    }

    /* ---- 診断ログ (CLOTH_DEBUG 時のみ。毎検定で fopen するため通常は無効) ---- */
    if (cloth_debug_enabled()) {
        const char* path = "/tmp/cloth_detection_events.csv";
        FILE* fh = fopen(path, "r");
        int need_header = (fh == NULL);
        if (fh) fclose(fh);
        fh = fopen(path, "a");
        if (fh) {
            if (need_header)
                fprintf(fh,
                    "timestamp,node_id,latency_ms,p_value,is_fail,"
                    "suspicion_before,suspicion_after,should_report\n");
            fprintf(fh,
                "%" PRIu64 ",%ld,%.3f,%.6f,%d,%d,%d,%d\n",
                result_time, forwarding_node->id,
                latency_ms, p_value, is_fail,
                old_suspicion, forwarding_node->suspicion_score,
                should_report);
            fclose(fh);
        }
    }

    return should_report;
}

/* === Attack Report Tracking: per-payment reporter registry === */

void register_attack_reporter(struct payment* payment, long node_id) {
    if (payment == NULL) return;
    if (payment->num_attack_reporters >= payment->attack_reporters_capacity) {
        int new_cap = (payment->attack_reporters_capacity == 0) ? 8 : payment->attack_reporters_capacity * 2;
        payment->attack_reporters = (long*)realloc(payment->attack_reporters, new_cap * sizeof(long));
        if (payment->attack_reporters == NULL) return;
        payment->attack_reporters_capacity = new_cap;
    }
    payment->attack_reporters[payment->num_attack_reporters++] = node_id;
}

int has_attack_reporter(struct payment* payment, long node_id) {
    if (payment == NULL) return 0;
    for (int i = 0; i < payment->num_attack_reporters; i++) {
        if (payment->attack_reporters[i] == node_id) return 1;
    }
    return 0;
}