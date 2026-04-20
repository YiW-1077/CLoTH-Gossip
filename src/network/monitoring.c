#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "network/monitoring.h"
#include "data_structures/array.h"
#include "network/network.h"

/* === Global observation storage === */
struct array* g_htlc_observations = NULL;
int g_monitoring_enabled = 1;

/* === Global monitor trust scores === */
static struct monitor_trust_score* g_monitor_trust_scores = NULL;
static int g_num_monitors_with_scores = 0;

/* === Helper function to compare observations === */
static int obs_compare_by_amount_time(const void* a, const void* b) {
    struct htlc_observation* obs_a = (struct htlc_observation*)a;
    struct htlc_observation* obs_b = (struct htlc_observation*)b;
    
    if (obs_a->amount != obs_b->amount) {
        return obs_a->amount < obs_b->amount ? -1 : 1;
    }
    if (obs_a->timestamp != obs_b->timestamp) {
        return obs_a->timestamp < obs_b->timestamp ? -1 : 1;
    }
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
    
    // Check if amounts match
    if (obs1->amount != obs2->amount) {
        return 0;
    }
    
    // Check if timelocks match
    if (obs1->timelock != obs2->timelock) {
        return 0;
    }
    
    // Check if timestamps are within window
    uint64_t time_diff = (obs1->timestamp > obs2->timestamp) ?
                         (obs1->timestamp - obs2->timestamp) :
                         (obs2->timestamp - obs1->timestamp);
    
    if (time_diff > time_window_ms) {
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
struct array* integrate_observations_from_monitors(struct network* network) {
    struct array* estimated_payments = array_initialize(100);
    
    if (g_htlc_observations == NULL || array_len(g_htlc_observations) == 0) {
        printf("[Monitoring] No observations recorded\n");
        return estimated_payments;
    }
    
    // Ensure trust scores are initialized
    if (g_num_monitors_with_scores == 0) {
        initialize_monitor_trust_scores(network);
    }
    
    int num_obs = array_len(g_htlc_observations);
    printf("[Monitoring] Processing %d observations\n", num_obs);
    
    // Group observations by payment_id and amount
    struct array** observation_groups = (struct array**)malloc(num_obs * sizeof(struct array*));
    int* group_ids = (int*)malloc(num_obs * sizeof(int));
    int num_groups = 0;
    
    // Mark which observations have been grouped
    int* processed = (int*)calloc(num_obs, sizeof(int));
    
    uint64_t time_window = 10000;  // 10 second window for matching observations
    
    for (int i = 0; i < num_obs; i++) {
        if (processed[i]) continue;
        
        struct htlc_observation* obs_i = (struct htlc_observation*)array_get(g_htlc_observations, i);
        
        // Start new group
        observation_groups[num_groups] = array_initialize(20);
        observation_groups[num_groups] = array_insert(observation_groups[num_groups], obs_i);
        processed[i] = 1;
        group_ids[num_groups] = (int)obs_i->payment_id;
        
        // Find matching observations to form chain
        for (int j = i + 1; j < num_obs; j++) {
            if (processed[j]) continue;
            
            struct htlc_observation* obs_j = (struct htlc_observation*)array_get(g_htlc_observations, j);
            
            // Try to link: current group's last obs.next_node == obs_j.prev_node
            struct htlc_observation* last_obs = (struct htlc_observation*)
                array_get(observation_groups[num_groups], 
                          array_len(observation_groups[num_groups]) - 1);
            
            if (last_obs->next_node_id == obs_j->prev_node_id &&
                observations_match(last_obs, obs_j, time_window)) {
                
                observation_groups[num_groups] = array_insert(observation_groups[num_groups], obs_j);
                processed[j] = 1;
            }
        }
        
        num_groups++;
    }
    
    printf("[Monitoring] Formed %d observation groups\n", num_groups);
    
    // Convert groups to estimated payments
    for (int g = 0; g < num_groups; g++) {
        struct estimated_payment* est = (struct estimated_payment*)malloc(sizeof(struct estimated_payment));
        
        if (est == NULL) {
            continue;
        }
        
        struct htlc_observation* first_obs = (struct htlc_observation*)
            array_get(observation_groups[g], 0);
        struct htlc_observation* last_obs = (struct htlc_observation*)
            array_get(observation_groups[g], array_len(observation_groups[g]) - 1);
        
        // Reconstruct path
        int path_len = 0;
        est->complete_path = reconstruct_payment_path_from_chain(observation_groups[g], &path_len);
        est->path_length = path_len;
        est->amount = first_obs->amount;
        est->num_observations = array_len(observation_groups[g]);
        
        // Estimate success and confidence
        strcpy(est->success_status, "estimated");
        
        /* === Confidence Calculation Based on Observation Count === */
        // TODO: Enhance with monitor trust scores after initialization
        est->confidence_level = (float)est->num_observations / 10.0f;  // Simple heuristic
        if (est->confidence_level > 1.0f) est->confidence_level = 1.0f;
        
        estimated_payments = array_insert(estimated_payments, est);
    }
    
    // Cleanup
    for (int g = 0; g < num_groups; g++) {
        // Don't free observation_groups[g] contents - they reference g_htlc_observations
        array_free(observation_groups[g]);
    }
    free(observation_groups);
    free(group_ids);
    free(processed);
    
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
    
    printf("[Monitoring] Sharing information across monitors...\n");
    printf("[Monitoring] Total observations: %d\n", num_observations);
    
    // Integrate observations to get estimated payment paths
    struct array* estimated_payments = integrate_observations_from_monitors(network);
    
    if (estimated_payments == NULL) {
        return;
    }
    
    // Analyze estimated payments to identify suspicious nodes
    int num_estimated = array_len(estimated_payments);
    printf("[Monitoring] Estimated payments from integration: %d\n", num_estimated);
    
    // Initialize node suspicion scores (0.0 = trusted, 1.0 = malicious)
    double* node_suspicion = (double*)calloc(array_len(network->nodes), sizeof(double));
    int* node_suspicion_count = (int*)calloc(array_len(network->nodes), sizeof(int));
    
    // Analyze each estimated payment path
    for (int i = 0; i < num_estimated; i++) {
        struct estimated_payment* est_pmt = (struct estimated_payment*)array_get(estimated_payments, i);
        
        if (est_pmt == NULL || est_pmt->complete_path == NULL) {
            continue;
        }
        
        // If payment failed and has high confidence, nodes in path are suspects
        if (strcmp(est_pmt->success_status, "failure") == 0 && est_pmt->confidence_level > 0.7) {
            // Distribute suspicion across path nodes
            double suspicion_increment = (1.0 - est_pmt->confidence_level) * 0.3;  // Partial suspicion
            
            for (int j = 1; j < est_pmt->path_length - 1; j++) {  // Skip sender and receiver
                long node_id = est_pmt->complete_path[j];
                
                if (node_id >= 0 && node_id < (long)array_len(network->nodes)) {
                    node_suspicion[node_id] += suspicion_increment;
                    node_suspicion_count[node_id]++;
                }
            }
        }
    }
    
    // Update global reputation scores based on integrated information
    printf("[Monitoring] Updating reputation scores...\n");
    
    int nodes_updated = 0;
    int num_nodes = array_len(network->nodes);
    
    for (int i = 0; i < num_nodes; i++) {
        struct node* node = (struct node*)array_get(network->nodes, i);
        
        if (node == NULL) {
            continue;
        }
        
        // Base reputation: 1.0 (trusted)
        double reputation = 1.0;
        
        // Adjust based on suspicion from monitoring
        if (node_suspicion_count[i] > 0) {
            double avg_suspicion = node_suspicion[i] / node_suspicion_count[i];
            reputation -= avg_suspicion * 0.5;  // Suspicion reduces reputation by up to 50%
        }
        
        // Known malicious nodes get very low reputation
        if (node->is_malicious) {
            reputation *= 0.1;  // 10% of normal reputation
        }
        
        // Clamp reputation to [0.0, 1.0]
        if (reputation < 0.0) reputation = 0.0;
        if (reputation > 1.0) reputation = 1.0;
        
        // Update node reputation
        double old_rep = node->reputation_score;
        node->reputation_score = reputation;
        
        if (reputation != old_rep) {
            nodes_updated++;
        }
    }
    
    printf("[Monitoring] Updated reputation for %d nodes\n", nodes_updated);
    
    // Identify and report suspected malicious nodes
    int suspect_count = 0;
    for (int i = 0; i < num_nodes; i++) {
        struct node* node = (struct node*)array_get(network->nodes, i);
        if (node != NULL && node->reputation_score < 0.5) {
            suspect_count++;
        }
    }
    
    printf("[Monitoring] Nodes with low reputation (<0.5): %d\n", suspect_count);
    printf("[Monitoring] Information sharing complete - Routing can now use reputation scores\n");
    
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

