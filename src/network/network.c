#include <string.h>
#include <stdlib.h>
#include <gsl/gsl_math.h>
#include <gsl/gsl_rng.h>
#include "network/network.h"
#include "data_structures/array.h"
#include "data_structures/utils.h"


/* Functions in this file generate a payment-channel network where to simulate the execution of payments */
/* このファイルは LN 風の支払いチャネルネットワークを構築・管理する。
 * - スナップショット CSV からネットワーク生成
 * - ランダム (スケールフリー) ネットワーク生成
 * - グループ構造 (group) の更新・スナップショット取得・解放など。 */


/* 新しいノード構造体を確保して初期化するヘルパー。
 * id をセットし、open_edges/result 配列を初期状態にする。
 *
 * 通常はネットワーク生成時にのみ呼ばれる。 */
struct node* new_node(long id) {
  struct node* node;
  node = malloc(sizeof(struct node));
  node->id=id;
  node->open_edges = array_initialize(10);
  node->results = NULL;
  node->explored = 0;
  /* === Stage ① Initialize Malicious Fields === */
  node->is_malicious = 0;
  node->attack_probability = 0.0;
  /* === Stage ② Initialize Monitor Fields === */
  node->is_monitor = 0;
  node->monitor_id = -1;
  /* === Stage ③ Initialize Reputation Fields === */
  node->reputation_score = 1.0;     // Start with full reputation
  node->malicious_reports = 0;      // No incidents yet
  node->last_movement_time = 0;     // Not yet moved
  node->first_attack_time = 0;
  node->first_detection_time = 0;
  return node;
}


/* 新しいチャネル構造体を確保して初期化するヘルパー。
 * 片方向 edge ID と両端ノード ID、容量 (capacity) を受け取り、
 * is_closed=0 で初期化する。通常は generate_* 内部からのみ使用。 */
struct channel* new_channel(long id, long direction1, long direction2, long node1, long node2, uint64_t capacity) {
  struct channel* channel;
  channel = malloc(sizeof(struct channel));
  channel->id = id;
  channel->edge1 = direction1;
  channel->edge2 = direction2;
  channel->node1 = node1;
  channel->node2 = node2;
  channel->capacity = capacity;
  channel->is_closed = 0;
//  channel->occupied = 0;
//  channel->payment_history = NULL;
  return channel;
}


//struct edge* new_edge(long id, long channel_id, long counter_edge_id, long from_node_id, long to_node_id, uint64_t balance, struct policy policy, uint64_t channel_capacity){
/* 新しいエッジ (片方向チャネル) を生成するヘルパー。
 *
 * - balance, policy, 対向 edge ID を設定
 * - channel_capacity を初期 htlc_maximum_msat とする channel_update を 1 つ作成
 *
 * 通常はネットワーク生成時のみ呼ばれる。 */
struct edge* new_edge(long id, long channel_id, long counter_edge_id, long from_node_id, long to_node_id, uint64_t balance, struct policy policy, uint64_t channel_capacity){
  struct edge* edge;
  edge = malloc(sizeof(struct edge));
  edge->id = id;
  edge->channel_id = channel_id;
  edge->from_node_id = from_node_id;
  edge->to_node_id = to_node_id;
  edge->counter_edge_id = counter_edge_id;
  edge->policy = policy;
  edge->balance = balance;
  edge->is_closed = 0;
  edge->tot_flows = 0;
  edge->group = NULL;
  struct channel_update* channel_update = malloc(sizeof(struct channel_update));
  channel_update->htlc_maximum_msat = channel_capacity;
  channel_update->edge_id = edge->id;
  channel_update->time = 0;
  edge->channel_updates = push(NULL, channel_update);
  return edge;
}


/* after generating a network, write it in csv files "nodes.csv" "edges.csv" "channels.csv"
 *
 * ネットワーク生成直後の状態を、nodes.csv / channels.csv / edges.csv
 * の 3 つの CSV に書き出す。
 *
 * generate_random_network() の最後で 1 回呼ばれる想定。 */
void write_network_files(struct network* network){
  FILE* nodes_output_file, *edges_output_file, *channels_output_file;
  long i;
  struct node* node;
  struct channel* channel;
  struct edge* edge;

  nodes_output_file = fopen("nodes.csv", "w");
  if(nodes_output_file==NULL) {
    fprintf(stderr, "ERROR: cannot open file <%s>\n", "nodes.csv");
    exit(-1);
  }
  fprintf(nodes_output_file, "id\n");
  channels_output_file = fopen("channels.csv", "w");
  if(channels_output_file==NULL) {
    fprintf(stderr, "ERROR: cannot open file <%s>\n", "channels.csv");
    fclose(nodes_output_file);
    exit(-1);
  }
  fprintf(channels_output_file, "id,edge1_id,edge2_id,node1_id,node2_id,capacity\n");
  edges_output_file = fopen("edges.csv", "w");
  if(edges_output_file==NULL) {
    fprintf(stderr, "ERROR: cannot open file <%s>\n", "edges.csv");
    fclose(nodes_output_file);
    fclose(channels_output_file);
    exit(-1);
  }
  fprintf(edges_output_file, "id,channel_id,counter_edge_id,from_node_id,to_node_id,balance,fee_base,fee_proportional,min_htlc,timelock\n");

  for(i=0; i<array_len(network->nodes); i++){
    node = array_get(network->nodes, i);
    fprintf(nodes_output_file, "%ld\n", node->id);
  }

  for(i=0; i<array_len(network->channels); i++){
    channel = array_get(network->channels, i);
    fprintf(channels_output_file, "%ld,%ld,%ld,%ld,%ld,%ld\n", channel->id, channel->edge1, channel->edge2, channel->node1, channel->node2, channel->capacity);
  }

  for(i=0; i<array_len(network->edges); i++){
    edge = array_get(network->edges, i);
    fprintf(edges_output_file, "%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%d\n", edge->id, edge->channel_id, edge->counter_edge_id, edge->from_node_id, edge->to_node_id, edge->balance, (edge->policy).fee_base, (edge->policy).fee_proportional, (edge->policy).min_htlc, (edge->policy).timelock);
  }

  fclose(nodes_output_file);
  fclose(edges_output_file);
  fclose(channels_output_file);
}


/* スケールフリー生成用：各ノードのチャネル本数に応じた接続確率配列を更新。
 *
 * 既存チャネル数カウンタを更新し、その比率から
 * 次に接続される確率 distribution を計算する。 */
void update_probability_per_node(double *probability_per_node, int *channels_per_node, long n_nodes, long node1_id, long node2_id, long tot_channels){
  long i;
  channels_per_node[node1_id] += 1;
  channels_per_node[node2_id] += 1;
  for(i=0; i<n_nodes; i++)
    probability_per_node[i] = ((double)channels_per_node[i])/tot_channels;
}

/* generate a channel (connecting node1_id and node2_id) with random values */
void generate_random_channel(struct channel channel_data, uint64_t mean_channel_capacity, struct network* network, gsl_rng*random_generator, double cul_threshold_dist_alpha, double cul_threshold_dist_beta) {
  uint64_t capacity, edge1_balance, edge2_balance;
  struct policy edge1_policy, edge2_policy;
  double min_htlcP[]={0.7, 0.2, 0.05, 0.05}, fraction_capacity;
  gsl_ran_discrete_t* min_htlc_discrete;
  struct channel* channel;
  struct edge* edge1, *edge2;
  struct node* node;

  capacity = fabs(mean_channel_capacity + gsl_ran_ugaussian(random_generator));
  channel = new_channel(channel_data.id, channel_data.edge1, channel_data.edge2, channel_data.node1, channel_data.node2, capacity*1000);

  fraction_capacity = gsl_rng_uniform(random_generator);
  edge1_balance = fraction_capacity*((double) capacity);
  edge2_balance = capacity - edge1_balance;
  //multiplied by 1000 to convert satoshi to millisatoshi
  edge1_balance*=1000;
  edge2_balance*=1000;

  min_htlc_discrete = gsl_ran_discrete_preproc(4, min_htlcP);
  edge1_policy.fee_base = gsl_rng_uniform_int(random_generator, MAXFEEBASE - MINFEEBASE) + MINFEEBASE;
  edge1_policy.fee_proportional = (gsl_rng_uniform_int(random_generator, MAXFEEPROP-MINFEEPROP)+MINFEEPROP);
  edge1_policy.timelock = gsl_rng_uniform_int(random_generator, MAXTIMELOCK-MINTIMELOCK)+MINTIMELOCK;
  edge1_policy.min_htlc = gsl_pow_int(10, gsl_ran_discrete(random_generator, min_htlc_discrete));
  edge1_policy.min_htlc = edge1_policy.min_htlc == 1 ? 0 : edge1_policy.min_htlc;
  edge1_policy.cul_threshold = gsl_ran_beta(random_generator, cul_threshold_dist_alpha, cul_threshold_dist_beta);
  edge2_policy.fee_base = gsl_rng_uniform_int(random_generator, MAXFEEBASE - MINFEEBASE) + MINFEEBASE;
  edge2_policy.fee_proportional = (gsl_rng_uniform_int(random_generator, MAXFEEPROP-MINFEEPROP)+MINFEEPROP);
  edge2_policy.timelock = gsl_rng_uniform_int(random_generator, MAXTIMELOCK-MINTIMELOCK)+MINTIMELOCK;
  edge2_policy.min_htlc = gsl_pow_int(10, gsl_ran_discrete(random_generator, min_htlc_discrete));
  edge2_policy.min_htlc = edge2_policy.min_htlc == 1 ? 0 : edge2_policy.min_htlc;
  edge2_policy.cul_threshold = gsl_ran_beta(random_generator, cul_threshold_dist_alpha, cul_threshold_dist_beta);

  edge1 = new_edge(channel_data.edge1, channel_data.id, channel_data.edge2, channel_data.node1, channel_data.node2, edge1_balance, edge1_policy, channel_data.capacity);
  edge2 = new_edge(channel_data.edge2, channel_data.id, channel_data.edge1, channel_data.node2, channel_data.node1, edge2_balance, edge2_policy, channel_data.capacity);

  network->channels = array_insert(network->channels, channel);
  network->edges = array_insert(network->edges, edge1);
  network->edges = array_insert(network->edges, edge2);

  node = array_get(network->nodes, channel_data.node1);
  node->open_edges = array_insert(node->open_edges, &(edge1->id));
  node = array_get(network->nodes, channel_data.node2);
  node->open_edges = array_insert(node->open_edges, &(edge2->id));
}


/* generate a random payment-channel network;
   the model of the network is a snapshot of the Lightning Network (files "nodes_ln.csv", "channels_ln.csv");
   starting from this network, a random network is generated using the scale-free network model
 *
 * LN スナップショット (nodes_ln.csv / channels_ln.csv) をベースに、
 * 追加ノード + スケールフリー接続モデルでネットワークを拡張する。
 *
 * - net_params.n_nodes, n_channels, capacity_per_channel 等を利用
 * - 生成結果は write_network_files() で CSV にも出力される。 */
struct network* generate_random_network(struct network_params net_params, gsl_rng* random_generator){
  FILE* nodes_input_file, *channels_input_file;
  char row[256];
  long node_id_counter=0, id, channel_id_counter=0, tot_nodes, i, tot_channels, node_to_connect_id, edge_id_counter=0, j;
  double *probability_per_node;
  int *channels_per_node;
  struct network* network;
  struct node* node;
  gsl_ran_discrete_t* connection_probability;
  struct channel channel;

  nodes_input_file = fopen("nodes_ln.csv", "r");
  if(nodes_input_file==NULL) {
    fprintf(stderr, "ERROR: cannot open file <%s>\n", "nodes_ln.csv");
    exit(-1);
  }
  channels_input_file = fopen("channels_ln.csv", "r");
  if(channels_input_file==NULL) {
    fprintf(stderr, "ERROR: cannot open file <%s>\n", "channels_ln.csv");
    fclose(nodes_input_file);
    exit(-1);
  }

  network = (struct network*) malloc(sizeof(struct network));
  network->nodes = array_initialize(1000);
  network->channels = array_initialize(1000);
  network->edges = array_initialize(2000);

  fgets(row, 256, nodes_input_file);
  while(fgets(row, 256, nodes_input_file)!=NULL) {
    sscanf(row, "%ld,%*d", &id);
    node = new_node(id);
    network->nodes = array_insert(network->nodes, node);
    node_id_counter++;
  }
  tot_nodes = node_id_counter + net_params.n_nodes;
  if(tot_nodes == 0){
    fprintf(stderr, "ERROR: it is not possible to generate a network with 0 nodes\n");
    fclose(nodes_input_file);
    fclose(channels_input_file);
    exit(-1);
  }

  channels_per_node = malloc(sizeof(int)*(tot_nodes));
  for(i = 0; i < tot_nodes; i++){
    channels_per_node[i] = 0;
  }

  fgets(row, 256, channels_input_file);
  while(fgets(row, 256, channels_input_file)!=NULL) {
    sscanf(row, "%ld,%ld,%ld,%ld,%ld,%*d,%*d", &(channel.id), &(channel.edge1), &(channel.edge2), &(channel.node1), &(channel.node2));
    generate_random_channel(channel, net_params.capacity_per_channel, network, random_generator, net_params.cul_threshold_dist_alpha, net_params.cul_threshold_dist_beta);
    channels_per_node[channel.node1] += 1;
    channels_per_node[channel.node2] += 1;
    ++channel_id_counter;
    edge_id_counter+=2;
  }
  tot_channels = channel_id_counter;
  if(tot_channels == 0){
    fprintf(stderr, "ERROR: it is not possible to generate a network with 0 channels\n");
    fclose(nodes_input_file);
    fclose(channels_input_file);
    exit(-1);
  }

  probability_per_node = malloc(sizeof(double)*tot_nodes);
  for(i=0; i<tot_nodes; i++){
    probability_per_node[i] = ((double)channels_per_node[i])/tot_channels;
  }

  /* scale-free algorithm that creates a network starting from an existing network;
     the probability of connecting nodes is directly proprotional to the number of channels that a node has already open */
  for(i=0; i<net_params.n_nodes; i++){
    node = new_node(node_id_counter);
    network->nodes = array_insert(network->nodes, node);
    for(j=0; j<net_params.n_channels; j++){
      connection_probability = gsl_ran_discrete_preproc(node_id_counter, probability_per_node);
      node_to_connect_id = gsl_ran_discrete(random_generator, connection_probability);
      channel.id = channel_id_counter;
      channel.edge1 = edge_id_counter;
      channel.edge2 = edge_id_counter + 1;
      channel.node1 = node->id;
      channel.node2 = node_to_connect_id;
      generate_random_channel(channel, net_params.capacity_per_channel, network, random_generator, net_params.cul_threshold_dist_alpha, net_params.cul_threshold_dist_beta);
      channel_id_counter++;
      edge_id_counter += 2;
      update_probability_per_node(probability_per_node, channels_per_node, tot_nodes, node->id, node_to_connect_id, channel_id_counter);
    }
    ++node_id_counter;
  }

  fclose(nodes_input_file);
  fclose(channels_input_file);
  free(channels_per_node);
  free(probability_per_node);

  write_network_files(network);

  return network;
}


/* generate a payment-channel network from input files
 *
 * ユーザ指定の CSV (nodes/channels/edges) からネットワークを構築する。
 *
 * 引数はファイルパス文字列で、各 CSV のフォーマットは
 * 対応する *_template.csv を参照。cloth_input.txt の
 * generate_network_from_file=true の場合に使われる。 */
struct network* generate_network_from_files(char nodes_filename[256], char channels_filename[256], char edges_filename[256]) {
  char row[2048];
  struct node* node;
  long id, direction1, direction2, node_id1, node_id2, channel_id, other_direction;
  struct policy policy;
  uint64_t capacity, balance;
  struct channel* channel;
  struct edge* edge;
  struct network* network;
  FILE *nodes_file, *channels_file, *edges_file;

  nodes_file = fopen(nodes_filename, "r");
  if(nodes_file==NULL) {
    fprintf(stderr, "ERROR: cannot open file <%s>\n", nodes_filename);
    exit(-1);
  }
  channels_file = fopen(channels_filename, "r");
  if(channels_file==NULL) {
    fprintf(stderr, "ERROR: cannot open file <%s>\n", channels_filename);
    fclose(nodes_file);
    exit(-1);
  }
  edges_file = fopen(edges_filename, "r");
  if(edges_file==NULL) {
    fprintf(stderr, "ERROR: cannot open file <%s>\n", edges_filename);
    fclose(nodes_file);
    fclose(channels_file);
    exit(-1);
  }

  network = (struct network*) malloc(sizeof(struct network));
  network->nodes = array_initialize(1000);
  network->channels = array_initialize(1000);
  network->edges = array_initialize(2000);

  fgets(row, 2048, nodes_file);
  while(fgets(row, 2048, nodes_file)!=NULL) {
    sscanf(row, "%ld", &id);
    node = new_node(id);
    network->nodes = array_insert(network->nodes, node);
  }
  fclose(nodes_file);

  fgets(row, 2048, channels_file);
  while(fgets(row, 2048, channels_file)!=NULL) {
    sscanf(row, "%ld,%ld,%ld,%ld,%ld,%ld", &id, &direction1, &direction2, &node_id1, &node_id2, &capacity);
    channel = new_channel(id, direction1, direction2, node_id1, node_id2, capacity);
    network->channels = array_insert(network->channels, channel);
  }
  fclose(channels_file);


  fgets(row, 2048, edges_file);
  while(fgets(row, 2048, edges_file)!=NULL) {
    sscanf(row, "%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%d,%lf", &id, &channel_id, &other_direction, &node_id1, &node_id2, &balance, &policy.fee_base, &policy.fee_proportional, &policy.min_htlc, &policy.timelock, &policy.cul_threshold);
    channel = array_get(network->channels, channel_id);
    edge = new_edge(id, channel_id, other_direction, node_id1, node_id2, balance, policy, channel->capacity);
    network->edges = array_insert(network->edges, edge);
    node = array_get(network->nodes, node_id1);
    node->open_edges = array_insert(node->open_edges, &(edge->id));
  }
  fclose(edges_file);

  return network;
}


/* === Stage ① Malicious Node Initialization ===
 *
 * Randomly designate a fraction (malicious_node_ratio) of nodes as malicious.
 * Each malicious node is assigned a failure_probability that determines the
 * chance it will reject/fail an HTLC during forwarding.
 *
 * Parameters:
 *   - network: populated network structure
 *   - malicious_ratio: fraction [0.0, 1.0] of nodes to mark as malicious
 *   - failure_prob: probability of HTLC failure on malicious nodes
 *   - rng: GSL random generator
 */
void initialize_malicious_nodes(struct network* network, 
                                 double malicious_ratio, 
                                 double failure_prob,
                                 gsl_rng* rng) {
    long n_nodes = array_len(network->nodes);
    long n_malicious = (long)(n_nodes * malicious_ratio);
    
    if (n_malicious <= 0) {
        // No malicious nodes
        printf("[Malicious Nodes] Disabled (ratio=%.2f)\n", malicious_ratio);
        return;
    }
    
    printf("[Malicious Nodes] Initializing: %ld nodes out of %ld will be malicious\n",
           n_malicious, n_nodes);
    
    // Create a shuffled array of node indices and select first n_malicious
    long* node_indices = (long*)malloc(n_nodes * sizeof(long));
    for (long i = 0; i < n_nodes; i++) {
        node_indices[i] = i;
    }
    
    // Fisher-Yates shuffle
    for (long i = n_nodes - 1; i > 0; i--) {
        long j = gsl_rng_uniform_int(rng, i + 1);
        long temp = node_indices[i];
        node_indices[i] = node_indices[j];
        node_indices[j] = temp;
    }
    
    // Mark first n_malicious nodes as malicious
    for (long i = 0; i < n_malicious; i++) {
        struct node* node = (struct node*)array_get(network->nodes, node_indices[i]);
        node->is_malicious = 1;
        node->attack_probability = failure_prob;
    }
    
    free(node_indices);
    
    printf("[Malicious Nodes] Deployment complete: %ld malicious nodes, failure_prob=%.2f\n",
           n_malicious, failure_prob);
}


/* === Stage ② Hub Detection and Analysis ===
 *
 * Scans the network for hub nodes (degree > threshold) and extracts their
 * neighbor information. Results stored in network->hubs array.
 */
void initialize_hub_info(struct network* network, int hub_threshold) {
    long n_nodes = array_len(network->nodes);
    int temp_hub_count = 0;
    
    // Pass 1: Count hubs
    for (long i = 0; i < n_nodes; i++) {
        struct node* node = (struct node*)array_get(network->nodes, i);
        if ((int)array_len(node->open_edges) > hub_threshold) {
            temp_hub_count++;
        }
    }
    
    network->hubs = (HubInfo*)malloc(temp_hub_count * sizeof(HubInfo));
    network->num_hubs = 0;
    
    // Pass 2: Extract hub info
    for (long i = 0; i < n_nodes; i++) {
        struct node* node = (struct node*)array_get(network->nodes, i);
        int degree = (int)array_len(node->open_edges);
        
        if (degree > hub_threshold) {
            HubInfo* hub = &network->hubs[network->num_hubs];
            hub->hub_id = (int)i;
            hub->degree = degree;
            hub->neighbor_ids = (int*)malloc(degree * sizeof(int));
            hub->num_neighbors = 0;
            
            // Extract neighbor IDs from edges
            for (long j = 0; j < array_len(node->open_edges); j++) {
                long edge_id = *(long*)array_get(node->open_edges, j);
                struct edge* edge = (struct edge*)array_get(network->edges, edge_id);
                int neighbor_id = (edge->from_node_id == i) ? 
                    (int)edge->to_node_id : (int)edge->from_node_id;
                hub->neighbor_ids[hub->num_neighbors++] = neighbor_id;
            }
            
            network->num_hubs++;
        }
    }
    
    printf("[Hub Detection] Found %d hubs (degree > %d)\n", network->num_hubs, hub_threshold);
}


/* === Stage ② Leaf Neighbor Analysis ===
 *
 * For each hub, identifies neighbors with degree <= threshold (likely leaf nodes)
 * and stores them separately for monitor placement.
 */
void analyze_leaf_neighbors(struct network* network, int leaf_threshold) {
    for (int h = 0; h < network->num_hubs; h++) {
        HubInfo* hub = &network->hubs[h];
        
        // Pass 1: Count leaf neighbors
        int leaf_count = 0;
        for (int n = 0; n < hub->num_neighbors; n++) {
            int neighbor_id = hub->neighbor_ids[n];
            struct node* neighbor = (struct node*)array_get(network->nodes, neighbor_id);
            int neighbor_degree = (int)array_len(neighbor->open_edges);
            
            if (neighbor_degree <= leaf_threshold) {
                leaf_count++;
            }
        }
        
        // Pass 2: Store leaf neighbor IDs
        hub->leaf_neighbor_ids = (int*)malloc(leaf_count * sizeof(int));
        hub->num_leaf_neighbors = 0;
        
        for (int n = 0; n < hub->num_neighbors; n++) {
            int neighbor_id = hub->neighbor_ids[n];
            struct node* neighbor = (struct node*)array_get(network->nodes, neighbor_id);
            int neighbor_degree = (int)array_len(neighbor->open_edges);
            
            if (neighbor_degree <= leaf_threshold) {
                hub->leaf_neighbor_ids[hub->num_leaf_neighbors++] = neighbor_id;
            }
        }
    }
    
    printf("[Leaf Analysis] Leaf nodes categorized for all hubs\n");
}


/* === Stage ② Method 1: Hub-Leaf Monitor Deployment ===
 *
 * Places monitoring agents on low-degree nodes connected to hubs.
 * Expected coverage: ~70% of payment paths
 *
 * Algorithm:
 *   1. For each hub, identify low-degree neighbors (likely end-users)
 *   2. Deploy monitor on each leaf node, watching the hub
 *   3. Record monitoring relationship in MonitorAgent structure
 */
int deploy_monitors_method1(struct network* network, int hub_threshold, int leaf_threshold) {
    // Stage 1: Hub detection
    initialize_hub_info(network, hub_threshold);
    analyze_leaf_neighbors(network, leaf_threshold);
    
    // Stage 2: Deploy monitors on leaf nodes
    int total_monitors = 0;
    network->monitors = NULL;
    
    for (int h = 0; h < network->num_hubs; h++) {
        HubInfo* hub = &network->hubs[h];
        
        for (int l = 0; l < hub->num_leaf_neighbors; l++) {
            if (total_monitors >= MONITOR_NODE_LIMIT) {
                break;
            }
            int leaf_node_id = hub->leaf_neighbor_ids[l];
            
            // Allocate monitor
            network->monitors = (MonitorAgent*)realloc(network->monitors, 
                (total_monitors + 1) * sizeof(MonitorAgent));
            
            MonitorAgent* m = &network->monitors[total_monitors];
            m->monitor_id = total_monitors;
            m->node_id = leaf_node_id;
            m->deployed_at_stage = 1;  // Method 1
            m->watching_hub_id = hub->hub_id;
            m->direct_hub_connections = NULL;
            m->num_direct_hubs = 0;
            
            // Initialize observation statistics
            m->total_htlcs_observed = 0;
            m->htlcs_with_correlated_pairs = 0;
            m->payments_captured = 0;
            
            // Mark node as having a monitor
            struct node* leaf_node = (struct node*)array_get(network->nodes, leaf_node_id);
            leaf_node->is_monitor = 1;
            leaf_node->monitor_id = total_monitors;
            
            total_monitors++;
        }

        if (total_monitors >= MONITOR_NODE_LIMIT) {
            break;
        }
    }
    
    network->num_monitors = total_monitors;
    network->cumulative_monitor_assignments = total_monitors;
    network->cumulative_monitor_relocations = 0;
    printf("[Method1 Deployment] Placed %d monitors on leaf nodes\n", total_monitors);
    
    return total_monitors;
}


/* === Stage ② Utility: Get Top Hubs by Degree ===
 *
 * Sorts hubs by degree and returns top K hub IDs.
 */
static int compare_hub_by_degree(const void* a, const void* b) {
    return ((HubInfo*)b)->degree - ((HubInfo*)a)->degree;
}

typedef struct {
    int node_id;
    int degree;
} NodeDegree;

static int compare_node_degree_desc(const void* a, const void* b) {
    const NodeDegree* na = (const NodeDegree*)a;
    const NodeDegree* nb = (const NodeDegree*)b;
    return nb->degree - na->degree;
}

static int* get_top_hubs_by_degree(struct network* network, int top_k) {
    if (top_k > network->num_hubs) {
        top_k = network->num_hubs;
    }
    
    // Sort hubs by degree
    HubInfo* sorted_hubs = (HubInfo*)malloc(network->num_hubs * sizeof(HubInfo));
    memcpy(sorted_hubs, network->hubs, network->num_hubs * sizeof(HubInfo));
    qsort(sorted_hubs, network->num_hubs, sizeof(HubInfo), compare_hub_by_degree);
    
    // Extract top K hub IDs
    int* top_hub_ids = (int*)malloc(top_k * sizeof(int));
    for (int i = 0; i < top_k; i++) {
        top_hub_ids[i] = sorted_hubs[i].hub_id;
    }
    
    free(sorted_hubs);
    return top_hub_ids;
}


/* === Stage ② Method 2: Enhanced with Top Hub Connections ===
 *
 * Extends Method 1 by adding direct virtual connections to top K hubs.
 * Expected coverage: ~85% of payment paths
 *
 * Algorithm:
 *   1. Deploy all Method 1 monitors
 *   2. Identify top K hubs by degree
 *   3. Add virtual direct connections from all monitors to top K hubs
 */
int deploy_monitors_method2_enhanced(struct network* network, int hub_threshold, 
                                      int leaf_threshold, int top_hub_count) {
    // Stage 1: Deploy Method 1
    deploy_monitors_method1(network, hub_threshold, leaf_threshold);
    int deployed_method1_count = network->num_monitors;
    
    // Stage 2: Get top hubs
    int* top_hubs = get_top_hubs_by_degree(network, top_hub_count);
    
    printf("[Method2] Top %d hubs by degree:\n", top_hub_count);
    for (int i = 0; i < top_hub_count; i++) {
        HubInfo* hub_info = NULL;
        for (int h = 0; h < network->num_hubs; h++) {
            if (network->hubs[h].hub_id == top_hubs[i]) {
                hub_info = &network->hubs[h];
                break;
            }
        }
        if (hub_info) {
            printf("  Hub %d: degree=%d\n", top_hubs[i], hub_info->degree);
        }
    }
    
    // Stage 3: Add virtual connections to all monitors
    for (int m = 0; m < deployed_method1_count; m++) {
        MonitorAgent* monitor = &network->monitors[m];
        
        monitor->direct_hub_connections = (int*)malloc(top_hub_count * sizeof(int));
        for (int h = 0; h < top_hub_count; h++) {
            monitor->direct_hub_connections[h] = top_hubs[h];
        }
        monitor->num_direct_hubs = top_hub_count;
    }
    
    free(top_hubs);
    
    printf("[Method2 Enhancement] Added top-%d hub connections to all %d monitors\n",
           top_hub_count, deployed_method1_count);
    
    return network->num_monitors;
}


/* === Stage ② HTLC Observation Logging ===
 *
 * When an HTLC passes through a monitor node, record the observation.
 * Multiple monitors observing the same payment enables information correlation.
 */
void detect_and_record_htlc_observation(struct network* network, long payment_id, 
                                        uint64_t amount, int node_id, int direction) {
    if (!network || network->num_monitors == 0) {
        return;
    }
    
    // Check if this node is a monitor
    struct node* node = (struct node*)array_get(network->nodes, node_id);
    if (!node || !node->is_monitor) {
        return;
    }
    
    int monitor_id = node->monitor_id;
    if (monitor_id < 0 || monitor_id >= network->num_monitors) {
        return;
    }
    
    MonitorAgent* monitor = &network->monitors[monitor_id];
    
    if (direction == 0) {  // Incoming HTLC
        monitor->total_htlcs_observed++;
    } else {               // Outgoing HTLC
        // Could track outgoing separately if needed
    }
}


/* === Stage ③ Initialize Reputation Scores ===
 * Set all nodes to full reputation (1.0) at start
 */
void initialize_reputation_scores(struct network* network) {
    if (network == NULL || network->nodes == NULL) {
        return;
    }
    
    for (int i = 0; i < array_len(network->nodes); i++) {
        struct node* node = (struct node*)array_get(network->nodes, i);
        if (node != NULL) {
            node->reputation_score = 1.0;
            node->malicious_reports = 0;
            node->last_movement_time = 0;
            node->first_attack_time = 0;
            node->first_detection_time = 0;
        }
    }
}


/* === Stage ③ Update Node Reputation on Detection ===
 * Called when a monitor detects malicious activity from a node
 * Reduces reputation by penalty amount
 */
void update_node_reputation_on_detection(struct node* node, double penalty, uint64_t detection_time) {
    if (node == NULL) {
        return;
    }

    if (node->first_detection_time == 0 && detection_time > 0) {
        node->first_detection_time = detection_time;
    }

    node->malicious_reports++;
    node->reputation_score -= penalty;
    
    // Clamp to [0.0, 1.0]
    if (node->reputation_score < 0.0) {
        node->reputation_score = 0.0;
    } else if (node->reputation_score > 1.0) {
        node->reputation_score = 1.0;
    }
}


/* === Stage ③ Apply Reputation Decay to All Nodes ===
 * Decays reputation scores over time
 * This models "forgetting" older incidents
 */
void apply_reputation_decay_all_nodes(struct network* network, double decay_rate) {
    if (network == NULL || network->nodes == NULL) {
        return;
    }
    
    for (int i = 0; i < array_len(network->nodes); i++) {
        struct node* node = (struct node*)array_get(network->nodes, i);
        if (node != NULL && !node->is_malicious) {
            // Honest nodes recover reputation over time (decay is negative penalty)
            node->reputation_score += decay_rate;
            
            // Clamp to [0.0, 1.0]
            if (node->reputation_score > 1.0) {
                node->reputation_score = 1.0;
            }
        }
    }
}


/* === Stage ③ Suggest Monitor Movement ===
 * Called periodically to determine if monitors should relocate
 * Monitors move to higher-degree hubs if current hub is poorly balanced
 * Returns number of monitors that relocated
 */
int suggest_monitor_movement(struct network* network, struct network_params params, uint64_t current_time) {
    if (network == NULL || network->monitors == NULL || !params.enable_monitor_movement || network->num_monitors <= 0) {
        return 0;
    }

    int n_nodes = array_len(network->nodes);
    if (n_nodes <= 0) {
        return 0;
    }

    int monitor_count = network->num_monitors;
    if (monitor_count > MONITOR_NODE_LIMIT) {
        monitor_count = MONITOR_NODE_LIMIT;
    }

    NodeDegree* candidates = (NodeDegree*)malloc(n_nodes * sizeof(NodeDegree));
    int candidate_count = 0;
    for (int i = 0; i < n_nodes; i++) {
        struct node* node = (struct node*)array_get(network->nodes, i);
        if (node == NULL) {
            continue;
        }
        candidates[candidate_count].node_id = (int)node->id;
        candidates[candidate_count].degree = (int)array_len(node->open_edges);
        candidate_count++;
    }

    if (candidate_count == 0) {
        free(candidates);
        return 0;
    }

    qsort(candidates, candidate_count, sizeof(NodeDegree), compare_node_degree_desc);

    int shift_base = (network->monitor_rotation_epoch * monitor_count) % candidate_count;
    int relocations = 0;

    for (int m = 0; m < monitor_count; m++) {
        MonitorAgent* monitor = &network->monitors[m];
        int old_node_id = monitor->node_id;
        int new_node_id = candidates[(shift_base + m) % candidate_count].node_id;

        if (old_node_id == new_node_id) {
            continue;
        }

        struct node* old_node = (struct node*)array_get(network->nodes, old_node_id);
        if (old_node != NULL && old_node->monitor_id == monitor->monitor_id) {
            old_node->is_monitor = 0;
            old_node->monitor_id = -1;
        }

        struct node* new_node = (struct node*)array_get(network->nodes, new_node_id);
        if (new_node != NULL) {
            new_node->is_monitor = 1;
            new_node->monitor_id = monitor->monitor_id;
            new_node->last_movement_time = (long)current_time;
        }

        monitor->node_id = new_node_id;
        relocations++;
    }

    network->cumulative_monitor_assignments += monitor_count;
    network->cumulative_monitor_relocations += relocations;
    network->monitor_rotation_epoch++;
    free(candidates);
    return relocations;
}


/* cloth.c の main から呼ばれるネットワーク初期化関数。
 *
 * - generate_network_from_file フラグに応じて、CSV から or ランダム生成
 * - 必要なら cul_threshold を再サンプリング
 * - 各ノードの mission-control 結果配列 (results) を確保
 * - group 配列を空で初期化し、後続の construct_groups で埋める。
 */
struct network* initialize_network(struct network_params net_params, gsl_rng* random_generator) {
  struct network* network;
  double faulty_prob[2];
  long n_nodes;
  long i, j;
  struct node* node;

  if(net_params.network_from_file) {
      network = generate_network_from_files(net_params.nodes_filename, net_params.channels_filename,net_params.edges_filename);

      // override the cul_threshold if cul_threshold is set in cloth_input.txt
      if(net_params.cul_threshold_dist_alpha != -1 && net_params.cul_threshold_dist_beta != -1) {
          for(i=0; i<array_len(network->edges); i++) {
              struct edge* edge = array_get(network->edges, i);
              edge->policy.cul_threshold = gsl_ran_beta(random_generator, net_params.cul_threshold_dist_alpha, net_params.cul_threshold_dist_beta);
          }
      }
  }else {
      network = generate_random_network(net_params, random_generator);
  }

  faulty_prob[0] = 1-net_params.faulty_node_prob;
  faulty_prob[1] = net_params.faulty_node_prob;
  network->faulty_node_prob = gsl_ran_discrete_preproc(2, faulty_prob);

  n_nodes = array_len(network->nodes);
  for(i=0; i<n_nodes; i++){
    node = array_get(network->nodes, i);
    node->results = (struct element**) malloc(n_nodes*sizeof(struct element*));
    for(j=0; j<n_nodes; j++)
      node->results[j] = NULL;
  }

  network->groups = array_initialize(1000);
  network->cumulative_monitor_assignments = 0;
  network->cumulative_monitor_relocations = 0;
  network->monitor_rotation_epoch = 0;

  return  network;
}

/* open a new channel during the simulation
 *
 * シミュレーション途中で新しいチャネルをランダムに開くための関数。
 * 現状はイベントが生成されておらず「未使用 (NOT USED)」。
 * 将来的にダイナミックなトポロジ変更を入れたい場合に利用できる。 */
void open_channel(struct network* network, gsl_rng* random_generator, struct network_params net_params) {
  struct channel channel;
  channel.id = array_len(network->channels);
  channel.edge1 = array_len(network->edges);
  channel.edge2 = array_len(network->edges) + 1;
  channel.node1 = gsl_rng_uniform_int(random_generator, array_len(network->nodes));
  do{
    channel.node2 = gsl_rng_uniform_int(random_generator, array_len(network->nodes));
  } while(channel.node2==channel.node1);
  generate_random_channel(channel, 1000, network, random_generator, net_params.cul_threshold_dist_alpha, net_params.cul_threshold_dist_beta);
}

// if triggered_edge is NULL, it means that this function is called by construct_groups()
/* グループ内エッジの残高から group_cap を再計算し、閉鎖すべきか判定する。
 *
 * - routing_method に応じて group_limit / cul_threshold 条件で close_flg を設定
 * - 必要に応じて「偽の残高」(fake_balance_update) を生成して履歴に記録
 * - group->history に group_update レコードを push する。
 *
 * 戻り値: 1 = グループを閉じるべき / 0 = 継続。 */
int update_group(struct group* group, struct network_params net_params, uint64_t current_time, gsl_rng* random_generator, int enable_fake_balance_update, struct edge* triggered_edge) {
    int close_flg = 0;

    // update group cap
    uint64_t min = UINT64_MAX;
    uint64_t max = 0;
    struct edge* fake_value_edge = NULL;
    uint64_t fake_value = 0;
    for (int i = 0; i < array_len(group->edges); i++) {
        struct edge* edge = array_get(group->edges, i);

        // 前回最小値だったedgeは嘘の値で更新する
        uint64_t group_cap_msg_value;
        if(enable_fake_balance_update == 1 && triggered_edge != NULL) {
            if(group->group_cap == edge->balance) {
                // gen fake value by beta distribution
                double r = gsl_ran_beta(random_generator, 1.0, 3.0);
                fake_value = edge->balance + (uint64_t)((double)(group->max_cap_limit - edge->balance) * r);
                fake_value_edge = edge;
                group_cap_msg_value = fake_value;
            }else{
                group_cap_msg_value = edge->balance;
            }
        }else{
            group_cap_msg_value = edge->balance;
        }
        if(group_cap_msg_value < min) min = group_cap_msg_value;
        if(group_cap_msg_value > max) max = group_cap_msg_value;

        // close group if edge balance is less than min or more than max
        if(net_params.routing_method == GROUP_ROUTING){
            if(group_cap_msg_value < group->min_cap_limit || group_cap_msg_value > group->max_cap_limit) close_flg = 1;
        }
    }

    // close group if edge's cul surpasses the threshold
    if(net_params.routing_method == GROUP_ROUTING_CUL){
        for(int i = 0; i < array_len(group->edges); i++) {
            struct edge* edge = array_get(group->edges, i);
            if(min > edge->balance) close_flg = 1;
            if(min < edge->balance - (uint64_t)((double)edge->balance * edge->policy.cul_threshold)) close_flg = 1;

        }
    }

    // update group capacity
    if(net_params.group_cap_update) {
        group->group_cap = min;
    }else{
        group->group_cap = group->min_cap_limit;
    }

    // record group_update history
    struct group_update* group_update = malloc(sizeof(struct group_update));
    group_update->group_cap = group->group_cap;
    group_update->time = current_time;
    if(triggered_edge != NULL) {
        group_update->triggered_edge_id = triggered_edge->id;
    }else{
        group_update->triggered_edge_id = -1;
    }
    group_update->edge_balances = malloc(sizeof(uint64_t) * array_len(group->edges));
    for (int i = 0; i < array_len(group->edges); i++) {
        struct edge* edge = array_get(group->edges, i);
        if(fake_value_edge != NULL){
            if(edge->id == fake_value_edge->id){
                group_update->edge_balances[i] = fake_value;
            }else{
                group_update->edge_balances[i] = edge->balance;
            }
        }else{
            group_update->edge_balances[i] = edge->balance;
        }
    }
    if(fake_value_edge != NULL) {
        group_update->fake_balance_updated_edge_id = fake_value_edge->id;
        group_update->fake_balance_updated_edge_actual_balance = fake_value_edge->balance;
    }else {
        group_update->fake_balance_updated_edge_id = -1;
        group_update->fake_balance_updated_edge_actual_balance = 0;
    }
    group->history = push(group->history, group_update);

    return close_flg;
}

/* list_insert_sorted_position で使用するための、edge->balance 取得関数。
 * ソートキーとしてエッジ残高 (uint64_t) を long で返す。 */
long get_edge_balance(struct edge* e){
    return e->balance;
}

/* 支払い試行時点での edge の状態スナップショットを作成する。
 *
 * - edge ID / 残高 / 送金額 / グループ所属情報 / group_cap
 * - channel_update が存在すればその最大 HTLC 値も保持
 *
 * payments.c の add_attempt_history() から呼ばれる。 */
struct edge_snapshot* take_edge_snapshot(struct edge* e, uint64_t sent_amt, short is_in_group, uint64_t group_cap) {
    struct edge_snapshot* snapshot = malloc(sizeof(struct edge_snapshot));
    snapshot->id = e->id;
    snapshot->balance = e->balance;
    snapshot->sent_amt = sent_amt;
    snapshot->is_in_group = is_in_group;
    snapshot->group_cap = group_cap;
    if(e->channel_updates != NULL) {
        struct channel_update* cu = e->channel_updates->data;
        snapshot->does_channel_update_exist = 1;
        snapshot->last_channle_update_value = cu->htlc_maximum_msat;
    }else {
        snapshot->does_channel_update_exist = 0;
        snapshot->last_channle_update_value = 0;
    }
    return snapshot;
}

/* ネットワークに紐づく動的メモリをすべて解放するヘルパー。
 *
 * - 各 node の open_edges / results
 * - 各 edge の channel_updates
 * - 各 channel
 * - 各 group の history
 *
 * cloth.c では現在コメントアウトされているが、長時間の連続実行など
 * でリークを避けたい場合に利用できる。 */
void free_network(struct network* network){
    for(uint64_t i = 0; array_len(network->nodes); i++){
        struct node* n = array_get(network->nodes, i);
        if(n == NULL) continue;
        array_free(n->open_edges);
        for(struct element* iterator = (struct element *) n->results; iterator != NULL; iterator = iterator->next){
            list_free(iterator->data);
        }
        free(n);
    }
    for(uint64_t i = 0; array_len(network->edges); i++){
        struct edge* e = array_get(network->edges, i);
        if(e == NULL) continue;
        list_free(e->channel_updates);
        free(e);
    }
    for(uint64_t i = 0; array_len(network->channels); i++){
        struct channel* c = array_get(network->channels, i);
        if(c == NULL) continue;
        free(c);
    }
    for(uint64_t i = 0; array_len(network->groups); i++){
        struct group* g = array_get(network->groups, i);
        if(g == NULL) continue;
        list_free(g->history);
        free(g);
    }
}
