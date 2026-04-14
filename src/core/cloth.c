#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <stdint.h>
#include <inttypes.h>
#include <dirent.h>

#include <gsl/gsl_rng.h>
#include <gsl/gsl_cdf.h>

#include "core/payments.h"
#include "data_structures/heap.h"
#include "data_structures/array.h"
#include "network/routing.h"
#include "simulation/htlc.h"
#include "data_structures/list.h"
#include "core/cloth.h"
#include "network/network.h"
#include "core/event.h"

/* This file contains the main, where the simulation logic is executed;
   additionally, it contains the the initialization functions,
   a function that reads the input and a function that writes the output values in csv files */

/* シミュレーション全体のエントリポイント (main) と、
   ネットワーク/支払いの初期化および入出力処理をまとめたファイル。 */


/* === Stage ① Write Baseline Metrics CSV ===
 *
 * Analyzes payment success rates and generates baseline metrics.
 * Output: baseline_metrics.csv with columns:
 *   - n_payments: total payments
 *   - n_successful: successful payments
 *   - n_failed: failed payments
 *   - success_rate: success percentage
 *   - avg_delay: average payment completion time
 *   - total_attacks_triggered: count of HTLC rejections
 */
void write_baseline_metrics(struct network* network, struct array* payments, struct network_params net_params, char output_dir_name[]) {
  FILE* csv_metrics;
  char output_filename[512];
  long i;
  long n_payments = array_len(payments);
  long n_successful = 0;
  long n_failed = 0;
  long total_delay = 0;
  long total_attacks = 0;
  struct payment* payment;

  // Count successful payments and collect statistics
  for (i = 0; i < n_payments; i++) {
    payment = array_get(payments, i);
    if (payment->id == -1) continue;

    if (payment->is_success) {
      n_successful++;
    } else {
      n_failed++;
    }

    total_delay += (payment->end_time - payment->start_time);
    total_attacks += payment->offline_node_count;  // Malicious nodes are recorded as offline
  }

  double success_rate = (n_payments > 0) ? ((double)n_successful / (double)n_payments) : 0.0;
  double avg_delay = (n_payments > 0) ? ((double)total_delay / (double)n_payments) : 0.0;

  // Write metrics to CSV
  strcpy(output_filename, output_dir_name);
  strcat(output_filename, "baseline_metrics.csv");
  csv_metrics = fopen(output_filename, "w");
  if (csv_metrics == NULL) {
    printf("ERROR cannot open baseline_metrics.csv\n");
    return;
  }

  fprintf(csv_metrics, "n_payments,n_successful,n_failed,success_rate,avg_delay,malicious_ratio,malicious_prob,total_attacks_triggered\n");
  fprintf(csv_metrics, "%ld,%ld,%ld,%.4f,%.2f,%.2f,%.2f,%ld\n",
          n_payments,
          n_successful,
          n_failed,
          success_rate,
          avg_delay,
          net_params.malicious_node_ratio,
          net_params.malicious_failure_probability,
          total_attacks);

  fclose(csv_metrics);
  printf("[Output] Wrote baseline metrics to %s\n", output_filename);
}


/* === Stage ② Write Monitor Placement CSV ===
 *
 * Records deployment location and configuration of each monitor
 */
void write_monitor_placement_csv(struct network* network, char output_dir_name[]) {
  if (!network || network->num_monitors == 0) {
    return;
  }
  
  FILE* csv_monitors;
  char output_filename[512];
  
  strcpy(output_filename, output_dir_name);
  strcat(output_filename, "monitor_placement.csv");
  csv_monitors = fopen(output_filename, "w");
  if (csv_monitors == NULL) {
    printf("ERROR cannot open monitor_placement.csv\n");
    return;
  }
  
  fprintf(csv_monitors, "monitor_id,node_id,deployment_method,watching_hub_id,direct_hubs_count,direct_hubs_list\n");
  
  for (int i = 0; i < network->num_monitors; i++) {
    MonitorAgent* m = &network->monitors[i];
    
    fprintf(csv_monitors, "%d,%d,%d,%d,%d,",
            m->monitor_id,
            m->node_id,
            m->deployed_at_stage,
            m->watching_hub_id,
            m->num_direct_hubs);
    
    // Direct hubs list (pipe-separated)
    for (int h = 0; h < m->num_direct_hubs; h++) {
      if (h > 0) fprintf(csv_monitors, "|");
      fprintf(csv_monitors, "%d", m->direct_hub_connections[h]);
    }
    fprintf(csv_monitors, "\n");
  }
  
  fclose(csv_monitors);
  printf("[Output] Wrote monitor placement to %s\n", output_filename);
}


/* === Stage ② Write Monitoring Metrics CSV ===
 *
 * Summarizes monitoring effectiveness: coverage rate, observability, etc.
 */
void write_monitoring_metrics_csv(struct network* network, long n_payments, int routing_method, char output_dir_name[]) {
  if (!network || network->num_monitors == 0) {
    return;
  }
  
  FILE* csv_metrics;
  char output_filename[512];
  
  strcpy(output_filename, output_dir_name);
  strcat(output_filename, "monitor_metrics.csv");
  csv_metrics = fopen(output_filename, "w");
  if (csv_metrics == NULL) {
    printf("ERROR cannot open monitor_metrics.csv\n");
    return;
  }
  
  // Calculate aggregate statistics
  long total_htlcs_observed = 0;
  long total_payments_captured = 0;
  
  for (int i = 0; i < network->num_monitors; i++) {
    total_htlcs_observed += network->monitors[i].total_htlcs_observed;
    total_payments_captured += network->monitors[i].payments_captured;
  }
  
  double coverage_rate = (n_payments > 0) ? ((double)total_payments_captured / (double)n_payments) : 0.0;
  double observability_per_monitor = (network->num_monitors > 0) ? 
    ((double)total_payments_captured / (double)network->num_monitors) : 0.0;
  double avg_htlcs_observed = (network->num_monitors > 0) ? 
    ((double)total_htlcs_observed / (double)network->num_monitors) : 0.0;
  
  fprintf(csv_metrics, "routing_method,num_monitors,total_payments,coverage_rate,observability_per_monitor,avg_htlcs_observed\n");
  fprintf(csv_metrics, "%d,%d,%ld,%.4f,%.2f,%.2f\n",
          routing_method,
          network->num_monitors,
          n_payments,
          coverage_rate,
          observability_per_monitor,
          avg_htlcs_observed);
  
  fclose(csv_metrics);
  printf("[Output] Wrote monitoring metrics to %s\n", output_filename);
}


/* === Stage ③ Write Reputation Dynamics CSV ===
 * Outputs reputation scores of all nodes for analysis
 */
void write_reputation_dynamics_csv(struct network* network, char output_dir_name[]) {
  if (network == NULL || network->nodes == NULL) {
    return;
  }
  
  char output_filename[512];
  strcpy(output_filename, output_dir_name);
  strcat(output_filename, "reputation_dynamics.csv");
  
  FILE* csv_reputation = fopen(output_filename, "w");
  if (csv_reputation == NULL) {
    fprintf(stderr, "ERROR: Cannot open %s\n", output_filename);
    return;
  }
  
  // Header
  fprintf(csv_reputation, "node_id,is_malicious,is_monitor,reputation_score,malicious_reports,degree\n");
  
  // Write reputation data for each node
  for (int i = 0; i < array_len(network->nodes); i++) {
    struct node* node = (struct node*)array_get(network->nodes, i);
    if (node != NULL) {
      int degree = array_len(node->open_edges);
      fprintf(csv_reputation, "%ld,%d,%d,%.4f,%d,%d\n",
              node->id,
              node->is_malicious,
              node->is_monitor,
              node->reputation_score,
              node->malicious_reports,
              degree);
    }
  }
  
  fclose(csv_reputation);
  printf("[Output] Wrote reputation dynamics to %s\n", output_filename);
}

void write_prt_statistics_csv(struct array* payments, char output_dir_name[]) {
  if (payments == NULL) {
    return;
  }
  
  char output_filename[512];
  strcpy(output_filename, output_dir_name);
  strcat(output_filename, "prt_statistics.csv");
  
  FILE* csv_prt = fopen(output_filename, "w");
  if (csv_prt == NULL) {
    fprintf(stderr, "ERROR: Cannot open %s\n", output_filename);
    return;
  }
  
  // Header
  fprintf(csv_prt, "payment_id,reconstruction_count,prt_abort_triggered,prt_abort_time,is_success,attempts\n");
  
  int abort_count = 0;
  int threshold_exceeded_count = 0;
  
  // Write PRT data for each payment
  for (int i = 0; i < array_len(payments); i++) {
    struct payment* payment = (struct payment*)array_get(payments, i);
    if (payment != NULL) {
      fprintf(csv_prt, "%ld,%d,%d,%llu,%d,%d\n",
              payment->id,
              payment->reconstruction_count,
              payment->prt_abort_triggered,
              payment->prt_abort_time,
              payment->is_success,
              payment->attempts);
      
      if (payment->prt_abort_triggered) {
        abort_count++;
        threshold_exceeded_count++;
      }
    }
  }
  
  fclose(csv_prt);
  printf("[Output] Wrote PRT statistics to %s (aborts=%d)\n", output_filename, abort_count);
}

void write_stage4_comparison_csv(struct array* payments, struct network* network, 
                                 char output_dir_name[], struct network_params net_params) {
  if (payments == NULL || network == NULL) {
    return;
  }
  
  char output_filename[512];
  strcpy(output_filename, output_dir_name);
  strcat(output_filename, "stage4_comparison.csv");
  
  FILE* csv_stage4 = fopen(output_filename, "w");
  if (csv_stage4 == NULL) {
    fprintf(stderr, "ERROR: Cannot open %s\n", output_filename);
    return;
  }
  
  // Calculate statistics
  int total_payments = array_len(payments);
  int successful_payments = 0;
  int aborted_payments = 0;
  int high_recon_count = 0;
  uint64_t total_delay = 0;
  int total_attempts = 0;
  
  for (int i = 0; i < total_payments; i++) {
    struct payment* pmt = (struct payment*)array_get(payments, i);
    if (pmt != NULL) {
      if (pmt->is_success) successful_payments++;
      if (pmt->prt_abort_triggered) aborted_payments++;
      if (pmt->reconstruction_count > 5) high_recon_count++;
      if (pmt->end_time > pmt->start_time) {
        total_delay += (pmt->end_time - pmt->start_time);
      }
      total_attempts += pmt->attempts;
    }
  }
  
  // Count malicious nodes that were detected
  int detected_malicious = 0;
  for (int i = 0; i < array_len(network->nodes); i++) {
    struct node* node = (struct node*)array_get(network->nodes, i);
    if (node != NULL && node->is_malicious && node->reputation_score < 0.5) {
      detected_malicious++;
    }
  }
  
  // Header
  fprintf(csv_stage4, "metric,value\n");
  fprintf(csv_stage4, "total_payments,%d\n", total_payments);
  fprintf(csv_stage4, "successful_payments,%d\n", successful_payments);
  fprintf(csv_stage4, "success_rate,%.4f\n", (double)successful_payments / total_payments);
  fprintf(csv_stage4, "prt_aborted_payments,%d\n", aborted_payments);
  fprintf(csv_stage4, "high_recon_count_payments,%d\n", high_recon_count);
  fprintf(csv_stage4, "avg_payment_delay_ms,%.2f\n", 
          (double)total_delay / total_payments);
  fprintf(csv_stage4, "avg_attempts_per_payment,%.2f\n", 
          (double)total_attempts / total_payments);
  fprintf(csv_stage4, "malicious_nodes_detected,%d\n", detected_malicious);
  fprintf(csv_stage4, "enable_prt,%d\n", net_params.enable_prt);
  fprintf(csv_stage4, "enable_rbr,%d\n", net_params.enable_rbr);
  fprintf(csv_stage4, "prt_threshold,%d\n", net_params.prt_threshold);
  fprintf(csv_stage4, "rbr_weight,%.2f\n", net_params.rbr_reputation_weight);
  
  fclose(csv_stage4);
  printf("[Output] Wrote Stage ④ comparison to %s\n", output_filename);
}


/* write the final values of nodes, channels, edges and payments in csv files
 *
 * network と payments に格納された最終状態を、複数の CSV ファイル
 * (channels_output.csv, groups_output.csv, edges_output.csv,
 *  payments_output.csv, nodes_output.csv) として出力する。
 *
 * 引数:
 *   network: シミュレーション完了後のネットワーク状態
 *   payments: シミュレーション完了後の支払い配列
 *   output_dir_name: 出力先ディレクトリパス (末尾に '/' を付けることを推奨)
 *
 * 指定ディレクトリが存在しない場合は警告を出し、カレントディレクトリ
 * ('./') に出力する。main の終了直前に 1 回呼び出す想定。 */
void write_output(struct network* network, struct array* payments, char output_dir_name[]) {
  FILE* csv_channel_output, *csv_group_output, *csv_edge_output, *csv_payment_output, *csv_node_output;
  long i,j, *id;
  struct channel* channel;
  struct edge* edge;
  struct payment* payment;
  struct node* node;
  struct route* route;
  struct array* hops;
  struct route_hop* hop;
  DIR* results_dir;
  char output_filename[512];

  results_dir = opendir(output_dir_name);
  if(!results_dir){
    printf("cloth.c: Cannot find the output directory. The output will be stored in the current directory.\n");
    strcpy(output_dir_name, "./");
  }

  strcpy(output_filename, output_dir_name);
  strcat(output_filename, "channels_output.csv");
  csv_channel_output = fopen(output_filename, "w");
  if(csv_channel_output  == NULL) {
    printf("ERROR cannot open channel_output.csv\n");
    exit(-1);
  }
  fprintf(csv_channel_output, "id,edge1,edge2,node1,node2,capacity,is_closed\n");
  for(i=0; i<array_len(network->channels); i++) {
    channel = array_get(network->channels, i);
    fprintf(csv_channel_output, "%ld,%ld,%ld,%ld,%ld,%ld,%d\n", channel->id, channel->edge1, channel->edge2, channel->node1, channel->node2, channel->capacity, channel->is_closed);
  }
  fclose(csv_channel_output);

  strcpy(output_filename, output_dir_name);
  strcat(output_filename, "groups_output.csv");
  csv_group_output = fopen(output_filename, "w");
  if(csv_group_output  == NULL) {
    printf("ERROR cannot open groups_output.csv\n");
    exit(-1);
  }
  fprintf(csv_group_output, "id,edges,is_closed(closed_time),constructed_time,min_cap_limit,max_cap_limit,group_update_history,cul_average,used_count\n");
  for(i=0; i<array_len(network->groups); i++) {
    struct group *group = array_get(network->groups, i);
    fprintf(csv_group_output, "%ld,", group->id);
    long n_members = array_len(group->edges);
    for(j=0; j< n_members; j++){
        struct edge* edge_snapshot = array_get(group->edges, j);
        fprintf(csv_group_output, "%ld", edge_snapshot->id);
        if(j < n_members -1){
            fprintf(csv_group_output, "-");
        }else{
            fprintf(csv_group_output, ",");
        }
    }
    fprintf(csv_group_output, "%lu,%lu,%lu,%lu,", group->is_closed, group->constructed_time, group->min_cap_limit, group->max_cap_limit);
    fprintf(csv_group_output, "\"[");
    float cul_avg = 0.0f;
    for(struct element* iterator = group->history; iterator != NULL; iterator = iterator->next) {
        struct group_update* group_update = iterator->data;
        fprintf(csv_group_output, "{\"\"edge_balances\"\":[");
        float sum_cul = 0.0f;
        for(j=0; j<n_members; j++) {
            struct edge* e = array_get(group->edges, j);
            float cul = (1.0f - ((float)group_update->group_cap / (float)group_update->edge_balances[j]));
            sum_cul += cul;
            if(group_update->fake_balance_updated_edge_id == e->id){
                fprintf(csv_group_output, "{\"\"edge_id\"\":%ld,\"\"balance\"\":%ld,\"\"cul\"\":%f,\"\"fake_balance_update\"\":%s,\"\"actual_balance\"\":%ld}", e->id, group_update->edge_balances[j], cul, "true", group_update->fake_balance_updated_edge_actual_balance);
            }else{
                fprintf(csv_group_output, "{\"\"edge_id\"\":%ld,\"\"balance\"\":%ld,\"\"cul\"\":%f,\"\"fake_balance_update\"\":%s}", e->id, group_update->edge_balances[j], cul, "false");
            }
            if(j < n_members - 1) {
                fprintf(csv_group_output, ",");
            }
        }
        float cul = sum_cul / (float)n_members;
        cul_avg += cul / (float) list_len(group->history);
        fprintf(csv_group_output, "],\"\"time\"\":%lu,\"\"group_cap\"\":%lu,\"\"cul_avg\"\":%f,\"\"triggered_edge_id\"\":%ld}", group_update->time, group_update->group_cap, cul, group_update->fake_balance_updated_edge_id, group_update->fake_balance_updated_edge_actual_balance, group_update->triggered_edge_id);
        if(iterator->next != NULL) {
            fprintf(csv_group_output, ",");
        }
    }
    fprintf(csv_group_output, "]\",%f,%ld\n", cul_avg, list_len(group->history)-1);
  }
  fclose(csv_group_output);

  strcpy(output_filename, output_dir_name);
  strcat(output_filename, "edges_output.csv");
  csv_edge_output = fopen(output_filename, "w");
  if(csv_edge_output  == NULL) {
    printf("ERROR cannot open edge_output.csv\n");
    exit(-1);
  }
  fprintf(csv_edge_output, "id,channel_id,counter_edge_id,from_node_id,to_node_id,balance,fee_base,fee_proportional,min_htlc,timelock,is_closed,tot_flows,cul_threshold,channel_updates,group\n");
  for(i=0; i<array_len(network->edges); i++) {
    edge = array_get(network->edges, i);
    fprintf(csv_edge_output, "%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%d,%d,%ld,%lf,", edge->id, edge->channel_id, edge->counter_edge_id, edge->from_node_id, edge->to_node_id, edge->balance, edge->policy.fee_base, edge->policy.fee_proportional, edge->policy.min_htlc, edge->policy.timelock, edge->is_closed, edge->tot_flows, edge->policy.cul_threshold);
    char channel_updates_text[1000000] = "";
    for (struct element *iterator = edge->channel_updates; iterator != NULL; iterator = iterator->next) {
        struct channel_update *channel_update = iterator->data;
        char temp[1000000];
        int written = 0;
        if(iterator->next != NULL) {
            written = snprintf(temp, sizeof(temp), "-%ld%s", channel_update->htlc_maximum_msat, channel_updates_text);
        }else{
            written = snprintf(temp, sizeof(temp), "%ld%s", channel_update->htlc_maximum_msat, channel_updates_text);
        }
        // Check if the output was truncated
        if (written < 0 || (size_t)written >= sizeof(temp)) {
            fprintf(stderr, "Error: Buffer overflow detected.\n");
            exit(1);
        }
        strncpy(channel_updates_text, temp, sizeof(channel_updates_text) - 1);
    }
    fprintf(csv_edge_output, "%s,", channel_updates_text);
    if(edge->group == NULL){
        fprintf(csv_edge_output, "NULL\n");
    }else{
        fprintf(csv_edge_output, "%ld\n", edge->group->id);
    }
  }
  fclose(csv_edge_output);

  strcpy(output_filename, output_dir_name);
  strcat(output_filename, "payments_output.csv");
  csv_payment_output = fopen(output_filename, "w");
  if(csv_payment_output  == NULL) {
    printf("ERROR cannot open payment_output.csv\n");
    exit(-1);
  }
  fprintf(csv_payment_output, "id,sender_id,receiver_id,amount,start_time,max_fee_limit,end_time,mpp,is_success,no_balance_count,offline_node_count,timeout_exp,attempts,route,total_fee,attempts_history\n");
  for(i=0; i<array_len(payments); i++)  {
    payment = array_get(payments, i);
    if (payment->id == -1) continue;
    fprintf(csv_payment_output, "%ld,%ld,%ld,%ld,%ld,%ld,%ld,%u,%u,%d,%d,%u,%d,", payment->id, payment->sender, payment->receiver, payment->amount, payment->start_time, payment->max_fee_limit, payment->end_time, payment->is_shard, payment->is_success, payment->no_balance_count, payment->offline_node_count, payment->is_timeout, payment->attempts);
    route = payment->route;
    if(route==NULL)
      fprintf(csv_payment_output, ",,");
    else {
      hops = route->route_hops;
      for(j=0; j<array_len(hops); j++) {
        hop = array_get(hops, j);
        if(j==array_len(hops)-1)
          fprintf(csv_payment_output,"%ld,",hop->edge_id);
        else
          fprintf(csv_payment_output,"%ld-",hop->edge_id);
      }
      fprintf(csv_payment_output, "%ld,",route->total_fee);
    }
    // build attempts history json
    if(payment->history != NULL) {
        fprintf(csv_payment_output, "\"[");
        for (struct element *iterator = payment->history; iterator != NULL; iterator = iterator->next) {
            struct attempt *attempt = iterator->data;
            fprintf(csv_payment_output, "{\"\"attempts\"\":%d,\"\"is_succeeded\"\":%d,\"\"end_time\"\":%lu,\"\"error_edge\"\":%lu,\"\"error_type\"\":%d,\"\"route\"\":[", attempt->attempts, attempt->is_succeeded, attempt->end_time, attempt->error_edge_id, attempt->error_type);
            for (j = 0; j < array_len(attempt->route); j++) {
                struct edge_snapshot* edge_snapshot = array_get(attempt->route, j);
                edge = array_get(network->edges, edge_snapshot->id);
                channel = array_get(network->channels, edge->channel_id);
                fprintf(csv_payment_output,"{\"\"edge_id\"\":%lu,\"\"from_node_id\"\":%lu,\"\"to_node_id\"\":%lu,\"\"sent_amt\"\":%lu,\"\"edge_cap\"\":%lu,\"\"channel_cap\"\":%lu,", edge_snapshot->id, edge->from_node_id, edge->to_node_id, edge_snapshot->sent_amt, edge_snapshot->balance, channel->capacity);
                if(edge_snapshot->is_in_group) fprintf(csv_payment_output, "\"\"group_cap\"\":%lu,", edge_snapshot->group_cap);
                else fprintf(csv_payment_output,"\"\"group_cap\"\":null,");
                if(edge_snapshot->does_channel_update_exist) fprintf(csv_payment_output,"\"\"channel_update\"\":%lu}", edge_snapshot->last_channle_update_value);
                else fprintf(csv_payment_output,"\"\"channel_update\"\":}");
                if (j != array_len(attempt->route) - 1) fprintf(csv_payment_output, ",");
            }
            fprintf(csv_payment_output, "]}");
            if (iterator->next != NULL) fprintf(csv_payment_output, ",");
            else fprintf(csv_payment_output, "]");
        }
        fprintf(csv_payment_output, "\"");
    }
    fprintf(csv_payment_output, "\n");
  }
  fclose(csv_payment_output);

  strcpy(output_filename, output_dir_name);
  strcat(output_filename, "nodes_output.csv");
  csv_node_output = fopen(output_filename, "w");
  if(csv_node_output  == NULL) {
    printf("ERROR cannot open nodes_output.csv\n");
    return;
  }
  fprintf(csv_node_output, "id,open_edges\n");
  for(i=0; i<array_len(network->nodes); i++) {
    node = array_get(network->nodes, i);
    fprintf(csv_node_output, "%ld,", node->id);
    if(array_len(node->open_edges)==0)
      fprintf(csv_node_output, "-1");
    else {
      for(j=0; j<array_len(node->open_edges); j++) {
        id = array_get(node->open_edges, j);
        if(j==array_len(node->open_edges)-1)
          fprintf(csv_node_output,"%ld",*id);
        else
          fprintf(csv_node_output,"%ld-",*id);
      }
    }
    fprintf(csv_node_output,"\n");
  }
  fclose(csv_node_output);
}


/* cloth_input.txt を読む前に、network_params / payments_params を
 * 既定値 (0 や空文字列) で初期化するヘルパー。
 *
 * 通常は read_input() の先頭からのみ呼ばれ、外部から直接呼ぶ必要はない。
 * 構造体メンバを追加した場合は、この関数も更新すること。 */
void initialize_input_parameters(struct network_params *net_params, struct payments_params *pay_params) {
  net_params->n_nodes = net_params->n_channels = net_params->capacity_per_channel = 0;
  net_params->faulty_node_prob = 0.0;
  /* === Stage ① Malicious Node Parameters === */
  net_params->malicious_node_ratio = 0.0;
  net_params->malicious_failure_probability = 0.0;
  /* === Stage ② Monitor Placement Parameters === */
  net_params->hub_degree_threshold = 50;
  net_params->monitoring_strategy = 0;  // 0=disabled, 1=method1, 2=method2
  net_params->top_hub_count = 30;
  /* === Stage ③ Reputation System Parameters === */
  net_params->enable_reputation_system = 0;
  net_params->reputation_decay_rate = 0.01;      // 1% decay per event
  net_params->reputation_penalty_on_detection = 0.3;  // 30% penalty
  net_params->reputation_recovery_rate = 0.02;   // 2% recovery per honest period
  net_params->enable_monitor_movement = 0;
  net_params->movement_credit_limit = 5;
  /* === Stage ④ DoS Mitigation Defaults === */
  net_params->enable_pra = 0;                    // PRA disabled by default
  net_params->enable_prt = 0;                    // PRT disabled by default
  net_params->prt_threshold = 30;                // 30 reconstruction attempts
  net_params->prt_abort_wait_time = 1000;        // 1 second wait
  net_params->enable_rbr = 0;                    // RBR disabled by default
  net_params->rbr_reputation_weight = 10.0;      // Weight in routing penalty
  net_params->network_from_file = 0;
  strcpy(net_params->nodes_filename, "\0");
  strcpy(net_params->channels_filename, "\0");
  strcpy(net_params->edges_filename, "\0");
  pay_params->inverse_payment_rate = pay_params->amount_mu = 0.0;
  pay_params->n_payments = 0;
  pay_params->payments_from_file = 0;
  strcpy(pay_params->payments_filename, "\0");
  pay_params->mpp = 0;
}


/* parse the input parameters in "cloth_input.txt" */
/* cloth_input.txt を開き、1 行ずつ key=value 形式でパースして
 * network_params / payments_params 構造体を埋める。
 *
 * - = の前後に空白がある行はエラーとして終了する。
 * - 一部のパラメータは空文字列を特別な値 (-1 や 0) として解釈する。
 * - 不明なキーや不正な値がある場合は stderr に出力して即時 exit(-1)。
 *
 * 実行時カレントディレクトリに cloth_input.txt が存在する必要がある。 */
void read_input(struct network_params* net_params, struct payments_params* pay_params){
  FILE* input_file;
  char *parameter, *value, line[1024];

  initialize_input_parameters(net_params, pay_params);

  input_file = fopen("cloth_input.txt","r");

  if(input_file==NULL){
    fprintf(stderr, "ERROR: cannot open file <cloth_input.txt> in current directory.\n");
    exit(-1);
  }

  while(fgets(line, 1024, input_file)){

    parameter = strtok(line, "=");
    value = strtok(NULL, "=");
    if(parameter==NULL || value==NULL){
      fprintf(stderr, "ERROR: wrong format in file <cloth_input.txt>\n");
      fclose(input_file);
      exit(-1);
    }

    if(value[0]==' ' || parameter[strlen(parameter)-1]==' '){
      fprintf(stderr, "ERROR: no space allowed after/before <=> character in <cloth_input.txt>. Space detected in parameter <%s>\n", parameter);
      fclose(input_file);
      exit(-1);
    }

    value[strlen(value)-1] = '\0';

    if(strcmp(parameter, "generate_network_from_file")==0){
      if(strcmp(value, "true")==0)
        net_params->network_from_file=1;
      else if(strcmp(value, "false")==0)
        net_params->network_from_file=0;
      else{
        fprintf(stderr, "ERROR: wrong value of parameter <%s> in <cloth_input.txt>. Possible values are <true> or <false>\n", parameter);
        fclose(input_file);
        exit(-1);
      }
    }
    else if(strcmp(parameter, "nodes_filename")==0){
      strcpy(net_params->nodes_filename, value);
    }
    else if(strcmp(parameter, "channels_filename")==0){
      strcpy(net_params->channels_filename, value);
    }
    else if(strcmp(parameter, "edges_filename")==0){
      strcpy(net_params->edges_filename, value);
    }
    else if(strcmp(parameter, "n_additional_nodes")==0){
      net_params->n_nodes = strtol(value, NULL, 10);
    }
    else if(strcmp(parameter, "n_channels_per_node")==0){
      net_params->n_channels = strtol(value, NULL, 10);
    }
    else if(strcmp(parameter, "capacity_per_channel")==0){
      net_params->capacity_per_channel = strtol(value, NULL, 10);
    }
    else if(strcmp(parameter, "faulty_node_probability")==0){
      net_params->faulty_node_prob = strtod(value, NULL);
    }
    /* === Stage ① Malicious Node Parameters === */
    else if(strcmp(parameter, "malicious_node_ratio")==0){
      net_params->malicious_node_ratio = strtod(value, NULL);
    }
    else if(strcmp(parameter, "malicious_failure_probability")==0){
      net_params->malicious_failure_probability = strtod(value, NULL);
    }
    /* === Stage ② Monitor Placement Parameters === */
    else if(strcmp(parameter, "hub_degree_threshold")==0){
      net_params->hub_degree_threshold = strtol(value, NULL, 10);
    }
    else if(strcmp(parameter, "monitoring_strategy")==0){
      if(strcmp(value, "method1")==0)
        net_params->monitoring_strategy = 1;
      else if(strcmp(value, "method2")==0)
        net_params->monitoring_strategy = 2;
      else
        net_params->monitoring_strategy = 0;
    }
    else if(strcmp(parameter, "top_hub_count")==0){
      net_params->top_hub_count = strtol(value, NULL, 10);
    }
    /* === Stage ③ Reputation System Parameters === */
    else if(strcmp(parameter, "enable_reputation_system")==0){
      net_params->enable_reputation_system = (strcmp(value, "true")==0) ? 1 : 0;
    }
    else if(strcmp(parameter, "reputation_decay_rate")==0){
      net_params->reputation_decay_rate = strtod(value, NULL);
    }
    else if(strcmp(parameter, "reputation_penalty_on_detection")==0){
      net_params->reputation_penalty_on_detection = strtod(value, NULL);
    }
    else if(strcmp(parameter, "reputation_recovery_rate")==0){
      net_params->reputation_recovery_rate = strtod(value, NULL);
    }
    else if(strcmp(parameter, "enable_monitor_movement")==0){
      net_params->enable_monitor_movement = (strcmp(value, "true")==0) ? 1 : 0;
    }
    else if(strcmp(parameter, "movement_credit_limit")==0){
      net_params->movement_credit_limit = strtol(value, NULL, 10);
    }
    /* === Stage ④ DoS Mitigation Parameters === */
    else if(strcmp(parameter, "enable_pra")==0){
      net_params->enable_pra = (strcmp(value, "true")==0) ? 1 : 0;
    }
    else if(strcmp(parameter, "enable_prt")==0){
      net_params->enable_prt = (strcmp(value, "true")==0) ? 1 : 0;
    }
    else if(strcmp(parameter, "prt_threshold")==0){
      net_params->prt_threshold = strtol(value, NULL, 10);
    }
    else if(strcmp(parameter, "prt_abort_wait_time")==0){
      net_params->prt_abort_wait_time = (uint64_t)strtol(value, NULL, 10);
    }
    else if(strcmp(parameter, "enable_rbr")==0){
      net_params->enable_rbr = (strcmp(value, "true")==0) ? 1 : 0;
    }
    else if(strcmp(parameter, "rbr_reputation_weight")==0){
      net_params->rbr_reputation_weight = strtod(value, NULL);
    }
    else if(strcmp(parameter, "generate_payments_from_file")==0){
      if(strcmp(value, "true")==0)
        pay_params->payments_from_file=1;
      else if(strcmp(value, "false")==0)
        pay_params->payments_from_file=0;
      else{
        fprintf(stderr, "ERROR: wrong value of parameter <%s> in <cloth_input.txt>. Possible values are <true> or <false>\n", parameter);
        fclose(input_file);
        exit(-1);
      }
    }
    else if(strcmp(parameter, "enable_fake_balance_update")==0){
      if(strcmp(value, "true")==0)
        net_params->enable_fake_balance_update = 1;
      else if(strcmp(value, "false")==0)
        net_params->enable_fake_balance_update = 0;
      else{
        fprintf(stderr, "ERROR: wrong value of parameter <%s> in <cloth_input.txt>. Possible values are <true> or <false>\n", parameter);
        fclose(input_file);
        exit(-1);
      }
    }
    else if(strcmp(parameter, "payment_timeout")==0) {
        net_params->payment_timeout=strtol(value, NULL, 10);
    }
    else if(strcmp(parameter, "average_payment_forward_interval")==0) {
        net_params->average_payment_forward_interval=strtol(value, NULL, 10);
    }
    else if(strcmp(parameter, "variance_payment_forward_interval")==0) {
        net_params->variance_payment_forward_interval=strtol(value, NULL, 10);
    }
    else if(strcmp(parameter, "group_broadcast_delay")==0) {
        net_params->group_broadcast_delay=strtol(value, NULL, 10);
    }
    else if(strcmp(parameter, "routing_method")==0){
      if(strcmp(value, "cloth_original")==0)
        net_params->routing_method=CLOTH_ORIGINAL;
      else if(strcmp(value, "channel_update")==0)
        net_params->routing_method=CHANNEL_UPDATE;
      else if(strcmp(value, "group_routing_cul")==0)
        net_params->routing_method=GROUP_ROUTING_CUL;
      else if(strcmp(value, "group_routing")==0)
        net_params->routing_method=GROUP_ROUTING;
      else if(strcmp(value, "ideal")==0)
        net_params->routing_method=IDEAL;
      else{
        fprintf(stderr, "ERROR: wrong value of parameter <%s> in <cloth_input.txt>. Possible values are [\"cloth_original\", \"channel_update\", \"group_routing\", \"ideal\"]\n", parameter);
        fclose(input_file);
        exit(-1);
      }
    }
    else if(strcmp(parameter, "group_cap_update")==0){
      if(strcmp(value, "true")==0)
        net_params->group_cap_update=1;
      else if(strcmp(value, "false")==0)
        net_params->group_cap_update=0;
      else
        net_params->group_cap_update=-1;
    }
    else if(strcmp(parameter, "group_size")==0){
        if(strcmp(value, "")==0) net_params->group_size = -1;
        else net_params->group_size = strtol(value, NULL, 10);
    }
    else if(strcmp(parameter, "group_limit_rate")==0){
        if(strcmp(value, "")==0) net_params->group_limit_rate = -1;
        else net_params->group_limit_rate = strtof(value, NULL);
    }
    else if(strcmp(parameter, "cul_threshold_dist_alpha")==0){
        if(strcmp(value, "")==0) net_params->cul_threshold_dist_alpha = -1;
        else net_params->cul_threshold_dist_alpha = strtof(value, NULL);
    }
    else if(strcmp(parameter, "cul_threshold_dist_beta")==0){
        if(strcmp(value, "")==0) net_params->cul_threshold_dist_beta = -1;
        else net_params->cul_threshold_dist_beta = strtof(value, NULL);
    }
    else if(strcmp(parameter, "payments_filename")==0){
      strcpy(pay_params->payments_filename, value);
    }
    else if(strcmp(parameter, "payment_rate")==0){
      pay_params->inverse_payment_rate = 1.0/strtod(value, NULL);
    }
    else if(strcmp(parameter, "n_payments")==0){
      pay_params->n_payments = strtol(value, NULL, 10);
    }
    else if(strcmp(parameter, "average_payment_amount")==0){
      pay_params->amount_mu = strtod(value, NULL);
    }
    else if(strcmp(parameter, "variance_payment_amount")==0){
      pay_params->amount_sigma = strtod(value, NULL);
    }
    else if(strcmp(parameter, "mpp")==0){
      pay_params->mpp = strtoul(value, NULL, 10);
    }
    else if(strcmp(parameter, "average_max_fee_limit")==0){
        pay_params->max_fee_limit_mu = strtod(value, NULL);
    }
    else if(strcmp(parameter, "variance_max_fee_limit")==0){
        pay_params->max_fee_limit_sigma = strtod(value, NULL);
    }
    else{
      fprintf(stderr, "ERROR: unknown parameter <%s>\n", parameter);
      fclose(input_file);
      exit(-1);
    }
  }
  // check invalid group settings
  if(net_params->routing_method == GROUP_ROUTING){
      if(net_params->group_limit_rate < 0 || net_params->group_limit_rate > 1){
          fprintf(stderr, "ERROR: wrong value of parameter <group_limit_rate> in <cloth_input.txt>.\n");
          exit(-1);
      }
      if(net_params->group_size < 0){
          fprintf(stderr, "ERROR: wrong value of parameter <group_size> in <cloth_input.txt>.\n");
          exit(-1);
      }
      if(net_params->group_cap_update == -1){
          fprintf(stderr, "ERROR: wrong value of parameter <group_cap_update> in <cloth_input.txt>.\n");
          exit(-1);
      }
  }
  fclose(input_file);
}


/* 支払いが 2 つのシャード (MPP) を持つかどうかを判定するユーティリティ。
 * shards_id[0], shards_id[1] の両方が -1 以外であれば true を返す。
 *
 * 主に post_process_payment_stats() からのみ利用される想定。 */
unsigned int has_shards(struct payment* payment){
  return (payment->shards_id[0] != -1 && payment->shards_id[1] != -1);
}


/* process stats of payments that were split (mpp payments)
 *
 * MPP により 2 分割された支払いについて、シャード 2 つの結果から
 * 元の支払い (親 payment) の統計値を再集計する。
 *
 * - end_time, is_success, 各種カウンタ類を 2 シャードから集約
 * - ルートが両方存在する場合は、より長いルートを代表として合計手数料を設定
 * - 処理済みのシャードは id=-1 に書き換え、後続処理から除外する
 *
 * シミュレーション終了後、write_output() の前に一度だけ呼び出す。 */
void post_process_payment_stats(struct array* payments){
  long i;
  struct payment* payment, *shard1, *shard2;
  for(i = 0; i < array_len(payments); i++){
    payment = array_get(payments, i);
    if(payment->id == -1) continue;
    if(!has_shards(payment)) continue;
    shard1 = array_get(payments, payment->shards_id[0]);
    shard2 = array_get(payments, payment->shards_id[1]);
    payment->end_time = shard1->end_time > shard2->end_time ? shard1->end_time : shard2->end_time;
    payment->is_success = shard1->is_success && shard2->is_success ? 1 : 0;
    payment->no_balance_count = shard1->no_balance_count + shard2->no_balance_count;
    payment->offline_node_count = shard1->offline_node_count + shard2->offline_node_count;
    payment->is_timeout = shard1->is_timeout || shard2->is_timeout ? 1 : 0;
    payment->attempts = shard1->attempts + shard2->attempts;
    if(shard1->route != NULL && shard2->route != NULL){
      payment->route = array_len(shard1->route->route_hops) > array_len(shard2->route->route_hops) ? shard1->route : shard2->route;
      payment->route->total_fee = shard1->route->total_fee + shard2->route->total_fee;
    }
    else{
      payment->route = NULL;
    }
    //a trick to avoid processing already processed shards
    shard1->id = -1;
    shard2->id = -1;
  }
}


/* GSL の乱数生成器 (gsl_rng) を環境変数設定に従って初期化して返す。
 *
 * - gsl_rng_env_setup() により RNG の型やシードは環境変数に依存
 * - 呼び出し側で gsl_rng_free() ではなく free() を使っている点に注意
 *   (既存コードと整合させるため、そのままにしている)
 *
 * main() から 1 回だけ呼び出し、simulation->random_generator に保持する。 */
gsl_rng* initialize_random_generator(){
  gsl_rng_env_setup();
  return gsl_rng_alloc (gsl_rng_default);
}


/* シミュレーションのエントリポイント。
 * 1) cloth_input.txt を読み込んでネットワーク/支払いパラメータを設定
 * 2) ネットワーク・支払い・イベントキュー・初期ダイクストラを初期化
 * 3) イベントキューから最小時刻のイベントを取り出して処理し続ける
 * 4) 必要に応じて MPP の統計を再集計し、最終状態を CSV に書き出して終了
 *
 * 使い方:
 *   ./CLoTH_Gossip <output_dir/>
 * output_dir は末尾に '/' を付けることを推奨 (パス連結の都合上)。
 * 実行時のカレントディレクトリに cloth_input.txt と各種 CSV が必要。 */
int main(int argc, char *argv[]) {
  struct event* event;
  clock_t  begin, end;
  double time_spent=0.0;
  long time_spent_thread = 0;
  struct network_params net_params;
  struct payments_params pay_params;
  struct timespec start, finish;
  struct network *network;
  long n_nodes, n_edges;
  struct array* payments;
  struct simulation* simulation;
  char output_dir_name[256];

  if(argc != 2) {
    fprintf(stderr, "ERROR cloth.c: please specify the output directory\n");
    return -1;
  }
  strcpy(output_dir_name, argv[1]);

  read_input(&net_params, &pay_params);

  simulation = malloc(sizeof(struct simulation));
  simulation->current_time = 0;

  simulation->random_generator = initialize_random_generator();
  printf("NETWORK INITIALIZATION\n");
  network = initialize_network(net_params, simulation->random_generator);
  n_nodes = array_len(network->nodes);
  n_edges = array_len(network->edges);

  /* === Stage ① Initialize Malicious Nodes === */
  if (net_params.malicious_node_ratio > 0.0) {
    initialize_malicious_nodes(network, 
                               net_params.malicious_node_ratio,
                               net_params.malicious_failure_probability,
                               simulation->random_generator);
  }

  /* === Stage ② Deploy Monitoring Agents === */
  if (net_params.monitoring_strategy > 0) {
    if (net_params.monitoring_strategy == 1) {
      deploy_monitors_method1(network, net_params.hub_degree_threshold, 5);  // leaf_threshold=5
    } else if (net_params.monitoring_strategy == 2) {
      deploy_monitors_method2_enhanced(network, net_params.hub_degree_threshold, 5, net_params.top_hub_count);
    }
  }

  /* === Stage ③ Initialize Reputation System === */
  if (net_params.enable_reputation_system) {
    initialize_reputation_scores(network);
  }

    // add edge which is not a member of any group to group_add_queue
    struct element* group_add_queue = NULL;
    if(net_params.routing_method == GROUP_ROUTING || net_params.routing_method == GROUP_ROUTING_CUL) {
        for (int i = 0; i < n_edges; i++) {
            group_add_queue = list_insert_sorted_position(group_add_queue, array_get(network->edges, i), (long (*)(void *)) get_edge_balance);
        }
        group_add_queue = construct_groups(simulation, group_add_queue, network, net_params);
    }
    printf("group_cover_rate on init : %f\n", (float)(array_len(network->edges) - list_len(group_add_queue)) / (float)(array_len(network->edges)));

  printf("PAYMENTS INITIALIZATION\n");
  payments = initialize_payments(pay_params,  n_nodes, simulation->random_generator);

  printf("EVENTS INITIALIZATION\n");
  simulation->events = initialize_events(payments);
  initialize_dijkstra(n_nodes, n_edges, payments);

  printf("INITIAL DIJKSTRA THREADS EXECUTION\n");
  clock_gettime(CLOCK_MONOTONIC, &start);
  run_dijkstra_threads(network, payments, 0, net_params.routing_method);
  clock_gettime(CLOCK_MONOTONIC, &finish);
  time_spent_thread = finish.tv_sec - start.tv_sec;
  printf("Time consumed by initial dijkstra executions: %ld s\n", time_spent_thread);

  printf("EXECUTION OF THE SIMULATION\n");

  /* core of the discrete-event simulation: extract next event, advance simulation time, execute the event */
  begin = clock();
  simulation->current_time = 1;
  long completed_payments = 0;
  while(heap_len(simulation->events) != 0) {
    event = heap_pop(simulation->events, compare_event);

    simulation->current_time = event->time;
    switch(event->type){
    case FINDPATH:
      find_path(event, simulation, network, &payments, pay_params.mpp, net_params.routing_method, net_params);
      break;
    case SENDPAYMENT:
      send_payment(event, simulation, network, net_params);
      break;
    case FORWARDPAYMENT:
      forward_payment(event, simulation, network, net_params);
      break;
    case RECEIVEPAYMENT:
      receive_payment(event, simulation, network, net_params);
      break;
    case FORWARDSUCCESS:
      forward_success(event, simulation, network, net_params);
      break;
    case RECEIVESUCCESS:
      receive_success(event, simulation, network, net_params);
      break;
    case FORWARDFAIL:
      forward_fail(event, simulation, network, net_params);
      break;
    case RECEIVEFAIL:
      receive_fail(event, simulation, network, net_params);
      break;
    case OPENCHANNEL:
      open_channel(network, simulation->random_generator, net_params);
      break;
    case CHANNELUPDATEFAIL:
      channel_update_fail(event, simulation, network);
    case CHANNELUPDATESUCCESS:
      channel_update_success(event, simulation, network);
    case UPDATEGROUP:
      group_add_queue = request_group_update(event, simulation, network, net_params, group_add_queue);
      break;
    case CONSTRUCTGROUPS:
      group_add_queue = construct_groups(simulation, group_add_queue, network, net_params);
      break;
    default:
      printf("ERROR wrong event type\n");
      exit(-1);
    }

    struct payment* p = array_get(payments, event->payment->id);
    if(p->end_time != 0 && event->type != UPDATEGROUP && event->type != CONSTRUCTGROUPS && event->type != CHANNELUPDATEFAIL && event->type != CHANNELUPDATESUCCESS){
        completed_payments++;
        char progress_filename[512];
        strcpy(progress_filename, output_dir_name);
        strcat(progress_filename, "progress.tmp");
        FILE* progress_file = fopen(progress_filename, "w");
        if(progress_file != NULL){
            fprintf(progress_file, "%f", (float)completed_payments / (float)array_len(payments));
        }
        fclose(progress_file);
    }

    free(event);
  }
  printf("\n");
  end = clock();

  if(pay_params.mpp)
    post_process_payment_stats(payments);

  time_spent = (double) (end - begin)/CLOCKS_PER_SEC;
  printf("Time consumed by simulation events: %lf s\n", time_spent);

  /* === Stage ① Write Baseline Metrics === */
  write_baseline_metrics(network, payments, net_params, output_dir_name);

  /* === Stage ② Write Monitor Placement Metrics === */
  if (network->num_monitors > 0) {
    write_monitor_placement_csv(network, output_dir_name);
    write_monitoring_metrics_csv(network, array_len(payments), net_params.routing_method, output_dir_name);
  }

  /* === Stage ③ Write Reputation Dynamics === */
  if (net_params.enable_reputation_system) {
    write_reputation_dynamics_csv(network, output_dir_name);
  }

  /* === Stage ④ Write PRT Statistics === */
  if (net_params.enable_prt) {
    write_prt_statistics_csv(payments, output_dir_name);
  }

  /* === Stage ④ Write Comparison Metrics === */
  if (net_params.enable_prt || net_params.enable_rbr) {
    write_stage4_comparison_csv(payments, network, output_dir_name, net_params);
  }

  write_output(network, payments, output_dir_name);

    list_free(group_add_queue);
    free(simulation->random_generator);
    heap_free(simulation->events);
  free(simulation);

//    free_network(network);

  return 0;
}
