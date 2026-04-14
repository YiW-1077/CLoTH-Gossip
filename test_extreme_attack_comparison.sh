#!/bin/bash
#
# test_extreme_attack_comparison.sh
#
# より攻撃的な条件での検知・回避効果測定
# Extreme Attack Condition: 25% malicious, 95% attack success rate
#
# このテストでは、防御メカニズムが効果を発揮するかどうかを測定する
# より強い攻撃条件を使用して、検知と回避の効果を実証する
#

set -e

OUTPUT_BASE="/tmp/cloth-extreme-attack-$$"
mkdir -p "$OUTPUT_BASE"

echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║   極限攻撃条件での検知・回避効果比較テスト                                ║"
echo "║   Extreme Attack Defense Effectiveness Comparison                         ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Output Base: $OUTPUT_BASE"
echo ""

# Extreme Test Parameters
SEED=42
N_PAYMENTS=2000
MALICIOUS_RATIO=0.25  # 15% → 25%
ATTACK_SUCCESS_RATE=0.95  # 80% → 95%

echo "Parameters:"
echo "  - n_payments: $N_PAYMENTS"
echo "  - malicious_node_ratio: $MALICIOUS_RATIO (25% 攻撃ノード)"
echo "  - attack_success_rate: $ATTACK_SUCCESS_RATE (95% 攻撃成功)"
echo "  - Expected attacks: ~$((N_PAYMENTS * 25 / 100 * 95 / 100)) incidents"
echo ""

# ============================================================================
# Test A: No Defense, No Avoidance
# ============================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test A: Extreme Attack WITHOUT Defense"
echo "  - 25% malicious nodes, 95% attack success"
echo "  - No monitoring, No reputation, No RBR"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

TEST_A_DIR="$OUTPUT_BASE/test_a_extreme_no_defense"
mkdir -p "$TEST_A_DIR"

./run-simulation.sh $SEED "$TEST_A_DIR/" \
    n_payments=$N_PAYMENTS \
    malicious_node_ratio=$MALICIOUS_RATIO \
    malicious_failure_probability=$ATTACK_SUCCESS_RATE \
    enable_reputation_system=false \
    enable_rbr=false \
    routing_method=cloth_original \
    2>&1 | tail -25

echo ""
echo "Test A: Analyzing..."

if [ -f "$TEST_A_DIR/payments_output.csv" ]; then
  TOTAL_A=$(tail -n +2 "$TEST_A_DIR/payments_output.csv" | wc -l)
  SUCCESS_A=$(tail -n +2 "$TEST_A_DIR/payments_output.csv" | awk -F',' '$9=="1" {count++} END {print count+0}')
  FAIL_A=$(tail -n +2 "$TEST_A_DIR/payments_output.csv" | awk -F',' '$9=="0" {count++} END {print count+0}')
  
  SUCCESS_RATE_A=$(echo "scale=2; $SUCCESS_A * 100 / $TOTAL_A" | bc 2>/dev/null || echo "N/A")
  
  echo "✓ Test A Results:"
  echo "    Total:   $TOTAL_A"
  echo "    Success: $SUCCESS_A ($SUCCESS_RATE_A%)"
  echo "    Fail:    $FAIL_A"
else
  echo "ERROR: Test A output not found"
  SUCCESS_RATE_A="ERROR"
fi

echo ""

# ============================================================================
# Test B: Detection Only (reputation enabled, no RBR routing)
# ============================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test B: Extreme Attack WITH Detection Only"
echo "  - 25% malicious nodes, 95% attack success"
echo "  - Reputation enabled, No RBR routing"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

TEST_B_DIR="$OUTPUT_BASE/test_b_extreme_detection_only"
mkdir -p "$TEST_B_DIR"

./run-simulation.sh $SEED "$TEST_B_DIR/" \
    n_payments=$N_PAYMENTS \
    malicious_node_ratio=$MALICIOUS_RATIO \
    malicious_failure_probability=$ATTACK_SUCCESS_RATE \
    enable_reputation_system=true \
    enable_rbr=false \
    routing_method=cloth_original \
    2>&1 | tail -25

echo ""
echo "Test B: Analyzing..."

if [ -f "$TEST_B_DIR/payments_output.csv" ]; then
  TOTAL_B=$(tail -n +2 "$TEST_B_DIR/payments_output.csv" | wc -l)
  SUCCESS_B=$(tail -n +2 "$TEST_B_DIR/payments_output.csv" | awk -F',' '$9=="1" {count++} END {print count+0}')
  FAIL_B=$(tail -n +2 "$TEST_B_DIR/payments_output.csv" | awk -F',' '$9=="0" {count++} END {print count+0}')
  
  SUCCESS_RATE_B=$(echo "scale=2; $SUCCESS_B * 100 / $TOTAL_B" | bc 2>/dev/null || echo "N/A")
  
  echo "✓ Test B Results:"
  echo "    Total:   $TOTAL_B"
  echo "    Success: $SUCCESS_B ($SUCCESS_RATE_B%)"
  echo "    Fail:    $FAIL_B"
else
  echo "ERROR: Test B output not found"
  SUCCESS_RATE_B="ERROR"
fi

echo ""

# ============================================================================
# Test C: Full Defense (reputation tracking + RBR routing)
# ============================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test C: Extreme Attack WITH Full Defense"
echo "  - 25% malicious nodes, 95% attack success"
echo "  - Reputation enabled, RBR routing enabled"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

TEST_C_DIR="$OUTPUT_BASE/test_c_extreme_full_defense"
mkdir -p "$TEST_C_DIR"

./run-simulation.sh $SEED "$TEST_C_DIR/" \
    n_payments=$N_PAYMENTS \
    malicious_node_ratio=$MALICIOUS_RATIO \
    malicious_failure_probability=$ATTACK_SUCCESS_RATE \
    enable_reputation_system=true \
    enable_rbr=true \
    routing_method=cloth_original \
    2>&1 | tail -25

echo ""
echo "Test C: Analyzing..."

if [ -f "$TEST_C_DIR/payments_output.csv" ]; then
  TOTAL_C=$(tail -n +2 "$TEST_C_DIR/payments_output.csv" | wc -l)
  SUCCESS_C=$(tail -n +2 "$TEST_C_DIR/payments_output.csv" | awk -F',' '$9=="1" {count++} END {print count+0}')
  FAIL_C=$(tail -n +2 "$TEST_C_DIR/payments_output.csv" | awk -F',' '$9=="0" {count++} END {print count+0}')
  
  SUCCESS_RATE_C=$(echo "scale=2; $SUCCESS_C * 100 / $TOTAL_C" | bc 2>/dev/null || echo "N/A")
  
  echo "✓ Test C Results:"
  echo "    Total:   $TOTAL_C"
  echo "    Success: $SUCCESS_C ($SUCCESS_RATE_C%)"
  echo "    Fail:    $FAIL_C"
else
  echo "ERROR: Test C output not found"
  SUCCESS_RATE_C="ERROR"
fi

echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo "EXTREME ATTACK COMPARISON SUMMARY"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""

if [ -n "$SUCCESS_RATE_A" ] && [ "$SUCCESS_RATE_A" != "ERROR" ] && \
   [ -n "$SUCCESS_RATE_B" ] && [ "$SUCCESS_RATE_B" != "ERROR" ] && \
   [ -n "$SUCCESS_RATE_C" ] && [ "$SUCCESS_RATE_C" != "ERROR" ]; then
  
  echo "Test A (No Defense):                $SUCCESS_RATE_A%  ($SUCCESS_A/$TOTAL_A)"
  echo "Test B (Detection Only):             $SUCCESS_RATE_B%  ($SUCCESS_B/$TOTAL_B)"
  echo "Test C (Full Defense + RBR):         $SUCCESS_RATE_C%  ($SUCCESS_C/$TOTAL_C)"
  echo ""
  
  IMPROVEMENT_B=$(echo "scale=2; $SUCCESS_RATE_B - $SUCCESS_RATE_A" | bc 2>/dev/null || echo "N/A")
  IMPROVEMENT_C=$(echo "scale=2; $SUCCESS_RATE_C - $SUCCESS_RATE_A" | bc 2>/dev/null || echo "N/A")
  
  echo "Defense Effectiveness vs No Defense:"
  echo "  Detection Only:     +$IMPROVEMENT_B%"
  echo "  Full Defense (RBR):  +$IMPROVEMENT_C%"
  
  if [ "$(echo "$IMPROVEMENT_B > 0" | bc 2>/dev/null || echo 0)" -eq 1 ] || \
     [ "$(echo "$IMPROVEMENT_C > 0" | bc 2>/dev/null || echo 0)" -eq 1 ]; then
    echo ""
    echo "✓ Defense mechanisms show positive effect in extreme attack conditions!"
  else
    echo ""
    echo "⚠️  Defense mechanisms still show no measurable improvement"
    echo "    This indicates network redundancy still dominates"
  fi
fi

echo ""
echo "Output Directory: $OUTPUT_BASE"
echo ""
echo "Detailed Results:"
echo "  Test A: $TEST_A_DIR/payments_output.csv"
echo "  Test B: $TEST_B_DIR/payments_output.csv"
echo "  Test C: $TEST_C_DIR/payments_output.csv"
echo ""
