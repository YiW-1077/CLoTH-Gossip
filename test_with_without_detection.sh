#!/bin/bash
#
# test_with_without_detection.sh
#
# 攻撃シナリオで、検知・回避の有無による成功率の比較
# 
# Test A: No Detection, No Avoidance (reputation disabled)
# Test B: Detection Only (reputation enabled, but routing ignores it)
# Test C: Full Defense (reputation enabled, RBR routing enabled)
#

set -e

OUTPUT_BASE="/tmp/cloth-detection-test-$$"
mkdir -p "$OUTPUT_BASE"

echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║   攻撃検知・回避効果の比較テスト                                            ║"
echo "║   Comparison: No Detection vs Detection Only vs Full Defense               ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Output Base: $OUTPUT_BASE"
echo ""

# Test Parameters
SEED=42
N_PAYMENTS=1000
MALICIOUS_RATIO=0.15
ATTACK_SUCCESS_RATE=0.80

echo "Parameters:"
echo "  - n_payments: $N_PAYMENTS"
echo "  - malicious_node_ratio: $MALICIOUS_RATIO"
echo "  - attack_success_rate: $ATTACK_SUCCESS_RATE"
echo ""

# ============================================================================
# Test A: No Detection, No Avoidance
# ============================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test A: Attack without Detection & Avoidance"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

TEST_A_DIR="$OUTPUT_BASE/test_a_no_defense"
mkdir -p "$TEST_A_DIR"

./run-simulation.sh $SEED "$TEST_A_DIR/" \
    n_payments=$N_PAYMENTS \
    malicious_node_ratio=$MALICIOUS_RATIO \
    malicious_failure_probability=$ATTACK_SUCCESS_RATE \
    enable_reputation_system=false \
    enable_rbr=false \
    routing_method=cloth_original \
    2>&1 | tail -20

echo ""
echo "Test A completed. Analyzing results..."

if [ -f "$TEST_A_DIR/payments_output.csv" ]; then
  TOTAL_A=$(tail -n +2 "$TEST_A_DIR/payments_output.csv" | wc -l)
  SUCCESS_A=$(tail -n +2 "$TEST_A_DIR/payments_output.csv" | awk -F',' '$9=="1" {count++} END {print count+0}')
  FAIL_A=$(tail -n +2 "$TEST_A_DIR/payments_output.csv" | awk -F',' '$9=="0" {count++} END {print count+0}')
  
  SUCCESS_RATE_A=$(echo "scale=2; $SUCCESS_A * 100 / $TOTAL_A" | bc 2>/dev/null || echo "N/A")
  
  echo "Test A Results:"
  echo "  Total:   $TOTAL_A"
  echo "  Success: $SUCCESS_A"
  echo "  Fail:    $FAIL_A"
  echo "  Success Rate: $SUCCESS_RATE_A%"
else
  echo "ERROR: Test A output file not found"
fi

echo ""

# ============================================================================
# Test B: Detection Only (reputation tracking, but no RBR routing)
# ============================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test B: Attack with Detection Only (no RBR routing)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

TEST_B_DIR="$OUTPUT_BASE/test_b_detection_only"
mkdir -p "$TEST_B_DIR"

./run-simulation.sh $SEED "$TEST_B_DIR/" \
    n_payments=$N_PAYMENTS \
    malicious_node_ratio=$MALICIOUS_RATIO \
    malicious_failure_probability=$ATTACK_SUCCESS_RATE \
    enable_reputation_system=true \
    enable_rbr=false \
    routing_method=cloth_original \
    2>&1 | tail -20

echo ""
echo "Test B completed. Analyzing results..."

if [ -f "$TEST_B_DIR/payments_output.csv" ]; then
  TOTAL_B=$(tail -n +2 "$TEST_B_DIR/payments_output.csv" | wc -l)
  SUCCESS_B=$(tail -n +2 "$TEST_B_DIR/payments_output.csv" | awk -F',' '$9=="1" {count++} END {print count+0}')
  FAIL_B=$(tail -n +2 "$TEST_B_DIR/payments_output.csv" | awk -F',' '$9=="0" {count++} END {print count+0}')
  
  SUCCESS_RATE_B=$(echo "scale=2; $SUCCESS_B * 100 / $TOTAL_B" | bc 2>/dev/null || echo "N/A")
  
  echo "Test B Results:"
  echo "  Total:   $TOTAL_B"
  echo "  Success: $SUCCESS_B"
  echo "  Fail:    $FAIL_B"
  echo "  Success Rate: $SUCCESS_RATE_B%"
else
  echo "ERROR: Test B output file not found"
fi

echo ""

# ============================================================================
# Test C: Full Defense (reputation tracking + RBR routing)
# ============================================================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test C: Attack with Full Defense (detection + RBR routing)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

TEST_C_DIR="$OUTPUT_BASE/test_c_full_defense"
mkdir -p "$TEST_C_DIR"

./run-simulation.sh $SEED "$TEST_C_DIR/" \
    n_payments=$N_PAYMENTS \
    malicious_node_ratio=$MALICIOUS_RATIO \
    malicious_failure_probability=$ATTACK_SUCCESS_RATE \
    enable_reputation_system=true \
    enable_rbr=true \
    routing_method=cloth_original \
    2>&1 | tail -20

echo ""
echo "Test C completed. Analyzing results..."

if [ -f "$TEST_C_DIR/payments_output.csv" ]; then
  TOTAL_C=$(tail -n +2 "$TEST_C_DIR/payments_output.csv" | wc -l)
  SUCCESS_C=$(tail -n +2 "$TEST_C_DIR/payments_output.csv" | awk -F',' '$9=="1" {count++} END {print count+0}')
  FAIL_C=$(tail -n +2 "$TEST_C_DIR/payments_output.csv" | awk -F',' '$9=="0" {count++} END {print count+0}')
  
  SUCCESS_RATE_C=$(echo "scale=2; $SUCCESS_C * 100 / $TOTAL_C" | bc 2>/dev/null || echo "N/A")
  
  echo "Test C Results:"
  echo "  Total:   $TOTAL_C"
  echo "  Success: $SUCCESS_C"
  echo "  Fail:    $FAIL_C"
  echo "  Success Rate: $SUCCESS_RATE_C%"
else
  echo "ERROR: Test C output file not found"
fi

echo ""
echo "════════════════════════════════════════════════════════════════════════════"
echo "COMPARISON SUMMARY"
echo "════════════════════════════════════════════════════════════════════════════"
echo ""

if [ -n "$SUCCESS_RATE_A" ] && [ -n "$SUCCESS_RATE_B" ] && [ -n "$SUCCESS_RATE_C" ]; then
  echo "Test A (No Detection & No Avoidance):     $SUCCESS_RATE_A%  ($SUCCESS_A/$TOTAL_A)"
  echo "Test B (Detection Only):                   $SUCCESS_RATE_B%  ($SUCCESS_B/$TOTAL_B)"
  echo "Test C (Full Defense + RBR):               $SUCCESS_RATE_C%  ($SUCCESS_C/$TOTAL_C)"
  echo ""
  
  IMPROVEMENT_B=$(echo "scale=2; $SUCCESS_RATE_B - $SUCCESS_RATE_A" | bc 2>/dev/null || echo "N/A")
  IMPROVEMENT_C=$(echo "scale=2; $SUCCESS_RATE_C - $SUCCESS_RATE_A" | bc 2>/dev/null || echo "N/A")
  
  echo "Improvements vs No Defense:"
  echo "  Detection Only:     +$IMPROVEMENT_B%"
  echo "  Full Defense (RBR):  +$IMPROVEMENT_C%"
fi

echo ""
echo "Output Directory: $OUTPUT_BASE"
echo ""
echo "Detailed Results:"
echo "  Test A: $TEST_A_DIR/payments_output.csv"
echo "  Test B: $TEST_B_DIR/payments_output.csv"
echo "  Test C: $TEST_C_DIR/payments_output.csv"
echo ""
