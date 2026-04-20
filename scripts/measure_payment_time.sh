#!/bin/bash
# Measure payment time from simulation results
# Usage: ./measure_payment_time.sh <result_directory>

if [ $# -lt 1 ]; then
    echo "Usage: $0 <result_directory>"
    echo "Example: $0 /tmp/cloth-out"
    exit 1
fi

result_dir="$1"
csv_file="$result_dir/payments_output.csv"

if [ ! -f "$csv_file" ]; then
    echo "Error: $csv_file not found"
    exit 1
fi

# Extract start_time and end_time columns and calculate duration
# Skip header line (1d) and calculate: end_time(col7) - start_time(col5)
awk -F',' 'NR > 1 {
    duration = $7 - $5
    total_duration += duration
    count++
    print "Payment " $1 ": " duration " ms"
}
END {
    if (count > 0) {
        print ""
        print "===== Payment Timing Summary ====="
        print "Total payments: " count
        print "Total time: " total_duration " ms"
        printf "Average time per payment: %.2f ms\n", total_duration / count
        print "==================================="
    }
}' "$csv_file"
