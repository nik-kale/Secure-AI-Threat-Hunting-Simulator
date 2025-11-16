#!/bin/bash
# Run all attack scenarios and generate reports

set -e

echo "=========================================="
echo "Running All Attack Scenarios"
echo "=========================================="
echo ""

OUTPUT_BASE="./output/scenarios"
mkdir -p "$OUTPUT_BASE"

SCENARIOS=("iam_priv_escalation" "container_escape" "cred_stuffing")

for scenario in "${SCENARIOS[@]}"; do
    echo ""
    echo "===================="
    echo "Running: $scenario"
    echo "===================="

    output_dir="$OUTPUT_BASE/$scenario"

    python cli/run_scenario.py \
        --scenario "$scenario" \
        --output "$output_dir" \
        --analyze

    if [ $? -eq 0 ]; then
        echo "✓ $scenario completed successfully"
    else
        echo "✗ $scenario failed"
        exit 1
    fi
done

echo ""
echo "=========================================="
echo "✓ All scenarios completed!"
echo "=========================================="
echo ""
echo "Results saved to: $OUTPUT_BASE"
echo ""
