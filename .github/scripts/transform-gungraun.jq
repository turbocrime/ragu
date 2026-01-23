# Transform gungraun JSON output to github-action-benchmark format
# Tracks the Instructions (Ir) metric only
#
# Schema reference: https://github.com/gungraun/gungraun/raw/refs/heads/main/gungraun-runner/schemas/summary.v6.schema.json
# - Benchmark name: module_path + function_name (+ id if present)
# - Ir metric path: profiles[].summaries.total.summary.Callgrind.Ir.metrics
# - Metric value is EitherOrBoth (Left/Right/Both) containing Int or Float

# Helper to extract numeric value from Metric (Int or Float)
def extract_metric_value:
    if .Int then .Int
    elif .Float then .Float
    else null
    end;

# Helper to get current value from EitherOrBoth metrics
# Right = new only, Both = [old, new], Left = old only
def extract_current_value:
    if .Right then .Right | extract_metric_value
    elif .Both then .Both[1] | extract_metric_value
    elif .Left then .Left | extract_metric_value
    else null
    end;

[.[] | {
    name: (
        .module_path + "::" + .function_name +
        (if .id then ("::" + .id) else "" end)
    ),
    unit: "instructions",
    value: (
        .profiles[0].summaries.total.summary.Callgrind.Ir.metrics
        | extract_current_value
    )
}]
