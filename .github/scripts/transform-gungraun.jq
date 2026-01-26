# Transform gungraun JSON output to github-action-benchmark format
# Extracts all Callgrind metrics from each benchmark
#
# Schema reference: https://github.com/gungraun/gungraun/raw/refs/heads/main/gungraun-runner/schemas/summary.v6.schema.json

# Helper to extract numeric value from Metric (Int or Float)
def extract_metric_value:
    if .Int then .Int
    elif .Float then .Float
    else null
    end;

# Extract current run's value from metrics
# Prefers Right (new only), falls back to Both[1] (new in comparison)
def extract_current_value:
    (.Right // .Both[1]) | extract_metric_value;

# Map metric name to appropriate unit based on Callgrind EventKind descriptions
def metric_unit:
    # Core counts
    if . == "Ir" then "instructions"
    elif . == "Dr" then "data reads"
    elif . == "Dw" then "data writes"
    # L1 instruction cache
    elif . == "I1mr" then "I1 read misses"
    # L1 data cache
    elif . == "D1mr" then "D1 read misses"
    elif . == "D1mw" then "D1 write misses"
    # LL (last-level) instruction cache
    elif . == "ILmr" then "LL instruction misses"
    # LL data cache
    elif . == "DLmr" then "LL data read misses"
    elif . == "DLmw" then "LL data write misses"
    # Dirty misses (write-back simulation)
    elif . == "ILdmr" then "LL instruction dirty misses"
    elif . == "DLdmr" then "LL data read dirty misses"
    elif . == "DLdmw" then "LL data write dirty misses"
    # Cache hits (derived)
    elif . == "L1hits" then "L1 hits"
    elif . == "LLhits" then "LL hits"
    elif . == "RamHits" then "RAM hits"
    # Miss rates
    elif . == "I1MissRate" then "I1 miss rate"
    elif . == "D1MissRate" then "D1 miss rate"
    elif . == "LLiMissRate" then "LL instruction miss rate"
    elif . == "LLdMissRate" then "LL data miss rate"
    elif . == "LLMissRate" then "LL miss rate"
    # Hit rates
    elif . == "L1HitRate" then "L1 hit rate"
    elif . == "LLHitRate" then "LL hit rate"
    elif . == "RamHitRate" then "RAM hit rate"
    # Derived totals
    elif . == "TotalRW" then "total accesses"
    elif . == "EstimatedCycles" then "cycles"
    # Branch simulation
    elif . == "Bc" then "conditional branches"
    elif . == "Bcm" then "conditional branch misses"
    elif . == "Bi" then "indirect branches"
    elif . == "Bim" then "indirect branch misses"
    # System calls
    elif . == "SysCount" then "syscalls"
    elif . == "SysTime" then "syscall time (ns)"
    elif . == "SysCpuTime" then "syscall CPU time (ns)"
    # Global bus events
    elif . == "Ge" then "global bus events"
    # Locality counters
    elif . == "AcCost1" then "L1 temporal locality cost"
    elif . == "AcCost2" then "LL temporal locality cost"
    elif . == "SpLoss1" then "L1 spatial locality loss"
    elif . == "SpLoss2" then "LL spatial locality loss"
    else "count"
    end;

# Main transformation: flatten benchmark results into github-action-benchmark format
#
# Input: array of gungraun benchmark results (use --slurp to combine multiple summary.json files)
# Output: array of {name, unit, value} objects for github-action-benchmark
#
# Example output entry (matches terminal header format):
#   {"name": "pcd::pcd::verify_leaf verify_leaf:setup_verify_leaf() Ir", "unit": "instructions", "value": 123456}
[.[] |
    # Build benchmark name to match terminal output format:
    # "module_path::function_name id" e.g., "pcd::pcd::verify_leaf verify_leaf:setup_verify_leaf()"
    (.module_path + "::" + .function_name + (if .id then (" " + .id) else "" end)) as $bench_name |

    # Extract Callgrind metrics from the first profile's total summary
    # Each metric (Ir, Dr, EstimatedCycles, etc.) becomes a separate benchmark entry
    .profiles[0].summaries.total.summary.Callgrind | to_entries[] |

    # Skip metrics without values (can happen with some Callgrind configurations)
    select(.value.metrics != null) |

    # Emit one entry per metric in github-action-benchmark format
    {
        name: ($bench_name + " " + .key),  # e.g., "pcd::pcd::verify_leaf verify_leaf:setup_verify_leaf() Ir"
        unit: (.key | metric_unit),         # e.g., "instructions" for Ir
        value: (.value.metrics | extract_current_value)
    }
]
# Filter out any entries where value extraction failed
| map(select(.value != null))
