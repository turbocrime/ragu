# Extract regressions from gungraun summaries that include comparison data
# Input: array of gungraun summary objects (use --slurp)
# Expects --argjson threshold (e.g., 1.5 for 150%)
# Output: array of regression objects sorted by ratio descending
#
# Gungraun uses EitherOrBoth for comparison:
#   - Both: [new, old] when baseline exists
#   - Left: new value only (no baseline)

def extract_metric_value:
  if .Int then .Int
  elif .Float then .Float
  else null
  end;

[.[] |
  (.module_path + "::" + .function_name + (if .id then " " + .id else "" end)) as $name |
  .profiles[0].summaries.total.summary.Callgrind.Ir.metrics as $metrics |

  # Only process entries with comparison data (Both)
  select($metrics.Both != null) |

  ($metrics.Both[0] | extract_metric_value) as $new |
  ($metrics.Both[1] | extract_metric_value) as $old |

  select($new != null and $old != null and $old > 0) |

  {name: $name, current: $new, baseline: $old, ratio: ($new / $old)} |
  select(.ratio > $threshold)
] | sort_by(-.ratio)
