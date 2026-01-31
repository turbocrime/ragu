# Format regressions as markdown table rows
# Input: array of regression objects from find-regressions.jq
# Output: markdown table rows (one per line)

.[] | "| `\(.name)` | \(.current) | \(.baseline) | \(.ratio * 100 | round / 100) |"
