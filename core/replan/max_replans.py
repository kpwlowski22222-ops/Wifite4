# core.replan.max_replans
#
# Raised from 25 → 50 to give the re-plan loop enough room for target-adaptive
# real-world tuning. Each "re-plan" is the chain planner receiving
# `prior_results` + `gather_failure_context` and proposing 1-3 new steps.
# A typical successful chain takes 5-15 steps; a target-adaptive chain that
# hits live-edit + tool-install can take 30-40. 50 is generous but bounded.

MAX_REPLANS = 50
