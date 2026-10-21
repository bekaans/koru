# Attributing file access to AI agents via process lineage

Agent signatures live in `packages/agents/*.toml`; the accessing process and its ancestors are matched against them. In the end-to-end suite, 40/40 AI-agent-context accesses were attributed ([metrics report](../../../docs/reports/metrics.md)).
