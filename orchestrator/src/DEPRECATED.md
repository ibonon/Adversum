# Deprecated — do not use (P4)

`orchestrator/src/` (`pipeline.py`, `wrapper.py`, `scanner.py`,
`reasoning.py`, `schemas.py`, `main.py`) is a legacy prototype kept
only so old imports fail loudly rather than silently. The production
pipeline is `orchestrator/pipeline/analysis_pipeline.py` with
`orchestrator/core_bridge/core_wrapper.py`. New code must import from
`orchestrator.pipeline` / `orchestrator.core_bridge`, never from
`orchestrator.src`. Removal is pending a full import audit.
