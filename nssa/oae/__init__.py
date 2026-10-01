"""OAE — Offline Analysis Engine.

Consumes signed APU probe artifacts and a Segmentation Policy Model to produce
fully-enriched AuditFindings ranked by severity and exposure priority.

Pipeline stages (see engine.py):
  1. Reachability  — reverse BFS over the observed graph → ReachabilityIndex
  2. Classification — ECM/TCM comparison → FindingCandidates → PolicyFindings
  3. Audit          — correlation, violated-rule summaries, priority scoring

Entry points: nssa.oae.engine.OAEEngine and nssa.oae.engine.evaluate()
CLI:         nssa-evaluate (see nssa/oae/cli.py)
"""
