"""Analysis module, detection half — Di Pietro et al., ASIA CCS '25, §3.

Paper concept                          Module
-------------------------------------  ---------------------------------------
Operational primitives (§3.1)          noirlycan_core.models.PrimitiveKind
API equivalence classes (§3.1, App. B) api_classes.PAPER_API_CLASSES
Execute vs. context-read APIs          primitives
Minimal core ops / congruence /        rules
temporal consistency (§3.2)
Per (actor, victim) chain, time window correlator.Correlator
Recursive injection chains (§3.1)      injection_graph

Lab extensions (not in the paper): scoring, provenance, network_watch.
Technique classification lives in noirlycan_core.classification.
"""
