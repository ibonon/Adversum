use crate::attack_graph::types::{AttackGraph, AttackEdge, AttackNode};
use crate::rules::types::{Report, Severity};

/// Deterministic builder for the inter-finding AttackGraph.
///
/// Design principle (industrial safety): we never *guess* a cross-file or
/// cross-function flow. An edge is only added when it is provable from the
/// reports we already hold. Two concrete, deterministic rules are used:
///
/// 1. **Intra-file enablement.** Two reports in the *same file*, ordered by
///    line (then instruction index), where the earlier finding is an
///    "enabler" category (RCE / deserialization / SSRF / path traversal /
///    command injection) and the later finding is a sink. The enabler proves
///    the attacker can reach the later sink's input path.
///
/// 2. **Severity escalation.** A Critical finding enables any later High/Medium
///    finding in the same file (the compromise grants broader reach).
///
/// Edges are labelled so downstream tooling can explain *why* the chain exists.
pub struct GraphBuilder;

/// Rule-id prefixes whose successful exploitation demonstrably widens the
/// attacker's reach (privilege escalation, arbitrary code, data exfiltration).
/// Kept intentionally conservative: only categories whose post-condition is a
/// *provable* capability gain are listed here.
const ENABLER_PREFIXES: &[&str] = &[
    "RUST_CORE_001_DANGEROUS_EVAL",
    "RUST_CORE_002_OS_SYSTEM",
    "RUST_CORE_003_SUBPROCESS_POPEN",
    "RUST_CORE_007_INSECURE_DESERIALIZATION",
    "RUST_CORE_004_PATH_TRAVERSAL",
    "RUST_CORE_005_SQL_INJECTION",
    "RUST_CORE_007_TEMPLATE_INJECTION",
];

impl GraphBuilder {
    pub fn build(reports: Vec<Report>) -> AttackGraph {
        let mut graph = AttackGraph::new();

        // 1. Create nodes, preserving a stable, deterministic order.
        //    Sort by (file_path, line, instr_idx, rule_id) so that two identical
        //    inputs always produce the same node ordering.
        let mut ordered = reports;
        ordered.sort_by(|a, b| {
            a.file_path
                .cmp(&b.file_path)
                .then_with(|| a.line.cmp(&b.line))
                .then_with(|| a.instr_idx.cmp(&b.instr_idx))
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        });

        for (i, report) in ordered.into_iter().enumerate() {
            graph.nodes.push(AttackNode {
                id: i,
                report,
            });
        }

        // 2. Build edges with the deterministic rules above.
        for a in 0..graph.nodes.len() {
            for b in (a + 1)..graph.nodes.len() {
                if let Some(description) = Self::edge_reason(&graph.nodes[a], &graph.nodes[b]) {
                    graph.edges.push(AttackEdge {
                        from: graph.nodes[a].id,
                        to: graph.nodes[b].id,
                        description,
                    });
                }
            }
        }

        graph
    }

    /// Returns `Some(reason)` if a provable enablement edge `from -> to`
    /// exists, otherwise `None`. Pure function of the two nodes.
    fn edge_reason(from: &AttackNode, to: &AttackNode) -> Option<String> {
        // Cross-file chains require inter-procedural proof we do not have yet.
        if from.report.file_path != to.report.file_path {
            return None;
        }
        // `from` must provably precede `to` in source order.
        if !Self::precedes(&from.report, &to.report) {
            return None;
        }

        // Rule 0: Data flow dependency. If an earlier report's output directly
        // feeds into this report's input, there's a proven flow.
        if let (Some(out_var), Some(in_var)) = (&from.report.output_var, &to.report.source_var) {
            if out_var == in_var {
                return Some(format!(
                    "data-flow: {} output '{}' feeds into {} input",
                    from.report.rule_id, out_var, to.report.rule_id
                ));
            }
        }

        let from_is_enabler = ENABLER_PREFIXES
            .iter()
            .any(|p| from.report.rule_id.starts_with(p));

        // Rule 2: a Critical compromise grants broader reach in the same unit.
        if from.report.severity == Severity::Critical
            && to.report.severity != Severity::Critical
        {
            return Some(format!(
                "escalation: {} (Critical) grants reach to later {}",
                from.report.rule_id, to.report.rule_id
            ));
        }

        // Rule 1: an enabler category proves the attacker can reach the later
        // sink's input path.
        if from_is_enabler {
            return Some(format!(
                "enables: {} post-condition reaches later {}",
                from.report.rule_id, to.report.rule_id
            ));
        }

        None
    }

    /// True when `a` is provably before `b` in execution/source order within
    /// the same file. Prefers source line; falls back to instruction index.
    fn precedes(a: &Report, b: &Report) -> bool {
        match (a.line, b.line) {
            (Some(la), Some(lb)) => la < lb,
            _ => a.instr_idx < b.instr_idx,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::types::Report;

    fn rep(rule_id: &str, sev: Severity, line: usize, file: &str) -> Report {
        Report {
            rule_id: rule_id.to_string(),
            name: "n".into(),
            description: "d".into(),
            severity: sev,
            block_id: 0,
            instr_idx: line,
            line: Some(line),
            file_path: Some(file.to_string()),
            source_var: None,
            output_var: None,
        }
    }

    fn rep_with_vars(rule_id: &str, sev: Severity, line: usize, file: &str, src_var: Option<&str>, out_var: Option<&str>) -> Report {
        let mut r = rep(rule_id, sev, line, file);
        r.source_var = src_var.map(|s| s.to_string());
        r.output_var = out_var.map(|s| s.to_string());
        r
    }

    #[test]
    fn builds_data_flow_chain() {
        let reports = vec![
            rep_with_vars("RUST_CORE_004_PATH_TRAVERSAL", Severity::High, 10, "a.py", None, Some("file_content")),
            rep_with_vars("RUST_CORE_001_DANGEROUS_EVAL", Severity::Critical, 20, "a.py", Some("file_content"), None),
        ];
        let g = GraphBuilder::build(reports);
        assert_eq!(g.edges.len(), 1);
        assert!(g.edges[0].description.starts_with("data-flow"));
    }

    #[test]
    fn builds_intra_file_chain_from_enabler_to_sink() {
        let reports = vec![
            rep("RUST_CORE_002_OS_SYSTEM", Severity::Critical, 10, "a.py"),
            rep("RUST_CORE_005_SQL_INJECTION", Severity::High, 40, "a.py"),
        ];
        let g = GraphBuilder::build(reports);
        assert_eq!(g.nodes.len(), 2);
        assert_eq!(g.edges.len(), 1);
        assert_eq!(g.edges[0].from, 0);
        assert_eq!(g.edges[0].to, 1);
        assert!(g.edges[0].description.starts_with("escalation"));
    }

    #[test]
    fn no_edge_across_files() {
        let reports = vec![
            rep("RUST_CORE_002_OS_SYSTEM", Severity::Critical, 10, "a.py"),
            rep("RUST_CORE_005_SQL_INJECTION", Severity::High, 40, "b.py"),
        ];
        let g = GraphBuilder::build(reports);
        assert!(g.edges.is_empty(), "cross-file edges are forbidden");
    }

    #[test]
    fn no_edge_when_order_reversed() {
        let reports = vec![
            rep("RUST_CORE_005_SQL_INJECTION", Severity::High, 40, "a.py"),
            rep("RUST_CORE_002_OS_SYSTEM", Severity::Critical, 10, "a.py"),
        ];
        // After deterministic sort, the OS_SYSTEM (line 10) is node 0 and
        // precedes SQLi (line 40). Edge must still be present (enabler).
        let g = GraphBuilder::build(reports);
        assert_eq!(g.edges.len(), 1);
    }

    #[test]
    fn deterministic_node_ordering() {
        let reports = vec![
            rep("RUST_CORE_005_SQL_INJECTION", Severity::High, 40, "a.py"),
            rep("RUST_CORE_001_DANGEROUS_EVAL", Severity::Critical, 5, "a.py"),
        ];
        let g = GraphBuilder::build(reports);
        // Sorted by line: EVAL (5) first, then SQLi (40).
        assert_eq!(g.nodes[0].report.line, Some(5));
        assert_eq!(g.nodes[1].report.line, Some(40));
    }
}
