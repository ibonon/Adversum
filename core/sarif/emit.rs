use crate::sarif::types::*;
use crate::scoring::cvss::CvssV4;
use crate::Finding;

/// CWE mapping from rule ID pattern
pub fn rule_to_cwe(rule_id: &str) -> &'static str {
    match rule_id {
        r if r.contains("EVAL") => "CWE-95",
        r if r.contains("SYSTEM") || r.contains("SUBPROCESS") => "CWE-78",
        r if r.contains("SQL") => "CWE-89",
        r if r.contains("PATH") || r.contains("TRAVERSAL") => "CWE-22",
        r if r.contains("TEMPLATE") || r.contains("SSTI") => "CWE-94",
        r if r.contains("DESERIALIZATION") || r.contains("PICKLE") => "CWE-502",
        r if r.contains("YAML") => "CWE-20",
        r if r.contains("XSS") => "CWE-79",
        _ => "CWE-0",
    }
}

pub fn severity_to_level(severity: &str) -> &'static str {
    match severity {
        "CRITICAL" | "HIGH" => "error",
        "MEDIUM" => "warning",
        _ => "note",
    }
}

/// Build a SARIF 2.1.0 log from Adversum findings.
/// `file_path`: the analyzed source file path.
/// `findings`: slice of Finding structs from the pipeline.
pub fn emit_sarif(findings: &[Finding], file_path: &str) -> SarifLog {
    let mut sarif_results = Vec::new();
    let mut sarif_rules = Vec::new();
    let mut seen_rules = std::collections::HashSet::new();

    for finding in findings {
        let cwe = rule_to_cwe(&finding.id);
        let cvss = CvssV4::from_cwe(cwe);
        
        let level = severity_to_level(&finding.severity);

        let location = SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: finding.file_path.clone().unwrap_or_else(|| file_path.to_string()),
                    index: 0,
                },
                region: SarifRegion {
                    start_line: finding.line,
                },
            },
        };

        sarif_results.push(SarifResult {
            rule_id: finding.id.clone(),
            level: level.to_string(),
            message: SarifMessage {
                text: finding.message.clone(),
            },
            locations: vec![location],
            code_flows: vec![],
            properties: SarifResultProperties {
                severity: finding.severity.clone(),
                cvss_score: cvss.base_score(),
                cvss_vector: cvss.vector_string(),
                cwe: cwe.to_string(),
            },
        });

        if seen_rules.insert(finding.id.clone()) {
            sarif_rules.push(SarifRule {
                id: finding.id.clone(),
                name: finding.id.clone(),
                short_description: SarifMessage { text: finding.message.clone() },
                properties: SarifRuleProperties {
                    tags: vec![cwe.to_string()],
                    precision: "high".to_string(),
                    problem_severity: level.to_string(),
                    cwe: vec![cwe.to_string()],
                },
            });
        }
    }

    let artifact = SarifArtifact {
        location: SarifArtifactLocation {
            uri: file_path.to_string(),
            index: 0,
        },
        mime_type: "text/x-python".to_string(),
    };

    let run = SarifRun {
        tool: SarifTool {
            driver: SarifToolComponent {
                name: "Adversum".to_string(),
                version: "4.0".to_string(),
                rules: sarif_rules,
                information_uri: "https://adversum.io".to_string(),
            },
        },
        results: sarif_results,
        artifacts: vec![artifact],
    };

    SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![run],
    }
}
