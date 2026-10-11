use crate::rules::types::{MatchContext, Report, Rule, Severity};

pub struct GenericTaintRule {
    pub rule_id: String,
    pub rule_name: String,
    pub description: String,
    pub severity: Severity,
    pub sink_function_names: Vec<String>,
}

impl GenericTaintRule {
    pub fn new(id: &str, name: &str, desc: &str, sev: Severity, sinks: Vec<&str>) -> Self {
        Self {
            rule_id: id.to_string(),
            rule_name: name.to_string(),
            description: desc.to_string(),
            severity: sev,
            sink_function_names: sinks.into_iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Rule for GenericTaintRule {
    fn id(&self) -> &str {
        &self.rule_id
    }

    fn name(&self) -> &str {
        &self.rule_name
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn severity(&self) -> Severity {
        self.severity
    }

    fn evaluate(&self, ctx: &MatchContext) -> Vec<Report> {
        let mut reports = Vec::new();

        for finding in &ctx.dataflow.findings {
            let func_name = ctx.interner.resolve(finding.sink_func);
            if self.sink_function_names.contains(&func_name.to_string()) {
                reports.push(Report {
                    rule_id: self.rule_id.clone(),
                    name: self.rule_name.clone(),
                    description: finding.evidence.clone(),
                    severity: self.severity,
                    block_id: 0,
                    instr_idx: finding.sink_instr_idx,
                    line: Some(finding.line),
                    file_path: None,
                    source_var: None,
                    output_var: None,
                });
            }
        }

        reports
    }
}
