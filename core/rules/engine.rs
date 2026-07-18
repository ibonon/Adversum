use crate::rules::types::{Rule, MatchContext, Report};

pub struct RuleEngine {
    rules: Vec<Box<dyn Rule>>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
        }
    }

    pub fn add_rule<R: Rule + 'static>(&mut self, rule: R) {
        self.rules.push(Box::new(rule));
    }

    pub fn execute(&self, ctx: &MatchContext) -> Vec<Report> {
        let mut all_reports = Vec::new();
        for rule in &self.rules {
            let reports = rule.evaluate(ctx);
            all_reports.extend(reports);
        }
        all_reports
    }
}
