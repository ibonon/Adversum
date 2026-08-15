// Deterministic Validator - Rust Implementation
// Replaces the slow Python sequential validator with parallel Rust processing

use pyo3::prelude::*;
use serde::{Serialize, Deserialize};
use rayon::prelude::*;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use once_cell::sync::Lazy;

use crate::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SanitizerType {
    Escape,
    Validate,
    Encode,
    Parameterize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[pyclass(get_all)]
pub struct ValidatedFinding {
    pub raw: Finding,
    pub validation_status: String,  // "CONFIRMED", "REJECTED", "LOW_RISK"
    pub ai_confidence: f32,
    pub reasoning_notes: String,
    pub remediation_suggestion: String,
    pub fix_description: Option<String>,
    pub fix_code: Option<String>,
}

#[pymethods]
impl ValidatedFinding {
    #[new]
    fn new(
        raw: Finding,
        validation_status: String,
        ai_confidence: f32,
        reasoning_notes: String,
        remediation_suggestion: String,
        fix_description: Option<String>,
        fix_code: Option<String>,
    ) -> Self {
        Self {
            raw,
            validation_status,
            ai_confidence,
            reasoning_notes,
            remediation_suggestion,
            fix_description,
            fix_code,
        }
    }
}

#[derive(Debug, Clone)]
struct ValidationRule {
    rule_id: String,
    required_sanitizers: Vec<SanitizerType>,
    false_positive_patterns: Vec<Regex>,
    confidence: f32,
}

pub struct DeterministicValidator {
    sanitizers: HashMap<String, SanitizerType>,
    validation_rules: HashMap<String, ValidationRule>,
}

// Pre-compile all regex patterns at startup
static FALSE_POSITIVE_REGEXES: Lazy<HashMap<String, Vec<Regex>>> = Lazy::new(|| {
    let mut map = HashMap::new();
    
    // DANGEROUS_EVAL patterns
    map.insert("RUST_CORE_001_DANGEROUS_EVAL".to_string(), vec![
        Regex::new(r"ast\.literal_eval").unwrap(),
        Regex::new(r"json\.loads").unwrap(),
        Regex::new(r"#.*test.*eval").unwrap(),
        Regex::new(r#"['"].*['"]"#).unwrap(),
    ]);
    
    // OS_SYSTEM patterns
    map.insert("RUST_CORE_002_OS_SYSTEM".to_string(), vec![
        Regex::new(r"shlex\.quote").unwrap(),
        Regex::new(r"subprocess\.run").unwrap(),
        Regex::new(r"#.*test").unwrap(),
    ]);
    
    // SUBPROCESS_POPEN patterns
    map.insert("RUST_CORE_003_SUBPROCESS_POPEN".to_string(), vec![
        Regex::new(r"shell=False").unwrap(),
        Regex::new(r"subprocess\.run").unwrap(),
    ]);
    
    map
});

impl DeterministicValidator {
    pub fn new() -> Self {
        let mut sanitizers = HashMap::new();
        
        // Escape sanitizers
        sanitizers.insert("shlex.quote".to_string(), SanitizerType::Escape);
        sanitizers.insert("shlex.quote_plus".to_string(), SanitizerType::Escape);
        sanitizers.insert("html.escape".to_string(), SanitizerType::Escape);
        sanitizers.insert("cgi.escape".to_string(), SanitizerType::Escape);
        sanitizers.insert("urllib.parse.quote".to_string(), SanitizerType::Escape);
        sanitizers.insert("urllib.parse.quote_plus".to_string(), SanitizerType::Escape);
        sanitizers.insert("DOMPurify.sanitize".to_string(), SanitizerType::Escape);
        sanitizers.insert("StringEscapeUtils.escapeHtml4".to_string(), SanitizerType::Escape);
        
        // Validation sanitizers
        sanitizers.insert("re.match".to_string(), SanitizerType::Validate);
        sanitizers.insert("re.search".to_string(), SanitizerType::Validate);
        sanitizers.insert("re.fullmatch".to_string(), SanitizerType::Validate);
        sanitizers.insert("str.isalnum".to_string(), SanitizerType::Validate);
        sanitizers.insert("str.isalpha".to_string(), SanitizerType::Validate);
        sanitizers.insert("str.isdigit".to_string(), SanitizerType::Validate);
        
        // Encoding sanitizers
        sanitizers.insert("base64.b64encode".to_string(), SanitizerType::Encode);
        sanitizers.insert("urllib.parse.urlencode".to_string(), SanitizerType::Encode);
        
        // Parameterization
        sanitizers.insert("sqlite3.execute".to_string(), SanitizerType::Parameterize);
        sanitizers.insert("psycopg2.execute".to_string(), SanitizerType::Parameterize);
        sanitizers.insert("pymysql.execute".to_string(), SanitizerType::Parameterize);
        sanitizers.insert("mysql.format".to_string(), SanitizerType::Parameterize);
        sanitizers.insert("PreparedStatement".to_string(), SanitizerType::Parameterize);
        
        let mut validation_rules = HashMap::new();
        
        // Rule: DANGEROUS_EVAL
        validation_rules.insert(
            "RUST_CORE_001_DANGEROUS_EVAL".to_string(),
            ValidationRule {
                rule_id: "RUST_CORE_001_DANGEROUS_EVAL".to_string(),
                required_sanitizers: vec![SanitizerType::Escape, SanitizerType::Validate],
                false_positive_patterns: FALSE_POSITIVE_REGEXES
                    .get("RUST_CORE_001_DANGEROUS_EVAL")
                    .cloned()
                    .unwrap_or_default(),
                confidence: 0.95,
            },
        );
        
        // Rule: OS_SYSTEM
        validation_rules.insert(
            "RUST_CORE_002_OS_SYSTEM".to_string(),
            ValidationRule {
                rule_id: "RUST_CORE_002_OS_SYSTEM".to_string(),
                required_sanitizers: vec![SanitizerType::Escape],
                false_positive_patterns: FALSE_POSITIVE_REGEXES
                    .get("RUST_CORE_002_OS_SYSTEM")
                    .cloned()
                    .unwrap_or_default(),
                confidence: 0.95,
            },
        );
        
        // Rule: SUBPROCESS_POPEN
        validation_rules.insert(
            "RUST_CORE_003_SUBPROCESS_POPEN".to_string(),
            ValidationRule {
                rule_id: "RUST_CORE_003_SUBPROCESS_POPEN".to_string(),
                required_sanitizers: vec![SanitizerType::Escape],
                false_positive_patterns: FALSE_POSITIVE_REGEXES
                    .get("RUST_CORE_003_SUBPROCESS_POPEN")
                    .cloned()
                    .unwrap_or_default(),
                confidence: 0.90,
            },
        );
        
        Self {
            sanitizers,
            validation_rules,
        }
    }
    
    /// Validate findings in parallel using Rayon
    pub fn validate_parallel(&self, findings: Vec<Finding>) -> Vec<ValidatedFinding> {
        findings
            .par_iter()
            .map(|finding| self.validate_single(finding))
            .collect()
    }
    
    fn validate_single(&self, raw: &Finding) -> ValidatedFinding {
        // Get validation rule for this finding
        let rule = self.validation_rules.get(&raw.id);
        
        if rule.is_none() {
            // Unknown rule: conservative validation (CONFIRMED)
            return ValidatedFinding {
                raw: raw.clone(),
                validation_status: "CONFIRMED".to_string(),
                ai_confidence: 0.8,
                reasoning_notes: "[Deterministic] Unknown rule, conservative validation.".to_string(),
                remediation_suggestion: self.generate_fix(&raw.id, &raw.snippet).0,
                fix_description: Some(self.generate_fix(&raw.id, &raw.snippet).0),
                fix_code: Some(self.generate_fix(&raw.id, &raw.snippet).1),
            };
        }
        
        let rule = rule.unwrap();
        
        // Detect sanitizers in flow path
        let sanitizers_found = self.detect_sanitizers(&raw.flow_path, &raw.snippet);
        
        // Check for false positive patterns
        let is_false_positive = self.check_false_positive_patterns(rule, &raw.snippet);
        
        // Check if required sanitizers are present
        let has_required_sanitizers = self.check_required_sanitizers(
            &rule.required_sanitizers,
            &sanitizers_found,
        );
        
        // Deterministic decision
        let (status, confidence, notes) = if is_false_positive {
            (
                "REJECTED".to_string(),
                0.1,
                format!("[Deterministic] False positive pattern detected: {}", raw.id),
            )
        } else if has_required_sanitizers {
            (
                "LOW_RISK".to_string(),
                0.3,
                format!("[Deterministic] Sanitizers detected in flow path: {:?}", sanitizers_found),
            )
        } else {
            (
                "CONFIRMED".to_string(),
                rule.confidence,
                format!(
                    "[Deterministic] No sanitizers detected. Flow path: {}",
                    if raw.flow_path.is_empty() {
                        "Direct".to_string()
                    } else {
                        raw.flow_path.join(" -> ")
                    }
                ),
            )
        };
        
        // Generate deterministic fix
        let (fix_description, fix_code) = self.generate_fix(&raw.id, &raw.snippet);
        
        ValidatedFinding {
            raw: raw.clone(),
            validation_status: status,
            ai_confidence: confidence,
            reasoning_notes: notes,
            remediation_suggestion: format!("Deterministic fix: {}", fix_description),
            fix_description: Some(fix_description),
            fix_code: Some(fix_code),
        }
    }
    
    fn detect_sanitizers(&self, flow_path: &[String], snippet: &str) -> Vec<SanitizerType> {
        let mut found = HashSet::new();
        
        // Analyze flow_path
        for step in flow_path {
            for (sanitizer_name, sanitizer_type) in &self.sanitizers {
                if step.contains(sanitizer_name) {
                    found.insert(*sanitizer_type);
                }
            }
        }
        
        // Analyze snippet
        for (sanitizer_name, sanitizer_type) in &self.sanitizers {
            if snippet.to_lowercase().contains(&sanitizer_name.to_lowercase()) {
                found.insert(*sanitizer_type);
            }
        }
        
        found.into_iter().collect()
    }
    
    fn check_false_positive_patterns(&self, rule: &ValidationRule, snippet: &str) -> bool {
        for pattern in &rule.false_positive_patterns {
            if pattern.is_match(snippet) {
                return true;
            }
        }
        false
    }
    
    fn check_required_sanitizers(
        &self,
        required: &[SanitizerType],
        found: &[SanitizerType],
    ) -> bool {
        if required.is_empty() {
            return false;
        }
        
        let found_set: HashSet<_> = found.iter().collect();
        required.iter().any(|req| found_set.contains(req))
    }
    
    fn generate_fix(&self, rule_id: &str, _snippet: &str) -> (String, String) {
        match rule_id {
            "RUST_CORE_001_DANGEROUS_EVAL" => (
                "Replace eval() with ast.literal_eval() for safe evaluation of literals only".to_string(),
                "import ast\nresult = ast.literal_eval(user_input)".to_string(),
            ),
            "RUST_CORE_002_OS_SYSTEM" => (
                "Use subprocess.run() with shell=False and shlex.quote() for arguments".to_string(),
                "import subprocess\nimport shlex\nsubprocess.run([command] + shlex.split(args), shell=False)".to_string(),
            ),
            "RUST_CORE_003_SUBPROCESS_POPEN" => (
                "Use subprocess.run() with shell=False instead of Popen with shell=True".to_string(),
                "import subprocess\nsubprocess.run([command, arg1, arg2], shell=False)".to_string(),
            ),
            _ => (
                "Apply input validation and sanitization before using user input".to_string(),
                "# TODO: Add sanitization based on rule requirements".to_string(),
            ),
        }
    }
}

impl Default for DeterministicValidator {
    fn default() -> Self {
        Self::new()
    }
}
