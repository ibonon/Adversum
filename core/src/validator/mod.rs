// Deterministic Validator - Rust Implementation
// High-performance parallel validator for security findings across Web2 and Web3 / EVM domains

use once_cell::sync::Lazy;
use pyo3::prelude::*;
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SanitizerType {
    Escape,
    Validate,
    Encode,
    Parameterize,
    PathResolve,
    CryptographicHash,
    EnvSecret,
    ReentrancyGuard,
    AccessControl,
    LowLevelCheck,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[pyclass(get_all)]
pub struct ValidatedFinding {
    pub raw: Finding,
    pub validation_status: String, // "CONFIRMED", "REJECTED", "LOW_RISK"
    pub ai_confidence: f32,
    pub reasoning_notes: String,
    pub remediation_suggestion: String,
    pub fix_description: Option<String>,
    pub fix_code: Option<String>,
}

#[pymethods]
impl ValidatedFinding {
    #[new]
    #[pyo3(signature = (raw, validation_status, ai_confidence, reasoning_notes, remediation_suggestion, fix_description=None, fix_code=None))]
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
    #[allow(dead_code)]
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
    map.insert(
        "RUST_CORE_001_DANGEROUS_EVAL".to_string(),
        vec![
            Regex::new(r"ast\.literal_eval").unwrap(),
            Regex::new(r"json\.loads").unwrap(),
            Regex::new(r"#.*test.*eval").unwrap(),
            Regex::new(r#"^eval\(['"][a-zA-Z0-9_\s+*-/]+['"]\)$"#).unwrap(),
        ],
    );

    // OS_SYSTEM patterns
    map.insert(
        "RUST_CORE_002_OS_SYSTEM".to_string(),
        vec![
            Regex::new(r"shlex\.quote").unwrap(),
            Regex::new(r"subprocess\.run").unwrap(),
            Regex::new(r#"os\.system\(['"][a-zA-Z0-9_\-\s]+['"]\)"#).unwrap(),
            Regex::new(r"#.*test").unwrap(),
        ],
    );

    // SUBPROCESS_POPEN patterns
    map.insert(
        "RUST_CORE_003_SUBPROCESS_POPEN".to_string(),
        vec![
            Regex::new(r"shell\s*=\s*False").unwrap(),
            Regex::new(r#"subprocess\.(?:run|call|Popen)\(\s*\[['"][a-zA-Z0-9_\-]+['"]"#).unwrap(),
        ],
    );

    // PATH_TRAVERSAL patterns (static string literals are not user-controlled traversal)
    map.insert(
        "RUST_CORE_004_PATH_TRAVERSAL".to_string(),
        vec![Regex::new(r#"open\(['"][a-zA-Z0-9_\-./]+\.[a-zA-Z0-9]+['"]\)"#).unwrap()],
    );

    // SQL_INJECTION patterns
    map.insert(
        "RUST_CORE_005_SQL_INJECTION".to_string(),
        vec![
            Regex::new(r#"execute\(\s*['"][^'"]*['"]\s*,\s*[\(\[]"#).unwrap(),
            Regex::new(
                r#"execute\(\s*['"]SELECT\s+[a-zA-Z0-9_*,\s]+FROM\s+[a-zA-Z0-9_]+['"]\s*\)"#,
            )
            .unwrap(),
            Regex::new(r"params\s*=").unwrap(),
        ],
    );

    // TEMPLATE_INJECTION patterns
    map.insert(
        "RUST_CORE_007_TEMPLATE_INJECTION".to_string(),
        vec![
            Regex::new(r"render_template\(").unwrap(),
            Regex::new(r#"Template\(['"][a-zA-Z0-9_\s\n<>\/]+['"]\)"#).unwrap(),
        ],
    );

    // INSECURE_DESERIALIZATION / YAML patterns
    map.insert(
        "RUST_CORE_008_INSECURE_DESERIALIZATION".to_string(),
        vec![Regex::new(r"json\.loads").unwrap()],
    );
    map.insert(
        "RUST_CORE_009_INSECURE_YAML".to_string(),
        vec![Regex::new(r"yaml\.safe_load").unwrap()],
    );

    // HARDCODED_SECRET patterns (ignore test dummy credentials & env vars)
    map.insert(
        "HARDCODED_SECRET".to_string(),
        vec![
            Regex::new(r"(?i)example|dummy|placeholder|test_token|fake_key|xxx|test_password")
                .unwrap(),
            Regex::new(r"os\.getenv|os\.environ").unwrap(),
        ],
    );

    // TLS_VERIFY_DISABLED patterns
    map.insert(
        "TLS_VERIFY_DISABLED".to_string(),
        vec![Regex::new(r#"verify\s*=\s*(?:True|['"][^'"]+['"])"#).unwrap()],
    );

    // SOLIDITY / SMART CONTRACT HEURISTICS
    map.insert(
        "HEU-001".to_string(), // Selfdestruct: comments or docstrings are false positives
        vec![Regex::new(r"^\s*//|^\s*/\*").unwrap()],
    );
    map.insert(
        "HEU-002".to_string(), // Delegatecall
        vec![Regex::new(r"^\s*//|^\s*/\*").unwrap()],
    );
    map.insert(
        "HEU-003".to_string(), // tx.origin
        vec![
            Regex::new(r"tx\.origin\s*==\s*msg\.sender").unwrap(),
            Regex::new(r"^\s*//|^\s*/\*").unwrap(),
        ],
    );
    map.insert(
        "HEU-004".to_string(), // Reentrancy
        vec![Regex::new(r"^\s*//|^\s*/\*").unwrap()],
    );
    map.insert(
        "HEU-010".to_string(), // Low level call
        vec![Regex::new(r"^\s*//|^\s*/\*").unwrap()],
    );

    map
});

impl DeterministicValidator {
    pub fn new() -> Self {
        let mut sanitizers = HashMap::new();

        // ── Escape Sanitizers ────────────────────────────────────────────────
        sanitizers.insert("shlex.quote".to_string(), SanitizerType::Escape);
        sanitizers.insert("shlex.quote_plus".to_string(), SanitizerType::Escape);
        sanitizers.insert("html.escape".to_string(), SanitizerType::Escape);
        sanitizers.insert("cgi.escape".to_string(), SanitizerType::Escape);
        sanitizers.insert("urllib.parse.quote".to_string(), SanitizerType::Escape);
        sanitizers.insert("urllib.parse.quote_plus".to_string(), SanitizerType::Escape);
        sanitizers.insert("DOMPurify.sanitize".to_string(), SanitizerType::Escape);
        sanitizers.insert(
            "StringEscapeUtils.escapeHtml4".to_string(),
            SanitizerType::Escape,
        );

        // ── Validation Sanitizers ────────────────────────────────────────────
        sanitizers.insert("re.match".to_string(), SanitizerType::Validate);
        sanitizers.insert("re.search".to_string(), SanitizerType::Validate);
        sanitizers.insert("re.fullmatch".to_string(), SanitizerType::Validate);
        sanitizers.insert("str.isalnum".to_string(), SanitizerType::Validate);
        sanitizers.insert("str.isalpha".to_string(), SanitizerType::Validate);
        sanitizers.insert("str.isdigit".to_string(), SanitizerType::Validate);

        // ── Encoding Sanitizers ──────────────────────────────────────────────
        sanitizers.insert("base64.b64encode".to_string(), SanitizerType::Encode);
        sanitizers.insert("urllib.parse.urlencode".to_string(), SanitizerType::Encode);

        // ── Parameterization (SQL) ───────────────────────────────────────────
        sanitizers.insert("sqlite3.execute".to_string(), SanitizerType::Parameterize);
        sanitizers.insert("psycopg2.execute".to_string(), SanitizerType::Parameterize);
        sanitizers.insert("pymysql.execute".to_string(), SanitizerType::Parameterize);
        sanitizers.insert("mysql.format".to_string(), SanitizerType::Parameterize);
        sanitizers.insert("PreparedStatement".to_string(), SanitizerType::Parameterize);
        sanitizers.insert("sqlmodel.select".to_string(), SanitizerType::Parameterize);
        sanitizers.insert("sqlalchemy.select".to_string(), SanitizerType::Parameterize);

        // ── Path Sanitizers ──────────────────────────────────────────────────
        sanitizers.insert("os.path.abspath".to_string(), SanitizerType::PathResolve);
        sanitizers.insert("os.path.realpath".to_string(), SanitizerType::PathResolve);
        sanitizers.insert("Path.resolve".to_string(), SanitizerType::PathResolve);
        sanitizers.insert("secure_filename".to_string(), SanitizerType::PathResolve);
        sanitizers.insert("is_relative_to".to_string(), SanitizerType::PathResolve);

        // ── Cryptographic Hash ───────────────────────────────────────────────
        sanitizers.insert(
            "hashlib.sha256".to_string(),
            SanitizerType::CryptographicHash,
        );
        sanitizers.insert(
            "hashlib.sha512".to_string(),
            SanitizerType::CryptographicHash,
        );
        sanitizers.insert(
            "secrets.token_hex".to_string(),
            SanitizerType::CryptographicHash,
        );
        sanitizers.insert(
            "secrets.token_bytes".to_string(),
            SanitizerType::CryptographicHash,
        );

        // ── Environment / Secret Management ──────────────────────────────────
        sanitizers.insert("os.getenv".to_string(), SanitizerType::EnvSecret);
        sanitizers.insert("os.environ.get".to_string(), SanitizerType::EnvSecret);
        sanitizers.insert("SecretStr".to_string(), SanitizerType::EnvSecret);

        // ── Web3 / Solidity Guards ───────────────────────────────────────────
        sanitizers.insert("nonReentrant".to_string(), SanitizerType::ReentrancyGuard);
        sanitizers.insert(
            "ReentrancyGuard".to_string(),
            SanitizerType::ReentrancyGuard,
        );
        sanitizers.insert("onlyOwner".to_string(), SanitizerType::AccessControl);
        sanitizers.insert("onlyRole".to_string(), SanitizerType::AccessControl);
        sanitizers.insert("AccessControl".to_string(), SanitizerType::AccessControl);
        sanitizers.insert("require(success".to_string(), SanitizerType::LowLevelCheck);
        sanitizers.insert("SafeERC20".to_string(), SanitizerType::LowLevelCheck);
        sanitizers.insert("ECDSA.recover".to_string(), SanitizerType::Validate);

        let mut validation_rules = HashMap::new();

        // Register Web2 SAST rules
        let rules_config = vec![
            (
                "RUST_CORE_001_DANGEROUS_EVAL",
                vec![SanitizerType::Escape, SanitizerType::Validate],
                0.95,
            ),
            ("RUST_CORE_002_OS_SYSTEM", vec![SanitizerType::Escape], 0.95),
            (
                "RUST_CORE_003_SUBPROCESS_POPEN",
                vec![SanitizerType::Escape],
                0.90,
            ),
            (
                "RUST_CORE_004_PATH_TRAVERSAL",
                vec![SanitizerType::PathResolve],
                0.90,
            ),
            (
                "RUST_CORE_005_SQL_INJECTION",
                vec![SanitizerType::Parameterize],
                0.95,
            ),
            (
                "RUST_CORE_007_TEMPLATE_INJECTION",
                vec![SanitizerType::Escape],
                0.90,
            ),
            (
                "RUST_CORE_008_INSECURE_DESERIALIZATION",
                vec![SanitizerType::Validate],
                0.90,
            ),
            (
                "RUST_CORE_009_INSECURE_YAML",
                vec![SanitizerType::Validate],
                0.90,
            ),
            ("HARDCODED_SECRET", vec![SanitizerType::EnvSecret], 0.85),
            ("TLS_VERIFY_DISABLED", vec![SanitizerType::Validate], 0.95),
            // Web3 / Solidity rules
            ("HEU-001", vec![SanitizerType::AccessControl], 0.95),
            ("HEU-002", vec![SanitizerType::AccessControl], 0.90),
            ("HEU-003", vec![SanitizerType::Validate], 0.95),
            ("HEU-004", vec![SanitizerType::ReentrancyGuard], 0.95),
            ("HEU-010", vec![SanitizerType::LowLevelCheck], 0.90),
        ];

        for (id, req_sanitizers, conf) in rules_config {
            let fp_patterns = FALSE_POSITIVE_REGEXES.get(id).cloned().unwrap_or_default();

            validation_rules.insert(
                id.to_string(),
                ValidationRule {
                    rule_id: id.to_string(),
                    required_sanitizers: req_sanitizers,
                    false_positive_patterns: fp_patterns,
                    confidence: conf,
                },
            );
        }

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

    pub fn validate_single(&self, raw: &Finding) -> ValidatedFinding {
        let rule = self.validation_rules.get(&raw.id);

        if rule.is_none() {
            // Unknown rule: conservative validation (CONFIRMED)
            let (fix_desc, fix_code) = self.generate_fix(&raw.id, &raw.snippet);
            return ValidatedFinding {
                raw: raw.clone(),
                validation_status: "CONFIRMED".to_string(),
                ai_confidence: 0.8,
                reasoning_notes: "[Deterministic] Unknown rule, conservative validation."
                    .to_string(),
                remediation_suggestion: fix_desc.clone(),
                fix_description: Some(fix_desc),
                fix_code: Some(fix_code),
            };
        }

        let rule = rule.unwrap();

        // Detect sanitizers in flow path and snippet
        let sanitizers_found = self.detect_sanitizers(&raw.flow_path, &raw.snippet);

        // Check for false positive patterns
        let is_false_positive = self.check_false_positive_patterns(rule, &raw.snippet);

        // Check if required sanitizers are present
        let has_required_sanitizers =
            self.check_required_sanitizers(&rule.required_sanitizers, &sanitizers_found);

        // Deterministic decision
        let (status, confidence, notes) = if is_false_positive {
            (
                "REJECTED".to_string(),
                0.1,
                format!(
                    "[Deterministic] False positive pattern detected for {}",
                    raw.id
                ),
            )
        } else if has_required_sanitizers {
            (
                "LOW_RISK".to_string(),
                0.3,
                format!(
                    "[Deterministic] Sanitizers detected in flow path: {:?}",
                    sanitizers_found
                ),
            )
        } else {
            (
                "CONFIRMED".to_string(),
                rule.confidence,
                format!(
                    "[Deterministic] High confidence violation. Flow path: {}",
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
            if snippet
                .to_lowercase()
                .contains(&sanitizer_name.to_lowercase())
            {
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
            "RUST_CORE_004_PATH_TRAVERSAL" => (
                "Resolve file path against base directory and verify containment".to_string(),
                "from pathlib import Path\ntarget = (Path(BASE_DIR) / filename).resolve()\nif not target.is_relative_to(Path(BASE_DIR).resolve()):\n    raise PermissionError('Path traversal detected')".to_string(),
            ),
            "RUST_CORE_005_SQL_INJECTION" => (
                "Use parameterized SQL queries with tuple parameter binding instead of string concatenation".to_string(),
                "cursor.execute(\"SELECT * FROM users WHERE id = ?\", (user_id,))".to_string(),
            ),
            "RUST_CORE_007_TEMPLATE_INJECTION" => (
                "Render template from static file with auto-escaping instead of dynamic string evaluation".to_string(),
                "from flask import render_template\nreturn render_template('profile.html', username=user_input)".to_string(),
            ),
            "RUST_CORE_008_INSECURE_DESERIALIZATION" => (
                "Replace unsafe pickle deserialization with structured JSON or SafeLoader".to_string(),
                "import json\ndata = json.loads(payload)".to_string(),
            ),
            "RUST_CORE_009_INSECURE_YAML" => (
                "Use yaml.safe_load() instead of yaml.load()".to_string(),
                "import yaml\nconfig = yaml.safe_load(raw_yaml)".to_string(),
            ),
            "HARDCODED_SECRET" => (
                "Extract credential to environment variables or secret manager".to_string(),
                "import os\napi_key = os.getenv('API_KEY')".to_string(),
            ),
            "TLS_VERIFY_DISABLED" => (
                "Enable strict TLS certificate validation".to_string(),
                "response = requests.get(url, verify=True)".to_string(),
            ),
            // Web3 / Solidity Fixes
            "HEU-001" => (
                "Remove selfdestruct or add 48h multi-sig timelock".to_string(),
                "// Remove selfdestruct or protect with timelock\nmodifier onlyTimelock() { require(msg.sender == timelockController, 'Not timelock'); _; }".to_string(),
            ),
            "HEU-002" => (
                "Guard delegatecall target with strict address allowlist".to_string(),
                "require(isAllowedImplementation[target], 'Untrusted target');\n(bool ok, ) = target.delegatecall(data);\nrequire(ok, 'Call failed');".to_string(),
            ),
            "HEU-003" => (
                "Replace tx.origin with msg.sender to prevent phishing attacks".to_string(),
                "require(msg.sender == owner, 'Unauthorized');".to_string(),
            ),
            "HEU-004" => (
                "Apply Checks-Effects-Interactions pattern and add nonReentrant modifier".to_string(),
                "balances[msg.sender] = 0;\n(bool ok, ) = msg.sender.call{value: amount}('');\nrequire(ok, 'Transfer failed');".to_string(),
            ),
            "HEU-010" => (
                "Explicitly verify the return boolean of low-level call()".to_string(),
                "(bool success, ) = recipient.call{value: amount}('');\nrequire(success, 'Transfer failed');".to_string(),
            ),
            _ => (
                "Apply strict input validation and defense-in-depth sanitization".to_string(),
                "# Ensure untrusted input is validated before use".to_string(),
            ),
        }
    }
}

impl Default for DeterministicValidator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_finding(id: &str, snippet: &str, flow_path: Vec<String>) -> Finding {
        Finding {
            id: id.to_string(),
            message: "Test vulnerability".to_string(),
            severity: "HIGH".to_string(),
            line: 42,
            snippet: snippet.to_string(),
            file_path: Some("src/main.rs".to_string()),
            flow_path,
            proof: None,
            immune_context: None,
        }
    }

    #[test]
    fn test_eval_confirmed_without_sanitizer() {
        let validator = DeterministicValidator::new();
        let f = dummy_finding("RUST_CORE_001_DANGEROUS_EVAL", "eval(user_input)", vec![]);
        let val = validator.validate_single(&f);
        assert_eq!(val.validation_status, "CONFIRMED");
        assert!(val.ai_confidence >= 0.9);
    }

    #[test]
    fn test_eval_rejected_for_ast_literal_eval() {
        let validator = DeterministicValidator::new();
        let f = dummy_finding(
            "RUST_CORE_001_DANGEROUS_EVAL",
            "ast.literal_eval(user_input)",
            vec![],
        );
        let val = validator.validate_single(&f);
        assert_eq!(val.validation_status, "REJECTED");
        assert!(val.ai_confidence <= 0.2);
    }

    #[test]
    fn test_path_traversal_low_risk_with_resolve() {
        let validator = DeterministicValidator::new();
        let f = dummy_finding(
            "RUST_CORE_004_PATH_TRAVERSAL",
            "Path(base).resolve() / user_file",
            vec!["Path.resolve".to_string()],
        );
        let val = validator.validate_single(&f);
        assert_eq!(val.validation_status, "LOW_RISK");
    }

    #[test]
    fn test_sql_injection_rejected_for_parameterized_query() {
        let validator = DeterministicValidator::new();
        let f = dummy_finding(
            "RUST_CORE_005_SQL_INJECTION",
            "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            vec![],
        );
        let val = validator.validate_single(&f);
        assert_eq!(val.validation_status, "REJECTED");
    }

    #[test]
    fn test_yaml_safe_load_rejected() {
        let validator = DeterministicValidator::new();
        let f = dummy_finding(
            "RUST_CORE_009_INSECURE_YAML",
            "yaml.safe_load(data)",
            vec![],
        );
        let val = validator.validate_single(&f);
        assert_eq!(val.validation_status, "REJECTED");
    }

    #[test]
    fn test_solidity_reentrancy_low_risk_with_guard() {
        let validator = DeterministicValidator::new();
        let f = dummy_finding(
            "HEU-004",
            "function withdraw() external nonReentrant {",
            vec!["nonReentrant".to_string()],
        );
        let val = validator.validate_single(&f);
        assert_eq!(val.validation_status, "LOW_RISK");
    }

    #[test]
    fn test_solidity_tx_origin_confirmed() {
        let validator = DeterministicValidator::new();
        let f = dummy_finding("HEU-003", "require(tx.origin == owner);", vec![]);
        let val = validator.validate_single(&f);
        assert_eq!(val.validation_status, "CONFIRMED");
        assert!(val.fix_code.as_ref().unwrap().contains("msg.sender"));
    }

    #[test]
    fn test_parallel_validation() {
        let validator = DeterministicValidator::new();
        let findings = vec![
            dummy_finding("RUST_CORE_001_DANGEROUS_EVAL", "eval(user_input)", vec![]),
            dummy_finding(
                "RUST_CORE_001_DANGEROUS_EVAL",
                "ast.literal_eval(payload)",
                vec![],
            ),
            dummy_finding(
                "HEU-004",
                "function withdraw() external nonReentrant {",
                vec!["nonReentrant".to_string()],
            ),
        ];
        let results = validator.validate_parallel(findings);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].validation_status, "CONFIRMED");
        assert_eq!(results[1].validation_status, "REJECTED");
        assert_eq!(results[2].validation_status, "LOW_RISK");
    }
}
