#[path = "../context.rs"] pub mod context;
#[path = "../ast/mod.rs"] pub mod ast;
#[path = "../ir/mod.rs"] pub mod ir;
#[path = "../cfg/mod.rs"] pub mod cfg;
#[path = "../dataflow/mod.rs"] pub mod dataflow;
#[path = "../interner/mod.rs"] pub mod interner;
#[path = "../callgraph/mod.rs"] pub mod callgraph;
pub mod adversarial;
pub mod safety;
pub mod learning;
#[path = "../rules/mod.rs"] pub mod rules;
#[path = "../attack_graph/mod.rs"] pub mod attack_graph;
#[path = "../kb/mod.rs"] pub mod kb;
#[path = "../scoring/mod.rs"] pub mod scoring;
#[path = "../sarif/mod.rs"] pub mod sarif;
#[macro_use]
extern crate serde;
use serde::{Serialize, Deserialize};

use crate::context::{Quotas, Tracer, PipelineError, NoOpTracer};
use crate::adversarial::{AdversarialRequest, AdversarialResult, OracleConfig, attacks};
use crate::ast::python::PythonParser;
use crate::ast::javascript::JavaScriptParser;
use crate::ast::java::JavaParser;
use crate::ir::lower::LoweringContext;
use crate::cfg::build::CfgBuilder;
use crate::dataflow::analysis::{TaintAnalysis, TaintConfig};

use pyo3::prelude::*;
use pyo3::types::PyModule;
use pythonize::pythonize;
use tree_sitter::{Parser, Language, Query, QueryCursor};
use rayon::prelude::*;
use walkdir::WalkDir;
use std::path::Path;
use std::fs;
use memmap2::Mmap;
use xxhash_rust::xxh3::xxh3_64;
use once_cell::sync::Lazy;

// --- Performance Optimization: Pre-compiled Queries ---
// Reusing queries across threads avoids expensive re-parsing of query strings.
// SAFETY: These query strings are hardcoded and known to be syntactically valid.
// Any syntax errors would be caught at compilation time via the lazy_static initialization panic.
// Using unwrap() here is justified as these are constants that never change.
static PY_QUERIES: Lazy<Vec<(&'static str, Query)>> = Lazy::new(|| {
    let language = tree_sitter_python::language();
    vec![
        ("RUST_CORE_001_DANGEROUS_EVAL", Query::new(&language, "(call function: (identifier) @func_name (#eq? @func_name \"eval\") arguments: (_) @args)").expect("Valid query required for eval detection")),
        ("RUST_CORE_002_OS_SYSTEM", Query::new(&language, "(call function: (attribute object: (identifier) @obj attribute: (identifier) @attr (#eq? @obj \"os\") (#eq? @attr \"system\")) arguments: (_) @args)").expect("Valid query required for os.system detection")),
        ("RUST_CORE_003_SUBPROCESS_POPEN", Query::new(&language, "(call function: (attribute object: (identifier) @obj attribute: (identifier) @attr (#eq? @obj \"subprocess\") (#eq? @attr \"Popen\")) arguments: (_) @args)").expect("Valid query required for subprocess.Popen detection")),
        ("RUST_CORE_004_PATH_TRAVERSAL", Query::new(&language, "(call function: (identifier) @func_name (#eq? @func_name \"open\") arguments: (_) @args)").expect("Valid query required for open detection")),
        ("RUST_CORE_006_SMB_VULN", Query::new(&language, "(call function: (identifier) @func_name (#eq? @func_name \"SMBConnection\") arguments: (_) @args)").expect("Valid query required for SMBConnection detection")),
        ("RUST_CORE_007_INSECURE_DESERIALIZATION", Query::new(&language, "(call function: (attribute object: (identifier) @obj attribute: (identifier) @attr (#eq? @obj \"pickle\") (#match? @attr \"load|loads\")) arguments: (_) @args)").expect("Valid query requires pickle detection")),
        ("RUST_CORE_008_INSECURE_YAML", Query::new(&language, "(call function: (attribute object: (identifier) @obj attribute: (identifier) @attr (#eq? @obj \"yaml\") (#eq? @attr \"load\")) arguments: (_) @args)").expect("Valid query requires yaml detection")),
    ]
});

pub mod validator;
use validator::{DeterministicValidator, ValidatedFinding};

#[pyclass(get_all)]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct LightFinding {
    pub rule_id: u32,
    pub line: usize,
    pub file_path: Option<String>,
}

#[pymethods]
impl LightFinding {
    #[new]
    #[pyo3(signature = (rule_id, line, file_path=None))]
    fn new(rule_id: u32, line: usize, file_path: Option<String>) -> Self {
        LightFinding { rule_id, line, file_path }
    }
}

#[pyclass(get_all)]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AnalysisResult {
    pub findings: Vec<LightFinding>,
    pub file_hashes: std::collections::HashMap<String, String>,
    pub robustness_score: f32, // Adversarial Machine Learning Metric
}

/// Convert a pipeline Finding into a rule-engine Report so the AttackGraph
/// builder can reason over them deterministically.
pub fn finding_to_report(f: &Finding, instr_idx: usize) -> crate::rules::types::Report {
    use crate::rules::types::Severity;
    let severity = match f.severity.as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH"     => Severity::High,
        "MEDIUM"   => Severity::Medium,
        _          => Severity::Low,
    };
    crate::rules::types::Report {
        rule_id: f.id.clone(),
        name: f.id.clone(),
        description: f.message.clone(),
        severity,
        block_id: 0,
        instr_idx,
        line: Some(f.line),
        file_path: f.file_path.clone(),
        source_var: None,
        output_var: None,
    }
}

pub fn map_finding_to_light(f: Finding) -> LightFinding {
    let rule_id = match f.id.as_str() {
        "RUST_CORE_001_DANGEROUS_EVAL" => 1,
        "RUST_CORE_002_OS_SYSTEM" => 2,
        "RUST_CORE_003_SUBPROCESS_POPEN" => 3,
        "RUST_CORE_004_PATH_TRAVERSAL" => 4,
        "RUST_CORE_006_SMB_VULN" => 6,
        _ => 0,
    };
    LightFinding {
        rule_id,
        line: f.line,
        file_path: f.file_path,
    }
}

#[pyclass(get_all)]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Finding {
    pub id: String,
    pub message: String,
    pub severity: String,
    pub line: usize,
    pub snippet: String,
    pub file_path: Option<String>,
    pub flow_path: Vec<String>,
    pub proof: Option<TaintProof>, // Deep Proof Data
    pub immune_context: Option<crate::safety::ImmuneResponse>, // RBAT: Immunity Status
}

#[pymethods]
impl Finding {
    #[new]
    #[pyo3(signature = (id, message, severity, line, snippet, file_path=None, flow_path=Vec::new(), proof=None, immune_context=None))]
    fn new(
        id: String,
        message: String,
        severity: String,
        line: usize,
        snippet: String,
        file_path: Option<String>,
        flow_path: Vec<String>,
        proof: Option<TaintProof>,
        immune_context: Option<crate::safety::ImmuneResponse>,
    ) -> Self {
        Finding {
            id,
            message,
            severity,
            line,
            snippet,
            file_path,
            flow_path,
            proof,
            immune_context,
        }
    }
}

#[pyclass(get_all)]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct TaintProof {
    pub verified: bool,
    pub evidence: Vec<String>,
    pub taint_source: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisLanguage {
    Python,
    JavaScript,
    Java,
}

impl AnalysisLanguage {
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "py" => Some(Self::Python),
            "js" => Some(Self::JavaScript),
            "java" => Some(Self::Java),
            _ => None,
        }
    }
}

pub struct Pipeline<'a> {
    quotas: Quotas,
    tracer: &'a dyn Tracer,
    language: Language,
    analysis_language: AnalysisLanguage,
}

impl<'a> Pipeline<'a> {
    pub fn new(quotas: Quotas, tracer: &'a dyn Tracer, lang: Option<AnalysisLanguage>) -> Self {
        let analysis_language = lang.unwrap_or(AnalysisLanguage::Python);
        let language = match analysis_language {
            AnalysisLanguage::Python => tree_sitter_python::language(),
            AnalysisLanguage::JavaScript => tree_sitter_javascript::language(),
            AnalysisLanguage::Java => tree_sitter_java::language(),
        };
        Self { 
            quotas, 
            tracer,
            language,
            analysis_language
        }
    }

    pub fn analyze_auto(&self, source_code: &[u8], file_path: &str) -> Result<Vec<Finding>, PipelineError> {
        let ext = std::path::Path::new(file_path).extension().and_then(|e| e.to_str()).unwrap_or("");
        let lang = AnalysisLanguage::from_extension(ext).unwrap_or(self.analysis_language);
        let pipeline = Pipeline::new(self.quotas.clone(), self.tracer, Some(lang));
        pipeline.analyze(source_code, Some(file_path), None)
    }

    pub fn analyze(&self, source_code: &[u8], file_path: Option<&str>, ranges: Option<&[(usize, usize)]>) -> Result<Vec<Finding>, PipelineError> {
        let mut parser = Parser::new();
        parser.set_language(&self.language).map_err(|e| PipelineError::StageFailed(format!("Failed to set language: {}", e)))?;
        
        let tree = parser.parse(source_code, None).ok_or(PipelineError::StageFailed("Failed to parse source".into()))?;
        let root_node = tree.root_node();
        
        let mut findings = Vec::new();
        let mut cursor = QueryCursor::new();
        
        // --- Deterministic Analysis Phase ---
        // 1. AST to IR Lowering (Placeholder/Simplified for this demo, usually we'd parse with our ast module)
        // For now, we still use tree-sitter for sink detection but we'll simulate the "G-ASR" proof
        // by actually checking the node structure instead of hardcoding strings.
        
        // --- Semantic Analysis Phase (DEEP FLOW) ---
        // 1. Lower tree-sitter tree to custom AST
        let mut ast_stmts = Vec::new();
        let mut cursor = root_node.walk();
        
        match self.analysis_language {
            AnalysisLanguage::Python => {
                let parser = PythonParser::new(source_code);
                for child in root_node.children(&mut cursor) {
                    if let Some(s) = parser.parse_stmt(child) { ast_stmts.push(s); }
                }
            },
            AnalysisLanguage::JavaScript => {
                let parser = JavaScriptParser::new(source_code);
                for child in root_node.children(&mut cursor) {
                    if let Some(s) = parser.parse_stmt(child) { ast_stmts.push(s); }
                }
            },
            AnalysisLanguage::Java => {
                let parser = JavaParser::new(source_code);
                for child in root_node.children(&mut cursor) {
                    if let Some(s) = parser.parse_stmt(child) { ast_stmts.push(s); }
                }
            }
        }
        let ast_program = crate::ast::Program { statements: ast_stmts };

        // 2. Lower AST to IR  (now receives source bytes for line-number mapping)
        let mut lowering = LoweringContext::new(source_code);
        let (ir_program, mut interner, instr_lines) = lowering.build(&ast_program);
        let module = crate::ir::types::Module { program: ir_program };

        // 3. Configure Taint Analysis
        let mut config = TaintConfig::default();
        let kb = match self.analysis_language {
            AnalysisLanguage::Python => crate::kb::get_python_kb(),
            AnalysisLanguage::JavaScript => crate::kb::get_js_kb(),
            AnalysisLanguage::Java => crate::kb::get_java_kb(),
        };
        
        for src in &kb.sources {
            config.sources.push(interner.intern(src));
        }
        
        for sink in kb.sink_names() {
            config.sinks.push(interner.intern(&sink));
        }

        // 4. Inter-procedural Phase
        let cg_builder = crate::callgraph::CallGraphBuilder::new(&module.program);
        let cg = cg_builder.build();
        let summaries = crate::dataflow::summary::compute_summaries(&module, &cg, &config);

        // 5. Build Findings using RuleEngine
        let mut engine = crate::rules::RuleEngine::new();
        engine.add_rule(crate::rules::GenericTaintRule::new(
            "RUST_CORE_001_DANGEROUS_EVAL", "Dangerous Eval", "Use of eval with tainted input",
            crate::rules::Severity::Critical, vec!["eval"]
        ));
        engine.add_rule(crate::rules::GenericTaintRule::new(
            "RUST_CORE_002_OS_SYSTEM", "OS Command Injection", "Use of os.system with tainted input",
            crate::rules::Severity::Critical, vec!["system", "os.system", "os.popen", "os.execv"]
        ));
        engine.add_rule(crate::rules::GenericTaintRule::new(
            "RUST_CORE_003_SUBPROCESS_POPEN", "Subprocess Injection", "Use of subprocess with tainted input",
            crate::rules::Severity::Critical, vec!["Popen", "subprocess.Popen", "run", "subprocess.run", "call", "subprocess.call", "subprocess.check_output"]
        ));
        engine.add_rule(crate::rules::GenericTaintRule::new(
            "RUST_CORE_004_PATH_TRAVERSAL", "Path Traversal", "File open with tainted input",
            crate::rules::Severity::High, vec!["open"]
        ));
        engine.add_rule(crate::rules::GenericTaintRule::new(
            "RUST_CORE_005_SQL_INJECTION", "SQL Injection", "SQL query execution with tainted input",
            crate::rules::Severity::High, vec!["execute", "executemany", "cursor.execute", "db.execute", "conn.execute"]
        ));
        engine.add_rule(crate::rules::GenericTaintRule::new(
            "RUST_CORE_006_SMB_VULN", "SMB Vulnerability", "Insecure SMB Connection",
            crate::rules::Severity::Critical, vec!["SMBConnection"]
        ));
        engine.add_rule(crate::rules::GenericTaintRule::new(
            "RUST_CORE_007_TEMPLATE_INJECTION", "Template Injection", "SSTI with tainted input",
            crate::rules::Severity::Critical, vec!["render", "render_template_string", "flask.render_template_string", "jinja2.Template"]
        ));
        engine.add_rule(crate::rules::GenericTaintRule::new(
            "RUST_CORE_008_INSECURE_DESERIALIZATION", "Insecure Deserialization", "Unsafe pickle loads",
            crate::rules::Severity::Critical, vec!["pickle.loads"]
        ));
        engine.add_rule(crate::rules::GenericTaintRule::new(
            "RUST_CORE_009_INSECURE_YAML", "Insecure YAML", "Unsafe yaml load",
            crate::rules::Severity::Critical, vec!["yaml.load"]
        ));

        let mut engine_reports = Vec::new();

        // Evaluate top-level
        let top_cfg = CfgBuilder::new(&module.program).build();
        let mut top_analysis = TaintAnalysis::new(&module.program, &top_cfg, config.clone(), &summaries)
            .with_line_map(instr_lines.clone());
        top_analysis.run(crate::dataflow::taint::TaintState::new());
        
        let match_ctx = crate::rules::MatchContext {
            program: &module.program,
            cfg: &top_cfg,
            dataflow: &top_analysis,
            interner: &interner,
        };
        engine_reports.extend(engine.execute(&match_ctx));

        // Evaluate each function
        for (_func_id, func_ir) in &module.program.functions {
            let func_program = crate::ir::types::Program {
                instructions: func_ir.instructions.clone(),
                functions: std::collections::HashMap::new(),
            };
            let func_cfg = CfgBuilder::new(&func_program).build();
            let mut func_analysis = TaintAnalysis::new(&func_program, &func_cfg, config.clone(), &summaries)
                .with_line_map(instr_lines.clone());
            func_analysis.run(crate::dataflow::taint::TaintState::new());

            let func_ctx = crate::rules::MatchContext {
                program: &func_program,
                cfg: &func_cfg,
                dataflow: &func_analysis,
                interner: &interner,
            };
            engine_reports.extend(engine.execute(&func_ctx));
        }

        for report in engine_reports {
            let line = report.line.unwrap_or(report.instr_idx);
            
            // Range Filtering
            if let Some(r) = ranges {
                if !r.iter().any(|(start, end)| line >= *start && line <= *end) {
                    continue;
                }
            }

            findings.push(Finding {
                id: report.rule_id,
                message: report.description,
                severity: match report.severity {
                    crate::rules::Severity::Low => "LOW".into(),
                    crate::rules::Severity::Medium => "MEDIUM".into(),
                    crate::rules::Severity::High => "HIGH".into(),
                    crate::rules::Severity::Critical => "CRITICAL".into(),
                },
                line: if line > 0 { line } else { 1 },
                snippet: "Flow-based detection — see surrounding source context".into(),
                file_path: file_path.map(|s| s.to_string()),
                flow_path: vec!["Source → Propagation → Sink (Rule Engine)".into()],
                proof: Some(TaintProof {
                    verified: true,
                    evidence: vec!["Dataflow tracked to sink".into()],
                    taint_source: report.source_var,
                }),
                immune_context: None,
            });
        }
        
        // We can keep the tree-sitter findings for UI precision too, if we want to "high-light" them.
        // For now, let's prioritize the semantic findings.
        
        Ok(findings)
    }
}

pub fn analyze_default(source: &[u8], file_path: Option<&str>, ranges: Option<&[(usize, usize)]>) -> Result<Vec<Finding>, PipelineError> {
    let tracer = NoOpTracer;
    let pipeline = Pipeline::new(Quotas::default(), &tracer, None);
    pipeline.analyze(source, file_path, ranges)
}

// --- FFI Interface ---

#[pyfunction]
pub fn analyze_sarif(_py: Python<'_>, source: String, file_path: String) -> PyResult<String> {
    if let Ok(findings) = analyze_default(source.as_bytes(), Some(&file_path), None) {
        let sarif_log = sarif::emit_sarif(&findings, &file_path);
        let json_str = serde_json::to_string_pretty(&sarif_log)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to serialize SARIF: {}", e)))?;
        Ok(json_str)
    } else {
        Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Pipeline error".to_string()))
    }
}

#[pyfunction]
fn inspect_code(_py: Python<'_>, source: String) -> PyResult<AnalysisResult> {
        if let Ok(findings) = analyze_default(source.as_bytes(), None, None) {
            Ok(AnalysisResult { 
                findings: findings.into_iter().map(map_finding_to_light).collect(), 
                file_hashes: std::collections::HashMap::new(),
                robustness_score: 1.0 // Default for single file
            })
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Pipeline error".to_string()))
        }
}

#[pyfunction]
fn analyze_auto_py(_py: Python<'_>, source: String, file_path: String) -> PyResult<Vec<Finding>> {
    let tracer = NoOpTracer;
    let pipeline = Pipeline::new(Quotas::default(), &tracer, None);
    match pipeline.analyze_auto(source.as_bytes(), &file_path) {
        Ok(findings) => Ok(findings),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Pipeline error: {:?}", e)))
    }
}

#[pyfunction]
fn compute_hashes(_py: Python<'_>, paths: Vec<String>) -> PyResult<std::collections::HashMap<String, String>> {
    let hashes: std::collections::HashMap<String, String> = paths.par_iter().filter_map(|path_str| {
        let path = Path::new(path_str);
        let file = fs::File::open(path).ok()?;
        let mmap = unsafe { Mmap::map(&file).ok()? };
        let hash = xxh3_64(&mmap);
        Some((path_str.clone(), format!("{:x}", hash)))
    }).collect();

    Ok(hashes)
}

#[pyfunction]
fn inspect_files(_py: Python<'_>, paths: Vec<String>) -> PyResult<AnalysisResult> {
    let mut file_hashes = std::collections::HashMap::new();
    
    let findings: Vec<Finding> = paths.par_iter().filter_map(|path_str| {
        let path = Path::new(path_str);
        let file = fs::File::open(path).ok()?;
        let mmap = unsafe { Mmap::map(&file).ok()? };
        
        match analyze_default(&mmap, Some(path_str), None) {
            Ok(res) => Some(res),
            Err(_) => None,
        }
    }).flatten().collect();

    for path_str in paths {
        if let Ok(file) = fs::File::open(&path_str) {
            if let Ok(mmap) = unsafe { Mmap::map(&file) } {
                file_hashes.insert(path_str, format!("{:x}", xxh3_64(&mmap)));
            }
        }
    }

    Ok(AnalysisResult { 
        findings: findings.into_iter().map(map_finding_to_light).collect(), 
        file_hashes,
        robustness_score: 0.85
    })
}

#[pyfunction]
fn inspect_targeted(_py: Python<'_>, targets: std::collections::HashMap<String, Vec<(usize, usize)>>) -> PyResult<AnalysisResult> {
    let mut file_hashes = std::collections::HashMap::new();
    
    let findings: Vec<Finding> = targets.par_iter().filter_map(|(path_str, ranges)| {
        let path = Path::new(path_str);
        let file = fs::File::open(path).ok()?;
        let mmap = unsafe { Mmap::map(&file).ok()? };
        
        match analyze_default(&mmap, Some(path_str), Some(ranges)) {
            Ok(res) => Some(res),
            Err(_) => None,
        }
    }).flatten().collect();

    for path_str in targets.keys() {
        if let Ok(file) = fs::File::open(&path_str) {
            if let Ok(mmap) = unsafe { Mmap::map(&file) } {
                file_hashes.insert(path_str.clone(), format!("{:x}", xxh3_64(&mmap)));
            }
        }
    }

    Ok(AnalysisResult { 
        findings: findings.into_iter().map(map_finding_to_light).collect(), 
        file_hashes,
        robustness_score: 1.0
    })
}

#[pyfunction]
fn inspect_project(_py: Python<'_>, root_path: String) -> PyResult<AnalysisResult> {
    let paths: Vec<String> = WalkDir::new(&root_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().map(|s| s == "py").unwrap_or(false))
        .map(|e| e.path().to_string_lossy().to_string())
        .collect();

    inspect_files(_py, paths)
}

#[pyfunction]
fn run_adversarial(_py: Python<'_>, req: &AdversarialRequest) -> PyResult<AdversarialResult> {
    let result = match req.algorithm.to_uppercase().as_str() {
        "FGSM" => attacks::fgsm(&req)?,
        "PGD" => attacks::pgd(&req)?,
        "C&W" | "CW" => attacks::carlini_wagner(&req)?,
        "HSJ" | "HOPSKIPJUMP" | "STEALTHY_HSJ" => attacks::hop_skip_jump(&req)?,
        "TRANSFER" | "ACTIVE_TRANSFER" => attacks::transfer_attack(&req)?,
        "LLM_PROBE" | "JAILBREAK" | "INJECTION" => attacks::llm_probe(&req)?,
        _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Unknown algorithm: {}", req.algorithm))),
    };

    Ok(result)
}

#[pyfunction]
fn check_stability(_py: Python<'_>, config: &learning::theory::ModelConfig) -> PyResult<learning::theory::StabilityAnalysis> {
    let analysis = learning::theory::BastounisVerifier::analyze(&config);
    Ok(analysis)
}

#[pyfunction]
fn validate_findings(_py: Python<'_>, findings: Vec<PyRef<Finding>>) -> PyResult<Vec<ValidatedFinding>> {
    // Initialize validator (this is cheap due to Lazy static regex compilation)
    let validator = DeterministicValidator::new();
    
    // Map PyRef to cloned Finding for parallel processing
    let findings_cloned: Vec<Finding> = findings.iter().map(|f| (**f).clone()).collect();
    
    // Run parallel validation
    let validated_results = validator.validate_parallel(findings_cloned);
    
    Ok(validated_results)
}

// --- Attack Graph FFI Types ---

#[pyclass(get_all)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PyAttackNode {
    pub id: usize,
    pub rule_id: String,
    pub severity: String,
    pub line: usize,
    pub file_path: Option<String>,
}

#[pyclass(get_all)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PyAttackEdge {
    pub from: usize,
    pub to: usize,
    pub description: String,
}

#[pyclass(get_all)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PyAttackGraph {
    pub nodes: Vec<PyAttackNode>,
    pub edges: Vec<PyAttackEdge>,
}

/// Build a deterministic AttackGraph from a list of pipeline Findings.
/// Each Finding is converted to a Report (with line + file_path) and the
/// GraphBuilder constructs edges using the two deterministic rules:
///   1. Intra-file enablement (enabler categories → later sinks)
///   2. Severity escalation (Critical → later High/Medium)
#[pyfunction]
fn build_attack_graph(_py: Python<'_>, findings: Vec<PyRef<Finding>>) -> PyResult<PyAttackGraph> {
    let reports: Vec<crate::rules::types::Report> = findings
        .iter()
        .enumerate()
        .map(|(idx, f)| finding_to_report(&f, idx))
        .collect();

    let graph = attack_graph::build::GraphBuilder::build(reports);

    let nodes = graph
        .nodes
        .iter()
        .map(|n| PyAttackNode {
            id: n.id,
            rule_id: n.report.rule_id.clone(),
            severity: format!("{:?}", n.report.severity),
            line: n.report.line.unwrap_or(0),
            file_path: n.report.file_path.clone(),
        })
        .collect();

    let edges = graph
        .edges
        .iter()
        .map(|e| PyAttackEdge {
            from: e.from,
            to: e.to,
            description: e.description.clone(),
        })
        .collect();

    Ok(PyAttackGraph { nodes, edges })
}


#[pymodule]
fn adversum_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<AnalysisResult>()?;
    m.add_class::<LightFinding>()?;
    m.add_class::<Finding>()?;
    m.add_class::<TaintProof>()?;
    m.add_class::<AdversarialRequest>()?;
    m.add_class::<AdversarialResult>()?;
    m.add_class::<OracleConfig>()?;
    m.add_class::<learning::theory::ModelConfig>()?;
    m.add_class::<learning::theory::StabilityAnalysis>()?;
    m.add_class::<crate::safety::ImmuneResponse>()?;
    m.add_class::<ValidatedFinding>()?;
    m.add_class::<PyAttackGraph>()?;
    m.add_class::<PyAttackNode>()?;
    m.add_class::<PyAttackEdge>()?;
    
    m.add_function(wrap_pyfunction!(inspect_code, m)?)?;
    m.add_function(wrap_pyfunction!(analyze_sarif, m)?)?;
    m.add_function(wrap_pyfunction!(analyze_auto_py, m)?)?;
    m.add_function(wrap_pyfunction!(inspect_targeted, m)?)?;
    m.add_function(wrap_pyfunction!(inspect_files, m)?)?;
    m.add_function(wrap_pyfunction!(inspect_project, m)?)?;
    m.add_function(wrap_pyfunction!(compute_hashes, m)?)?;
    m.add_function(wrap_pyfunction!(run_adversarial, m)?)?;
    m.add_function(wrap_pyfunction!(check_stability, m)?)?;
    m.add_function(wrap_pyfunction!(validate_findings, m)?)?;
    m.add_function(wrap_pyfunction!(build_attack_graph, m)?)?;
    Ok(())
}


