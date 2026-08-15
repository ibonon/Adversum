use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct SinkEntry {
    pub name: String,
    pub cwe: String,
    pub severity: String,
}

#[derive(Debug, Deserialize)]
pub struct SanitizerEntry {
    pub name: String,
    pub clears: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum SinkOrString {
    Full(SinkEntry),
    Short(String),
}

#[derive(Debug, Deserialize)]
pub struct KbFile {
    pub language: String,
    pub sources: Vec<String>,
    pub sinks: Vec<SinkOrString>,
    #[serde(default)]
    pub sanitizers: Vec<SanitizerEntry>,
}

impl KbFile {
    pub fn sink_names(&self) -> Vec<String> {
        self.sinks.iter().map(|s| match s {
            SinkOrString::Full(e) => e.name.clone(),
            SinkOrString::Short(s) => s.clone(),
        }).collect()
    }
    
    pub fn cwe_map(&self) -> HashMap<String, String> {
        self.sinks.iter().filter_map(|s| match s {
            SinkOrString::Full(e) => Some((e.name.clone(), e.cwe.clone())),
            _ => None,
        }).collect()
    }
}

pub fn load_kb(json_str: &str) -> Result<KbFile, serde_json::Error> {
    serde_json::from_str(json_str)
}

// Embedded KB files at compile time
pub const PYTHON_KB: &str = include_str!("../../knowledge/taint/python_sinks.json");
pub const JS_KB: &str = include_str!("../../knowledge/taint/sources_js.json");
pub const JAVA_KB: &str = include_str!("../../knowledge/taint/sources_java.json");

pub fn get_python_kb() -> KbFile { load_kb(PYTHON_KB).expect("Invalid Python KB JSON") }
pub fn get_js_kb() -> KbFile { load_kb(JS_KB).expect("Invalid JS KB JSON") }
pub fn get_java_kb() -> KbFile { load_kb(JAVA_KB).expect("Invalid Java KB JSON") }
