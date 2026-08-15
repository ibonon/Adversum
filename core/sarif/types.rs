use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Serialize, Deserialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
    pub artifacts: Vec<SarifArtifact>,
}

#[derive(Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifToolComponent,
}

#[derive(Serialize, Deserialize)]
pub struct SarifToolComponent {
    pub name: String,
    pub version: String,
    pub rules: Vec<SarifRule>,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
}

#[derive(Serialize, Deserialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    pub properties: SarifRuleProperties,
}

#[derive(Serialize, Deserialize)]
pub struct SarifRuleProperties {
    pub tags: Vec<String>,
    pub precision: String,
    #[serde(rename = "problem.severity")]
    pub problem_severity: String,
    pub cwe: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    #[serde(rename = "codeFlows", skip_serializing_if = "Vec::is_empty")]
    pub code_flows: Vec<SarifCodeFlow>,
    pub properties: SarifResultProperties,
}

#[derive(Serialize, Deserialize)]
pub struct SarifResultProperties {
    pub severity: String,
    #[serde(rename = "cvssScore")]
    pub cvss_score: f64,
    #[serde(rename = "cvssVector")]
    pub cvss_vector: String,
    pub cwe: String,
}

#[derive(Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Serialize, Deserialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Serialize, Deserialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
    pub index: usize,
}

#[derive(Serialize, Deserialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: usize,
}

#[derive(Serialize, Deserialize)]
pub struct SarifArtifact {
    pub location: SarifArtifactLocation,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
}

#[derive(Serialize, Deserialize)]
pub struct SarifCodeFlow {
    #[serde(rename = "threadFlows")]
    pub thread_flows: Vec<SarifThreadFlow>,
}

#[derive(Serialize, Deserialize)]
pub struct SarifThreadFlow {
    pub locations: Vec<SarifThreadFlowLocation>,
}

#[derive(Serialize, Deserialize)]
pub struct SarifThreadFlowLocation {
    pub location: SarifLocation,
    pub state: std::collections::HashMap<String, String>,
}
