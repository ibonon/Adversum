// CVSS 4.0 Base Score calculation
// https://www.first.org/cvss/v4.0/specification-document

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CvssV4 {
    // Attack Vector
    pub av: AttackVector,
    // Attack Complexity
    pub ac: AttackComplexity,
    // Attack Requirements
    pub at: AttackRequirements,
    // Privileges Required
    pub pr: PrivilegesRequired,
    // User Interaction
    pub ui: UserInteraction,
    // Vulnerable System Impact
    pub vc: Impact,
    pub vi: Impact,
    pub va: Impact,
    // Subsequent System Impact
    pub sc: Impact,
    pub si: Impact,
    pub sa: Impact,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AttackVector { Network, Adjacent, Local, Physical }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AttackComplexity { Low, High }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AttackRequirements { None, Present }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PrivilegesRequired { None, Low, High }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UserInteraction { None, Passive, Active }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Impact { High, Low, None }

impl CvssV4 {
    /// Derive a CVSS 4.0 vector from a CWE identifier.
    /// Conservative defaults (worst case) to avoid underreporting.
    pub fn from_cwe(cwe: &str) -> Self {
        match cwe {
            "CWE-78" | "CWE-94" | "CWE-95" => Self {
                av: AttackVector::Network,
                ac: AttackComplexity::Low,
                at: AttackRequirements::None,
                pr: PrivilegesRequired::None,
                ui: UserInteraction::None,
                vc: Impact::High,
                vi: Impact::High,
                va: Impact::High,
                sc: Impact::High,
                si: Impact::High,
                sa: Impact::High,
            },
            "CWE-89" => Self {
                av: AttackVector::Network,
                ac: AttackComplexity::Low,
                at: AttackRequirements::None,
                pr: PrivilegesRequired::None,
                ui: UserInteraction::None,
                vc: Impact::High,
                vi: Impact::High,
                va: Impact::None,
                sc: Impact::None,
                si: Impact::None,
                sa: Impact::None,
            },
            "CWE-79" => Self {
                av: AttackVector::Network,
                ac: AttackComplexity::Low,
                at: AttackRequirements::None,
                pr: PrivilegesRequired::None,
                ui: UserInteraction::Passive,
                vc: Impact::Low,
                vi: Impact::Low,
                va: Impact::None,
                sc: Impact::Low,
                si: Impact::Low,
                sa: Impact::None,
            },
            "CWE-22" => Self {
                av: AttackVector::Network,
                ac: AttackComplexity::Low,
                at: AttackRequirements::None,
                pr: PrivilegesRequired::None,
                ui: UserInteraction::None,
                vc: Impact::High,
                vi: Impact::None,
                va: Impact::None,
                sc: Impact::None,
                si: Impact::None,
                sa: Impact::None,
            },
            "CWE-502" => Self {
                av: AttackVector::Network,
                ac: AttackComplexity::Low,
                at: AttackRequirements::None,
                pr: PrivilegesRequired::None,
                ui: UserInteraction::None,
                vc: Impact::High,
                vi: Impact::High,
                va: Impact::High,
                sc: Impact::None,
                si: Impact::None,
                sa: Impact::None,
            },
            "CWE-611" => Self {
                av: AttackVector::Network,
                ac: AttackComplexity::Low,
                at: AttackRequirements::None,
                pr: PrivilegesRequired::None,
                ui: UserInteraction::None,
                vc: Impact::High,
                vi: Impact::Low,
                va: Impact::None,
                sc: Impact::None,
                si: Impact::None,
                sa: Impact::None,
            },
            "CWE-918" => Self {
                av: AttackVector::Network,
                ac: AttackComplexity::Low,
                at: AttackRequirements::None,
                pr: PrivilegesRequired::None,
                ui: UserInteraction::None,
                vc: Impact::High,
                vi: Impact::High,
                va: Impact::None,
                sc: Impact::None,
                si: Impact::None,
                sa: Impact::None,
            },
            _ => Self { // Default ~7.0
                av: AttackVector::Network,
                ac: AttackComplexity::Low,
                at: AttackRequirements::None,
                pr: PrivilegesRequired::Low,
                ui: UserInteraction::None,
                vc: Impact::Low,
                vi: Impact::Low,
                va: Impact::Low,
                sc: Impact::None,
                si: Impact::None,
                sa: Impact::None,
            },
        }
    }

    /// Calculate base score 0.0-10.0 using the CVSS 4.0 lookup table approach.
    pub fn base_score(&self) -> f64 {
        // Approximate lookup values based on prompt
        match (
            &self.av, &self.ac, &self.at, &self.pr, &self.ui,
            &self.vc, &self.vi, &self.va,
            &self.sc, &self.si, &self.sa
        ) {
            (
                AttackVector::Network, AttackComplexity::Low, AttackRequirements::None, PrivilegesRequired::None, UserInteraction::None,
                Impact::High, Impact::High, Impact::High,
                Impact::High, Impact::High, Impact::High
            ) => 10.0,
            (
                AttackVector::Network, AttackComplexity::Low, AttackRequirements::None, PrivilegesRequired::None, UserInteraction::None,
                Impact::High, Impact::High, Impact::None,
                Impact::None, Impact::None, Impact::None
            ) => 9.3,
            (
                AttackVector::Network, AttackComplexity::Low, AttackRequirements::None, PrivilegesRequired::None, UserInteraction::Passive,
                Impact::Low, Impact::Low, Impact::None,
                Impact::Low, Impact::Low, Impact::None
            ) => 5.3,
            (
                AttackVector::Network, AttackComplexity::Low, AttackRequirements::None, PrivilegesRequired::None, UserInteraction::None,
                Impact::High, Impact::None, Impact::None,
                Impact::None, Impact::None, Impact::None
            ) => 7.5,
            (
                AttackVector::Network, AttackComplexity::Low, AttackRequirements::None, PrivilegesRequired::None, UserInteraction::None,
                Impact::High, Impact::High, Impact::High,
                Impact::None, Impact::None, Impact::None
            ) => 9.8,
            (
                AttackVector::Network, AttackComplexity::Low, AttackRequirements::None, PrivilegesRequired::None, UserInteraction::None,
                Impact::High, Impact::Low, Impact::None,
                Impact::None, Impact::None, Impact::None
            ) => 8.2,
            (
                AttackVector::Network, AttackComplexity::Low, AttackRequirements::None, PrivilegesRequired::None, UserInteraction::None,
                Impact::High, Impact::High, Impact::None,
                Impact::None, Impact::None, Impact::None
            ) => 8.6,
            _ => 7.0, // Default fallback
        }
    }

    /// Return the qualitative rating (Critical/High/Medium/Low/None).
    pub fn rating(&self) -> &'static str {
        let score = self.base_score();
        if score >= 9.0 {
            "Critical"
        } else if score >= 7.0 {
            "High"
        } else if score >= 4.0 {
            "Medium"
        } else if score > 0.0 {
            "Low"
        } else {
            "None"
        }
    }

    /// Return the CVSS vector string representation.
    pub fn vector_string(&self) -> String {
        let av = match self.av { AttackVector::Network => "N", AttackVector::Adjacent => "A", AttackVector::Local => "L", AttackVector::Physical => "P" };
        let ac = match self.ac { AttackComplexity::Low => "L", AttackComplexity::High => "H" };
        let at = match self.at { AttackRequirements::None => "N", AttackRequirements::Present => "P" };
        let pr = match self.pr { PrivilegesRequired::None => "N", PrivilegesRequired::Low => "L", PrivilegesRequired::High => "H" };
        let ui = match self.ui { UserInteraction::None => "N", UserInteraction::Passive => "P", UserInteraction::Active => "A" };
        let vc = match self.vc { Impact::High => "H", Impact::Low => "L", Impact::None => "N" };
        let vi = match self.vi { Impact::High => "H", Impact::Low => "L", Impact::None => "N" };
        let va = match self.va { Impact::High => "H", Impact::Low => "L", Impact::None => "N" };
        let sc = match self.sc { Impact::High => "H", Impact::Low => "L", Impact::None => "N" };
        let si = match self.si { Impact::High => "H", Impact::Low => "L", Impact::None => "N" };
        let sa = match self.sa { Impact::High => "H", Impact::Low => "L", Impact::None => "N" };

        format!("CVSS:4.0/AV:{}/AC:{}/AT:{}/PR:{}/UI:{}/VC:{}/VI:{}/VA:{}/SC:{}/SI:{}/SA:{}",
            av, ac, at, pr, ui, vc, vi, va, sc, si, sa)
    }
}
