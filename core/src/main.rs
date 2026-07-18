use adversum_core::*;
use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: adversum_cli <file_path> <language>");
        std::process::exit(1);
    }

    let file_path = &args[1];
    let _language = &args[2];

    match fs::read(file_path) {
        Ok(content) => {
            // Pass None for ranges (full-file scan) — 3rd argument added
            match analyze_default(&content, Some(file_path.as_str()), None) {
                Ok(findings) => {
                    let result = AnalysisResult {
                        // map_finding_to_light converts Finding -> LightFinding
                        findings: findings.into_iter().map(map_finding_to_light).collect(),
                        file_hashes: std::collections::HashMap::new(),
                        robustness_score: 1.0,
                    };
                    match serde_json::to_string(&result) {
                        Ok(json) => println!("{}", json),
                        Err(e) => eprintln!("Error serializing result: {}", e),
                    }
                }
                Err(e) => eprintln!("Error analyzing file: {:?}", e),
            }
        },
        Err(e) => {
            eprintln!("Error reading file {}: {}", file_path, e);
        }
    }
}
