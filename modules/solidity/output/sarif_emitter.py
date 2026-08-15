def to_sarif(findings: list) -> dict:
    runs = []
    
    # Process findings into SARIF results
    results = []
    for f in findings:
        result = {
            "ruleId": f.rule_id,
            "level": "error" if f.severity in ["CRITICAL", "HIGH"] else "warning",
            "message": {
                "text": f"{f.title}: {f.description}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file
                        },
                        "region": {
                            "startLine": f.line,
                            "snippet": {
                                "text": f.snippet
                            }
                        }
                    }
                }
            ],
            "properties": {
                "cvssScore": f.cvss_score,
                "cwe": f.cwe,
                "swc": f.swc,
                "recommendation": f.recommendation
            }
        }
        results.append(result)
        
    run = {
        "tool": {
            "driver": {
                "name": "Adversum Solidity Scanner",
                "version": "1.0.0",
                "informationUri": "https://alphanex.local/sast"
            }
        },
        "results": results
    }
    runs.append(run)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs
    }
