use super::*;
use super::attacks::*;
use ndarray::{ArrayD, IxDyn};

// ============================================================================
// FGSM Tests
// ============================================================================

#[test]
fn test_fgsm_basic_functionality() {
    let input_data = vec![0.5, 0.5, 0.5, 0.5];
    let req = AdversarialRequest {
        algorithm: "FGSM".to_string(),
        input_data: input_data.clone(),
        shape: vec![2, 2],
        target_class: Some(1),
        epsilon: 0.1,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: None,
    };

    let result = fgsm(&req);
    
    assert_eq!(result.algorithm, "FGSM");
    assert!(result.success);
    assert_eq!(result.perturbed_data.len(), input_data.len());
    assert_eq!(result.perturbation_norm, 0.1);
}

#[test]
fn test_fgsm_perturbation_direction() {
    let input_data = vec![0.5, -0.3, 0.8, -0.1];
    let epsilon = 0.2;
    let req = AdversarialRequest {
        algorithm: "FGSM".to_string(),
        input_data: input_data.clone(),
        shape: vec![4],
        target_class: None,
        epsilon,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: None,
    };

    let result = fgsm(&req);
    
    // Verify perturbation is applied in the correct direction
    for (i, &original) in input_data.iter().enumerate() {
        let perturbed = result.perturbed_data[i];
        if original >= 0.0 {
            assert!((perturbed - (original + epsilon)).abs() < 1e-5);
        } else {
            assert!((perturbed - (original - epsilon)).abs() < 1e-5);
        }
    }
}

#[test]
fn test_fgsm_zero_epsilon() {
    let input_data = vec![0.5, 0.5, 0.5, 0.5];
    let req = AdversarialRequest {
        algorithm: "FGSM".to_string(),
        input_data: input_data.clone(),
        shape: vec![2, 2],
        target_class: None,
        epsilon: 0.0,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: None,
    };

    let result = fgsm(&req);
    
    // With zero epsilon, output should equal input
    assert_eq!(result.perturbed_data, input_data);
    assert_eq!(result.perturbation_norm, 0.0);
}

#[test]
fn test_fgsm_large_epsilon() {
    let input_data = vec![0.5, 0.5, 0.5, 0.5];
    let epsilon = 10.0;
    let req = AdversarialRequest {
        algorithm: "FGSM".to_string(),
        input_data: input_data.clone(),
        shape: vec![2, 2],
        target_class: None,
        epsilon,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: None,
    };

    let result = fgsm(&req);
    
    assert!(result.success);
    assert_eq!(result.perturbation_norm, epsilon);
}

// ============================================================================
// PGD Tests
// ============================================================================

#[test]
fn test_pgd_basic_functionality() {
    let input_data = vec![0.5, 0.5, 0.5, 0.5];
    let epsilon = 0.1;
    let req = AdversarialRequest {
        algorithm: "PGD".to_string(),
        input_data: input_data.clone(),
        shape: vec![2, 2],
        target_class: Some(1),
        epsilon,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: None,
    };

    let result = pgd(&req);
    
    assert_eq!(result.algorithm, "PGD");
    assert!(result.success);
    assert_eq!(result.perturbed_data.len(), input_data.len());
}

#[test]
fn test_pgd_epsilon_ball_projection() {
    let input_data = vec![0.5, 0.5, 0.5, 0.5];
    let epsilon = 0.1;
    let req = AdversarialRequest {
        algorithm: "PGD".to_string(),
        input_data: input_data.clone(),
        shape: vec![2, 2],
        target_class: None,
        epsilon,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: None,
    };

    let result = pgd(&req);
    
    // Verify all perturbed values stay within epsilon ball
    for (i, &original) in input_data.iter().enumerate() {
        let perturbed = result.perturbed_data[i];
        let diff = (perturbed - original).abs();
        assert!(diff <= epsilon + 1e-5, "Perturbation {} exceeds epsilon {}", diff, epsilon);
    }
}

#[test]
fn test_pgd_valid_range_constraint() {
    let input_data = vec![0.1, 0.9, 0.5, 0.2];
    let epsilon = 0.5;
    let req = AdversarialRequest {
        algorithm: "PGD".to_string(),
        input_data: input_data.clone(),
        shape: vec![4],
        target_class: None,
        epsilon,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: None,
    };

    let result = pgd(&req);
    
    // Verify all values stay in [0, 1]
    for &val in &result.perturbed_data {
        assert!(val >= 0.0 && val <= 1.0, "Value {} out of range [0, 1]", val);
    }
}

#[test]
fn test_pgd_zero_epsilon() {
    let input_data = vec![0.5, 0.5, 0.5, 0.5];
    let req = AdversarialRequest {
        algorithm: "PGD".to_string(),
        input_data: input_data.clone(),
        shape: vec![2, 2],
        target_class: None,
        epsilon: 0.0,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: None,
    };

    let result = pgd(&req);
    
    // With zero epsilon, output should equal input
    for (i, &original) in input_data.iter().enumerate() {
        assert!((result.perturbed_data[i] - original).abs() < 1e-5);
    }
}

// ============================================================================
// Carlini & Wagner Tests
// ============================================================================

#[test]
fn test_carlini_wagner_basic_functionality() {
    let input_data = vec![0.5, 0.5, 0.5, 0.5];
    let req = AdversarialRequest {
        algorithm: "C&W".to_string(),
        input_data: input_data.clone(),
        shape: vec![2, 2],
        target_class: Some(1),
        epsilon: 0.1,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: None,
    };

    let result = carlini_wagner(&req);
    
    assert_eq!(result.algorithm, "C&W");
    assert!(result.success);
    assert_eq!(result.perturbed_data.len(), input_data.len());
    assert!(result.perturbation_norm >= 0.0);
}

#[test]
fn test_carlini_wagner_l2_norm() {
    let input_data = vec![0.5, 0.5, 0.5, 0.5];
    let req = AdversarialRequest {
        algorithm: "C&W".to_string(),
        input_data: input_data.clone(),
        shape: vec![2, 2],
        target_class: None,
        epsilon: 0.2,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: None,
    };

    let result = carlini_wagner(&req);
    
    // Manually compute L2 norm
    let mut sum_sq = 0.0;
    for (i, &original) in input_data.iter().enumerate() {
        let diff = result.perturbed_data[i] - original;
        sum_sq += diff * diff;
    }
    let computed_l2 = sum_sq.sqrt();
    
    assert!((result.perturbation_norm - computed_l2).abs() < 1e-4);
}

#[test]
fn test_carlini_wagner_valid_range() {
    let input_data = vec![0.1, 0.9, 0.5, 0.2];
    let req = AdversarialRequest {
        algorithm: "C&W".to_string(),
        input_data: input_data.clone(),
        shape: vec![4],
        target_class: None,
        epsilon: 0.3,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: None,
    };

    let result = carlini_wagner(&req);
    
    // Verify all values stay in [0, 1]
    for &val in &result.perturbed_data {
        assert!(val >= 0.0 && val <= 1.0, "Value {} out of range [0, 1]", val);
    }
}

// ============================================================================
// HopSkipJump Tests
// ============================================================================

#[test]
fn test_hop_skip_jump_basic_functionality() {
    let input_data = vec![0.5, 0.5, 0.5, 0.5];
    let req = AdversarialRequest {
        algorithm: "HSJ".to_string(),
        input_data: input_data.clone(),
        shape: vec![2, 2],
        target_class: None,
        epsilon: 0.3,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: Some(500),
    };

    let result = hop_skip_jump(&req);
    
    assert_eq!(result.algorithm, "HSJ");
    assert_eq!(result.perturbed_data.len(), input_data.len());
    assert!(result.query_count > 0);
    assert!(result.cost >= 0.0);
}

#[test]
fn test_hop_skip_jump_query_budget() {
    let input_data = vec![0.5, 0.5, 0.5, 0.5];
    let budget = 50;
    let req = AdversarialRequest {
        algorithm: "HSJ".to_string(),
        input_data: input_data.clone(),
        shape: vec![2, 2],
        target_class: None,
        epsilon: 0.2,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: Some(budget),
    };

    let result = hop_skip_jump(&req);
    
    // Query count should not exceed budget
    assert!(result.query_count <= budget, "Query count {} exceeds budget {}", result.query_count, budget);
}

#[test]
fn test_hop_skip_jump_with_defense() {
    let input_data = vec![0.5, 0.5, 0.5, 0.5];
    let oracle_config = OracleConfig {
        boundary_type: "distance".to_string(),
        threshold: 0.3,
        sensitive_patterns: None,
        defense_level: 0.8,
        defense_type: Some("geometric_filter".to_string()),
        waf_enabled: false,
        threat_threshold: 50.0,
        block_threshold: 100.0,
    };
    
    let req = AdversarialRequest {
        algorithm: "HSJ".to_string(),
        input_data: input_data.clone(),
        shape: vec![2, 2],
        target_class: None,
        epsilon: 0.2,
        oracle_config: Some(oracle_config),
        shadow_model_id: None,
        query_budget: Some(300),
    };

    let result = hop_skip_jump(&req);
    
    // Defense may detect the attack
    assert_eq!(result.perturbed_data.len(), input_data.len());
}

#[test]
fn test_hop_skip_jump_waf_blocking() {
    let input_data = vec![0.5, 0.5, 0.5, 0.5];
    let oracle_config = OracleConfig {
        boundary_type: "distance".to_string(),
        threshold: 0.3,
        sensitive_patterns: None,
        defense_level: 0.5,
        defense_type: None,
        waf_enabled: true,
        threat_threshold: 10.0,  // Low threshold for quick detection
        block_threshold: 50.0,   // Low threshold for quick blocking
    };
    
    let req = AdversarialRequest {
        algorithm: "HSJ".to_string(),
        input_data: input_data.clone(),
        shape: vec![2, 2],
        target_class: None,
        epsilon: 0.2,
        oracle_config: Some(oracle_config),
        shadow_model_id: None,
        query_budget: Some(500),
    };

    let result = hop_skip_jump(&req);
    
    // WAF should eventually block or detect
    assert!(result.detected || result.blocked_by_waf || result.success);
    if result.blocked_by_waf {
        assert!(!result.success);
        assert!(result.threat_score >= 50.0);
    }
}

#[test]
fn test_hop_skip_jump_stealthy_variant() {
    let input_data = vec![0.5, 0.5, 0.5, 0.5];
    let req = AdversarialRequest {
        algorithm: "STEALTHY_HSJ".to_string(),
        input_data: input_data.clone(),
        shape: vec![2, 2],
        target_class: None,
        epsilon: 0.2,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: Some(300),
    };

    let result = hop_skip_jump(&req);
    
    assert_eq!(result.algorithm, "STEALTHY_HSJ");
    // Stealthy variant should use more queries due to dummy queries
    assert!(result.query_count > 0);
}

#[test]
fn test_hop_skip_jump_pattern_boundary() {
    let input_data = vec![0.1, 0.2, 0.3, 0.4];
    let oracle_config = OracleConfig {
        boundary_type: "pattern".to_string(),
        threshold: 0.5,
        sensitive_patterns: None,
        defense_level: 0.0,
        defense_type: None,
        waf_enabled: false,
        threat_threshold: 50.0,
        block_threshold: 100.0,
    };
    
    let req = AdversarialRequest {
        algorithm: "HSJ".to_string(),
        input_data: input_data.clone(),
        shape: vec![4],
        target_class: None,
        epsilon: 0.3,
        oracle_config: Some(oracle_config),
        shadow_model_id: None,
        query_budget: Some(200),
    };

    let result = hop_skip_jump(&req);
    
    assert_eq!(result.perturbed_data.len(), input_data.len());
}

#[test]
fn test_hop_skip_jump_zero_budget() {
    let input_data = vec![0.5, 0.5, 0.5, 0.5];
    let req = AdversarialRequest {
        algorithm: "HSJ".to_string(),
        input_data: input_data.clone(),
        shape: vec![2, 2],
        target_class: None,
        epsilon: 0.2,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: Some(0),
    };

    let result = hop_skip_jump(&req);
    
    // Should fail immediately with zero budget
    assert!(!result.success);
    assert_eq!(result.query_count, 0);
}

// ============================================================================
// Transfer Attack Tests
// ============================================================================

#[test]
fn test_transfer_attack_basic_functionality() {
    let input_data = vec![0.5, 0.5, 0.5, 0.5];
    let req = AdversarialRequest {
        algorithm: "TRANSFER".to_string(),
        input_data: input_data.clone(),
        shape: vec![2, 2],
        target_class: Some(1),
        epsilon: 0.2,
        oracle_config: None,
        shadow_model_id: Some("shadow_model_1".to_string()),
        query_budget: None,
    };

    let result = transfer_attack(&req);
    
    assert_eq!(result.algorithm, "TRANSFER");
    assert_eq!(result.perturbed_data.len(), input_data.len());
    assert!(result.query_count > 0);
    assert_eq!(result.query_count, 1); // Only one oracle query
}

#[test]
fn test_transfer_attack_active_learning() {
    let input_data = vec![0.5, 0.5, 0.5, 0.5];
    let epsilon = 0.2;
    let req = AdversarialRequest {
        algorithm: "TRANSFER_ACTIVE".to_string(),
        input_data: input_data.clone(),
        shape: vec![2, 2],
        target_class: None,
        epsilon,
        oracle_config: None,
        shadow_model_id: Some("shadow_model_2".to_string()),
        query_budget: None,
    };

    let result = transfer_attack(&req);
    
    assert_eq!(result.algorithm, "TRANSFER_ACTIVE");
    // Active learning should use refined epsilon (1.1x)
    assert!(result.perturbation_norm > 0.0);
}

#[test]
fn test_transfer_attack_uses_pgd() {
    let input_data = vec![0.3, 0.7, 0.4, 0.6];
    let req = AdversarialRequest {
        algorithm: "TRANSFER".to_string(),
        input_data: input_data.clone(),
        shape: vec![4],
        target_class: None,
        epsilon: 0.15,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: None,
    };

    let result = transfer_attack(&req);
    
    // Transfer attack should produce valid output
    assert_eq!(result.perturbed_data.len(), input_data.len());
    for &val in &result.perturbed_data {
        assert!(val >= 0.0 && val <= 1.0);
    }
}

// ============================================================================
// Property-Based Tests
// ============================================================================

#[test]
fn test_all_attacks_preserve_shape() {
    let input_data = vec![0.5; 12];
    let shape = vec![3, 4];
    
    let algorithms = vec!["FGSM", "PGD", "C&W", "HSJ", "TRANSFER"];
    
    for algo in algorithms {
        let req = AdversarialRequest {
            algorithm: algo.to_string(),
            input_data: input_data.clone(),
            shape: shape.clone(),
            target_class: None,
            epsilon: 0.1,
            oracle_config: None,
            shadow_model_id: None,
            query_budget: Some(100),
        };
        
        let result = match algo {
            "FGSM" => fgsm(&req),
            "PGD" => pgd(&req),
            "C&W" => carlini_wagner(&req),
            "HSJ" => hop_skip_jump(&req),
            "TRANSFER" => transfer_attack(&req),
            _ => panic!("Unknown algorithm"),
        };
        
        assert_eq!(result.perturbed_data.len(), input_data.len(), 
                   "Algorithm {} did not preserve shape", algo);
    }
}

#[test]
fn test_fgsm_deterministic() {
    let input_data = vec![0.5, 0.3, 0.7, 0.2];
    let req = AdversarialRequest {
        algorithm: "FGSM".to_string(),
        input_data: input_data.clone(),
        shape: vec![4],
        target_class: None,
        epsilon: 0.1,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: None,
    };

    let result1 = fgsm(&req);
    let result2 = fgsm(&req);
    
    // FGSM should be deterministic
    assert_eq!(result1.perturbed_data, result2.perturbed_data);
}

#[test]
fn test_pgd_deterministic() {
    let input_data = vec![0.5, 0.3, 0.7, 0.2];
    let req = AdversarialRequest {
        algorithm: "PGD".to_string(),
        input_data: input_data.clone(),
        shape: vec![4],
        target_class: None,
        epsilon: 0.1,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: None,
    };

    let result1 = pgd(&req);
    let result2 = pgd(&req);
    
    // PGD should be deterministic (no randomness in current implementation)
    assert_eq!(result1.perturbed_data, result2.perturbed_data);
}

#[test]
fn test_multidimensional_shapes() {
    let test_cases = vec![
        (vec![0.5; 24], vec![2, 3, 4]),
        (vec![0.5; 60], vec![3, 4, 5]),
        (vec![0.5; 8], vec![2, 2, 2]),
    ];
    
    for (input_data, shape) in test_cases {
        let req = AdversarialRequest {
            algorithm: "FGSM".to_string(),
            input_data: input_data.clone(),
            shape: shape.clone(),
            target_class: None,
            epsilon: 0.1,
            oracle_config: None,
            shadow_model_id: None,
            query_budget: None,
        };
        
        let result = fgsm(&req);
        assert_eq!(result.perturbed_data.len(), input_data.len());
    }
}

#[test]
fn test_valid_range_preservation() {
    let algorithms = vec!["PGD", "C&W"];
    let input_data = vec![0.0, 0.25, 0.5, 0.75, 1.0];
    
    for algo in algorithms {
        let req = AdversarialRequest {
            algorithm: algo.to_string(),
            input_data: input_data.clone(),
            shape: vec![5],
            target_class: None,
            epsilon: 0.3,
            oracle_config: None,
            shadow_model_id: None,
            query_budget: Some(100),
        };
        
        let result = match algo {
            "PGD" => pgd(&req),
            "C&W" => carlini_wagner(&req),
            _ => panic!("Unknown algorithm"),
        };
        
        for &val in &result.perturbed_data {
            assert!(val >= 0.0 && val <= 1.0, 
                    "Algorithm {} produced out-of-range value {}", algo, val);
        }
    }
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_single_element_input() {
    let input_data = vec![0.5];
    let req = AdversarialRequest {
        algorithm: "FGSM".to_string(),
        input_data: input_data.clone(),
        shape: vec![1],
        target_class: None,
        epsilon: 0.1,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: None,
    };

    let result = fgsm(&req);
    assert_eq!(result.perturbed_data.len(), 1);
}

#[test]
fn test_large_input() {
    let input_data = vec![0.5; 10000];
    let req = AdversarialRequest {
        algorithm: "FGSM".to_string(),
        input_data: input_data.clone(),
        shape: vec![100, 100],
        target_class: None,
        epsilon: 0.05,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: None,
    };

    let result = fgsm(&req);
    assert_eq!(result.perturbed_data.len(), 10000);
}

#[test]
fn test_extreme_values() {
    let input_data = vec![0.0, 1.0, 0.0, 1.0];
    let req = AdversarialRequest {
        algorithm: "PGD".to_string(),
        input_data: input_data.clone(),
        shape: vec![4],
        target_class: None,
        epsilon: 0.1,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: None,
    };

    let result = pgd(&req);
    
    for &val in &result.perturbed_data {
        assert!(val >= 0.0 && val <= 1.0);
    }
}
