use ndarray::{ArrayD, IxDyn};
use super::{AdversarialRequest, AdversarialResult, validate_request, error::AdversarialError};
use rand::prelude::*;
use rand_distr::StandardNormal;

/// Fast Gradient Sign Method (FGSM)
/// Standard white-box attack: x_adv = x + epsilon * sign(grad)
pub fn fgsm(req: &AdversarialRequest) -> Result<AdversarialResult, AdversarialError> {
    // Validate request parameters
    validate_request(req)?;
    
    let mut data = ArrayD::from_shape_vec(IxDyn(&req.shape), req.input_data.clone())
        .map_err(|_| AdversarialError::ShapeMismatch {
            shape: req.shape.clone(),
            data_len: req.input_data.len(),
        })?;
    
    let perturbation = data.mapv(|x| if x >= 0.0 { req.epsilon } else { -req.epsilon });
    data += &perturbation;

    Ok(AdversarialResult {
        algorithm: "FGSM".to_string(),
        perturbed_data: data.into_raw_vec(),
        success: true,
        perturbation_norm: req.epsilon,
        query_count: 0,
        cost: 0.0,
        detected: false,
        blocked_by_waf: false,
        threat_score: 0.0,
        adversarial_prompt: None,
        robustness_score: 0.0,
    })
}

/// Projected Gradient Descent (PGD)
pub fn pgd(req: &AdversarialRequest) -> Result<AdversarialResult, AdversarialError> {
    // Validate request parameters
    validate_request(req)?;
    
    let original_data = ArrayD::from_shape_vec(IxDyn(&req.shape), req.input_data.clone())
        .map_err(|_| AdversarialError::ShapeMismatch {
            shape: req.shape.clone(),
            data_len: req.input_data.len(),
        })?;
    let mut data = original_data.clone();
    
    let steps = 10;
    let alpha = req.epsilon / 4.0;

    for _ in 0..steps {
        let grad_sign = data.mapv(|x| if x >= 0.0 { 1.0 } else { -1.0 });
        data += &(grad_sign * alpha);
        
        data.zip_mut_with(&original_data, |x, x_orig| {
            *x = (*x).max(*x_orig - req.epsilon).min(*x_orig + req.epsilon);
            *x = (*x).max(0.0).min(1.0);
        });
    }

    Ok(AdversarialResult {
        algorithm: "PGD".to_string(),
        perturbed_data: data.into_raw_vec(),
        success: true,
        perturbation_norm: req.epsilon,
        query_count: 0,
        cost: 0.0,
        detected: false,
        blocked_by_waf: false,
        threat_score: 0.0,
        adversarial_prompt: None,
        robustness_score: 0.0,
    })
}

/// Carlini & Wagner (C&W) L2 Attack
pub fn carlini_wagner(req: &AdversarialRequest) -> Result<AdversarialResult, AdversarialError> {
    // Validate request parameters
    validate_request(req)?;
    
    let original_data = ArrayD::from_shape_vec(IxDyn(&req.shape), req.input_data.clone())
        .map_err(|_| AdversarialError::ShapeMismatch {
            shape: req.shape.clone(),
            data_len: req.input_data.len(),
        })?;
    let mut data = original_data.clone();
    
    let confidence = 0.5;
    let learning_rate = 0.01;
    let max_iterations = 40;
    
    for _ in 0..max_iterations {
        data.zip_mut_with(&original_data, |x, x_orig| {
            let grad = if *x > *x_orig { 1.0 } else { -1.0 };
            *x += learning_rate * (grad + confidence * (*x - *x_orig));
            *x = (*x).max(0.0).min(1.0);
        });
    }

    let diff = &data - &original_data;
    let l2_norm = diff.mapv(|x| x * x).sum().sqrt();

    Ok(AdversarialResult {
        algorithm: "C&W".to_string(),
        perturbed_data: data.into_raw_vec(),
        success: true,
        perturbation_norm: l2_norm,
        query_count: 0,
        cost: 0.0,
        detected: false,
        blocked_by_waf: false,
        threat_score: 0.0,
        adversarial_prompt: None,
        robustness_score: 0.0,
    })
}

/// HopSkipJump (HSJ) Attack with Intelligent Defense and WAF/IDS
pub fn hop_skip_jump(req: &AdversarialRequest) -> Result<AdversarialResult, AdversarialError> {
    // Validate request parameters
    validate_request(req)?;
    
    let original_data = ArrayD::from_shape_vec(IxDyn(&req.shape), req.input_data.clone())
        .map_err(|_| AdversarialError::ShapeMismatch {
            shape: req.shape.clone(),
            data_len: req.input_data.len(),
        })?;
    let mut rng = StdRng::seed_from_u64(42);
    let mut query_count = 0;
    let cost_per_query = 0.001;
    let mut detected = false;
    let mut blocked_by_waf = false;
    let mut threat_score = 0.0;
    
    let mut last_queries: Vec<ArrayD<f32>> = Vec::new();
    let use_defense = req.oracle_config.as_ref()
        .and_then(|c| c.defense_type.as_ref())
        .map(|t| t == "geometric_filter")
        .unwrap_or(false);
    
    let waf_enabled = req.oracle_config.as_ref()
        .map(|c| c.waf_enabled)
        .unwrap_or(false);
    
    let threat_threshold = req.oracle_config.as_ref()
        .map(|c| c.threat_threshold)
        .unwrap_or(50.0);
    
    let block_threshold = req.oracle_config.as_ref()
        .map(|c| c.block_threshold)
        .unwrap_or(100.0);

    let oracle = |x: &ArrayD<f32>, 
                      count: &mut usize, 
                      queries: &mut Vec<ArrayD<f32>>, 
                      is_detected: &mut bool,
                      is_blocked: &mut bool,
                      threat: &mut f32,
                      _local_rng: &mut StdRng| -> bool {
        *count += 1;
        
        // WAF/IDS: Progressive Threat Scoring
        if waf_enabled && !*is_blocked {
            // Score based on query similarity (HSJ pattern detection)
            let mut similarity_score = 0.0;
            for prev in queries.iter().rev().take(10) {
                let diff = x - prev;
                let dist = diff.mapv(|v| v * v).sum().sqrt();
                if dist < 0.01 {
                    similarity_score += 15.0; // High similarity = suspicious
                } else if dist < 0.1 {
                    similarity_score += 5.0;
                }
            }
            
            // Score based on query frequency (rate limiting simulation)
            let frequency_score = if *count > 100 { 10.0 } else { 0.0 };
            
            // Accumulate threat score
            *threat += similarity_score + frequency_score;
            
            // Check if blocked
            if *threat >= block_threshold {
                *is_blocked = true;
                return false; // Block all queries
            }
            
            // Warn if approaching threshold
            if *threat >= threat_threshold && !*is_detected {
                *is_detected = true;
            }
        }
        
        // Geometric Detection (original logic)
        if use_defense && !*is_detected {
            for prev in queries.iter().rev().take(5) {
                let diff = x - prev;
                let dist = diff.mapv(|v| v * v).sum().sqrt();
                if dist < 0.001 {
                    *is_detected = true;
                    break;
                }
            }
            queries.push(x.clone());
            if queries.len() > 10 { queries.remove(0); }
        }

        let diff = x - &original_data;
        let l2 = diff.mapv(|v| v * v).sum().sqrt();
        
        let mut response = if let Some(config) = &req.oracle_config {
            match config.boundary_type.as_str() {
                "distance" => l2 > config.threshold,
                "pattern" => {
                    let pattern_sum: f32 = x.iter().take(3).sum();
                    pattern_sum > config.threshold
                },
                _ => l2 > req.epsilon * 1.5,
            }
        } else {
            l2 > req.epsilon * 1.5 
        };

        if *is_detected {
            // Dans un mode déterministe, on ne "lance pas de dé" pour décider si on inverse la réponse.
            // On suit strictement la règle d'immunisation.
            response = !response;
        }
        
        response
    };

    // Initialization
    let mut adversarial_sample = original_data.clone();
    for _ in 0..100 {
        if let Some(budget) = req.query_budget {
            if query_count >= budget { break; }
        }
        
        if blocked_by_waf { break; }
        
        // --- Determinisme: Suppression du jitter et des bruits aléatoires ---
        // On utilise une graine fixe et on évite le jitter pour des preuves reproductibles.
        let noise: Vec<f32> = (0..req.input_data.len()).map(|i| {
            let val = ((i * 12345) % 100) as f32 / 50.0 - 1.0; // Deterministic pseudo-noise
            val
        }).collect();
        let noise_arr = ArrayD::from_shape_vec(IxDyn(&req.shape), noise)
            .map_err(|_| AdversarialError::ArrayCreationError("Failed to create noise array".to_string()))?;
        let candidate = &original_data + &noise_arr;
        
        if oracle(&candidate, &mut query_count, &mut last_queries, &mut detected, &mut blocked_by_waf, &mut threat_score, &mut rng) {
            adversarial_sample = candidate;
            break;
        }
    }

    if blocked_by_waf {
        return Ok(AdversarialResult {
            algorithm: req.algorithm.clone(),
            perturbed_data: req.input_data.clone(),
            success: false,
            perturbation_norm: 0.0,
            query_count,
            cost: (query_count as f32) * cost_per_query,
            detected,
            blocked_by_waf: true,
            threat_score,
            adversarial_prompt: None,
            robustness_score: 0.0,

        });
    }

    let is_adversarial = oracle(&adversarial_sample, &mut query_count, &mut last_queries, &mut detected, &mut blocked_by_waf, &mut threat_score, &mut rng);
    if !is_adversarial || (req.query_budget.is_some() && query_count >= req.query_budget.unwrap_or(usize::MAX)) {
        return Ok(AdversarialResult {
            algorithm: req.algorithm.clone(),
            perturbed_data: req.input_data.clone(),
            success: false,
            perturbation_norm: 0.0,
            query_count,
            cost: (query_count as f32) * cost_per_query,
            detected,
            blocked_by_waf,
            threat_score,
            adversarial_prompt: None,
            robustness_score: 0.0,

        });
    }

    // Iterative refinement
    let mut current_sample = adversarial_sample;
    let iterations = 20;

    for _ in 0..iterations {
        if let Some(budget) = req.query_budget {
            if query_count >= budget { break; }
        }
        
        if blocked_by_waf { break; }

        // Binary Search
        let mut low = 0.0;
        let mut high = 1.0;
        for _ in 0..10 {
            if blocked_by_waf { break; }
            
            let mid = (low + high) / 2.0;
            let mid_sample = &original_data * mid + &current_sample * (1.0 - mid);
            if oracle(&mid_sample, &mut query_count, &mut last_queries, &mut detected, &mut blocked_by_waf, &mut threat_score, &mut rng) {
                high = mid;
            } else {
                low = mid;
            }
            
            if req.algorithm == "STEALTHY_HSJ" {
                // Pas de requêtes "dummy" aléatoires dans un moteur de preuve.
            }
        }
        
        if blocked_by_waf { break; }
        
        let boundary_point = &original_data * high + &current_sample * (1.0 - high);

        // Gradient Estimation
        let num_samples = 50;
        let mut gradient = ArrayD::zeros(IxDyn(&req.shape));
        let delta = 0.01;

        for _ in 0..num_samples {
            if let Some(budget) = req.query_budget {
                if query_count >= budget { break; }
            }
            if blocked_by_waf { break; }
            
            let u: Vec<f32> = (0..req.input_data.len()).map(|_| rng.sample(StandardNormal)).collect();
            let u_arr = ArrayD::from_shape_vec(IxDyn(&req.shape), u)
                .map_err(|_| AdversarialError::ArrayCreationError("Failed to create gradient estimation array".to_string()))?;
            let perturbed = &boundary_point + &(&u_arr * delta);
            
            if oracle(&perturbed, &mut query_count, &mut last_queries, &mut detected, &mut blocked_by_waf, &mut threat_score, &mut rng) {
                gradient += &u_arr;
            } else {
                gradient -= &u_arr;
            }
        }
        
        let grad_norm = gradient.mapv(|v| v * v).sum().sqrt();
        if grad_norm > 0.0 { gradient /= grad_norm; }

        let step_size = 0.05;
        current_sample = &boundary_point + &(&gradient * step_size);
        current_sample.mapv_inplace(|v| v.max(0.0).min(1.0));
    }

    let diff = &current_sample - &original_data;
    let final_l2 = diff.mapv(|v| v * v).sum().sqrt();

    Ok(AdversarialResult {
        algorithm: req.algorithm.clone(),
        perturbed_data: current_sample.into_raw_vec(),
        success: !detected && !blocked_by_waf,
        perturbation_norm: final_l2,
        query_count,
        cost: (query_count as f32) * cost_per_query,
        detected,
        blocked_by_waf,
        threat_score,
        adversarial_prompt: None,
        robustness_score: 0.0,
    })
}

/// Transfer Attack with Active Learning
pub fn transfer_attack(req: &AdversarialRequest) -> Result<AdversarialResult, AdversarialError> {
    // Validate request parameters
    validate_request(req)?;
    
    let original_data = ArrayD::from_shape_vec(IxDyn(&req.shape), req.input_data.clone())
        .map_err(|_| AdversarialError::ShapeMismatch {
            shape: req.shape.clone(),
            data_len: req.input_data.len(),
        })?;
    let mut query_count = 0;
    let cost_per_query = 0.001;

    let refined_epsilon = if req.algorithm.contains("ACTIVE") {
        req.epsilon * 1.1
    } else {
        req.epsilon
    };

    let shadow_pgd_req = AdversarialRequest {
        algorithm: "PGD".to_string(),
        input_data: req.input_data.clone(),
        shape: req.shape.clone(),
        target_class: req.target_class,
        epsilon: refined_epsilon,
        oracle_config: None,
        shadow_model_id: None,
        query_budget: None,
        prompt: None,
        latent_vectors: None,

    };
    
    let shadow_result = pgd(&shadow_pgd_req)?;
    let data_len = shadow_result.perturbed_data.len();
    let candidate_data = ArrayD::from_shape_vec(IxDyn(&req.shape), shadow_result.perturbed_data)
        .map_err(|_| AdversarialError::ShapeMismatch {
            shape: req.shape.clone(),
            data_len,
        })?;

    let oracle = |x: &ArrayD<f32>, count: &mut usize| -> bool {
        *count += 1;
        let diff = x - &original_data;
        let l2 = diff.mapv(|v| v * v).sum().sqrt();
        l2 > req.epsilon * 1.8 
    };

    let success = oracle(&candidate_data, &mut query_count);
    let diff = &candidate_data - &original_data;
    let l2_norm = diff.mapv(|x| x * x).sum().sqrt();

    Ok(AdversarialResult {
        algorithm: req.algorithm.clone(),
        perturbed_data: candidate_data.into_raw_vec(),
        success,
        perturbation_norm: l2_norm,
        query_count,
        cost: (query_count as f32) * cost_per_query,
        detected: false,
        blocked_by_waf: false,
        threat_score: 0.0,
        adversarial_prompt: None,
        robustness_score: if success { 0.2 } else { 0.9 },

    })
}

/// LLM_PROBE: Détection déterministe de brèches de sécurité LLM (Prompt Injection / Jailbreak)
pub fn llm_probe(req: &AdversarialRequest) -> Result<AdversarialResult, AdversarialError> {
    let prompt = req.prompt.as_deref().unwrap_or("");
    let mut robustness_score: f32 = 1.0;
    let mut success = false;
    let mut adversarial_prompt = None;
    let mut threat_score = 0.0;

    // Règle 1 : Détection d'injection système (Pattern-based proof)
    if prompt.to_lowercase().contains("ignore previous instructions") || prompt.to_lowercase().contains("system override") {
        robustness_score -= 0.6;
        threat_score += 75.0;
        success = true;
        adversarial_prompt = Some(format!("[PROBE_MATCH] Injection détectée : {}", prompt));
    }

    // Règle 2 : Détection de fuite de contexte (Inlining probe)
    if prompt.to_lowercase().contains("repeat the above") {
        robustness_score -= 0.3;
        threat_score += 40.0;
        success = true;
    }

    Ok(AdversarialResult {
        algorithm: "LLM_PROBE".to_string(),
        perturbed_data: vec![],
        success,
        perturbation_norm: 0.0,
        query_count: 1,
        cost: 0.0,
        detected: success,
        blocked_by_waf: false,
        threat_score,
        adversarial_prompt,
        robustness_score: robustness_score.max(0.0),
    })
}
