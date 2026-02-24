//! WASM bindings for ai-wot trust scoring engine.
//!
//! Provides a JavaScript-friendly API for computing trust scores
//! entirely client-side in the browser.

use wasm_bindgen::prelude::*;
use std::collections::HashMap;
use crate::types::*;
use crate::scoring;

/// Initialize panic hook for better error messages in the browser console.
#[wasm_bindgen(start)]
pub fn init() {
    std::panic::set_hook(Box::new(console_error_panic_hook::hook));
}

// ─── JS-friendly wrapper types ──────────────────────────────────

/// A trust scoring engine that holds attestations and computes scores.
///
/// Usage from JS:
/// ```js
/// import init, { WotScorer } from './ai_wot.js';
/// await init();
///
/// const scorer = new WotScorer();
/// scorer.add_attestation("evt1", "alice_pub", "bob_pub", "service-quality", 1700000000, "Great work");
/// scorer.set_zap("evt1", 500);
/// const result = scorer.calculate_score("bob_pub");
/// console.log(result); // { raw: 2.34, display: 23, ... }
/// ```
#[wasm_bindgen]
pub struct WotScorer {
    attestations: Vec<Attestation>,
    zap_totals: HashMap<String, u64>,
    attester_scores: HashMap<String, TrustScore>,
    config: ScoringConfig,
}

#[wasm_bindgen]
impl WotScorer {
    /// Create a new scorer with default config.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            attestations: Vec::new(),
            zap_totals: HashMap::new(),
            attester_scores: HashMap::new(),
            config: ScoringConfig::default(),
        }
    }

    /// Set the current time (unix timestamp in seconds).
    #[wasm_bindgen]
    pub fn set_now(&mut self, now: u64) {
        self.config.now = now;
    }

    /// Set half-life in days for temporal decay.
    #[wasm_bindgen]
    pub fn set_half_life_days(&mut self, days: f64) {
        self.config.half_life_days = days;
    }

    /// Set max recursion depth for attester trust.
    #[wasm_bindgen]
    pub fn set_max_depth(&mut self, depth: u32) {
        self.config.max_depth = depth;
    }

    /// Set novelty multiplier (1.0 = no bonus).
    #[wasm_bindgen]
    pub fn set_novelty_multiplier(&mut self, mult: f64) {
        self.config.novelty_multiplier = mult;
    }

    /// Set minimum attester trust to accept negative attestations.
    #[wasm_bindgen]
    pub fn set_negative_trust_gate(&mut self, gate: u32) {
        self.config.negative_trust_gate = gate;
    }

    /// Add an attestation.
    #[wasm_bindgen]
    pub fn add_attestation(
        &mut self,
        event_id: &str,
        attester: &str,
        subject: &str,
        attestation_type: &str,
        created_at: u64,
        content: &str,
    ) -> bool {
        let att_type = match AttestationType::from_str(attestation_type) {
            Some(t) => t,
            None => return false,
        };

        self.attestations.push(Attestation {
            event_id: event_id.to_string(),
            attester: attester.to_string(),
            subject: subject.to_string(),
            attestation_type: att_type,
            created_at,
            content: content.to_string(),
        });
        true
    }

    /// Bulk-add attestations from a JSON array.
    /// Each object should have: event_id, attester, subject, attestation_type, created_at, content
    #[wasm_bindgen]
    pub fn add_attestations_json(&mut self, json: &str) -> Result<u32, JsValue> {
        let atts: Vec<Attestation> = serde_json::from_str(json)
            .map_err(|e| JsValue::from_str(&format!("JSON parse error: {}", e)))?;
        let count = atts.len() as u32;
        self.attestations.extend(atts);
        Ok(count)
    }

    /// Set zap amount for an event.
    #[wasm_bindgen]
    pub fn set_zap(&mut self, event_id: &str, sats: u64) {
        self.zap_totals.insert(event_id.to_string(), sats);
    }

    /// Set a pre-computed attester score (for recursive scoring).
    #[wasm_bindgen]
    pub fn set_attester_score(&mut self, pubkey: &str, raw: f64, display: u32) {
        self.attester_scores.insert(
            pubkey.to_string(),
            TrustScore {
                raw,
                display,
                attestation_count: 0,
                positive_count: 0,
                negative_count: 0,
                gated_count: 0,
                breakdown: vec![],
                diversity: DiversityScore::default(),
                category: None,
            },
        );
    }

    /// Calculate trust score for a subject. Returns JSON string.
    #[wasm_bindgen]
    pub fn calculate_score(&self, subject: &str) -> String {
        let relevant: Vec<Attestation> = self
            .attestations
            .iter()
            .filter(|a| a.subject == subject)
            .cloned()
            .collect();

        let resolver = MapResolver {
            scores: self.attester_scores.clone(),
        };

        let score = scoring::calculate_trust_score(
            &relevant,
            &self.zap_totals,
            &self.config,
            &resolver,
            0,
        );

        serde_json::to_string(&score).unwrap_or_else(|_| "{}".to_string())
    }

    /// Calculate category score. Returns JSON string.
    #[wasm_bindgen]
    pub fn calculate_category_score(&self, subject: &str, category: &str) -> String {
        let cat = match category {
            "commerce" => Category::Commerce,
            "identity" => Category::Identity,
            "code" => Category::Code,
            "general" => Category::General,
            _ => return "{}".to_string(),
        };

        let relevant: Vec<Attestation> = self
            .attestations
            .iter()
            .filter(|a| a.subject == subject)
            .cloned()
            .collect();

        let resolver = MapResolver {
            scores: self.attester_scores.clone(),
        };

        let score = scoring::calculate_category_score(
            &relevant,
            &self.zap_totals,
            cat,
            &self.config,
            &resolver,
            0,
        );

        serde_json::to_string(&score).unwrap_or_else(|_| "{}".to_string())
    }

    /// Calculate all category scores for a subject. Returns JSON string.
    #[wasm_bindgen]
    pub fn calculate_all_scores(&self, subject: &str) -> String {
        let relevant: Vec<Attestation> = self
            .attestations
            .iter()
            .filter(|a| a.subject == subject)
            .cloned()
            .collect();

        let resolver = MapResolver {
            scores: self.attester_scores.clone(),
        };

        let scores = scoring::calculate_all_category_scores(
            &relevant,
            &self.zap_totals,
            &self.config,
            &resolver,
            0,
        );

        serde_json::to_string(&scores).unwrap_or_else(|_| "{}".to_string())
    }

    /// Get all unique subjects in the loaded attestations.
    #[wasm_bindgen]
    pub fn get_subjects(&self) -> String {
        let subjects: Vec<&str> = self
            .attestations
            .iter()
            .map(|a| a.subject.as_str())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        serde_json::to_string(&subjects).unwrap_or_else(|_| "[]".to_string())
    }

    /// Get total attestation count.
    #[wasm_bindgen]
    pub fn attestation_count(&self) -> u32 {
        self.attestations.len() as u32
    }

    /// Clear all data.
    #[wasm_bindgen]
    pub fn clear(&mut self) {
        self.attestations.clear();
        self.zap_totals.clear();
        self.attester_scores.clear();
    }
}

// ─── Standalone functions ───────────────────────────────────────

/// Quick single-score calculation from JSON. Returns JSON string.
/// Input: { attestations: [...], zaps: {event_id: sats}, config?: {...} }
#[wasm_bindgen]
pub fn score_from_json(input: &str) -> Result<String, JsValue> {
    let v: serde_json::Value = serde_json::from_str(input)
        .map_err(|e| JsValue::from_str(&format!("JSON parse error: {}", e)))?;

    let attestations: Vec<Attestation> = serde_json::from_value(
        v.get("attestations")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![])),
    )
    .map_err(|e| JsValue::from_str(&format!("Attestations parse error: {}", e)))?;

    let zaps: HashMap<String, u64> = serde_json::from_value(
        v.get("zaps")
            .cloned()
            .unwrap_or(serde_json::Value::Object(Default::default())),
    )
    .unwrap_or_default();

    let config = match v.get("config") {
        Some(c) => serde_json::from_value(c.clone()).unwrap_or_default(),
        None => ScoringConfig::default(),
    };

    let resolver = NoOpResolver;
    let score = scoring::calculate_trust_score(&attestations, &zaps, &config, &resolver, 0);

    serde_json::to_string(&score)
        .map_err(|e| JsValue::from_str(&format!("Serialize error: {}", e)))
}

/// Compute temporal decay value (exported for testing/visualization).
#[wasm_bindgen]
pub fn compute_decay(created_at: u64, half_life_days: f64, now: u64) -> f64 {
    scoring::temporal_decay(created_at, half_life_days, now)
}

/// Compute zap weight (exported for testing/visualization).
#[wasm_bindgen]
pub fn compute_zap_weight(sats: u64) -> f64 {
    scoring::zap_weight(sats)
}
