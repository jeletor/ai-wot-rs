use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Constants ──────────────────────────────────────────────────

pub const NAMESPACE: &str = "ai.wot";
pub const DEFAULT_HALF_LIFE_DAYS: f64 = 90.0;
pub const ZAP_MULTIPLIER: f64 = 0.5;
pub const DAMPENING_FACTOR: f64 = 0.5;
pub const DEFAULT_NOVELTY_MULTIPLIER: f64 = 1.3;
pub const DEFAULT_NEGATIVE_TRUST_GATE: u32 = 20;

// ─── Attestation Types ──────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationType {
    ServiceQuality,
    WorkCompleted,
    IdentityContinuity,
    GeneralTrust,
    Dispute,
    Warning,
}

impl AttestationType {
    pub fn multiplier(&self) -> f64 {
        match self {
            Self::ServiceQuality => 1.5,
            Self::WorkCompleted => 1.2,
            Self::IdentityContinuity => 1.0,
            Self::GeneralTrust => 0.8,
            Self::Dispute => -1.5,
            Self::Warning => -0.8,
        }
    }

    pub fn is_negative(&self) -> bool {
        matches!(self, Self::Dispute | Self::Warning)
    }

    pub fn is_positive(&self) -> bool {
        !self.is_negative()
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "service-quality" => Some(Self::ServiceQuality),
            "work-completed" => Some(Self::WorkCompleted),
            "identity-continuity" => Some(Self::IdentityContinuity),
            "general-trust" => Some(Self::GeneralTrust),
            "dispute" => Some(Self::Dispute),
            "warning" => Some(Self::Warning),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ServiceQuality => "service-quality",
            Self::WorkCompleted => "work-completed",
            Self::IdentityContinuity => "identity-continuity",
            Self::GeneralTrust => "general-trust",
            Self::Dispute => "dispute",
            Self::Warning => "warning",
        }
    }
}

// ─── Category ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Commerce,
    Identity,
    Code,
    General,
}

impl Category {
    pub const ALL: &'static [Category] = &[
        Category::Commerce,
        Category::Identity,
        Category::Code,
        Category::General,
    ];

    /// Returns the attestation types that belong to this category.
    /// `None` means all types (no filter).
    pub fn types(&self) -> Option<&'static [AttestationType]> {
        match self {
            Self::Commerce => Some(&[AttestationType::WorkCompleted, AttestationType::ServiceQuality]),
            Self::Identity => Some(&[AttestationType::IdentityContinuity]),
            Self::Code => Some(&[AttestationType::ServiceQuality]),
            Self::General => None,
        }
    }

    /// Whether this category requires content-based filtering beyond type matching.
    pub fn requires_content_filter(&self) -> bool {
        matches!(self, Self::Code)
    }
}

// ─── Attestation (input) ────────────────────────────────────────

/// A parsed attestation ready for scoring.
/// This is the Rust-native representation — callers convert from Nostr events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// Nostr event ID (hex)
    pub event_id: String,
    /// Attester pubkey (hex)
    pub attester: String,
    /// Subject pubkey (hex)
    pub subject: String,
    /// Attestation type
    pub attestation_type: AttestationType,
    /// Unix timestamp
    pub created_at: u64,
    /// Human-readable comment
    pub content: String,
}

// ─── Score Config ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringConfig {
    pub half_life_days: f64,
    pub max_depth: u32,
    pub novelty_multiplier: f64,
    pub negative_trust_gate: u32,
    pub now: u64,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            half_life_days: DEFAULT_HALF_LIFE_DAYS,
            max_depth: 2,
            novelty_multiplier: DEFAULT_NOVELTY_MULTIPLIER,
            negative_trust_gate: DEFAULT_NEGATIVE_TRUST_GATE,
            now: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

// ─── Score Output ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakdownEntry {
    pub attester: String,
    pub attestation_type: AttestationType,
    pub zap_sats: u64,
    pub zap_weight: f64,
    pub decay_factor: f64,
    pub attester_trust: f64,
    pub type_multiplier: f64,
    pub contribution: f64,
    pub comment: String,
    pub event_id: String,
    pub timestamp: u64,
    pub gated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate_reason: Option<String>,
    pub novelty_bonus: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiversityScore {
    pub diversity: f64,
    pub unique_attesters: usize,
    pub max_attester_share: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_attester: Option<String>,
}

impl Default for DiversityScore {
    fn default() -> Self {
        Self {
            diversity: 0.0,
            unique_attesters: 0,
            max_attester_share: 0.0,
            top_attester: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    pub raw: f64,
    pub display: u32,
    pub attestation_count: usize,
    pub positive_count: usize,
    pub negative_count: usize,
    pub gated_count: usize,
    pub breakdown: Vec<BreakdownEntry>,
    pub diversity: DiversityScore,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<Category>,
}

// ─── Attester Score Resolver ────────────────────────────────────

/// Trait for resolving attester trust scores during recursive scoring.
/// Implement this to provide attester scores from your data source.
pub trait AttesterScoreResolver {
    fn resolve(&self, pubkey: &str, depth: u32) -> TrustScore;
}

/// A no-op resolver that returns default scores (trust = 1.0).
/// Use this when you don't need recursive scoring.
pub struct NoOpResolver;

impl AttesterScoreResolver for NoOpResolver {
    fn resolve(&self, _pubkey: &str, _depth: u32) -> TrustScore {
        TrustScore {
            raw: 1.0,
            display: 10,
            attestation_count: 0,
            positive_count: 0,
            negative_count: 0,
            gated_count: 0,
            breakdown: vec![],
            diversity: DiversityScore::default(),
            category: None,
        }
    }
}

/// A resolver backed by a pre-computed HashMap of scores.
pub struct MapResolver {
    pub scores: HashMap<String, TrustScore>,
}

impl AttesterScoreResolver for MapResolver {
    fn resolve(&self, pubkey: &str, _depth: u32) -> TrustScore {
        self.scores.get(pubkey).cloned().unwrap_or(TrustScore {
            raw: 0.0,
            display: 0,
            attestation_count: 0,
            positive_count: 0,
            negative_count: 0,
            gated_count: 0,
            breakdown: vec![],
            diversity: DiversityScore::default(),
            category: None,
        })
    }
}
