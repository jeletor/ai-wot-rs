//! ai-wot: High-performance trust scoring engine for AI agents
//!
//! Implements the ai.wot protocol scoring algorithm:
//! - Temporal decay (exponential, configurable half-life)
//! - Zap-weighted attestations (log2 scaling)
//! - Recursive attester trust with square-root dampening
//! - Sybil resistance via diversity scoring
//! - Category-based filtering
//! - Negative attestation gating
//! - Deduplication by (attester, subject, type)

pub mod scoring;
pub mod types;

pub use scoring::*;
pub use types::*;
