use std::collections::HashMap;

use crate::types::*;

// ─── Temporal Decay ─────────────────────────────────────────────

/// Exponential decay: 0.5 ^ (age_days / half_life_days)
#[inline]
pub fn temporal_decay(created_at: u64, half_life_days: f64, now: u64) -> f64 {
    let age_secs = now.saturating_sub(created_at) as f64;
    let age_days = age_secs / 86400.0;
    (0.5_f64).powf(age_days / half_life_days)
}

// ─── Zap Weight ─────────────────────────────────────────────────

/// Weight from zap sats: 1.0 + log2(1 + sats) * ZAP_MULTIPLIER
#[inline]
pub fn zap_weight(sats: u64) -> f64 {
    if sats == 0 {
        return 1.0;
    }
    1.0 + ((1 + sats) as f64).log2() * ZAP_MULTIPLIER
}

// ─── Deduplication ──────────────────────────────────────────────

/// Deduplicate attestations by (attester, subject, type), keeping most recent.
pub fn deduplicate(attestations: &[Attestation]) -> Vec<Attestation> {
    let mut groups: HashMap<(String, String, AttestationType), Attestation> = HashMap::new();

    for att in attestations {
        let key = (
            att.attester.clone(),
            att.subject.clone(),
            att.attestation_type,
        );
        match groups.get(&key) {
            Some(existing) if att.created_at > existing.created_at => {
                groups.insert(key, att.clone());
            }
            None => {
                groups.insert(key, att.clone());
            }
            _ => {}
        }
    }

    groups.into_values().collect()
}

// ─── Diversity ──────────────────────────────────────────────────

/// Calculate diversity score from non-gated breakdown entries.
pub fn calculate_diversity(breakdown: &[BreakdownEntry]) -> DiversityScore {
    let positive: Vec<_> = breakdown
        .iter()
        .filter(|b| !b.gated && b.contribution > 0.0)
        .collect();

    if positive.is_empty() {
        return DiversityScore::default();
    }

    let total_contribution: f64 = positive.iter().map(|b| b.contribution).sum();
    let mut attester_contributions: HashMap<&str, f64> = HashMap::new();

    for b in &positive {
        *attester_contributions.entry(&b.attester).or_insert(0.0) += b.contribution;
    }

    let unique_attesters = attester_contributions.len();
    let mut max_share = 0.0_f64;
    let mut top_attester: Option<String> = None;

    for (attester, contribution) in &attester_contributions {
        let share = if total_contribution > 0.0 {
            contribution / total_contribution
        } else {
            0.0
        };
        if share > max_share {
            max_share = share;
            top_attester = Some(attester.to_string());
        }
    }

    let attester_ratio = (unique_attesters as f64 / positive.len() as f64).min(1.0);
    let diversity = (attester_ratio * (1.0 - max_share) * 100.0).round() / 100.0;

    DiversityScore {
        diversity,
        unique_attesters,
        max_attester_share: (max_share * 100.0).round() / 100.0,
        top_attester,
    }
}

// ─── Category Filtering ─────────────────────────────────────────

/// Filter attestations by category.
pub fn filter_by_category(attestations: &[Attestation], category: Category) -> Vec<Attestation> {
    match category.types() {
        None => attestations.to_vec(),
        Some(types) => attestations
            .iter()
            .filter(|att| {
                if !types.contains(&att.attestation_type) {
                    return false;
                }
                if category.requires_content_filter() {
                    return att.content.to_lowercase().contains("code");
                }
                true
            })
            .cloned()
            .collect(),
    }
}

// ─── Core Scoring ───────────────────────────────────────────────

/// Calculate trust score from a set of attestations.
///
/// This is the core scoring function — a direct port of the JS `calculateTrustScore`.
///
/// `zap_totals`: map of event_id → total sats
/// `resolver`: provides attester trust scores for recursive scoring
/// `depth`: current recursion depth (start at 0)
pub fn calculate_trust_score(
    attestations: &[Attestation],
    zap_totals: &HashMap<String, u64>,
    config: &ScoringConfig,
    resolver: &dyn AttesterScoreResolver,
    depth: u32,
) -> TrustScore {
    // Deduplicate
    let deduped = deduplicate(attestations);

    // Build earliest-edge map for novelty detection
    let mut earliest_by_edge: HashMap<(String, String), u64> = HashMap::new();
    for att in attestations {
        let key = (att.attester.clone(), att.subject.clone());
        let entry = earliest_by_edge.entry(key).or_insert(att.created_at);
        if att.created_at < *entry {
            *entry = att.created_at;
        }
    }

    let mut raw_score = 0.0_f64;
    let mut breakdown = Vec::with_capacity(deduped.len());

    for att in &deduped {
        let att_type = att.attestation_type;
        let is_negative = att_type.is_negative();
        let type_mult = att_type.multiplier();

        // Negative attestations require non-empty content
        if is_negative && att.content.trim().is_empty() {
            breakdown.push(BreakdownEntry {
                attester: att.attester.clone(),
                attestation_type: att_type,
                zap_sats: 0,
                zap_weight: 0.0,
                decay_factor: 0.0,
                attester_trust: 0.0,
                type_multiplier: type_mult,
                contribution: 0.0,
                comment: String::new(),
                event_id: att.event_id.clone(),
                timestamp: att.created_at,
                gated: true,
                gate_reason: Some("empty content on negative attestation".into()),
                novelty_bonus: false,
            });
            continue;
        }

        // Zap weight
        let sats = zap_totals.get(&att.event_id).copied().unwrap_or(0);
        let z_weight = zap_weight(sats);

        // Temporal decay
        let decay = temporal_decay(att.created_at, config.half_life_days, config.now);

        // Attester trust (recursive)
        let mut attester_trust = 1.0_f64;
        let mut attester_display_score = 100_u32;

        if depth < config.max_depth {
            let attester_score = resolver.resolve(&att.attester, depth + 1);
            attester_display_score = attester_score.display;
            if attester_score.raw > 0.0 {
                attester_trust = attester_score.raw.powf(DAMPENING_FACTOR);
            }
        }

        // Gate negative attestations from low-trust attesters
        if is_negative && attester_display_score < config.negative_trust_gate {
            breakdown.push(BreakdownEntry {
                attester: att.attester.clone(),
                attestation_type: att_type,
                zap_sats: sats,
                zap_weight: round2(z_weight),
                decay_factor: round3(decay),
                attester_trust: round2(attester_trust),
                type_multiplier: type_mult,
                contribution: 0.0,
                comment: truncate(&att.content, 80),
                event_id: att.event_id.clone(),
                timestamp: att.created_at,
                gated: true,
                gate_reason: Some(format!(
                    "Attester trust {} < gate {}",
                    attester_display_score, config.negative_trust_gate
                )),
                novelty_bonus: false,
            });
            continue;
        }

        let mut contribution = z_weight * attester_trust * type_mult * decay;

        // Novelty bonus
        let edge_key = (att.attester.clone(), att.subject.clone());
        let is_novel = earliest_by_edge
            .get(&edge_key)
            .map_or(false, |&earliest| att.created_at == earliest);

        if is_novel && config.novelty_multiplier != 1.0 {
            contribution *= config.novelty_multiplier;
        }

        raw_score += contribution;

        breakdown.push(BreakdownEntry {
            attester: att.attester.clone(),
            attestation_type: att_type,
            zap_sats: sats,
            zap_weight: round2(z_weight),
            decay_factor: round3(decay),
            attester_trust: round2(attester_trust),
            type_multiplier: type_mult,
            contribution: round2(contribution),
            comment: truncate(&att.content, 80),
            event_id: att.event_id.clone(),
            timestamp: att.created_at,
            gated: false,
            gate_reason: None,
            novelty_bonus: is_novel,
        });
    }

    // Floor at 0
    let floored_raw = round2(raw_score.max(0.0));
    let display = ((raw_score.max(0.0) * 10.0).round() as u32).min(100);

    let non_gated: Vec<_> = breakdown.iter().filter(|b| !b.gated).cloned().collect();
    let diversity = calculate_diversity(&non_gated);

    TrustScore {
        raw: floored_raw,
        display,
        attestation_count: deduped.len(),
        positive_count: breakdown
            .iter()
            .filter(|b| !b.gated && b.contribution > 0.0)
            .count(),
        negative_count: breakdown
            .iter()
            .filter(|b| !b.gated && b.contribution < 0.0)
            .count(),
        gated_count: breakdown.iter().filter(|b| b.gated).count(),
        breakdown,
        diversity,
        category: None,
    }
}

/// Calculate trust score filtered by category.
pub fn calculate_category_score(
    attestations: &[Attestation],
    zap_totals: &HashMap<String, u64>,
    category: Category,
    config: &ScoringConfig,
    resolver: &dyn AttesterScoreResolver,
    depth: u32,
) -> TrustScore {
    let filtered = filter_by_category(attestations, category);
    let mut result = calculate_trust_score(&filtered, zap_totals, config, resolver, depth);
    result.category = Some(category);
    result
}

/// Calculate trust scores for all categories.
pub fn calculate_all_category_scores(
    attestations: &[Attestation],
    zap_totals: &HashMap<String, u64>,
    config: &ScoringConfig,
    resolver: &dyn AttesterScoreResolver,
    depth: u32,
) -> HashMap<Category, TrustScore> {
    Category::ALL
        .iter()
        .map(|&cat| {
            let score =
                calculate_category_score(attestations, zap_totals, cat, config, resolver, depth);
            (cat, score)
        })
        .collect()
}

// ─── Helpers ────────────────────────────────────────────────────

#[inline]
fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

#[inline]
fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        s[..max_len].to_string()
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_attestation(
        attester: &str,
        subject: &str,
        att_type: AttestationType,
        created_at: u64,
        content: &str,
    ) -> Attestation {
        Attestation {
            event_id: format!("evt_{}_{}", attester, created_at),
            attester: attester.to_string(),
            subject: subject.to_string(),
            attestation_type: att_type,
            created_at,
            content: content.to_string(),
        }
    }

    #[test]
    fn test_temporal_decay() {
        let now = 1000000;
        // Same time = no decay
        assert!((temporal_decay(now, 90.0, now) - 1.0).abs() < 1e-10);
        // 90 days later = 0.5
        let ninety_days = now + 90 * 86400;
        assert!((temporal_decay(now, 90.0, ninety_days) - 0.5).abs() < 1e-10);
        // 180 days = 0.25
        let one_eighty = now + 180 * 86400;
        assert!((temporal_decay(now, 90.0, one_eighty) - 0.25).abs() < 1e-10);
    }

    #[test]
    fn test_zap_weight() {
        assert_eq!(zap_weight(0), 1.0);
        // 100 sats: 1 + log2(101) * 0.5 ≈ 1 + 6.66 * 0.5 ≈ 4.33
        let w = zap_weight(100);
        assert!(w > 4.0 && w < 5.0);
    }

    #[test]
    fn test_empty_attestations() {
        let resolver = NoOpResolver;
        let config = ScoringConfig::default();
        let zaps = HashMap::new();
        let score = calculate_trust_score(&[], &zaps, &config, &resolver, 0);
        assert_eq!(score.raw, 0.0);
        assert_eq!(score.display, 0);
        assert_eq!(score.attestation_count, 0);
    }

    #[test]
    fn test_single_attestation() {
        let now = 1700000000;
        let config = ScoringConfig {
            now,
            ..Default::default()
        };
        let resolver = NoOpResolver;
        let zaps = HashMap::new();

        let atts = vec![make_attestation(
            "alice",
            "bob",
            AttestationType::ServiceQuality,
            now,
            "Great service",
        )];

        let score = calculate_trust_score(&atts, &zaps, &config, &resolver, 0);
        assert_eq!(score.attestation_count, 1);
        assert_eq!(score.positive_count, 1);
        assert!(score.raw > 0.0);
        assert!(score.display > 0);
    }

    #[test]
    fn test_negative_attestation_gated() {
        let now = 1700000000;
        let config = ScoringConfig {
            now,
            negative_trust_gate: 20,
            ..Default::default()
        };

        // Resolver returns low trust for the attester
        let mut scores = HashMap::new();
        scores.insert(
            "low_trust".to_string(),
            TrustScore {
                raw: 0.5,
                display: 5,
                attestation_count: 1,
                positive_count: 1,
                negative_count: 0,
                gated_count: 0,
                breakdown: vec![],
                diversity: DiversityScore::default(),
                category: None,
            },
        );
        let resolver = MapResolver { scores };
        let zaps = HashMap::new();

        let atts = vec![make_attestation(
            "low_trust",
            "target",
            AttestationType::Dispute,
            now,
            "Bad agent",
        )];

        let score = calculate_trust_score(&atts, &zaps, &config, &resolver, 0);
        assert_eq!(score.gated_count, 1);
        assert_eq!(score.negative_count, 0);
        assert_eq!(score.raw, 0.0);
    }

    #[test]
    fn test_deduplication() {
        let atts = vec![
            make_attestation("alice", "bob", AttestationType::ServiceQuality, 100, "v1"),
            make_attestation("alice", "bob", AttestationType::ServiceQuality, 200, "v2"),
            make_attestation("alice", "bob", AttestationType::GeneralTrust, 150, "other"),
        ];

        let deduped = deduplicate(&atts);
        assert_eq!(deduped.len(), 2);

        // The service-quality one should be the newer one
        let sq = deduped
            .iter()
            .find(|a| a.attestation_type == AttestationType::ServiceQuality)
            .unwrap();
        assert_eq!(sq.created_at, 200);
        assert_eq!(sq.content, "v2");
    }

    #[test]
    fn test_diversity_single_attester() {
        let now = 1700000000;
        let config = ScoringConfig {
            now,
            ..Default::default()
        };
        let resolver = NoOpResolver;
        let zaps = HashMap::new();

        let atts = vec![
            make_attestation("alice", "bob", AttestationType::ServiceQuality, now, "a"),
            make_attestation("alice", "bob", AttestationType::GeneralTrust, now, "b"),
        ];

        let score = calculate_trust_score(&atts, &zaps, &config, &resolver, 0);
        // Single attester → diversity should be 0 (max_share = 1.0, so 1-1=0)
        assert_eq!(score.diversity.unique_attesters, 1);
        assert_eq!(score.diversity.diversity, 0.0);
    }

    #[test]
    fn test_diversity_multiple_attesters() {
        let now = 1700000000;
        let config = ScoringConfig {
            now,
            ..Default::default()
        };
        let resolver = NoOpResolver;
        let zaps = HashMap::new();

        let atts = vec![
            make_attestation("alice", "bob", AttestationType::ServiceQuality, now, "a"),
            make_attestation("carol", "bob", AttestationType::ServiceQuality, now, "b"),
            make_attestation("dave", "bob", AttestationType::ServiceQuality, now, "c"),
        ];

        let score = calculate_trust_score(&atts, &zaps, &config, &resolver, 0);
        assert_eq!(score.diversity.unique_attesters, 3);
        assert!(score.diversity.diversity > 0.5);
    }

    #[test]
    fn test_category_filtering() {
        let atts = vec![
            make_attestation("a", "b", AttestationType::WorkCompleted, 100, "work"),
            make_attestation("a", "b", AttestationType::ServiceQuality, 100, "code review"),
            make_attestation("a", "b", AttestationType::IdentityContinuity, 100, "id"),
            make_attestation("a", "b", AttestationType::GeneralTrust, 100, "general"),
        ];

        let commerce = filter_by_category(&atts, Category::Commerce);
        assert_eq!(commerce.len(), 2); // work-completed + service-quality

        let identity = filter_by_category(&atts, Category::Identity);
        assert_eq!(identity.len(), 1);

        let code = filter_by_category(&atts, Category::Code);
        assert_eq!(code.len(), 1); // service-quality with "code" in content

        let general = filter_by_category(&atts, Category::General);
        assert_eq!(general.len(), 4);
    }

    #[test]
    fn test_zap_weighted_score() {
        let now = 1700000000;
        let config = ScoringConfig {
            now,
            ..Default::default()
        };
        let resolver = NoOpResolver;

        // Without zaps
        let atts = vec![make_attestation(
            "alice",
            "bob",
            AttestationType::ServiceQuality,
            now,
            "good",
        )];

        let no_zaps = HashMap::new();
        let score_no_zap = calculate_trust_score(&atts, &no_zaps, &config, &resolver, 0);

        // With 1000 sats zap
        let mut with_zaps = HashMap::new();
        with_zaps.insert(format!("evt_alice_{}", now), 1000);
        let score_zapped = calculate_trust_score(&atts, &with_zaps, &config, &resolver, 0);

        // Zapped score should be higher
        assert!(score_zapped.raw > score_no_zap.raw);
    }

    #[test]
    fn test_novelty_bonus() {
        let now = 1700000000;

        // Config with novelty
        let config_with = ScoringConfig {
            now,
            novelty_multiplier: 1.3,
            ..Default::default()
        };

        // Config without novelty
        let config_without = ScoringConfig {
            now,
            novelty_multiplier: 1.0,
            ..Default::default()
        };

        let resolver = NoOpResolver;
        let zaps = HashMap::new();

        let atts = vec![make_attestation(
            "alice",
            "bob",
            AttestationType::ServiceQuality,
            now,
            "first",
        )];

        let with_novelty = calculate_trust_score(&atts, &zaps, &config_with, &resolver, 0);
        let without_novelty = calculate_trust_score(&atts, &zaps, &config_without, &resolver, 0);

        assert!(with_novelty.raw > without_novelty.raw);
    }
}
