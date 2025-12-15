use crate::types::{hex, snapshot_to_string, ExecResult, ExtractedSemantics, VulnReport};

pub struct TransactionEvaluator;

pub struct EvalOutcome {
    #[allow(dead_code)]
    pub is_new_coverage: bool,
    pub is_objective: bool,
    pub report: Option<VulnReport>,
    pub semantics: ExtractedSemantics,
}

impl TransactionEvaluator {
    pub fn evaluate(exec: &ExecResult, best_cov_hash: &mut u64) -> EvalOutcome {
        let cov_hash = exec.coverage.hash16();
        let is_new_coverage = cov_hash != *best_cov_hash;
        if is_new_coverage {
            *best_cov_hash = cov_hash;
        }

        let is_objective = exec.signals.any();
        let report = if is_objective {
            Some(VulnReport {
                vuln_class: exec.signals.class().to_string(),
                tx_payload_hex: hex(&exec.tx.instruction.data),
                global_state_before: snapshot_to_string(&exec.pre_snapshot),
                global_state_after: snapshot_to_string(&exec.post_snapshot),
                trace_summary: exec.trace_summary.clone(),
            })
        } else {
            None
        };

        // semantic extractors (lite):
        // if we saw objective or new coverage, generate seed/layout hints from payload
        let mut semantics = ExtractedSemantics::default();
        if is_new_coverage && !exec.tx.instruction.data.is_empty() {
            // seed hint: first 8 bytes
            semantics.new_pda_seed_hint = Some(exec.tx.instruction.data.iter().take(8).copied().collect());
        }
        if is_objective && exec.tx.instruction.data.len() >= 8 {
            // layout hint: last 8 bytes
            semantics.new_account_layout_hint = Some(exec.tx.instruction.data.iter().rev().take(8).copied().collect());
        }

        EvalOutcome { is_new_coverage, is_objective, report, semantics }
    }
}
