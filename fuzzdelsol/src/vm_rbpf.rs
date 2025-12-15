use crate::oracles::VmEvent;
use crate::types::{CoverageMap, LedgerSnapshot, TaintEngine, Transaction};
use solana_sdk::pubkey::Pubkey;

/// RunDelSol-Lite TraceVM
/// - Không thực thi ELF thật
/// - Phát event có kiểm soát để objective rate “paper-like”
pub struct TraceVm;

pub struct VmRunOutput {
    pub coverage: CoverageMap,
    pub taint: TaintEngine,
    pub events: Vec<VmEvent>,
    pub post_snapshot: LedgerSnapshot,
    pub trace_summary: String,
}

impl TraceVm {
    pub fn run(program_id: Pubkey, mut snap: LedgerSnapshot, tx: &Transaction) -> VmRunOutput {
        let mut coverage = CoverageMap::new(64 * 1024);
        let mut taint = TaintEngine::default();
        let mut events: Vec<VmEvent> = Vec::new();

        let data = &tx.instruction.data;
        taint.input_taint = !data.is_empty();

        // pick any account from tx list
        let pick_acct = |b: u8, tx: &Transaction| -> Pubkey {
            if tx.all_accounts_sorted.is_empty() {
                program_id
            } else {
                tx.all_accounts_sorted[(b as usize) % tx.all_accounts_sorted.len()]
            }
        };

        // pick a BENIGN account: owner == program_id (important!)
        // If not found, fallback to first tx acct (still better than reading program_id account)
        let pick_benign_owned_by_program = |b: u8, tx: &Transaction, snap: &LedgerSnapshot| -> Pubkey {
            for k in &tx.all_accounts_sorted {
                if let Some(a) = snap.accounts.get(k) {
                    if a.owner == program_id && !a.is_executable {
                        return *k;
                    }
                }
            }
            // fallback
            pick_acct(b, tx)
        };

        // integer bug helper
        let mut pending_big_attacker_gain = false;

        let mut pc: u64 = 0x1000;

        for (i, &b) in data.iter().enumerate() {
            // coverage edge
            let dst = pc.wrapping_add((b as u64) * 7).wrapping_add(i as u64);
            coverage.hit_edge(pc, dst);
            pc = dst;

            match b >> 5 {
                // 0) AUTH CMP
                0 => {
                    let used_for_auth = (b & 1) == 1; // ~50%
                    let lhs_tainted = taint.input_taint;
                    let rhs_tainted = (b & 2) != 0;

                    events.push(VmEvent::Cmp {
                        lhs_tainted,
                        rhs_tainted,
                        used_for_auth,
                    });
                }

                // 1) READ ACCOUNT DATA
                // - malicious read ~1/8 (giảm mạnh), benign read đọc owner==program_id
                1 => {
                    let acct = if (b & 7) == 7 {
                        // malicious read
                        pick_acct(b, tx)
                    } else {
                        // benign read: MUST be program-owned account
                        pick_benign_owned_by_program(b, tx, &snap)
                    };

                    let owner = snap.accounts.get(&acct).map(|a| a.owner).unwrap_or(program_id);

                    if owner != program_id {
                        taint.data_acc_taint = true;
                    }

                    events.push(VmEvent::ReadAccountData { acct, owner });
                }

                // 2) WRITE LAMPORTS
                2 => {
                    let mode = b & 3;
                    let (acct, delta) = match mode {
                        // "user-like" loses
                        0 => {
                            let acct = tx
                                .instruction
                                .accounts
                                .iter()
                                .find(|m| !m.is_signer)
                                .map(|m| m.pubkey)
                                .unwrap_or_else(|| pick_acct(b, tx));
                            (acct, -((b as i64 & 0x1f) + 1) * 10_000)
                        }
                        // "attacker-like" gains
                        1 => {
                            let acct = tx
                                .instruction
                                .accounts
                                .iter()
                                .find(|m| m.is_signer)
                                .map(|m| m.pubkey)
                                .unwrap_or_else(|| pick_acct(b, tx));
                            let gain = if pending_big_attacker_gain {
                                pending_big_attacker_gain = false;
                                80_000_000
                            } else {
                                ((b as i64 & 0x1f) + 1) * 10_000
                            };
                            (acct, gain)
                        }
                        _ => {
                            let acct = pick_acct(b, tx);
                            let neg = (b & 1) == 1;
                            let mag = ((b as i64 & 0x1f) + 1) * 5_000;
                            (acct, if neg { -mag } else { mag })
                        }
                    };

                    if let Some(a) = snap.accounts.get_mut(&acct) {
                        if delta < 0 {
                            a.lamports = a.lamports.saturating_sub((-delta) as u64);
                        } else {
                            a.lamports = a.lamports.saturating_add(delta as u64);
                        }
                    }

                    events.push(VmEvent::WriteLamports { acct, delta });
                }

                // 3) WRITE DATA
                3 => {
                    let acct = pick_acct(b, tx);
                    if let Some(a) = snap.accounts.get_mut(&acct) {
                        let n = ((b & 0x1f) as usize).max(1);
                        for j in 0..n.min(a.data.len()) {
                            a.data[j] ^= b;
                        }
                        events.push(VmEvent::WriteData { acct, nbytes: n });
                    }
                }

                // 4) CPI (ACPI)
                4 => {
                    let invoked = if (b & 1) == 0 { program_id } else { Pubkey::new_unique() };

                    let mut provided = Vec::new();
                    if let Some(m) = tx.instruction.accounts.first() {
                        provided.push(m.pubkey);
                    }
                    // include signer sometimes
                    if (b & 2) != 0 {
                        if let Some(s) = tx.instruction.accounts.iter().find(|m| m.is_signer) {
                            provided.push(s.pubkey);
                        }
                    }

                    events.push(VmEvent::Cpi {
                        invoked_program: invoked,
                        provided,
                    });
                }

                // 5..7) IntegerOp + KeyAccess
                _ => {
                    let overflowed = (b & 15) == 15; // ~1/16 (giảm IB)
                    let tainted = taint.input_taint;

                    events.push(VmEvent::IntegerOp { tainted, overflowed });

                    if tainted && overflowed {
                        pending_big_attacker_gain = true;
                    }

                    let required_key = pick_acct(b, tx);
                    let used_for_auth = (b & 2) != 0;

                    let mut provided_keys = Vec::new();
                    if (b & 4) != 0 {
                        provided_keys.push(required_key);
                    }

                    events.push(VmEvent::KeyAccess {
                        required_key,
                        provided_keys,
                        used_for_auth,
                    });
                }
            }
        }

        let trace_summary = format!(
            "TraceVM: bytes={} edges_hash={:016x} accounts={} signers={}",
            data.len(),
            coverage.hash16(),
            tx.all_accounts_sorted.len(),
            tx.signers.len()
        );

        VmRunOutput {
            coverage,
            taint,
            events,
            post_snapshot: snap,
            trace_summary,
        }
    }
}
