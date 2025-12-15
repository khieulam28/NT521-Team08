use crate::types::{LedgerSnapshot, OracleSignals, TaintEngine, Transaction};
use solana_sdk::pubkey::Pubkey;
use std::collections::BTreeSet;

#[derive(Clone, Debug)]
pub struct OracleContext {
    pub program_id: Pubkey,
    pub attacker: Pubkey,
    pub user: Pubkey,
}

/// VM events
#[derive(Clone, Debug)]
pub enum VmEvent {
    Cmp {
        lhs_tainted: bool,
        rhs_tainted: bool,
        used_for_auth: bool,
    },
    ReadAccountData {
        acct: Pubkey,
        owner: Pubkey,
    },
    WriteLamports {
        acct: Pubkey,
        delta: i64,
    },
    WriteData {
        acct: Pubkey,
        nbytes: usize,
    },
    Cpi {
        invoked_program: Pubkey,
        provided: Vec<Pubkey>,
    },
    KeyAccess {
        required_key: Pubkey,
        provided_keys: Vec<Pubkey>,
        used_for_auth: bool,
    },
    IntegerOp {
        tainted: bool,
        overflowed: bool,
    },
}

pub struct Oracles {
    ctx: OracleContext,

    // auth gating
    saw_auth_cmp: bool,
    saw_auth_cmp_with_taint: bool,

    // 핵심 fix: auth decision depends on malicious-owner data
    auth_depends_on_malicious: bool,

    // MSC candidates: writable but not signer
    msc_candidates: BTreeSet<Pubkey>,

    // MOC malicious reads
    moc_malicious_reads: BTreeSet<Pubkey>,

    // modified accounts
    modified_accounts: BTreeSet<Pubkey>,

    // lamports baseline
    pre_user_lamports: u64,
    pre_attacker_lamports: u64,

    // integer bug
    saw_tainted_overflow: bool,
}

impl Oracles {
    pub fn new(ctx: OracleContext, pre: &LedgerSnapshot) -> Self {
        let pre_user_lamports = pre.accounts.get(&ctx.user).map(|a| a.lamports).unwrap_or(0);
        let pre_attacker_lamports = pre
            .accounts
            .get(&ctx.attacker)
            .map(|a| a.lamports)
            .unwrap_or(0);

        Self {
            ctx,
            saw_auth_cmp: false,
            saw_auth_cmp_with_taint: false,
            auth_depends_on_malicious: false,
            msc_candidates: BTreeSet::new(),
            moc_malicious_reads: BTreeSet::new(),
            modified_accounts: BTreeSet::new(),
            pre_user_lamports,
            pre_attacker_lamports,
            saw_tainted_overflow: false,
        }
    }

    pub fn process_event(
        &mut self,
        tx: &Transaction,
        taint: &TaintEngine,
        _pre: &LedgerSnapshot,
        _post: &LedgerSnapshot,
        ev: VmEvent,
        signals: &mut OracleSignals,
    ) {
        match ev {
            VmEvent::Cmp {
                lhs_tainted,
                rhs_tainted,
                used_for_auth,
            } => {
                if used_for_auth {
                    self.saw_auth_cmp = true;

                    // "tainted auth compare" (input/data taint)
                    if lhs_tainted || rhs_tainted || taint.input_taint || taint.data_acc_taint {
                        self.saw_auth_cmp_with_taint = true;
                    }

                    // 핵심 FIX (2): auth depends on malicious-owner data
                    // only if we have malicious reads AND tainted compare
                    if !self.moc_malicious_reads.is_empty()
                        && (lhs_tainted || rhs_tainted || taint.data_acc_taint)
                    {
                        self.auth_depends_on_malicious = true;
                    }

                    // MSC candidates: writable non-signer
                    for m in &tx.instruction.accounts {
                        if m.is_writable && !m.is_signer {
                            self.msc_candidates.insert(m.pubkey);
                        }
                    }
                }
            }

            VmEvent::ReadAccountData { acct, owner } => {
                if owner != self.ctx.program_id {
                    self.moc_malicious_reads.insert(acct);
                }
            }

            VmEvent::WriteLamports { acct, delta: _delta } => {
                self.modified_accounts.insert(acct);
            }

            VmEvent::WriteData { acct, nbytes: _nbytes } => {
                // _nbytes to silence warning
                self.modified_accounts.insert(acct);
            }

            // ACPI: only signal if auth tainted exists and attacker involved
            VmEvent::Cpi {
                invoked_program,
                provided,
            } => {
                let allowed = invoked_program == self.ctx.program_id;
                if !allowed && self.saw_auth_cmp_with_taint && provided.contains(&self.ctx.attacker) {
                    signals.acpi = true;
                }
            }

            // MKC: only when used_for_auth
            VmEvent::KeyAccess {
                required_key,
                provided_keys,
                used_for_auth,
            } => {
                if used_for_auth {
                    let ok = provided_keys.contains(&required_key);
                    let required_is_signer = tx.signers.contains(&required_key);
                    if !ok && !required_is_signer {
                        signals.mkc = true;
                    }
                }
            }

            VmEvent::IntegerOp { tainted, overflowed } => {
                if tainted && overflowed {
                    self.saw_tainted_overflow = true;
                }
            }
        }
    }

    pub fn finalize(
        &mut self,
        tx: &Transaction,
        pre: &LedgerSnapshot,
        post: &LedgerSnapshot,
        signals: &mut OracleSignals,
    ) {
        // ---------- MSC ----------
        // paper-like: need tainted auth cmp + actual harm to non-signer writable acct
        if self.saw_auth_cmp_with_taint {
            for acct in self.modified_accounts.iter() {
                if self.msc_candidates.contains(acct) {
                    let pre_l = pre.accounts.get(acct).map(|a| a.lamports).unwrap_or(0);
                    let post_l = post.accounts.get(acct).map(|a| a.lamports).unwrap_or(pre_l);
                    if post_l < pre_l {
                        signals.msc = true;
                        break;
                    }
                }
            }
        }

        // ---------- MOC (FIXED RATE) ----------
        // paper-correct: auth compare exists AND it depends on malicious-owner data AND victim modified
        if self.saw_auth_cmp && self.auth_depends_on_malicious {
            for acct in self.modified_accounts.iter() {
                if *acct != self.ctx.attacker {
                    let in_metas = tx
                        .instruction
                        .accounts
                        .iter()
                        .any(|m| m.pubkey == *acct && m.is_writable);
                    if in_metas {
                        signals.moc = true;
                        break;
                    }
                }
            }
        }

        // ---------- Lamports-theft ----------
        if tx.signers.contains(&self.ctx.attacker) {
            let pre_user = pre
                .accounts
                .get(&self.ctx.user)
                .map(|a| a.lamports)
                .unwrap_or(self.pre_user_lamports);
            let pre_att = pre
                .accounts
                .get(&self.ctx.attacker)
                .map(|a| a.lamports)
                .unwrap_or(self.pre_attacker_lamports);

            let post_user = post.accounts.get(&self.ctx.user).map(|a| a.lamports).unwrap_or(pre_user);
            let post_att = post
                .accounts
                .get(&self.ctx.attacker)
                .map(|a| a.lamports)
                .unwrap_or(pre_att);

            if post_user < pre_user && post_att > pre_att {
                signals.lamports_theft = true;
            }
        }

        // ---------- Integer Bugs ----------
        if self.saw_tainted_overflow {
            let post_att = post.accounts.get(&self.ctx.attacker).map(|a| a.lamports).unwrap_or(0);
            if post_att > self.pre_attacker_lamports.saturating_add(50_000_000) {
                signals.ib = true;
            }
        }
    }
}
