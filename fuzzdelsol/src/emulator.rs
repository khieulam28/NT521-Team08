use crate::types::{Account, ExtractedSemantics, LedgerSnapshot};
use solana_sdk::{pubkey::Pubkey, system_program};
use std::collections::BTreeMap;

/// Blockchain Emulator (paper-aligned, lite)
pub struct BlockchainEmulator {
    pub attacker: Pubkey,
    pub user: Pubkey,
    pub selectable_accounts: Vec<Pubkey>,

    // semantic feedback (lite)
    pub semantic_seed_hint: Vec<u8>,
    pub semantic_layout_hint: Vec<u8>,
}

impl BlockchainEmulator {
    pub fn new() -> Self {
        let attacker = Pubkey::new_unique();
        let user = Pubkey::new_unique();

        // pool accounts cho TxGen chọn
        let mut selectable = Vec::new();
        selectable.push(attacker);
        selectable.push(user);
        for _ in 0..14 {
            selectable.push(Pubkey::new_unique());
        }

        Self {
            attacker,
            user,
            selectable_accounts: selectable,
            semantic_seed_hint: vec![],
            semantic_layout_hint: vec![],
        }
    }

    /// Nhận semantic feedback từ evaluator
    pub fn update_semantics(&mut self, sem: &ExtractedSemantics) {
        if let Some(x) = &sem.new_pda_seed_hint {
            self.semantic_seed_hint = x.clone();
        }
        if let Some(x) = &sem.new_account_layout_hint {
            self.semantic_layout_hint = x.clone();
        }
    }

    /// Build ledger snapshot (paper: Blockchain Emulator)
    pub fn build_snapshot(&self, program_id: Pubkey, program_elf_bytes: &[u8]) -> LedgerSnapshot {
        let mut accounts: BTreeMap<Pubkey, Account> = BTreeMap::new();

        // 1) attacker & user wallets (system owned)
        accounts.insert(
            self.attacker,
            Account {
                owner: system_program::id(),
                lamports: 1_000_000_000,
                data: vec![],
                is_signer: true,
                is_writable: true,
                is_executable: false,
            },
        );

        accounts.insert(
            self.user,
            Account {
                owner: system_program::id(),
                lamports: 1_000_000_000,
                data: vec![],
                is_signer: true,
                is_writable: true,
                is_executable: false,
            },
        );

        // 2) program account (executable)
        accounts.insert(
            program_id,
            Account {
                owner: system_program::id(), // simplified
                lamports: 1,
                data: program_elf_bytes.to_vec(),
                is_signer: false,
                is_writable: false,
                is_executable: true,
            },
        );

        // 3) Other accounts: mix of honest + attacker-controlled owners
        for &k in &self.selectable_accounts {
            if k == self.attacker || k == self.user || k == program_id {
                continue;
            }

            // owner assignment helps MOC logic
            let attacker_controlled = (k.to_bytes()[0] & 1) == 1;
            let owner = if attacker_controlled {
                Pubkey::new_unique() // malicious owner != program_id
            } else {
                program_id
            };

            let mut data = vec![0u8; 64];

            // seed hints affect initial data shape (semantic feedback loop)
            if !self.semantic_seed_hint.is_empty() {
                let len = data.len();
                for (i, b) in self.semantic_seed_hint.iter().enumerate().take(len) {
                    data[i] ^= *b;
                }
            }

            if !self.semantic_layout_hint.is_empty() {
                let len = data.len();
                for (i, b) in self.semantic_layout_hint.iter().enumerate().take(len) {
                    let pos = (len - 1 - i) % len;
                    data[pos] ^= *b;
                }
            }

            accounts.insert(
                k,
                Account {
                    owner,
                    lamports: 100_000_000,
                    data,
                    is_signer: false,
                    is_writable: true,
                    is_executable: false,
                },
            );
        }

        LedgerSnapshot { program_id, accounts }
    }
}
