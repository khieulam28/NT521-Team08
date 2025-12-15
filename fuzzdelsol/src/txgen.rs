use crate::emulator::BlockchainEmulator;
use crate::types::{InstrAccountMeta, Instruction, Transaction};
use solana_sdk::pubkey::Pubkey;
use std::collections::BTreeSet;

pub struct TxGenerator;

impl TxGenerator {
    pub fn from_bytes(bytes: &[u8], emu: &BlockchainEmulator, program_id: Pubkey) -> Transaction {
        // Layout (lite):
        // [0] = n_accounts (1..=8)
        // [1] = signer mask (bit0=attacker, bit1=user)
        // [2] = mode byte (controls benign/malicious ratio + writable ratio)
        // next n bytes = indices
        // rest = ix.data

        let mut idx = 0usize;

        let n_raw = bytes.get(idx).copied().unwrap_or(3);
        idx += 1;
        let n_accounts = (n_raw % 8).max(1) as usize;

        // default signer mask: nhẹ hơn (tránh luôn attacker+user)
        let signer_mask = bytes.get(idx).copied().unwrap_or(0x1);
        idx += 1;

        // mode controls ratios
        let mode = bytes.get(idx).copied().unwrap_or(0x22);
        idx += 1;

        // Ratios:
        // malicious_ratio in {1/8, 1/4, 3/8} depending on mode bits
        let mal_mod = match (mode >> 6) & 0x3 {
            0 => 8,
            1 => 4,
            _ => 3, // ~1/3
        };

        // writable_ratio: 1/4 or 1/3
        let writable_mod = if (mode & 0x20) != 0 { 3 } else { 4 };

        // Build account pool partitions:
        // - benign pool: accounts (excluding attacker/user) that we *intend* to be program-owned in snapshot
        //   In emulator.rs owner is based on first byte parity; we can bias by choosing "even first byte" pubkeys.
        let mut benign_pool: Vec<Pubkey> = Vec::new();
        let mut malicious_pool: Vec<Pubkey> = Vec::new();

        for &k in &emu.selectable_accounts {
            if k == emu.attacker || k == emu.user {
                continue;
            }
            let attacker_controlled = (k.to_bytes()[0] & 1) == 1;
            if attacker_controlled {
                malicious_pool.push(k);
            } else {
                benign_pool.push(k);
            }
        }

        // Fallback nếu pool rỗng (hiếm)
        if benign_pool.is_empty() {
            benign_pool = emu
                .selectable_accounts
                .iter()
                .copied()
                .filter(|k| *k != emu.attacker && *k != emu.user)
                .collect();
        }
        if malicious_pool.is_empty() {
            malicious_pool = benign_pool.clone();
        }

        // Choose accounts with controlled ratio:
        // - mostly benign
        // - sometimes malicious
        let mut chosen: Vec<Pubkey> = Vec::new();
        for j in 0..n_accounts {
            let b = bytes.get(idx).copied().unwrap_or((j as u8).wrapping_mul(17));
            idx += 1;

            let take_malicious = (b as usize % mal_mod) == 0;
            let pool = if take_malicious { &malicious_pool } else { &benign_pool };

            let ai = (b as usize) % pool.len();
            chosen.push(pool[ai]);
        }

        // ensure attacker + user present (but not too aggressively)
        // always include user; include attacker only if bit0 set OR every ~4 cases
        chosen.push(emu.user);
        if (signer_mask & 1) != 0 || (mode & 0x10) != 0 {
            chosen.push(emu.attacker);
        }

        // dedup + sort
        chosen.sort();
        chosen.dedup();

        // signer set
        let mut signers = BTreeSet::new();
        if (signer_mask & 1) != 0 {
            signers.insert(emu.attacker);
        }
        if (signer_mask & 2) != 0 {
            signers.insert(emu.user);
        }

        // account metas:
        // - writable NOT for all (reduces MSC/MOC spam)
        // - keep attacker/user usually writable (realistic)
        let accounts = chosen
            .iter()
            .enumerate()
            .map(|(pos, k)| {
                let mut is_writable = ((pos + (mode as usize)) % writable_mod) == 0;

                // attacker/user more likely writable
                if *k == emu.attacker || *k == emu.user {
                    is_writable = true;
                }

                InstrAccountMeta {
                    pubkey: *k,
                    is_signer: signers.contains(k),
                    is_writable,
                }
            })
            .collect::<Vec<_>>();

        let data = bytes.get(idx..).unwrap_or(&[]).to_vec();

        let ix = Instruction {
            program_id,
            accounts,
            data,
        };

        Transaction {
            signers,
            all_accounts_sorted: chosen,
            instruction: ix,
        }
    }
}
