use solana_sdk::pubkey::Pubkey;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug)]
pub struct Account {
    // pubkey field bị warning vì không dùng -> bỏ luôn
    pub owner: Pubkey,
    pub lamports: u64,
    pub data: Vec<u8>,
    pub is_signer: bool,
    pub is_writable: bool,
    pub is_executable: bool,
}

#[derive(Clone, Debug)]
pub struct LedgerSnapshot {
    #[allow(dead_code)]
    pub program_id: Pubkey,
    pub accounts: BTreeMap<Pubkey, Account>,
}

impl LedgerSnapshot {
    #[allow(dead_code)]
    pub fn get_mut(&mut self, k: &Pubkey) -> Option<&mut Account> {
        self.accounts.get_mut(k)
    }
}

#[derive(Clone, Debug)]
pub struct InstrAccountMeta {
    #[allow(dead_code)]
    pub pubkey: Pubkey,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Clone, Debug)]
pub struct Instruction {
    pub program_id: Pubkey,
    pub accounts: Vec<InstrAccountMeta>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Transaction {
    pub signers: BTreeSet<Pubkey>,
    pub all_accounts_sorted: Vec<Pubkey>,
    pub instruction: Instruction,
}

/// Coverage map: edge = (src + dst) % size
#[derive(Clone, Debug)]
pub struct CoverageMap {
    pub size: usize,
    pub hits: Vec<u32>,
}

impl CoverageMap {
    pub fn new(size: usize) -> Self {
        Self {
            size,
            hits: vec![0; size],
        }
    }

    pub fn hit_edge(&mut self, src: u64, dst: u64) {
        let idx = ((src.wrapping_add(dst)) as usize) % self.size;
        self.hits[idx] = self.hits[idx].saturating_add(1);
    }

    pub fn hash16(&self) -> u64 {
        // cheap stable hash
        let mut h: u64 = 1469598103934665603;
        for &v in &self.hits {
            h ^= v as u64;
            h = h.wrapping_mul(1099511628211);
        }
        h
    }
}

#[derive(Clone, Debug, Default)]
pub struct TaintEngine {
    // keep for future rbpf hook; currently unused in TraceVM -> allow dead_code
    #[allow(dead_code)]
    pub reg_taint: [bool; 16],
    #[allow(dead_code)]
    pub heap_taint: bool,

    pub input_taint: bool,
    pub data_acc_taint: bool,
}

#[derive(Clone, Debug)]
pub struct OracleSignals {
    pub msc: bool,
    pub moc: bool,
    pub acpi: bool,
    pub mkc: bool,
    pub ib: bool,
    pub lamports_theft: bool,
}

impl OracleSignals {
    pub fn any(&self) -> bool {
        self.msc || self.moc || self.acpi || self.mkc || self.ib || self.lamports_theft
    }

    pub fn class(&self) -> &'static str {
        if self.lamports_theft {
            "LAMPORTS_THEFT"
        } else if self.moc {
            "MOC"
        } else if self.msc {
            "MSC"
        } else if self.acpi {
            "ACPI"
        } else if self.mkc {
            "MKC"
        } else if self.ib {
            "IB"
        } else {
            "NONE"
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ExtractedSemantics {
    pub new_pda_seed_hint: Option<Vec<u8>>,
    pub new_account_layout_hint: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct ExecResult {
    pub coverage: CoverageMap,
    pub signals: OracleSignals,

    // evaluator currently doesn't read semantics from exec; keep but allow dead_code
    #[allow(dead_code)]
    pub semantics: ExtractedSemantics,

    pub tx: Transaction,
    pub pre_snapshot: LedgerSnapshot,
    pub post_snapshot: LedgerSnapshot,
    pub trace_summary: String,
}

#[derive(Clone, Debug)]
pub struct VulnReport {
    pub vuln_class: String,
    pub tx_payload_hex: String,
    pub global_state_before: String,
    pub global_state_after: String,
    pub trace_summary: String,
}

pub fn hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn snapshot_to_string(s: &LedgerSnapshot) -> String {
    let mut lines = Vec::new();
    for (k, a) in &s.accounts {
        lines.push(format!(
            "{} owner={} lamports={} data_len={} signer={} writable={} exec={}",
            k,
            a.owner,
            a.lamports,
            a.data.len(),
            a.is_signer,
            a.is_writable,
            a.is_executable
        ));
    }
    lines.join("\n")
}
