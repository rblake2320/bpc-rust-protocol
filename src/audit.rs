use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{BpcError, Result};

/// Hash used as the predecessor of the first audit entry.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Upper bound for one in-process audit-chain verification. Older histories
/// should be checked in bounded segments against independently anchored heads.
pub const DEFAULT_AUDIT_VERIFY_MAX_ENTRIES: usize = 100_000;

/// Security-relevant events recorded by the BPC audit chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    VerifyPass,
    VerifyFail,
    Register,
    Approve,
    Revoke,
    Rotate,
    Lockout,
    Unlock,
    Expire,
    UsageCapExhausted,
}

impl AuditAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VerifyPass => "verify_pass",
            Self::VerifyFail => "verify_fail",
            Self::Register => "register",
            Self::Approve => "approve",
            Self::Revoke => "revoke",
            Self::Rotate => "rotate",
            Self::Lockout => "lockout",
            Self::Unlock => "unlock",
            Self::Expire => "expire",
            Self::UsageCapExhausted => "usage_cap_exhausted",
        }
    }
}

/// Normalized audit severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    Info,
    Warn,
    Critical,
}

impl AuditSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Critical => "critical",
        }
    }
}

/// Caller-controlled audit data. It never accepts key material or request bodies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub action: AuditAction,
    pub severity: AuditSeverity,
    pub pair_id: Option<String>,
    pub error_code: Option<String>,
    pub source_ip: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub request_id: Option<String>,
    /// Bounded, caller-sanitized operational context. Do not include secrets.
    pub detail: Option<String>,
}

impl AuditEvent {
    pub fn validate(&self) -> Result<()> {
        for (field, value, limit) in [
            ("pair_id", self.pair_id.as_deref(), 64),
            ("error_code", self.error_code.as_deref(), 128),
            ("source_ip", self.source_ip.as_deref(), 128),
            ("method", self.method.as_deref(), 16),
            ("path", self.path.as_deref(), 2048),
            ("request_id", self.request_id.as_deref(), 256),
            ("detail", self.detail.as_deref(), 4096),
        ] {
            if value.is_some_and(|value| value.is_empty() || value.len() > limit) {
                return Err(BpcError::PairRegistry(format!(
                    "audit {field} is empty or exceeds its maximum length"
                )));
            }
        }
        Ok(())
    }
}

/// One append-only, hash-chained BPC audit record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp_ms: u64,
    pub sequence: u64,
    pub previous_hash: String,
    pub chain_hash: String,
    #[serde(flatten)]
    pub event: AuditEvent,
}

/// A chain head that should be signed/anchored independently of the primary database.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditHead {
    pub sequence: u64,
    pub chain_hash: String,
    pub count: u64,
}

/// Detailed audit verification status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditVerification {
    pub valid: bool,
    pub broken_at_sequence: Option<u64>,
    pub reason: Option<&'static str>,
}

/// Append-only audit contract. Deployments should anchor returned heads outside the database.
pub trait AuditLog: Send + Sync {
    fn append_at(&self, event: AuditEvent, timestamp_ms: u64) -> Result<AuditEntry>;
    fn entries(&self) -> Result<Vec<AuditEntry>>;
    fn head(&self) -> Result<AuditHead>;
    fn verify(&self, expected_anchor: Option<&AuditHead>) -> Result<AuditVerification>;
}

struct MemoryAuditState {
    entries: Vec<AuditEntry>,
    head_hash: String,
    count: u64,
}

/// Process-local append-only audit log for tests and single-process development.
pub struct MemoryAuditLog {
    state: Mutex<MemoryAuditState>,
}

impl Default for MemoryAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryAuditLog {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(MemoryAuditState {
                entries: Vec::new(),
                head_hash: GENESIS_HASH.into(),
                count: 0,
            }),
        }
    }
}

impl AuditLog for MemoryAuditLog {
    fn append_at(&self, event: AuditEvent, timestamp_ms: u64) -> Result<AuditEntry> {
        event.validate()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| BpcError::PairRegistry("audit log lock poisoned".into()))?;
        let sequence = state.count.saturating_add(1);
        let mut entry = AuditEntry {
            id: format!("audit_{}", Uuid::new_v4().simple()),
            timestamp_ms,
            sequence,
            previous_hash: state.head_hash.clone(),
            chain_hash: String::new(),
            event,
        };
        entry.chain_hash = audit_hash(&entry)?;
        state.head_hash = entry.chain_hash.clone();
        state.count = sequence;
        state.entries.push(entry.clone());
        Ok(entry)
    }

    fn entries(&self) -> Result<Vec<AuditEntry>> {
        let state = self
            .state
            .lock()
            .map_err(|_| BpcError::PairRegistry("audit log lock poisoned".into()))?;
        Ok(state.entries.clone())
    }

    fn head(&self) -> Result<AuditHead> {
        let state = self
            .state
            .lock()
            .map_err(|_| BpcError::PairRegistry("audit log lock poisoned".into()))?;
        Ok(AuditHead {
            sequence: state.count,
            chain_hash: state.head_hash.clone(),
            count: state.count,
        })
    }

    fn verify(&self, expected_anchor: Option<&AuditHead>) -> Result<AuditVerification> {
        let state = self
            .state
            .lock()
            .map_err(|_| BpcError::PairRegistry("audit log lock poisoned".into()))?;
        if state.entries.len() > DEFAULT_AUDIT_VERIFY_MAX_ENTRIES {
            return Ok(AuditVerification {
                valid: false,
                broken_at_sequence: None,
                reason: Some("verification_work_limit_exceeded"),
            });
        }
        let entries = state.entries.clone();
        drop(state);
        verify_audit_entries(&entries, expected_anchor)
    }
}

/// Computes SHA-256 hex over the stable JSON-array evidence preimage shared by all audit backends.
pub fn audit_hash(entry: &AuditEntry) -> Result<String> {
    let preimage = serde_json::to_vec(&(
        entry.sequence,
        &entry.previous_hash,
        &entry.id,
        entry.timestamp_ms,
        entry.event.action.as_str(),
        entry.event.severity.as_str(),
        entry.event.pair_id.as_deref(),
        entry.event.error_code.as_deref(),
        entry.event.source_ip.as_deref(),
        entry.event.method.as_deref(),
        entry.event.path.as_deref(),
        entry.event.request_id.as_deref(),
        entry.event.detail.as_deref(),
    ))?;
    Ok(format!("{:x}", Sha256::digest(preimage)))
}

/// Verifies chain order, the genesis invariant, every hash/link, and an optional external anchor.
pub fn verify_audit_entries(
    entries: &[AuditEntry],
    expected_anchor: Option<&AuditHead>,
) -> Result<AuditVerification> {
    if entries.len() > DEFAULT_AUDIT_VERIFY_MAX_ENTRIES {
        return Ok(AuditVerification {
            valid: false,
            broken_at_sequence: None,
            reason: Some("verification_work_limit_exceeded"),
        });
    }
    if entries.is_empty() {
        return Ok(match expected_anchor {
            Some(anchor)
                if anchor.sequence != 0
                    || anchor.count != 0
                    || anchor.chain_hash != GENESIS_HASH =>
            {
                AuditVerification {
                    valid: false,
                    broken_at_sequence: Some(anchor.sequence),
                    reason: Some("truncated_below_anchor"),
                }
            }
            _ => AuditVerification {
                valid: true,
                broken_at_sequence: None,
                reason: None,
            },
        });
    }
    let mut ordered = entries.to_vec();
    ordered.sort_by_key(|entry| entry.sequence);
    let first = &ordered[0];
    if first.sequence != 1 || first.previous_hash != GENESIS_HASH {
        return Ok(AuditVerification {
            valid: false,
            broken_at_sequence: Some(first.sequence),
            reason: Some("invalid_genesis"),
        });
    }
    let mut previous = GENESIS_HASH.to_owned();
    for (index, entry) in ordered.iter().enumerate() {
        let expected_sequence = u64::try_from(index + 1).unwrap_or(u64::MAX);
        if entry.sequence != expected_sequence {
            return Ok(AuditVerification {
                valid: false,
                broken_at_sequence: Some(entry.sequence),
                reason: Some("non_contiguous_sequence"),
            });
        }
        if entry.previous_hash != previous {
            return Ok(AuditVerification {
                valid: false,
                broken_at_sequence: Some(entry.sequence),
                reason: Some("broken_link"),
            });
        }
        if audit_hash(entry)? != entry.chain_hash {
            return Ok(AuditVerification {
                valid: false,
                broken_at_sequence: Some(entry.sequence),
                reason: Some("entry_hash_mismatch"),
            });
        }
        previous = entry.chain_hash.clone();
    }
    if let Some(anchor) = expected_anchor {
        let last = ordered.last().expect("nonempty checked");
        if anchor.count != anchor.sequence
            || last.sequence < anchor.sequence
            || u64::try_from(ordered.len())
                .ok()
                .is_none_or(|count| count < anchor.count)
        {
            return Ok(AuditVerification {
                valid: false,
                broken_at_sequence: Some(anchor.sequence),
                reason: Some("truncated_below_anchor"),
            });
        }
        let Some(anchored) = ordered
            .iter()
            .find(|entry| entry.sequence == anchor.sequence)
        else {
            return Ok(AuditVerification {
                valid: false,
                broken_at_sequence: Some(anchor.sequence),
                reason: Some("anchor_missing"),
            });
        };
        if anchored.chain_hash != anchor.chain_hash {
            return Ok(AuditVerification {
                valid: false,
                broken_at_sequence: Some(anchor.sequence),
                reason: Some("anchor_mismatch"),
            });
        }
    }
    Ok(AuditVerification {
        valid: true,
        broken_at_sequence: None,
        reason: None,
    })
}

#[cfg(test)]
mod hash_vectors {
    use super::{AuditAction, AuditEntry, AuditEvent, AuditSeverity, GENESIS_HASH, audit_hash};

    #[test]
    fn audit_hash_fixed_vector_is_stable() {
        let entry = AuditEntry {
            id: "audit_fixed".into(),
            timestamp_ms: 1_740_000_000_000,
            sequence: 1,
            previous_hash: GENESIS_HASH.into(),
            chain_hash: String::new(),
            event: AuditEvent {
                action: AuditAction::VerifyPass,
                severity: AuditSeverity::Info,
                pair_id: Some("pair_protocol".into()),
                error_code: None,
                source_ip: None,
                method: Some("POST".into()),
                path: Some("/v1/widgets".into()),
                request_id: Some("request-fixed".into()),
                detail: Some("fixed test vector".into()),
            },
        };
        assert_eq!(
            audit_hash(&entry).unwrap(),
            "75e9c2b621ab7709834235abcefbe7971c2e00071b8ce99ad72d915466b6cd25"
        );
    }
}
