//! Authenticated, bounded WASM handoff message construction.
//!
//! This module deliberately does not make the existing media/geospatial stream
//! paths require artifact trust. It signs executable deployment metadata and
//! chunks only. Network adapters must provide mutually authenticated TLS 1.3
//! or an equivalently authenticated local transport; this module never opens
//! an unauthenticated socket itself.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const HANDOFF_CONTRACT: &str = "wasm-handoff/1";
pub const WASM_CORE_FORMAT: &str = "wasm-core-1";
pub const MAX_MODULE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_CHUNK_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_CHUNK_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum HandoffError {
    #[error("invalid handoff input: {0}")]
    InvalidInput(String),
    #[error("canonical JSON encoding failed: {0}")]
    Serialization(String),
    #[error("handoff signer failed: {0}")]
    Signing(String),
    #[error("handoff transport failed: {0}")]
    Transport(String),
    #[error("receiver rejected prepare: {0}")]
    Rejected(String),
    #[error("receiver returned an invalid prepare decision: {0}")]
    InvalidDecision(String),
}

/// The signer may be backed by an HSM, OS keystore, KMS, or a local Ed25519
/// implementation. Secret key bytes are intentionally not stored by this API.
pub trait HandoffSigner: Send + Sync {
    fn key_id(&self) -> &str;
    fn issuer(&self) -> &str;
    fn subject(&self) -> &str;
    fn sign_ed25519(&self, canonical_message: &[u8]) -> Result<[u8; 64], String>;
}

#[derive(Debug, Clone)]
pub struct HandoffIdentity {
    pub issuer: String,
    pub subject: String,
    pub key_id: String,
}

impl HandoffIdentity {
    fn validate(&self) -> Result<(), HandoffError> {
        validate_identifier(&self.issuer, 256, "issuer")?;
        validate_identifier(&self.subject, 256, "subject")?;
        validate_identifier(&self.key_id, 128, "key_id")
    }
}

#[derive(Debug, Clone)]
pub struct WasmArtifact {
    pub module_id: String,
    pub version: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct HandoffLimits {
    pub memory_bytes: u64,
    pub fuel: u64,
    pub wall_time_ms: u64,
    pub max_instances: u32,
}

impl Default for HandoffLimits {
    fn default() -> Self {
        Self {
            memory_bytes: 64 * 1024 * 1024,
            fuel: 100_000_000,
            wall_time_ms: 30_000,
            max_instances: 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PrepareOptions {
    pub receiver_audience: String,
    pub receipt_audience: String,
    pub publisher_audience: String,
    pub deployment_id: String,
    pub release_id: String,
    pub runtime_policy: String,
    pub required_capabilities: Vec<String>,
    pub limits: HandoffLimits,
    pub message_lifetime_secs: u64,
    pub preferred_backend: Option<String>,
}

impl Default for PrepareOptions {
    fn default() -> Self {
        Self {
            receiver_audience: "overhauled".into(),
            receipt_audience: "yukki-os".into(),
            publisher_audience: "wasm-artifact-publisher".into(),
            deployment_id: "default".into(),
            release_id: "current".into(),
            runtime_policy: "auto".into(),
            required_capabilities: Vec::new(),
            limits: HandoffLimits::default(),
            message_lifetime_secs: 300,
            preferred_backend: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHandoffMessage {
    pub message_id: String,
    /// Compact JSON envelope including the Ed25519 signature.
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PrepareDecision {
    pub accepted: bool,
    pub request_id: String,
    pub decision: String,
    #[serde(default)]
    pub rejection_code: Option<String>,
    #[serde(default, rename = "artifact_transfer_id")]
    pub transfer_id: Option<String>,
    #[serde(default)]
    pub chunk_size_bytes: usize,
    #[serde(default)]
    pub backend_id: Option<String>,
    #[serde(default)]
    pub engine: Option<String>,
    #[serde(default)]
    pub engine_version: Option<String>,
    #[serde(default)]
    pub abi_profile: Option<String>,
    #[serde(default)]
    pub accepted_capabilities: Vec<String>,
    pub message_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
    pub audience: String,
    pub issuer: String,
    pub subject: String,
    pub signer_key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct HandoffReceipt {
    pub request_id: String,
    pub deployment_id: String,
    pub release_id: String,
    pub state: String,
    pub backend_id: String,
    pub engine: String,
    pub engine_version: String,
    pub abi_profile: String,
    pub artifact_set_digest: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub message_id: String,
    pub nonce: String,
    pub audience: String,
    pub issuer: String,
    pub subject: String,
    pub signer_key_id: String,
    pub signature: String,
}

/// Verifies the receiver's Ed25519 receipt with a separately provisioned
/// receiver trust key. Implementations should pin issuer, subject, key ID and
/// audience, not merely accept any key that verifies the signature.
pub trait HandoffReceiptVerifier {
    fn verify_ed25519(
        &self,
        issuer: &str,
        subject: &str,
        key_id: &str,
        audience: &str,
        canonical_message: &[u8],
        signature_base64: &str,
    ) -> bool;
}

/// This is a protocol adapter boundary, not an unauthenticated TCP client.
/// Implementations must authenticate both ends of the connection, bind the
/// authenticated peer identity to these signed messages, bound message sizes,
/// and reject downgrade to plaintext.
pub trait HandoffTransport {
    fn prepare(&mut self, signed_request: &[u8]) -> Result<PrepareDecision, String>;
    fn append_chunk(&mut self, signed_chunk: &[u8]) -> Result<(), String>;
    fn activate(&mut self, signed_activation: &[u8]) -> Result<HandoffReceipt, String>;
}

pub struct HandoffSender {
    identity: HandoffIdentity,
    options: PrepareOptions,
    chunk_bytes: usize,
}

impl HandoffSender {
    pub fn new(
        identity: HandoffIdentity,
        options: PrepareOptions,
        chunk_bytes: usize,
    ) -> Result<Self, HandoffError> {
        identity.validate()?;
        validate_identifier(&options.receiver_audience, 256, "receiver audience")?;
        validate_identifier(&options.receipt_audience, 256, "receipt audience")?;
        validate_identifier(&options.publisher_audience, 256, "publisher audience")?;
        validate_identifier(&options.deployment_id, 128, "deployment_id")?;
        validate_identifier(&options.release_id, 128, "release_id")?;
        if options.message_lifetime_secs == 0 || options.message_lifetime_secs > 300 {
            return Err(HandoffError::InvalidInput(
                "message lifetime must be in 1..=300 seconds".into(),
            ));
        }
        if !(4096..=MAX_CHUNK_BYTES).contains(&chunk_bytes) {
            return Err(HandoffError::InvalidInput(format!(
                "chunk size must be in 4096..={MAX_CHUNK_BYTES}"
            )));
        }
        if options.limits.memory_bytes < 65_536
            || options.limits.fuel == 0
            || options.limits.wall_time_ms == 0
            || options.limits.wall_time_ms > 3_600_000
            || options.limits.max_instances == 0
            || options.limits.max_instances > 1024
        {
            return Err(HandoffError::InvalidInput(
                "WASM resource limits are outside the contract bounds".into(),
            ));
        }
        if options.runtime_policy != "auto" && options.runtime_policy != "wasmtime" {
            return Err(HandoffError::InvalidInput(
                "runtime policy must be auto or wasmtime".into(),
            ));
        }
        let mut capabilities = options.required_capabilities.clone();
        capabilities.sort();
        capabilities.dedup();
        if capabilities.len() != options.required_capabilities.len() {
            return Err(HandoffError::InvalidInput(
                "required capabilities must be unique".into(),
            ));
        }
        for capability in &capabilities {
            validate_identifier(capability, 128, "capability")?;
        }
        Ok(Self {
            identity,
            options,
            chunk_bytes,
        })
    }

    /// Build the signed prepare message. The deployment signer and publisher
    /// signer are separate so transport authorization does not imply artifact
    /// publisher provenance.
    pub fn build_prepare(
        &self,
        artifacts: &[WasmArtifact],
        deployment_signer: &dyn HandoffSigner,
        publisher_signer: &dyn HandoffSigner,
        issued_at: u64,
    ) -> Result<(String, SignedHandoffMessage), HandoffError> {
        self.validate_artifacts(artifacts)?;
        validate_signer(&self.identity, deployment_signer)?;
        validate_signer(
            &HandoffIdentity {
                issuer: publisher_signer.issuer().into(),
                subject: publisher_signer.subject().into(),
                key_id: publisher_signer.key_id().into(),
            },
            publisher_signer,
        )?;

        let descriptors = descriptors(artifacts)?;
        let manifest = manifest_value(&descriptors);
        let manifest_bytes = canonical_json(&manifest)?;
        let manifest_digest = sha256_hex(&manifest_bytes);
        let artifact_set_digest = artifact_set_digest(&descriptors)?;

        let publisher_issued = issued_at;
        let publisher_expires = issued_at + self.options.message_lifetime_secs;
        let publisher_claim = json!({
            "artifact_set_digest": artifact_set_digest,
            "audience": self.options.publisher_audience,
            "expires_at": publisher_expires,
            "issued_at": publisher_issued,
            "issuer": publisher_signer.issuer(),
            "key_id": publisher_signer.key_id(),
            "manifest_digest": manifest_digest,
            "subject": publisher_signer.subject()
        });
        let publisher_bytes = canonical_json(&publisher_claim)?;
        let publisher_signature = publisher_signer
            .sign_ed25519(&publisher_bytes)
            .map_err(HandoffError::Signing)?;
        let publisher_provenance = json!({
            "audience": self.options.publisher_audience,
            "expires_at": publisher_expires,
            "issued_at": publisher_issued,
            "issuer": publisher_signer.issuer(),
            "key_id": publisher_signer.key_id(),
            "signature": signature_value(publisher_signer.key_id(), &publisher_signature),
            "subject": publisher_signer.subject()
        });

        let request_id = Uuid::new_v4().to_string();
        let mut capabilities = self.options.required_capabilities.clone();
        capabilities.sort();
        let mut payload = Map::new();
        payload.insert("artifact_set_digest".into(), json!(artifact_set_digest));
        payload.insert("deployment_id".into(), json!(self.options.deployment_id));
        payload.insert("kind".into(), json!("prepare_request"));
        payload.insert(
            "limits".into(),
            json!({
                "fuel": self.options.limits.fuel,
                "max_instances": self.options.limits.max_instances,
                "memory_bytes": self.options.limits.memory_bytes,
                "wall_time_ms": self.options.limits.wall_time_ms
            }),
        );
        payload.insert("manifest_digest".into(), json!(manifest_digest));
        payload.insert("modules".into(), Value::Array(descriptors.clone()));
        payload.insert("publisher_provenance".into(), publisher_provenance);
        payload.insert("release_id".into(), json!(self.options.release_id));
        payload.insert("request_id".into(), json!(request_id));
        payload.insert(
            "required_capabilities".into(),
            Value::Array(capabilities.into_iter().map(Value::String).collect()),
        );
        payload.insert("runtime_policy".into(), json!(self.options.runtime_policy));
        if let Some(preferred) = &self.options.preferred_backend {
            payload.insert("preferred_backend".into(), json!(preferred));
        }

        let signed = signed_envelope(
            Value::Object(payload),
            &self.options.receiver_audience,
            deployment_signer,
            issued_at,
            self.options.message_lifetime_secs,
        )?;
        Ok((request_id, signed))
    }

    /// Build individually signed, bounded, sequential artifact chunks after
    /// the receiver has accepted prepare and returned its transfer UUID.
    /// Emit individually signed chunks one at a time. The callback provides
    /// backpressure so a maximum-sized artifact set is never duplicated into
    /// a second in-memory vector of base64-encoded chunks.
    pub fn for_each_chunk<F>(
        &self,
        artifacts: &[WasmArtifact],
        transfer_id: &str,
        deployment_signer: &dyn HandoffSigner,
        issued_at: u64,
        mut send: F,
    ) -> Result<(), HandoffError>
    where
        F: FnMut(SignedHandoffMessage) -> Result<(), HandoffError>,
    {
        self.validate_artifacts(artifacts)?;
        validate_uuid(transfer_id, "transfer_id")?;
        validate_signer(&self.identity, deployment_signer)?;
        let descriptors = descriptors(artifacts)?;
        let mut sorted_artifacts = artifacts.iter().collect::<Vec<_>>();
        sorted_artifacts.sort_by(|a, b| a.module_id.cmp(&b.module_id));
        for (artifact, descriptor) in sorted_artifacts.into_iter().zip(descriptors.iter()) {
            let bytes = &artifact.bytes;
            let count = bytes.len().div_ceil(self.chunk_bytes);
            for (index, chunk) in bytes.chunks(self.chunk_bytes).enumerate() {
                let offset = index * self.chunk_bytes;
                let payload = json!({
                    "artifact_digest": descriptor["digest"],
                    "chunk_digest": sha256_hex(chunk),
                    "data": base64_encode(chunk),
                    "final": index + 1 == count,
                    "kind": "artifact_chunk",
                    "offset": offset,
                    "total_length": bytes.len(),
                    "transfer_id": transfer_id
                });
                let message = signed_envelope(
                    payload,
                    &self.options.receiver_audience,
                    deployment_signer,
                    issued_at,
                    self.options.message_lifetime_secs,
                )?;
                send(message)?;
            }
        }
        Ok(())
    }

    pub fn build_activation(
        &self,
        request_id: &str,
        transfer_id: &str,
        deployment_signer: &dyn HandoffSigner,
        issued_at: u64,
    ) -> Result<SignedHandoffMessage, HandoffError> {
        validate_uuid(request_id, "request_id")?;
        validate_uuid(transfer_id, "transfer_id")?;
        validate_signer(&self.identity, deployment_signer)?;
        signed_envelope(
            json!({
                "kind": "activate_request",
                "request_id": request_id,
                "transfer_id": transfer_id
            }),
            &self.options.receiver_audience,
            deployment_signer,
            issued_at,
            self.options.message_lifetime_secs,
        )
    }

    /// Execute prepare -> bounded transfer -> activation through a caller
    /// supplied authenticated transport. The receiver's signed receipt should
    /// be verified by the caller against its provisioned receiver trust key.
    pub fn deploy(
        &self,
        artifacts: &[WasmArtifact],
        deployment_signer: &dyn HandoffSigner,
        publisher_signer: &dyn HandoffSigner,
        transport: &mut dyn HandoffTransport,
        receipt_verifier: &dyn HandoffReceiptVerifier,
        issued_at: u64,
    ) -> Result<HandoffReceipt, HandoffError> {
        let (request_id, prepare) = self.build_prepare(
            artifacts,
            deployment_signer,
            publisher_signer,
            issued_at,
        )?;
        let decision = transport.prepare(&prepare.bytes).map_err(HandoffError::Transport)?;
        verify_prepare_decision(
            &decision,
            &request_id,
            &self.options.receipt_audience,
            issued_at,
            receipt_verifier,
        )?;
        if !decision.accepted || decision.decision != "accepted" {
            return Err(HandoffError::Rejected(
                decision.rejection_code.unwrap_or_else(|| "unspecified".into()),
            ));
        }
        let transfer_id = decision.transfer_id.ok_or_else(|| {
            HandoffError::InvalidDecision("accepted decision omitted transfer_id".into())
        })?;
        if decision.chunk_size_bytes < 4096 || decision.chunk_size_bytes > MAX_CHUNK_BYTES {
            return Err(HandoffError::InvalidDecision(
                "receiver returned an invalid chunk size".into(),
            ));
        }

        // Respect the receiver's lower advertised chunk ceiling.
        let sender = Self {
            identity: self.identity.clone(),
            options: self.options.clone(),
            chunk_bytes: self.chunk_bytes.min(decision.chunk_size_bytes),
        };
        sender.for_each_chunk(
            artifacts,
            &transfer_id,
            deployment_signer,
            issued_at,
            |chunk| transport.append_chunk(&chunk.bytes).map_err(HandoffError::Transport),
        )?;
        let activation =
            self.build_activation(&request_id, &transfer_id, deployment_signer, issued_at)?;
        let receipt = transport
            .activate(&activation.bytes)
            .map_err(HandoffError::Transport)?;
        if receipt.request_id != request_id
            || receipt.deployment_id != self.options.deployment_id
            || receipt.release_id != self.options.release_id
            || receipt.state != "activated"
            || receipt.audience != self.options.receipt_audience
            || receipt.backend_id.is_empty()
            || receipt.engine != "wasmtime"
            || receipt.engine_version.is_empty()
            || receipt.abi_profile.is_empty()
            || receipt.expires_at <= receipt.issued_at
        {
            return Err(HandoffError::InvalidDecision(
                "activation receipt does not match the requested release or backend contract".into(),
            ));
        }
        validate_uuid(&receipt.message_id, "receipt message_id")?;
        validate_uuid(&receipt.nonce, "receipt nonce")?;
        let receipt_bytes = canonical_receipt(&receipt)?;
        if !receipt_verifier.verify_ed25519(
            &receipt.issuer,
            &receipt.subject,
            &receipt.signer_key_id,
            &receipt.audience,
            &receipt_bytes,
            &receipt.signature,
        ) {
            return Err(HandoffError::InvalidDecision(
                "receiver receipt signature or identity could not be verified".into(),
            ));
        }
        Ok(receipt)
    }

    fn validate_artifacts(&self, artifacts: &[WasmArtifact]) -> Result<(), HandoffError> {
        if artifacts.is_empty() || artifacts.len() > 256 {
            return Err(HandoffError::InvalidInput(
                "artifact set must contain 1..=256 modules".into(),
            ));
        }
        let mut total = 0usize;
        let mut module_ids = std::collections::BTreeSet::new();
        for artifact in artifacts {
            validate_identifier(&artifact.module_id, 128, "module_id")?;
            validate_identifier(&artifact.version, 64, "module version")?;
            if !module_ids.insert(&artifact.module_id) {
                return Err(HandoffError::InvalidInput("duplicate module_id".into()));
            }
            if artifact.bytes.len() < 8 || artifact.bytes.len() > MAX_MODULE_BYTES {
                return Err(HandoffError::InvalidInput(
                    "module size is outside 8..=64 MiB".into(),
                ));
            }
            if artifact.bytes[..8] != [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00] {
                return Err(HandoffError::InvalidInput(
                    "module is not WebAssembly core version 1".into(),
                ));
            }
            total = total.checked_add(artifact.bytes.len()).ok_or_else(|| {
                HandoffError::InvalidInput("artifact set size overflow".into())
            })?;
            if total > MAX_TOTAL_BYTES {
                return Err(HandoffError::InvalidInput(
                    "artifact set exceeds 256 MiB".into(),
                ));
            }
        }
        Ok(())
    }
}

fn validate_signer(
    expected: &HandoffIdentity,
    signer: &dyn HandoffSigner,
) -> Result<(), HandoffError> {
    expected.validate()?;
    if expected.issuer != signer.issuer()
        || expected.subject != signer.subject()
        || expected.key_id != signer.key_id()
    {
        return Err(HandoffError::InvalidInput(
            "signer identity does not match configured identity".into(),
        ));
    }
    Ok(())
}

fn validate_identifier(value: &str, max: usize, field: &str) -> Result<(), HandoffError> {
    if value.is_empty()
        || value.len() > max
        || value.contains(['\r', '\n', '|'])
    {
        return Err(HandoffError::InvalidInput(format!(
            "{field} is empty, too long, or contains forbidden control delimiters"
        )));
    }
    Ok(())
}

fn validate_uuid(value: &str, field: &str) -> Result<(), HandoffError> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| HandoffError::InvalidInput(format!("{field} is not a UUID")))
}

fn descriptors(artifacts: &[WasmArtifact]) -> Result<Vec<Value>, HandoffError> {
    let mut result = artifacts
        .iter()
        .map(|artifact| {
            json!({
                "digest": sha256_hex(&artifact.bytes),
                "format": WASM_CORE_FORMAT,
                "module_id": artifact.module_id,
                "size_bytes": artifact.bytes.len(),
                "version": artifact.version
            })
        })
        .collect::<Vec<_>>();
    result.sort_by(|a, b| {
        a["module_id"]
            .as_str()
            .cmp(&b["module_id"].as_str())
    });
    Ok(result)
}

fn manifest_value(descriptors: &[Value]) -> Value {
    json!({ "modules": descriptors })
}

fn artifact_set_digest(descriptors: &[Value]) -> Result<String, HandoffError> {
    let mut hasher = Sha256::new();
    for descriptor in descriptors {
        let digest = descriptor["digest"]
            .as_str()
            .ok_or_else(|| HandoffError::InvalidInput("module digest missing".into()))?;
        let hex = digest.strip_prefix("sha256:").ok_or_else(|| {
            HandoffError::InvalidInput("module digest has no sha256 prefix".into())
        })?;
        let bytes = decode_hex(hex)?;
        hasher.update(bytes);
    }
    Ok(format!("sha256:{}", lower_hex(&hasher.finalize())))
}

fn canonical_prepare_decision(decision: &PrepareDecision) -> Result<Vec<u8>, HandoffError> {
    let payload = if decision.accepted && decision.decision == "accepted" {
        json!({
            "accepted_capabilities": decision.accepted_capabilities,
            "abi_profile": decision.abi_profile,
            "artifact_transfer_id": decision.transfer_id,
            "backend_id": decision.backend_id,
            "chunk_size_bytes": decision.chunk_size_bytes,
            "decision": "accepted",
            "engine": decision.engine,
            "engine_version": decision.engine_version,
            "kind": "prepare_decision",
            "request_id": decision.request_id
        })
    } else {
        json!({
            "decision": "rejected",
            "kind": "prepare_decision",
            "rejection_code": decision.rejection_code,
            "request_id": decision.request_id
        })
    };
    let mut envelope = Map::new();
    envelope.insert("audience".into(), json!(decision.audience));
    envelope.insert("contract".into(), json!(HANDOFF_CONTRACT));
    envelope.insert("expires_at".into(), json!(decision.expires_at));
    envelope.insert("issued_at".into(), json!(decision.issued_at));
    envelope.insert("message_id".into(), json!(decision.message_id));
    envelope.insert("nonce".into(), json!(decision.nonce));
    envelope.insert("payload".into(), payload);
    envelope.insert("sender".into(), json!({
        "issuer": decision.issuer,
        "key_id": decision.signer_key_id,
        "subject": decision.subject
    }));
    canonical_json(&Value::Object(envelope))
}

fn verify_prepare_decision(
    decision: &PrepareDecision,
    expected_request_id: &str,
    expected_audience: &str,
    now: u64,
    verifier: &dyn HandoffReceiptVerifier,
) -> Result<(), HandoffError> {
    if decision.request_id != expected_request_id
        || decision.audience != expected_audience
        || decision.issuer.is_empty()
        || decision.subject.is_empty()
        || decision.signer_key_id.is_empty()
        || decision.expires_at <= decision.issued_at
        || decision.expires_at - decision.issued_at > 300
        || decision.issued_at > now.saturating_add(30)
        || decision.expires_at.saturating_add(30) < now
    {
        return Err(HandoffError::InvalidDecision(
            "prepare decision identity, audience, or lifetime is invalid".into(),
        ));
    }
    validate_uuid(&decision.message_id, "decision message_id")?;
    validate_uuid(&decision.nonce, "decision nonce")?;
    if decision.accepted != (decision.decision == "accepted") {
        return Err(HandoffError::InvalidDecision(
            "prepare decision accepted flag disagrees with decision state".into(),
        ));
    }
    if decision.accepted
        && (decision.transfer_id.is_none()
            || decision.chunk_size_bytes < 4096
            || decision.chunk_size_bytes > MAX_CHUNK_BYTES
            || decision.backend_id.as_deref().unwrap_or("").is_empty()
            || decision.engine.as_deref() != Some("wasmtime")
            || decision.engine_version.as_deref().unwrap_or("").is_empty()
            || decision.abi_profile.as_deref().unwrap_or("").is_empty())
    {
        return Err(HandoffError::InvalidDecision(
            "accepted prepare decision omitted a required backend/transfer field".into(),
        ));
    }
    let canonical = canonical_prepare_decision(decision)?;
    if !verifier.verify_ed25519(
        &decision.issuer,
        &decision.subject,
        &decision.signer_key_id,
        &decision.audience,
        &canonical,
        &decision.signature,
    ) {
        return Err(HandoffError::InvalidDecision(
            "prepare decision signature or receiver identity could not be verified".into(),
        ));
    }
    Ok(())
}

fn canonical_receipt(receipt: &HandoffReceipt) -> Result<Vec<u8>, HandoffError> {
    let payload = json!({
        "abi_profile": receipt.abi_profile,
        "artifact_set_digest": receipt.artifact_set_digest,
        "backend_id": receipt.backend_id,
        "deployment_id": receipt.deployment_id,
        "engine": receipt.engine,
        "engine_version": receipt.engine_version,
        "kind": "execution_receipt",
        "release_id": receipt.release_id,
        "request_id": receipt.request_id,
        "state": receipt.state
    });
    let mut envelope = Map::new();
    envelope.insert("audience".into(), json!(receipt.audience));
    envelope.insert("contract".into(), json!(HANDOFF_CONTRACT));
    envelope.insert("expires_at".into(), json!(receipt.expires_at));
    envelope.insert("issued_at".into(), json!(receipt.issued_at));
    envelope.insert("message_id".into(), json!(receipt.message_id));
    envelope.insert("nonce".into(), json!(receipt.nonce));
    envelope.insert("payload".into(), payload);
    envelope.insert("sender".into(), json!({
        "issuer": receipt.issuer,
        "key_id": receipt.signer_key_id,
        "subject": receipt.subject
    }));
    canonical_json(&Value::Object(envelope))
}

fn signed_envelope(
    payload: Value,
    audience: &str,
    signer: &dyn HandoffSigner,
    issued_at: u64,
    lifetime_secs: u64,
) -> Result<SignedHandoffMessage, HandoffError> {
    let message_id = Uuid::new_v4().to_string();
    let nonce = Uuid::new_v4().to_string();
    let expires_at = issued_at
        .checked_add(lifetime_secs)
        .ok_or_else(|| HandoffError::InvalidInput("message expiry overflow".into()))?;
    let mut envelope = Map::new();
    envelope.insert("audience".into(), json!(audience));
    envelope.insert("contract".into(), json!(HANDOFF_CONTRACT));
    envelope.insert("expires_at".into(), json!(expires_at));
    envelope.insert("issued_at".into(), json!(issued_at));
    envelope.insert("message_id".into(), json!(message_id));
    envelope.insert("nonce".into(), json!(nonce));
    envelope.insert("payload".into(), payload);
    envelope.insert(
        "sender".into(),
        json!({
            "issuer": signer.issuer(),
            "key_id": signer.key_id(),
            "subject": signer.subject()
        }),
    );
    let canonical = canonical_json(&Value::Object(envelope.clone()))?;
    let signature = signer
        .sign_ed25519(&canonical)
        .map_err(HandoffError::Signing)?;
    envelope.insert(
        "signature".into(),
        signature_value(signer.key_id(), &signature),
    );
    let bytes = canonical_json(&Value::Object(envelope))?;
    Ok(SignedHandoffMessage { message_id, bytes })
}

fn signature_value(key_id: &str, signature: &[u8; 64]) -> Value {
    json!({
        "alg": "Ed25519",
        "key_id": key_id,
        "value": base64_encode(signature)
    })
}

fn canonical_json(value: &Value) -> Result<Vec<u8>, HandoffError> {
    // serde_json::Map uses sorted keys unless its preserve_order feature is
    // enabled. This crate does not enable it. Contract numeric fields are
    // unsigned integers, avoiding floating-point JCS normalization ambiguity.
    serde_json::to_vec(value).map_err(|error| HandoffError::Serialization(error.to_string()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("sha256:{}", lower_hex(&Sha256::digest(bytes)))
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex(value: &str) -> Result<Vec<u8>, HandoffError> {
    if !value.len().is_multiple_of(2) {
        return Err(HandoffError::InvalidInput("invalid hexadecimal digest".into()));
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for pair in pairs {
        let digit = |byte: u8| -> Option<u8> {
            match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            }
        };
        let hi = digit(pair[0]).ok_or_else(|| HandoffError::InvalidInput("invalid digest hex".into()))?;
        let lo = digit(pair[1]).ok_or_else(|| HandoffError::InvalidInput("invalid digest hex".into()))?;
        output.push((hi << 4) | lo);
    }
    Ok(output)
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(4 * bytes.len().div_ceil(3));
    for chunk in bytes.chunks(3) {
        let a = chunk[0] as u32;
        let b = chunk.get(1).copied().unwrap_or(0) as u32;
        let c = chunk.get(2).copied().unwrap_or(0) as u32;
        let block = (a << 16) | (b << 8) | c;
        output.push(TABLE[((block >> 18) & 0x3f) as usize] as char);
        output.push(TABLE[((block >> 12) & 0x3f) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[((block >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(block & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestSigner {
        identity: HandoffIdentity,
    }

    impl HandoffSigner for TestSigner {
        fn key_id(&self) -> &str { &self.identity.key_id }
        fn issuer(&self) -> &str { &self.identity.issuer }
        fn subject(&self) -> &str { &self.identity.subject }
        fn sign_ed25519(&self, message: &[u8]) -> Result<[u8; 64], String> {
            let digest = Sha256::digest(message);
            let mut signature = [0u8; 64];
            signature[..32].copy_from_slice(&digest);
            signature[32..].copy_from_slice(&digest);
            Ok(signature)
        }
    }

    fn signer(issuer: &str, subject: &str, key_id: &str) -> TestSigner {
        TestSigner {
            identity: HandoffIdentity {
                issuer: issuer.into(),
                subject: subject.into(),
                key_id: key_id.into(),
            },
        }
    }

    fn wasm() -> WasmArtifact {
        WasmArtifact {
            module_id: "sample-module".into(),
            version: "1.0.0".into(),
            bytes: vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00],
        }
    }

    #[test]
    fn prepare_contains_signed_publisher_provenance_and_manifest_digests() {
        let deployment = signer("yukki-issuer", "node-7", "deploy-key");
        let publisher = signer("publisher-issuer", "release-bot", "publisher-key");
        let sender = HandoffSender::new(
            HandoffIdentity {
                issuer: deployment.identity.issuer.clone(),
                subject: deployment.identity.subject.clone(),
                key_id: deployment.identity.key_id.clone(),
            },
            PrepareOptions::default(),
            DEFAULT_CHUNK_BYTES,
        ).unwrap();
        let (request_id, message) = sender.build_prepare(
            &[wasm()], &deployment, &publisher, 1_800_000_000
        ).unwrap();
        assert_eq!(Uuid::parse_str(&request_id).unwrap().to_string(), request_id);
        let parsed: Value = serde_json::from_slice(&message.bytes).unwrap();
        assert_eq!(parsed["payload"]["kind"], "prepare_request");
        assert_eq!(parsed["payload"]["publisher_provenance"]["issuer"], "publisher-issuer");
        assert!(parsed["payload"]["manifest_digest"].as_str().unwrap().starts_with("sha256:"));
        assert_eq!(parsed["signature"]["alg"], "Ed25519");
        assert_eq!(parsed["signature"]["key_id"], "deploy-key");
    }

    #[test]
    fn chunks_are_sequential_bounded_and_individually_signed() {
        let deployment = signer("yukki-issuer", "node-7", "deploy-key");
        let sender = HandoffSender::new(
            deployment.identity.clone(), PrepareOptions::default(), 4096
        ).unwrap();
        let mut artifact = wasm();
        artifact.bytes.extend(std::iter::repeat_n(0x11, 8200));
        let mut chunks = Vec::new();
        sender.for_each_chunk(
            &[artifact], &Uuid::new_v4().to_string(), &deployment, 1_800_000_000,
            |chunk| {
                chunks.push(chunk);
                Ok(())
            },
        ).unwrap();
        assert_eq!(chunks.len(), 3);
        let first: Value = serde_json::from_slice(&chunks[0].bytes).unwrap();
        let last: Value = serde_json::from_slice(&chunks[2].bytes).unwrap();
        assert_eq!(first["payload"]["offset"], 0);
        assert_eq!(last["payload"]["offset"], 8192);
        assert_eq!(last["payload"]["final"], true);
        assert_ne!(first["nonce"], last["nonce"]);
    }

    #[test]
    fn rejects_invalid_wasm_and_duplicate_modules() {
        let deployment = signer("yukki-issuer", "node-7", "deploy-key");
        let sender = HandoffSender::new(
            deployment.identity.clone(), PrepareOptions::default(), 4096
        ).unwrap();
        let mut invalid = wasm();
        invalid.bytes[0] = 1;
        assert!(sender.build_prepare(&[invalid], &deployment, &deployment, 1).is_err());
        assert!(sender.build_prepare(&[wasm(), wasm()], &deployment, &deployment, 1).is_err());
    }

    #[test]
    fn sender_identity_cannot_be_swapped_after_configuration() {
        let deployment = signer("yukki-issuer", "node-7", "deploy-key");
        let attacker = signer("attacker", "node-x", "other-key");
        let sender = HandoffSender::new(
            deployment.identity.clone(), PrepareOptions::default(), 4096
        ).unwrap();
        assert!(sender.build_activation(
            &Uuid::new_v4().to_string(), &Uuid::new_v4().to_string(), &attacker, 1
        ).is_err());
    }
}
