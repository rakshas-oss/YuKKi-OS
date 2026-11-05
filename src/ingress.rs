//! Deterministic, bounded admission for untrusted JSON ingress.
//!
//! Admission is based only on input bytes and fixed structural limits, never
//! elapsed wall-clock time. The scan is iterative and allocation-free; only
//! admitted input reaches serde_json. This keeps parser work and recursion
//! bounded consistently across native and browser-WASM targets.

use serde::de::DeserializeOwned;
use thiserror::Error;

pub const CONTROL_MAX_BYTES: usize = 64 * 1024;
pub const CONTROL_MAX_STRING_BYTES: usize = 16 * 1024;
pub const CONTROL_MAX_DEPTH: usize = 32;
pub const CONTROL_MAX_TOKENS: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressLimits {
    pub max_bytes: usize,
    pub max_string_bytes: usize,
    pub max_depth: usize,
    pub max_tokens: usize,
    /// Deterministic byte-scan work units; one unit is charged per input byte.
    pub max_work_units: usize,
}

impl IngressLimits {
    pub const CONTROL: Self = Self {
        max_bytes: CONTROL_MAX_BYTES,
        max_string_bytes: CONTROL_MAX_STRING_BYTES,
        max_depth: CONTROL_MAX_DEPTH,
        max_tokens: CONTROL_MAX_TOKENS,
        max_work_units: CONTROL_MAX_BYTES,
    };

    pub const fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self.max_tokens = max_bytes;
        self.max_work_units = max_bytes;
        self
    }
}

impl Default for IngressLimits {
    fn default() -> Self {
        Self::CONTROL
    }
}

#[derive(Debug, Error)]
pub enum IngressError {
    #[error("JSON ingress is {actual} bytes; maximum is {max}")]
    PayloadTooLarge { actual: usize, max: usize },
    #[error("JSON string is longer than the {max}-byte limit")]
    StringTooLarge { max: usize },
    #[error("JSON nesting exceeds the depth limit of {max}")]
    NestingTooDeep { max: usize },
    #[error("JSON structural token count exceeds the limit of {max}")]
    TooManyTokens { max: usize },
    #[error("JSON ingress work budget exceeded ({used} > {max})")]
    WorkBudgetExceeded { used: usize, max: usize },
    #[error("malformed JSON: {0}")]
    Json(#[from] serde_json::Error),
}

impl PartialEq for IngressError {
    fn eq(&self, other: &Self) -> bool {
        use IngressError::*;
        match (self, other) {
            (PayloadTooLarge { actual: a, max: b }, PayloadTooLarge { actual: c, max: d }) => a == c && b == d,
            (StringTooLarge { max: a }, StringTooLarge { max: b }) => a == b,
            (NestingTooDeep { max: a }, NestingTooDeep { max: b }) => a == b,
            (TooManyTokens { max: a }, TooManyTokens { max: b }) => a == b,
            (WorkBudgetExceeded { used: a, max: b }, WorkBudgetExceeded { used: c, max: d }) => a == c && b == d,
            (Json(a), Json(b)) => a.to_string() == b.to_string(),
            _ => false,
        }
    }
}

impl Eq for IngressError {}

/// Perform the deterministic admission scan without parsing or allocating.
pub fn validate_json(bytes: &[u8], limits: IngressLimits) -> Result<(), IngressError> {
    if bytes.len() > limits.max_bytes {
        return Err(IngressError::PayloadTooLarge {
            actual: bytes.len(),
            max: limits.max_bytes,
        });
    }

    let mut depth = 0usize;
    let mut tokens = 0usize;
    let mut string_len = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (index, byte) in bytes.iter().copied().enumerate() {
        let work = index + 1;
        if work > limits.max_work_units {
            return Err(IngressError::WorkBudgetExceeded {
                used: work,
                max: limits.max_work_units,
            });
        }

        if in_string {
            if escaped {
                escaped = false;
                string_len = string_len.saturating_add(1);
            } else if byte == b'\\' {
                escaped = true;
                string_len = string_len.saturating_add(1);
            } else if byte == b'"' {
                in_string = false;
            } else {
                string_len = string_len.saturating_add(1);
            }
            if string_len > limits.max_string_bytes {
                return Err(IngressError::StringTooLarge {
                    max: limits.max_string_bytes,
                });
            }
            continue;
        }

        match byte {
            b'"' => {
                in_string = true;
                string_len = 0;
                tokens = tokens.saturating_add(1);
            }
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                if depth > limits.max_depth {
                    return Err(IngressError::NestingTooDeep {
                        max: limits.max_depth,
                    });
                }
                tokens = tokens.saturating_add(1);
            }
            b'}' | b']' | b',' | b':' => tokens = tokens.saturating_add(1),
            _ => {}
        }
        if tokens > limits.max_tokens {
            return Err(IngressError::TooManyTokens {
                max: limits.max_tokens,
            });
        }
    }
    Ok(())
}

/// Admit and deserialize JSON using fixed, deterministic resource limits.
pub fn from_slice<T: DeserializeOwned>(
    bytes: &[u8],
    limits: IngressLimits,
) -> Result<T, IngressError> {
    validate_json(bytes, limits)?;
    Ok(serde_json::from_slice(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_control_json_and_is_repeatable() {
        let input = br#"{"type":"ack","sequence":42}"#;
        for _ in 0..32 {
            validate_json(input, IngressLimits::CONTROL).unwrap();
        }
        let parsed: serde_json::Value =
            from_slice(input, IngressLimits::CONTROL).unwrap();
        assert_eq!(parsed["sequence"], 42);
    }

    #[test]
    fn rejects_oversized_payload_at_exact_boundary() {
        let limits = IngressLimits::CONTROL.with_max_bytes(8);
        assert!(validate_json(b"12345678", limits).is_ok());
        assert_eq!(
            validate_json(b"123456789", limits),
            Err(IngressError::PayloadTooLarge { actual: 9, max: 8 })
        );
    }

    #[test]
    fn rejects_oversized_string() {
        let limits = IngressLimits {
            max_string_bytes: 4,
            ..IngressLimits::CONTROL
        };
        assert_eq!(
            validate_json(br#"{"x":"12345"}"#, limits),
            Err(IngressError::StringTooLarge { max: 4 })
        );
    }

    #[test]
    fn rejects_excessive_nesting_iteratively() {
        let limits = IngressLimits {
            max_depth: 4,
            ..IngressLimits::CONTROL
        };
        assert!(matches!(
            validate_json(b"[[[[0]]]]", limits),
            Err(IngressError::NestingTooDeep { max: 4 })
        ));
        assert!(validate_json(b"[[[[0]]]]", IngressLimits {
            max_depth: 5,
            ..IngressLimits::CONTROL
        }).is_ok());
    }

    #[test]
    fn escaped_quotes_do_not_end_strings_early() {
        assert!(validate_json(br#"{"s":"a\\\"b"}"#, IngressLimits::CONTROL).is_ok());
    }

    #[test]
    fn rejects_token_and_work_budgets() {
        let token_limited = IngressLimits {
            max_tokens: 2,
            ..IngressLimits::CONTROL
        };
        assert!(matches!(
            validate_json(b"{\"a\":1}", token_limited),
            Err(IngressError::TooManyTokens { max: 2 })
        ));
        let work_limited = IngressLimits {
            max_work_units: 3,
            ..IngressLimits::CONTROL
        };
        assert!(matches!(
            validate_json(b"1234", work_limited),
            Err(IngressError::WorkBudgetExceeded { used: 4, max: 3 })
        ));
    }
}
