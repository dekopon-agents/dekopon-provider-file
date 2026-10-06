use dekopon_provider_sdk::schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::FileError;

pub(crate) const MAX_MIME_BYTES: usize = 127;
pub(crate) const MAX_LABEL_BYTES: usize = 256;

/// Closed input: the host admits the exact `data` reference before invoking the guest.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Input {
    /// Exact chat-asset:<N> reference, where N is an unsigned 64-bit decimal id.
    #[schemars(regex(pattern = "^chat-asset:[0-9]+$"))]
    pub data: String,
    /// Optional ignored opaque hint, at most 256 UTF-8 bytes, without controls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 256), extend("x-dekopon-maxUtf8Bytes" = 256))]
    pub filename: Option<String>,
    /// Optional ignored declared MIME, at most 127 UTF-8 bytes, without controls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 127), extend("x-dekopon-maxUtf8Bytes" = 127))]
    pub content_type: Option<String>,
}

pub(crate) fn reference(data: &str) -> Result<&str, FileError> {
    let id = data
        .strip_prefix("chat-asset:")
        .ok_or(FileError::InvalidInput)?;
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) || id.parse::<u64>().is_err() {
        return Err(FileError::InvalidInput);
    }
    Ok(data)
}

pub(crate) fn validate(input: &Input) -> Result<&str, FileError> {
    for (hint, max) in [
        (input.filename.as_deref(), MAX_LABEL_BYTES),
        (input.content_type.as_deref(), MAX_MIME_BYTES),
    ] {
        if hint.is_some_and(|s| s.len() > max || s.chars().any(char::is_control)) {
            return Err(FileError::InvalidInput);
        }
    }
    reference(&input.data)
}
