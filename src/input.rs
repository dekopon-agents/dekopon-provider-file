use base64::{Engine, engine::general_purpose::STANDARD};
use dekopon_provider_sdk::ProviderError;
use serde::Deserialize;
use serde_json::Value;

use crate::MAX_BYTES;

pub(crate) const MAX_ENCODED_BYTES: usize = MAX_BYTES.div_ceil(3) * 4;
pub(crate) const MAX_MIME_BYTES: usize = 127;
pub(crate) const MAX_LABEL_BYTES: usize = 256;
pub(crate) const MAX_DATA_URL_BYTES: usize = MAX_ENCODED_BYTES + MAX_MIME_BYTES + 13;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    data: String,
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    content_type: Option<String>,
}

pub(crate) fn too_large() -> ProviderError {
    ProviderError::new(
        "input-too-large",
        "file.identify accepts at most 262144 decoded bytes (256 KiB), without clipping. Supply a smaller complete input; large chat files need a future bounded gateway prefix-read API, not a path or URL.",
    )
}

fn invalid() -> ProviderError {
    ProviderError::new(
        "invalid-input",
        "expected closed {data, filename?, content_type?}; data must be data:<type/subtype>;base64,<canonical padded standard base64>; hints are bounded non-control text and never trusted",
    )
}

pub(crate) fn decode(value: Value) -> Result<Vec<u8>, ProviderError> {
    let input: Input = serde_json::from_value(value).map_err(|_| invalid())?;
    for (hint, max) in [
        (input.filename.as_deref(), MAX_LABEL_BYTES),
        (input.content_type.as_deref(), MAX_MIME_BYTES),
    ] {
        if hint.is_some_and(|s| s.len() > max || s.chars().any(char::is_control)) {
            return Err(invalid());
        }
    }
    if input.data.starts_with("chat-asset:") {
        return Err(ProviderError::new(
            "unresolved-asset",
            "chat-asset references must be expanded by an authorized gateway route before invocation; this provider cannot access gateway storage",
        ));
    }
    if input.data.len() > MAX_DATA_URL_BYTES {
        return Err(too_large());
    }
    let (mime, encoded) = input
        .data
        .strip_prefix("data:")
        .and_then(|s| s.split_once(";base64,"))
        .ok_or_else(invalid)?;
    let (kind, subtype) = mime.split_once('/').ok_or_else(invalid)?;
    let token = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&b))
    };
    if mime.len() > MAX_MIME_BYTES || !token(kind) || !token(subtype) {
        return Err(invalid());
    }
    if encoded.len() > MAX_ENCODED_BYTES {
        return Err(too_large());
    }
    // Length is checked before decoding/allocation; decoded check covers base64's final quantum.
    let bytes = STANDARD.decode(encoded).map_err(|_| invalid())?;
    if bytes.len() > MAX_BYTES {
        return Err(too_large());
    }
    Ok(bytes)
}
