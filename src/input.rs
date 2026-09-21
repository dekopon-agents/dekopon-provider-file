use dekopon_provider_sdk::ProviderError;
use serde::Deserialize;
use serde_json::Value;

pub(crate) const MAX_MIME_BYTES: usize = 127;
pub(crate) const MAX_LABEL_BYTES: usize = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    data: String,
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    content_type: Option<String>,
}

fn invalid() -> ProviderError {
    ProviderError::new(
        "invalid-input",
        "expected closed {data, filename?, content_type?}; data must be chat-asset:<N> (an unsigned 64-bit decimal id); hints are bounded non-control text and never trusted",
    )
}

pub(crate) fn reference(data: &str) -> Result<&str, ProviderError> {
    let id = data.strip_prefix("chat-asset:").ok_or_else(invalid)?;
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_digit()) || id.parse::<u64>().is_err() {
        return Err(invalid());
    }
    Ok(data)
}

pub(crate) fn parse(value: Value) -> Result<String, ProviderError> {
    let input: Input = serde_json::from_value(value).map_err(|_| invalid())?;
    for (hint, max) in [
        (input.filename.as_deref(), MAX_LABEL_BYTES),
        (input.content_type.as_deref(), MAX_MIME_BYTES),
    ] {
        if hint.is_some_and(|s| s.len() > max || s.chars().any(char::is_control)) {
            return Err(invalid());
        }
    }
    reference(&input.data)?;
    Ok(input.data)
}
