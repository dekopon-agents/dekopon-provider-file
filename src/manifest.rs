use dekopon_provider_sdk::{
    EffectKind, ProviderApiVersion, ProviderCapability, ProviderManifest, RiskLevel,
};
use serde_json::json;

use crate::{
    IDENTIFY,
    input::{MAX_DATA_URL_BYTES, MAX_LABEL_BYTES, MAX_MIME_BYTES},
};

pub(crate) fn manifest() -> ProviderManifest {
    ProviderManifest {
        api_version: ProviderApiVersion::V1Alpha1,
        id: "file".parse().expect("static provider"),
        description: "Content-based identification hints over bounded supplied bytes; no I/O, validation, or libmagic parity".into(),
        command_words: vec!["file".into()],
        capabilities: vec![ProviderCapability {
            id: IDENTIFY.parse().expect("static capability"),
            description: "Identify MIME, extension and description from a complete input of at most 256 KiB. Signatures can be forged or incomplete. No paths/URLs are opened. Gateway chat-asset expansion supports only PNG/JPEG/WebP/GIF at the current core pin; arbitrary documents and HEIC require directly supplied data URLs.".into(),
            effect: EffectKind::ReadOnly,
            risk: RiskLevel::Low,
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["data"],
                "properties": {
                    "data": {
                        "type": "string", "maxLength": MAX_DATA_URL_BYTES,
                        "description": "data:<type/subtype>;base64,<canonical padded standard base64>, at most 262144 decoded bytes; no whitespace or MIME parameters. A chat-asset:N marker requires route chatAssetInputs expansion before invocation; unresolved markers are refused. MIME is an untrusted label, ignored for detection. Never clip silently."
                    },
                    "filename": {
                        "type": ["string", "null"], "maxLength": MAX_LABEL_BYTES,
                        "description": "Optional opaque hint, at most 256 UTF-8 bytes, no controls. Ignored, never opened or returned."
                    },
                    "content_type": {
                        "type": ["string", "null"], "maxLength": MAX_MIME_BYTES,
                        "description": "Optional untrusted hint, at most 127 UTF-8 bytes, no controls. Ignored, never returned."
                    }
                }
            }),
        }],
    }
}
