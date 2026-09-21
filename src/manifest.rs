use dekopon_provider_sdk::{
    EffectKind, ProviderApiVersion, ProviderCapability, ProviderManifest, RiskLevel,
};
use serde_json::json;

use crate::{
    IDENTIFY,
    input::{MAX_LABEL_BYTES, MAX_MIME_BYTES},
};

pub(crate) fn manifest() -> ProviderManifest {
    ProviderManifest {
        api_version: ProviderApiVersion::V1Alpha1,
        id: "file".parse().expect("static provider"),
        description: "Content-based identification hints over a bounded chat-asset prefix; no validation or libmagic parity".into(),
        command_words: vec!["file".into()],
        capabilities: vec![ProviderCapability {
            id: IDENTIFY.parse().expect("static capability"),
            description: "Identify MIME, extension and description from at most 65536 decoded bytes of an opened chat asset. Signatures can be forged or incomplete. No paths or URLs are opened; no whole-file size ceiling is imposed by this provider.".into(),
            effect: EffectKind::ReadOnly,
            risk: RiskLevel::Low,
            input_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["data"],
                "properties": {
                    "data": {
                        "type": "string", "pattern": "^chat-asset:[0-9]+$",
                        "description": "Exact chat-asset:<N> reference passed by the gateway, where N is an unsigned 64-bit decimal id. Read only its bounded decoded prefix; declared MIME is ignored for detection."
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
