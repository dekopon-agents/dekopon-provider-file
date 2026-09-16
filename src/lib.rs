//! Import-free identification of bounded caller-supplied bytes, not file validation.
mod input;
mod manifest;

use dekopon_provider_sdk::clap::{Arg, Command};
use dekopon_provider_sdk::{
    CapabilityId, CommandInvocation, CommandRun, Provider, ProviderError, ProviderManifest, cli,
};
use file_format::FileFormat;
use serde_json::{Value, json};

pub const IDENTIFY: &str = "file.identify";
pub const MAX_BYTES: usize = 262_144;

#[allow(unsafe_code)]
mod bindings {
    wit_bindgen::generate!({ path: "wit", world: "provider" });
}
#[allow(unsafe_code)]
mod export {
    use super::bindings;
    dekopon_provider_sdk::export_provider_with_cli!(super::FileProvider, bindings);
}

pub struct FileProvider;

impl Provider for FileProvider {
    fn manifest() -> ProviderManifest {
        manifest::manifest()
    }

    fn invoke(capability: &CapabilityId, input: Value) -> Result<Value, ProviderError> {
        if capability.as_str() != IDENTIFY {
            return Err(ProviderError::new(
                "unsupported-capability",
                "the file provider exposes only file.identify",
            ));
        }
        let bytes = input::decode(input)?;
        let format = FileFormat::from_bytes(&bytes);
        let (status, evidence) = match format {
            FileFormat::Empty => ("empty", "empty-input"),
            FileFormat::ArbitraryBinaryData => ("unknown", "no-recognized-signature"),
            FileFormat::PlainText => ("identified", "bounded-text-heuristic"),
            _ => ("identified", "signature-heuristic"),
        };
        Ok(json!({
            "status": status,
            "mime": format.media_type(),
            "extension": if matches!(format, FileFormat::Empty | FileFormat::ArbitraryBinaryData) {
                None
            } else { Some(format.extension()) },
            "description": format.name(),
            "input_bytes": bytes.len(),
            "bytes_supplied_to_detector": bytes.len(),
            "input_clipped": false,
            "evidence": evidence,
            "validated": false,
            "detector": "file-format/0.29.0; reader-txt",
            "limitations": "Identification hint only: headers can be forged or incomplete; no structural, codec or safety validation. Text fallback checks at most 16 lines / 65536 bytes. Filename and declared MIME are ignored. Not libmagic parity."
        }))
    }

    fn run_command(argv: &[String], stdin: Option<&str>) -> Result<CommandRun, ProviderError> {
        let command = Command::new("file")
            .version(env!("CARGO_PKG_VERSION"))
            .about("Identify supplied data, never open a path or fetch a URL")
            .after_help("DATA is a chat-asset:N marker (gateway expansion required) or a base64 data URL. With no DATA, pipe one data URL. Maximum decoded input: 262144 bytes.")
            .arg(Arg::new("data").value_name("DATA"));
        cli::run_command(command, argv, stdin, |matches, stdin| {
            let data = match (matches.get_one::<String>("data"), stdin) {
                (Some(data), None) => data.as_str(),
                (None, Some(data)) => data,
                _ => {
                    return Err(ProviderError::new(
                        "usage",
                        "supply DATA or pipe one data URL, not both",
                    ));
                }
            };
            if data.len() > input::MAX_DATA_URL_BYTES {
                return Err(input::too_large());
            }
            Ok(CommandInvocation {
                capability: IDENTIFY.parse().expect("static capability"),
                input: json!({"data": data}),
                secret_use: None,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirrored_wit_and_manifest() {
        assert_eq!(
            include_str!("../wit/deps/provider.wit"),
            dekopon_provider_sdk::PROVIDER_WIT
        );
        let manifest = FileProvider::manifest();
        assert_eq!(
            serde_json::to_value(&manifest).unwrap(),
            serde_json::from_str::<Value>(include_str!("../tests/fixtures/manifest.json")).unwrap()
        );
        assert_eq!(manifest.id.as_str(), "file");
        assert_eq!(manifest.command_words, ["file"]);
        assert_eq!(manifest.capabilities.len(), 1);
        assert_eq!(manifest.capabilities[0].id.as_str(), IDENTIFY);
        assert_eq!(
            manifest.capabilities[0].effect,
            dekopon_provider_sdk::EffectKind::ReadOnly
        );
        assert_eq!(
            manifest.capabilities[0].risk,
            dekopon_provider_sdk::RiskLevel::Low
        );
    }
}
