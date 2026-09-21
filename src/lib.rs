//! Identification of a bounded decoded asset prefix, not file validation.
mod input;
mod manifest;

use dekopon_provider_sdk::clap::{Arg, Command};
use dekopon_provider_sdk::{
    CapabilityId, CommandInvocation, CommandRun, Provider, ProviderError, ProviderManifest, cli,
};
use file_format::FileFormat;
use serde_json::{Value, json};

pub const IDENTIFY: &str = "file.identify";
/// Decoded prefix budget, matching the detector's existing text-probe bound.
pub const PREFIX_BYTES: usize = 65_536;

#[allow(unsafe_code)]
mod bindings {
    wit_bindgen::generate!({
        path: "wit",
        world: "provider",
        with: {
            "dekopon:asset/asset@0.1.0": dekopon_provider_sdk::asset::bindings::dekopon::asset::asset,
        },
    });
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
        identify_with(input, asset::open)
    }

    fn run_command(argv: &[String], stdin: Option<&str>) -> Result<CommandRun, ProviderError> {
        let command = Command::new("file")
            .version(env!("CARGO_PKG_VERSION"))
            .about("Identify a chat asset's decoded prefix, never open a path or fetch a URL")
            .after_help("DATA must be chat-asset:<N>. With no DATA, pipe one exact reference. Reads at most 65536 decoded bytes; no provider whole-file size ceiling. Identification is a hint, not validation.")
            .arg(Arg::new("data").value_name("DATA"));
        cli::run_command(command, argv, stdin, |matches, stdin| {
            let data = match (matches.get_one::<String>("data"), stdin) {
                (Some(data), None) => data.as_str(),
                (None, Some(data)) => data,
                _ => {
                    return Err(ProviderError::new(
                        "usage",
                        "supply DATA or pipe one exact reference, not both",
                    ));
                }
            };
            input::reference(data)?;
            Ok(CommandInvocation {
                capability: IDENTIFY.parse().expect("static capability"),
                input: json!({"data": data}),
                secret_use: None,
            })
        })
    }
}

use dekopon_provider_sdk::asset::{self, AssetError, Handle};

trait AssetReader {
    fn read(&self, buffer: &mut [u8]) -> Result<usize, AssetError>;
}

impl AssetReader for Handle {
    fn read(&self, buffer: &mut [u8]) -> Result<usize, AssetError> {
        Handle::read(self, buffer)
    }
}

fn asset_error(error: AssetError) -> ProviderError {
    // Preserve the stable class, but never echo host details or input labels.
    ProviderError::new(
        error.code.as_str(),
        "could not read the referenced chat asset",
    )
}

fn identify_with<R: AssetReader>(
    input: Value,
    open: impl FnOnce(&str) -> Result<R, AssetError>,
) -> Result<Value, ProviderError> {
    let reference = input::parse(input)?;
    let handle = open(&reference).map_err(asset_error)?;
    let mut bytes = vec![0; PREFIX_BYTES];
    let mut used = 0;
    while used < PREFIX_BYTES {
        let read = handle.read(&mut bytes[used..]).map_err(asset_error)?;
        if read == 0 {
            break;
        }
        used += read;
    }
    bytes.truncate(used);
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
        "bytes_supplied_to_detector": bytes.len(),
        "prefix_limit_reached": bytes.len() == PREFIX_BYTES,
        "evidence": evidence,
        "validated": false,
        "detector": "file-format/0.29.0; reader-txt",
        "limitations": "Identification hint only: headers can be forged or incomplete; no structural, codec or safety validation. Text fallback checks at most 16 lines / 65536 bytes. Filename and declared MIME are ignored. Not libmagic parity."
    }))
}

#[cfg(test)]
#[path = "identify_tests.rs"]
mod identify_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirrored_wit_and_manifest() {
        assert_eq!(
            include_str!("../wit/deps/provider.wit"),
            dekopon_provider_sdk::PROVIDER_WIT
        );
        assert_eq!(
            include_str!("../wit/deps/asset.wit"),
            dekopon_provider_sdk::ASSET_WIT
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
