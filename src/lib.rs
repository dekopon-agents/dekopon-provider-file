//! Identification of a bounded decoded asset prefix, not file validation.
mod input;

use std::{fmt, io::Write};

use dekopon_provider_sdk::asset::{AssetError, Handle};
use dekopon_provider_sdk::clap::Parser;
use dekopon_provider_sdk::provider::{
    Assets, Capability, Code, Failure, Proposal, Provider, Stdout, Usage,
};
use dekopon_provider_sdk::{EffectKind, RiskLevel};
use file_format::FileFormat;
use serde_json::{Value, json};

pub const IDENTIFY: &str = "file.identify";
/// Decoded prefix budget, matching the detector's existing text-probe bound.
pub const PREFIX_BYTES: usize = 65_536;

#[derive(Parser)]
#[command(
    name = "file",
    version,
    about = "Identify a chat asset's decoded prefix, never open a path or fetch a URL",
    after_help = "Use a positional file chat-asset:<N>. Pipe-only references are not supported: the reference must be proposed before authorization. Reads at most 65536 decoded bytes; identification is a hint, not validation."
)]
pub struct FileArgs {
    /// Positional `chat-asset:<N>` reference (not a path or URL)
    #[arg(value_name = "DATA")]
    data: Option<String>,
}

pub struct FileProvider;
pub struct Identify;

impl Provider for FileProvider {
    const ID: &'static str = "file";
    const COMMAND_WORDS: &'static [&'static str] = &["file"];
    const DESCRIPTION: &'static str = "Content-based identification hints over a bounded chat-asset prefix; no validation or libmagic parity";
    type Args = FileArgs;
    type Capabilities = (Identify,);

    fn propose(args: Self::Args, _stdin_piped: bool) -> Result<Proposal<Self>, Usage> {
        let data = args.data.ok_or_else(|| Usage::new("supply a positional reference: file chat-asset:<N>; pipe-only references are not supported"))?;
        input::reference(&data)
            .map_err(|_| Usage::new("DATA must be a positional chat-asset:<N> reference"))?;
        Ok(Proposal::to::<Identify>(input::Input {
            data,
            filename: None,
            content_type: None,
        }))
    }
}

impl Capability for Identify {
    type Provider = FileProvider;
    const NAME: &'static str = "identify";
    const DESCRIPTION: &'static str = "Identify MIME, extension and description from at most 65536 decoded bytes of an opened chat asset. Signatures can be forged or incomplete. No paths or URLs are opened; no whole-file size ceiling is imposed by this provider.";
    const EFFECT: EffectKind = EffectKind::ReadOnly;
    const RISK: RiskLevel = RiskLevel::Low;
    type Input = input::Input;
    type Needs = Assets;
    type Error = FileError;

    fn run(input: Self::Input, assets: Assets, out: &mut Stdout) -> Result<(), Self::Error> {
        let value = identify_with(input, |reference| assets.open(reference))?;
        emit(&value, out)
    }
}

#[derive(Debug)]
pub enum FileError {
    InvalidInput,
    Asset(&'static str),
    OutputClosed,
}
impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "input does not match the closed file identification contract",
            Self::Asset(_) => "could not read the referenced chat asset",
            Self::OutputClosed => "stdout's reader has gone",
        })
    }
}
impl Failure for FileError {
    fn code(&self) -> Code {
        match self {
            Self::InvalidInput => Code::INVALID_INPUT,
            Self::Asset(code) => Code::new(code),
            Self::OutputClosed => Code::new("output-closed"),
        }
    }
}

trait AssetReader {
    fn read(&self, buffer: &mut [u8]) -> Result<usize, AssetError>;
}
impl AssetReader for Handle {
    fn read(&self, buffer: &mut [u8]) -> Result<usize, AssetError> {
        Handle::read(self, buffer)
    }
}
fn emit(value: &Value, out: &mut impl Write) -> Result<(), FileError> {
    serde_json::to_writer(&mut *out, value).map_err(|_| FileError::OutputClosed)?;
    out.write_all(b"\n").map_err(|_| FileError::OutputClosed)
}

fn asset_error(error: AssetError) -> FileError {
    FileError::Asset(error.code.as_str())
}
fn identify_with<R: AssetReader>(
    input: input::Input,
    open: impl FnOnce(&str) -> Result<R, AssetError>,
) -> Result<Value, FileError> {
    let reference = input::validate(&input)?;
    let handle = open(reference).map_err(asset_error)?;
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

#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code)]
mod guest {
    dekopon_provider_sdk::export!(super::FileProvider);
}

#[cfg(test)]
#[path = "identify_tests.rs"]
mod identify_tests;
