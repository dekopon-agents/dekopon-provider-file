use super::*;
use dekopon_provider_sdk::asset::AssetErrorCode;
use dekopon_provider_sdk::provider::{self, Code, Failure};
use serde_json::json;

fn input(value: Value) -> input::Input {
    serde_json::from_value(value).expect("valid input fixture")
}
use std::cell::{Cell, RefCell};
use std::rc::Rc;

struct FakeHandle {
    bytes: Vec<u8>,
    cursor: Cell<usize>,
    chunk: usize,
    requests: Rc<RefCell<Vec<usize>>>,
    fail: bool,
}
impl AssetReader for FakeHandle {
    fn read(&self, buffer: &mut [u8]) -> Result<usize, AssetError> {
        self.requests.borrow_mut().push(buffer.len());
        if self.fail {
            return Err(AssetError {
                code: AssetErrorCode::Io,
                message: "PRIVATE_SENTINEL".into(),
            });
        }
        let start = self.cursor.get();
        let len = buffer.len().min(self.chunk).min(self.bytes.len() - start);
        buffer[..len].copy_from_slice(&self.bytes[start..start + len]);
        self.cursor.set(start + len);
        Ok(len)
    }
}
fn fake(bytes: &[u8], chunk: usize) -> FakeHandle {
    FakeHandle {
        bytes: bytes.to_vec(),
        cursor: Cell::new(0),
        chunk,
        requests: Rc::default(),
        fail: false,
    }
}
fn identify(bytes: &[u8]) -> Value {
    identify_with(input(json!({"data":"chat-asset:1"})), |reference| {
        assert_eq!(reference, "chat-asset:1");
        Ok(fake(bytes, usize::MAX))
    })
    .unwrap()
}

#[test]
fn real_png_and_signature_vectors_are_content_based() {
    for (bytes, mime) in [
        (
            include_bytes!("../tests/fixtures/pixel.png").as_slice(),
            "image/png",
        ),
        (b"\xff\xd8\xff\xe0".as_slice(), "image/jpeg"),
        (b"%PDF-1.7\n".as_slice(), "application/pdf"),
        (b"PK\x03\x04".as_slice(), "application/zip"),
        (b"GIF89a".as_slice(), "image/gif"),
    ] {
        let result = identify_with(input(json!({"data":"chat-asset:1", "filename":"../../wrong.exe", "content_type":"text/plain"})), |_| Ok(fake(bytes, 3))).unwrap();
        assert_eq!(result["mime"], mime);
        assert_eq!(result, identify(bytes));
        assert_eq!(result["validated"], false);
        assert_eq!(result["prefix_limit_reached"], false);
        assert!(serde_json::to_vec(&result).unwrap().len() < 4096);
    }
}

#[test]
fn prefix_budget_handles_short_reads_eof_and_large_assets() {
    for size in [
        0,
        1,
        PREFIX_BYTES - 1,
        PREFIX_BYTES,
        PREFIX_BYTES + 1,
        8 * 1024 * 1024,
    ] {
        let bytes = vec![0; size];
        let reader = fake(&bytes, 997);
        let requests = reader.requests.clone();
        let result = identify_with(input(json!({"data":"chat-asset:9"})), |_| Ok(reader)).unwrap();
        assert_eq!(result["bytes_supplied_to_detector"], size.min(PREFIX_BYTES));
        assert_eq!(result["prefix_limit_reached"], size >= PREFIX_BYTES);
        let requests = requests.borrow();
        let mut consumed = 0;
        for request in requests.iter() {
            assert_eq!(*request, PREFIX_BYTES - consumed);
            consumed += (*request).min(997).min(size - consumed);
        }
        assert_eq!(consumed, size.min(PREFIX_BYTES));
    }
}

#[test]
fn invalid_inputs_never_open_and_errors_do_not_echo() {
    for invalid in [
        json!({}),
        json!({"data":7}),
        json!({"data":"chat-asset:"}),
        json!({"data":"chat-asset:-1"}),
        json!({"data":"chat-asset:18446744073709551616"}),
        json!({"data":"chat-asset:1\n"}),
        json!({"data":"chat-asset:1/private"}),
        json!({"data":"data:text/plain;base64,eA=="}),
        json!({"data":"/etc/passwd"}),
        json!({"data":"https://example.com/private"}),
        json!({"data":"PRIVATE_SENTINEL"}),
        json!({"data":"chat-asset:1", "extra":true}),
        json!({"data":"chat-asset:1", "filename":"λ".repeat(129)}),
        json!({"data":"chat-asset:1", "content_type":"x".repeat(128)}),
        json!({"data":"chat-asset:1", "filename":"\n"}),
    ] {
        if let Ok(input) = serde_json::from_value::<input::Input>(invalid) {
            let error =
                identify_with::<FakeHandle>(input, |_| panic!("must not open")).unwrap_err();
            assert_eq!(error.code(), Code::INVALID_INPUT);
            assert!(!error.to_string().contains("PRIVATE_SENTINEL"));
        }
    }
    let error = identify_with::<FakeHandle>(input(json!({"data":"chat-asset:1"})), |_| {
        Err(AssetError {
            code: AssetErrorCode::UnknownReference,
            message: "PRIVATE_SENTINEL".into(),
        })
    })
    .unwrap_err();
    assert_eq!(error.code(), Code::new("unknown-reference"));
    assert!(!error.to_string().contains("PRIVATE_SENTINEL"));
    let mut reader = fake(b"x", 1);
    reader.fail = true;
    let requests = reader.requests.clone();
    let error = identify_with(input(json!({"data":"chat-asset:1"})), |_| Ok(reader)).unwrap_err();
    assert!(!error.to_string().contains("PRIVATE_SENTINEL"));
    assert_eq!(requests.borrow().len(), 1);
    assert!(matches!(
        provider::command::<FileProvider>(&["bad-path".into()], false),
        dekopon_provider_sdk::CommandRunOutcome::Failed { .. }
    ));
}

#[test]
fn command_is_pure_and_accepts_only_references() {
    use dekopon_provider_sdk::CommandRunOutcome;
    for piped in [false, true] {
        let CommandRunOutcome::Proposed {
            capability,
            input,
            secret_use,
        } = provider::command::<FileProvider>(&["chat-asset:1".into()], piped)
        else {
            panic!("proposal")
        };
        assert_eq!(capability.as_str(), IDENTIFY);
        assert_eq!(input, json!({"data":"chat-asset:1"}));
        assert!(secret_use.is_none());
    }
    for data in [
        "data:text/plain;base64,eA==",
        "/etc/passwd",
        "chat-asset:1\n",
    ] {
        assert!(matches!(
            provider::command::<FileProvider>(&[data.into()], false),
            CommandRunOutcome::Failed { .. }
        ));
    }
    for piped in [false, true] {
        let CommandRunOutcome::Failed { error } = provider::command::<FileProvider>(&[], piped)
        else {
            panic!("usage")
        };
        assert_eq!(error.code, "usage");
        assert!(error.message.contains("positional"));
    }
    let CommandRunOutcome::Rendered { status, stdout, .. } =
        provider::command::<FileProvider>(&["--help".into()], false)
    else {
        panic!("help")
    };
    assert_eq!(status, 0);
    assert!(stdout.contains("65536"));
    assert!(stdout.contains("Pipe-only references are not supported"));
    assert!(matches!(
        provider::command::<FileProvider>(&["--mime".into()], false),
        CommandRunOutcome::Rendered { status: 2, .. }
    ));
}

#[test]
fn output_is_one_json_line_and_closed_stdout_fails() {
    let value = identify(b"hello\n");
    let mut output = Vec::new();
    emit(&value, &mut output).unwrap();
    assert_eq!(output.iter().filter(|&&byte| byte == b'\n').count(), 1);
    assert!(output.ends_with(b"\n"));
    let parsed: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(parsed, value);
    assert_eq!(parsed.as_object().unwrap().len(), 10);
    // A writer that refuses writes models the closed stdio reader.
    struct Closed;
    impl std::io::Write for Closed {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        emit(&value, &mut Closed).unwrap_err().code(),
        Code::new("output-closed")
    );
}

#[test]
fn typed_manifest_is_closed_and_minimal() {
    let manifest = provider::manifest::<FileProvider>().unwrap();
    assert_eq!(manifest.id.as_str(), "file");
    assert_eq!(manifest.command_words, ["file"]);
    assert_eq!(manifest.capabilities.len(), 1);
    let capability = &manifest.capabilities[0];
    assert_eq!(capability.id.as_str(), IDENTIFY);
    assert_eq!(capability.effect, EffectKind::ReadOnly);
    assert_eq!(capability.risk, RiskLevel::Low);
    let schema = &capability.input_schema;
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["required"], json!(["data"]));
    assert_eq!(
        schema["properties"]["data"]["pattern"],
        "^chat-asset:[0-9]+$"
    );
    assert_eq!(
        schema["properties"]["filename"]["x-dekopon-maxUtf8Bytes"],
        256
    );
    assert_eq!(
        schema["properties"]["content_type"]["x-dekopon-maxUtf8Bytes"],
        127
    );
}

fn bmff(brand: &[u8; 4], compatible: &[u8; 4]) -> Vec<u8> {
    [
        20_u32.to_be_bytes().as_slice(),
        b"ftyp",
        brand,
        &[0; 4],
        compatible,
    ]
    .concat()
}

#[test]
fn heic_heif_avif_major_brands_not_codec_validation() {
    for (brand, mime) in [
        (b"heic", "image/heic"),
        (b"heix", "image/heic"),
        (b"hevc", "image/heic-sequence"),
        (b"hevx", "image/heic-sequence"),
        (b"mif1", "image/heif"),
        (b"msf1", "image/heif-sequence"),
        (b"avif", "image/avif"),
        (b"avis", "image/avif-sequence"),
    ] {
        for compatible in [b"heic", b"avif", b"zzzz"] {
            let mut bytes = bmff(brand, compatible);
            assert_eq!(identify(&bytes)["mime"], mime);
            // A bogus declared box size still matches. The result never claims validity.
            bytes[..4].copy_from_slice(&u32::MAX.to_be_bytes());
            assert_eq!(identify(&bytes)["mime"], mime);
            bytes[..4].copy_from_slice(&1_u32.to_be_bytes());
            assert_eq!(identify(&bytes)["mime"], mime);
            for len in 0..=bytes.len() {
                let result = identify(&bytes[..len]);
                assert_eq!(result["validated"], false);
                assert_eq!(result["bytes_supplied_to_detector"], len);
                if len >= 12 {
                    assert_eq!(result["mime"], mime);
                }
            }
        }
    }
    assert_eq!(identify(&bmff(b"zzzz", b"heic"))["status"], "unknown");
}

#[test]
fn empty_unknown_text_and_truncated_signatures_are_honest() {
    assert_eq!(identify(b"")["status"], "empty");
    for bytes in [
        b"\0\0\0".as_slice(),
        b"\xff\xfe\0\xff",
        b"\x89PN",
        b"\xff\xfeH\0i\0",
    ] {
        assert_eq!(identify(bytes)["status"], "unknown");
        assert_eq!(identify(bytes)["extension"], Value::Null);
    }
    for text in ["hello\n", "λ 日本語\n"] {
        assert_eq!(identify(text.as_bytes())["mime"], "text/plain");
        assert_eq!(
            identify(text.as_bytes())["evidence"],
            "bounded-text-heuristic"
        );
    }
    // The detector's internal text probe is bounded, not whole-file validation.
    let late_binary = ["line\n".repeat(16).as_bytes(), b"\0\xff"].concat();
    assert_eq!(identify(&late_binary)["mime"], "text/plain");
    let late_binary = [vec![b'a'; 65_536], vec![0, 255]].concat();
    assert_eq!(identify(&late_binary)["mime"], "text/plain");
    for len in 0..8 {
        assert_ne!(identify(&b"\x89PNG\r\n\x1a\n"[..len])["mime"], "image/png");
    }
    assert_eq!(identify(b"\x89PNG\r\n\x1a\n")["mime"], "image/png");
}
