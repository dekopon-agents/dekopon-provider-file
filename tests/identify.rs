use base64::{Engine, engine::general_purpose::STANDARD};
use dekopon_file_provider::{FileProvider, IDENTIFY, MAX_BYTES};
use dekopon_provider_sdk::{CommandRun, Provider};
use serde_json::{Value, json};

fn input(bytes: &[u8]) -> Value {
    json!({"data": format!("data:application/octet-stream;base64,{}", STANDARD.encode(bytes))})
}

fn identify(bytes: &[u8]) -> Value {
    FileProvider::invoke(&IDENTIFY.parse().unwrap(), input(bytes)).unwrap()
}

#[test]
fn real_png_and_signature_vectors_are_content_based() {
    for (bytes, mime, extension) in [
        (
            include_bytes!("fixtures/pixel.png").as_slice(),
            "image/png",
            "png",
        ),
        (b"\xff\xd8\xff\xe0".as_slice(), "image/jpeg", "jpg"),
        (b"%PDF-1.7\n".as_slice(), "application/pdf", "pdf"),
        (b"PK\x03\x04".as_slice(), "application/zip", "zip"),
        (b"GIF89a".as_slice(), "image/gif", "gif"),
    ] {
        let mut misleading = input(bytes);
        misleading["filename"] = json!("../../malicious.exe");
        misleading["content_type"] = json!("text/plain");
        misleading["data"] = json!(format!("data:video/mp4;base64,{}", STANDARD.encode(bytes)));
        let result = FileProvider::invoke(&IDENTIFY.parse().unwrap(), misleading).unwrap();
        assert_eq!(result["mime"], mime);
        assert_eq!(result["extension"], extension);
        assert_eq!(result["validated"], false);
        assert_eq!(result["input_clipped"], false);
        assert_eq!(result["bytes_supplied_to_detector"], bytes.len());
        assert_eq!(result, identify(bytes));
        assert!(serde_json::to_vec(&result).unwrap().len() < 4096);
    }
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
                assert_eq!(result["input_bytes"], len);
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

#[test]
fn input_bounds_closed_fields_and_redacted_errors() {
    assert_eq!(identify(&vec![0; MAX_BYTES])["input_bytes"], MAX_BYTES);
    for size in [MAX_BYTES + 1, MAX_BYTES + 2, MAX_BYTES + 3] {
        let error =
            FileProvider::invoke(&IDENTIFY.parse().unwrap(), input(&vec![0; size])).unwrap_err();
        assert!(error.to_string().contains("262144"));
    }
    for invalid in [
        json!({}),
        json!({"data": 7}),
        json!({"data": "chat-asset:1"}),
        json!({"data": "https://example.com/private"}),
        json!({"data": "/etc/passwd"}),
        json!({"data": "data:text/plain;base64,!!!!"}),
        json!({"data": "data:text/plain;base64,YQ"}),
        json!({"data": "data:text/plain;base64,YR=="}),
        json!({"data": "data:text/plain;base64,YQ==\n"}),
        json!({"data": "data:text/plain;charset=utf-8;base64,YQ=="}),
        json!({"data": "data:text/plain;base64,", "extra": true}),
        json!({"data": "data:text/plain;base64,", "filename": "x".repeat(257)}),
        json!({"data": "data:text/plain;base64,", "filename": "λ".repeat(129)}),
        json!({"data": "data:text/plain;base64,", "content_type": "x".repeat(128)}),
        json!({"data": "data:text/plain;base64,", "filename": "\n"}),
    ] {
        assert!(FileProvider::invoke(&IDENTIFY.parse().unwrap(), invalid).is_err());
    }
    let sentinel = "PRIVATE_SENTINEL";
    let error =
        FileProvider::invoke(&IDENTIFY.parse().unwrap(), json!({"data": sentinel})).unwrap_err();
    assert!(!error.to_string().contains(sentinel));
    assert!(FileProvider::invoke(&"file.other".parse().unwrap(), input(b"x")).is_err());
}

#[test]
fn command_only_proposes_and_does_not_expand_markers() {
    let CommandRun::Proposal(proposal) =
        FileProvider::run_command(&["chat-asset:1".into()], None).unwrap()
    else {
        panic!("proposal")
    };
    assert_eq!(proposal.capability.as_str(), IDENTIFY);
    assert_eq!(proposal.input, json!({"data": "chat-asset:1"}));
    assert!(proposal.secret_use.is_none());
    let CommandRun::Rendered { status, stdout, .. } =
        FileProvider::run_command(&["--help".into()], None).unwrap()
    else {
        panic!("help")
    };
    assert_eq!(status, 0);
    assert!(stdout.contains("262144"));
    assert!(FileProvider::run_command(&[], None).is_err());
    assert!(FileProvider::run_command(&["x".into()], Some("x")).is_err());
    assert!(matches!(
        FileProvider::run_command(&["--mime".into()], None).unwrap(),
        CommandRun::Rendered { status: 2, .. }
    ));
    assert!(matches!(
        FileProvider::run_command(&[], Some("data:text/plain;base64,eA==")).unwrap(),
        CommandRun::Proposal(_)
    ));
}
