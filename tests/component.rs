//! Real component contract and admission tests. The testkit cannot inject asset descriptors;
//! successful decoded reads are proved with native fake handles, not this harness.
use std::{path::PathBuf, process::Command};

use dekopon_file_provider::FileProvider;
use dekopon_provider_sdk::CommandRunOutcome;
use dekopon_provider_sdk::provider;
use dekopon_provider_sdk_testkit::{Harness, conformance};
use serde_json::json;

fn component() -> PathBuf {
    std::env::var_os("DEKOPON_PROVIDER_COMPONENT")
        .expect("DEKOPON_PROVIDER_COMPONENT must point at the freshly built component")
        .into()
}

#[test]
fn real_component_conforms_to_assets_and_stdio_contract() {
    conformance::<FileProvider>(component())
        .expect("asset + stdio imports and closed typed manifest");
}

#[test]
fn component_has_only_assets_stdio_and_provider_export() {
    let output = Command::new("wasm-tools")
        .args(["component", "wit"])
        .arg(component())
        .output()
        .expect("wasm-tools is required");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let wit = String::from_utf8(output.stdout).unwrap();
    let imports: Vec<_> = wit
        .lines()
        .filter(|line| line.trim_start().starts_with("import "))
        .collect();
    assert_eq!(imports.len(), 2, "{wit}");
    assert!(
        imports
            .iter()
            .any(|line| line.contains("dekopon:asset/asset@0.1.0")),
        "{wit}"
    );
    assert!(
        imports
            .iter()
            .any(|line| line.contains("dekopon:stdio/streams@0.1.0")),
        "{wit}"
    );
    // Component WIT renders the SDK's dekopon:provider@0.4.0 world as root functions.
    for export in [
        "export describe: func() -> string",
        "export invoke: func(capability: string, input-json: string) -> result<_, u8>",
        "export run-command: func(argv: list<string>, stdin-piped: bool) -> string",
    ] {
        assert!(
            wit.contains(export),
            "missing provider@0.4.0 export {export}: {wit}"
        );
    }
    for denied in [
        "wasi:",
        "dekopon:http/",
        "dekopon:clock/",
        "dekopon:settings/",
        "dekopon:storage/",
    ] {
        assert!(!wit.contains(denied), "unexpected import {denied}: {wit}");
    }
}

#[test]
fn missing_descriptor_and_invalid_reference_are_refused() {
    let path = component();
    let CommandRunOutcome::Proposed {
        capability, input, ..
    } = provider::command::<FileProvider>(&["chat-asset:1".into()], false)
    else {
        panic!("proposal")
    };
    assert_eq!(capability.as_str(), "file.identify");
    assert_eq!(input, json!({"data":"chat-asset:1"}));
    let denied = Harness::<FileProvider>::get(&path)
        .call("file.identify", input)
        .expect_err("no descriptor was supplied");
    assert!(
        denied.to_string().contains("invalid invocation assets"),
        "{denied}"
    );
    let bad = Harness::<FileProvider>::get(&path)
        .call("file.identify", json!({"data":"/etc/passwd"}))
        .expect("invalid input exits from the guest without opening an asset");
    assert_eq!(bad.status, 2);
    assert!(bad.stdout.is_empty());
    assert_eq!(
        bad.stderr,
        "input does not match the closed file identification contract\n"
    );
    let CommandRunOutcome::Failed { error } = provider::command::<FileProvider>(&[], true) else {
        panic!("pipe-only must fail")
    };
    assert_eq!(error.code, "usage");
    assert!(error.message.contains("positional"));
}
