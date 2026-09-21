//! Mandatory component contract tests. Native fake handles cover asset reads:
//! the published testkit cannot supply asset descriptors.
use std::{path::PathBuf, process::Command};

use dekopon_provider_sdk_testkit::{CommandRunOutcome, FakeBroker};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn component() -> PathBuf {
    PathBuf::from(
        std::env::var_os("DEKOPON_PROVIDER_COMPONENT")
            .expect("DEKOPON_PROVIDER_COMPONENT must point at the freshly built component"),
    )
}

#[test]
fn component_imports_only_assets_and_has_three_exports() {
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
    assert_eq!(imports.len(), 1, "{wit}");
    assert!(imports[0].contains("dekopon:asset/asset@0.1.0"), "{wit}");
    let exports: Vec<_> = wit
        .lines()
        .filter(|line| line.trim_start().starts_with("export "))
        .collect();
    assert_eq!(exports.len(), 3, "{wit}");
    for name in ["describe", "invoke", "run-command"] {
        assert!(
            exports
                .iter()
                .any(|line| line.trim_start().starts_with(&format!("export {name}:"))),
            "{wit}"
        );
    }
}

#[tokio::test]
async fn broker_proposes_without_io_and_refuses_unpassed_assets() -> TestResult {
    let broker = FakeBroker::builder()
        .component(component())
        .provider("file")
        .build()
        .await?;
    for (args, stdin) in [
        (vec!["chat-asset:1".into()], None),
        (vec![], Some("chat-asset:1")),
    ] {
        let CommandRunOutcome::Proposed {
            capability,
            input,
            secret_use,
        } = broker.run_command("file", &args, stdin).await?
        else {
            panic!("proposal")
        };
        assert_eq!(capability.as_str(), "file.identify");
        assert_eq!(input, json!({"data":"chat-asset:1"}));
        assert!(secret_use.is_none());
        let error = broker
            .invoke(capability.as_str(), input)
            .await
            .expect_err("reference was not passed");
        assert_eq!(
            error.provider_failure().expect("guest refusal").0,
            "unknown-reference"
        );
    }
    for input in [
        json!({"data":"data:text/plain;base64,eA=="}),
        json!({"data":"/etc/passwd"}),
        json!({"data":"chat-asset:1", "extra":true}),
    ] {
        let error = broker
            .invoke("file.identify", input)
            .await
            .expect_err("invalid input");
        assert_eq!(
            error.provider_failure().expect("guest refusal").0,
            "invalid-input"
        );
    }
    let CommandRunOutcome::Rendered { stdout, status, .. } =
        broker.run_command("file", &["--help".into()], None).await?
    else {
        panic!("help")
    };
    assert_eq!(status, 0);
    assert!(stdout.contains("65536"));
    let error = broker
        .invoke("file.identify", json!({"data":"x".repeat(1_048_577)}))
        .await
        .expect_err("wire limit");
    assert!(error.provider_failure().is_none());
    Ok(())
}
