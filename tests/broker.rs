//! Mandatory component tests, including exact zero ambient or Dekopon imports.
use std::{path::PathBuf, process::Command};

use base64::{Engine, engine::general_purpose::STANDARD};
use dekopon_file_provider::MAX_BYTES;
use dekopon_provider_sdk_testkit::{BrokerHostLimits, CommandRunOutcome, FakeBroker};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn component() -> PathBuf {
    PathBuf::from(
        std::env::var_os("DEKOPON_PROVIDER_COMPONENT")
            .expect("DEKOPON_PROVIDER_COMPONENT must point at the freshly built component"),
    )
}

fn input(bytes: &[u8]) -> Value {
    json!({"data": format!("data:application/octet-stream;base64,{}", STANDARD.encode(bytes))})
}

#[test]
fn component_has_exactly_zero_imports_and_three_exports() {
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
    assert!(imports.is_empty(), "unexpected imports: {imports:?}");
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
async fn broker_runs_identification_cli_and_full_limit_without_extra_authority() -> TestResult {
    let limits = BrokerHostLimits::default();
    assert_eq!(limits.max_memory_bytes, 64 * 1024 * 1024);
    assert_eq!(limits.max_input_bytes, 1_048_576);
    let broker = FakeBroker::builder()
        .component(component())
        .provider("file")
        .host_limits(limits)
        .build()
        .await?;
    let png = broker
        .invoke("file.identify", input(include_bytes!("fixtures/pixel.png")))
        .await?;
    assert_eq!(png["mime"], "image/png");
    for bytes in [vec![0; MAX_BYTES], vec![b'a'; MAX_BYTES]] {
        let result = broker.invoke("file.identify", input(&bytes)).await?;
        assert_eq!(result["input_bytes"], MAX_BYTES);
        assert_eq!(result["validated"], false);
        assert!(serde_json::to_vec(&result)?.len() < 4096);
    }
    for (input, code) in [
        (input(&vec![0; MAX_BYTES + 1]), "input-too-large"),
        (json!({"data": "chat-asset:1"}), "unresolved-asset"),
        (
            json!({"data": "data:text/plain;base64,", "extra": true}),
            "invalid-input",
        ),
    ] {
        let error = broker
            .invoke("file.identify", input)
            .await
            .expect_err("provider refusal");
        assert_eq!(error.provider_failure().expect("guest error").0, code);
    }
    let CommandRunOutcome::Proposed {
        capability,
        input,
        secret_use,
    } = broker
        .run_command("file", &[], Some("data:text/plain;base64,aGVsbG8="))
        .await?
    else {
        panic!("proposal")
    };
    assert!(secret_use.is_none());
    assert_eq!(
        broker.invoke(capability.as_str(), input).await?["mime"],
        "text/plain"
    );
    let CommandRunOutcome::Rendered { stdout, status, .. } =
        broker.run_command("file", &["--help".into()], None).await?
    else {
        panic!("help")
    };
    assert_eq!(status, 0);
    assert!(stdout.contains("262144"));
    Ok(())
}

#[tokio::test]
async fn broker_fuel_and_wire_limits_remain_enforced() -> TestResult {
    let broker = FakeBroker::builder()
        .component(component())
        .provider("file")
        .host_limits(BrokerHostLimits {
            fuel: 1_000_000,
            ..BrokerHostLimits::default()
        })
        .build()
        .await?;
    let error = broker
        .invoke("file.identify", input(&vec![b'a'; MAX_BYTES]))
        .await
        .expect_err("fuel binds maximum input");
    assert!(error.provider_failure().is_none());
    let error = broker
        .invoke("file.identify", json!({"data": "x".repeat(1_048_577)}))
        .await
        .expect_err("wire limit");
    assert!(error.provider_failure().is_none());
    Ok(())
}
