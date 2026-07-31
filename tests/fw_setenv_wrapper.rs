//! Argument contract of the fw_setenv wrapper: key and value must always reach
//! fw_setenv as data. The wrapper is exercised with a stub instead of the real
//! binary, so the test asserts the argument vector.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

const WRAPPER_SRC: &str = "sudo/fw_setenv_no_script.sh";
const FW_SETENV_ASSIGNMENT: &str = "FW_SETENV=/usr/bin/fw_setenv";
const STUB_SRC: &str = "#!/bin/bash\nprintf '[%s]\\n' \"$@\"\n";
const EXECUTABLE_MODE: u32 = 0o755;
const USAGE_EXIT_CODE: i32 = 1;

fn write_executable(path: &Path, content: &str) {
    fs::write(path, content).expect("write script");
    fs::set_permissions(path, fs::Permissions::from_mode(EXECUTABLE_MODE)).expect("chmod script");
}

/// Copies the wrapper into `dir` with `FW_SETENV` pointing at a stub that dumps its arguments.
fn wrapper_with_stub(dir: &Path) -> PathBuf {
    let stub = dir.join("fw_setenv_stub");
    write_executable(&stub, STUB_SRC);

    let source = fs::read_to_string(WRAPPER_SRC).expect("read wrapper");
    assert!(
        source.contains(FW_SETENV_ASSIGNMENT),
        "{WRAPPER_SRC} no longer contains \"{FW_SETENV_ASSIGNMENT}\""
    );

    let wrapper = dir.join("fw_setenv_no_script.sh");
    write_executable(
        &wrapper,
        &source.replace(
            FW_SETENV_ASSIGNMENT,
            &format!("FW_SETENV={}", stub.display()),
        ),
    );
    wrapper
}

fn run(args: &[&str]) -> Output {
    let dir = TempDir::new().expect("temp dir");
    Command::new(wrapper_with_stub(dir.path()))
        .args(args)
        .output()
        .expect("run wrapper")
}

fn forwarded_args(key: &str, value: &str) -> Vec<String> {
    let output = run(&[key, value]);
    assert!(
        output.status.success(),
        "wrapper failed for [{key}] [{value}]: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("stub output is utf8")
        .lines()
        .map(str::to_string)
        .collect()
}

fn expected_args(key: &str, value: &str) -> Vec<String> {
    vec!["[--]".to_string(), format!("[{key}]"), format!("[{value}]")]
}

#[test]
fn key_and_value_are_forwarded_behind_double_dash() {
    assert_eq!(
        forwarded_args("factory-reset", "1"),
        expected_args("factory-reset", "1")
    );
}

#[test]
fn option_like_value_stays_data() {
    for value in [
        "-s/tmp/evil",
        "--script=/tmp/evil",
        "--scr=/tmp/evil",
        "-c/tmp/evil.conf",
    ] {
        assert_eq!(
            forwarded_args("omnect_extra_bootargs", value),
            expected_args("omnect_extra_bootargs", value),
            "value {value} was not forwarded as data"
        );
    }
}

#[test]
fn option_like_key_stays_data() {
    assert_eq!(
        forwarded_args("--scr=/tmp/evil", "1"),
        expected_args("--scr=/tmp/evil", "1")
    );
}

#[test]
fn value_with_spaces_stays_one_argument() {
    let value = "console=ttyS0 root=/dev/sda2";
    assert_eq!(
        forwarded_args("omnect_extra_bootargs", value),
        expected_args("omnect_extra_bootargs", value)
    );
}

/// An empty value must still be forwarded, otherwise the call turns into a delete.
#[test]
fn empty_value_is_forwarded() {
    assert_eq!(
        forwarded_args("omnect_extra_bootargs", ""),
        expected_args("omnect_extra_bootargs", "")
    );
}

#[test]
fn wrong_argument_count_is_rejected() {
    for args in [
        vec![],
        vec!["only-a-key"],
        vec!["key", "value", "surplus"],
        vec!["key", "value", "-s/tmp/evil"],
    ] {
        let output = run(&args);
        assert_eq!(
            output.status.code(),
            Some(USAGE_EXIT_CODE),
            "unexpected exit code for {args:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("Usage:"),
            "no usage message for {args:?}"
        );
        assert!(
            output.stdout.is_empty(),
            "fw_setenv was called for {args:?}"
        );
    }
}
