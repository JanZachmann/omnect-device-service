pub mod networkd;
pub mod unit;
pub mod watchdog;

use anyhow::{Context, Result};
use log::info;
use sd_notify::NotifyState;
use std::sync::Once;
use systemd_zbus::{ActiveState, ManagerProxy, SubState};
use tokio_stream::StreamExt;

pub fn sd_notify_ready() {
    static SD_NOTIFY_ONCE: Once = Once::new();
    SD_NOTIFY_ONCE.call_once(|| {
        info!("notify ready=1");
        let _ = sd_notify::notify(&[NotifyState::Ready]);
    });
}

async fn system_connection() -> Result<zbus::Connection> {
    zbus::Connection::system()
        .await
        .context("failed to connect to system bus")
}

#[cfg(not(feature = "mock"))]
pub async fn reboot(reason: &str, extra_info: &str) -> Result<()> {
    use crate::reboot_reason;
    use anyhow::Context;
    use log::{debug, error};
    use std::process::Command;

    info!("systemd::reboot");

    reboot_reason::write_reboot_reason(reason, extra_info).context(format!(
        "reboot: failed to write reason '{reason}' with info '{extra_info}'"
    ))?;

    //journalctl seems not to have a dbus api
    match Command::new("sudo").args(["journalctl", "--sync"]).status() {
        Ok(status) if !status.success() => error!("reboot: failed to execute 'journalctl --sync'"),
        Err(e) => error!("reboot: failed to execute 'journalctl --sync' with: {e:#}"),
        _ => debug!("reboot: succeeded to execute 'journalctl --sync'"),
    }

    // Spawn reboot in background with a small delay to allow this function to return
    // and the service to respond to the caller before the system shuts down
    let delay_ms = std::env::var("REBOOT_DELAY_MS")
        .unwrap_or("100".to_string())
        .parse::<u64>()
        .unwrap_or(100);

    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        debug!("triggering reboot.target");
        if let Err(e) = unit::unit_action(
            "reboot.target",
            unit::UnitAction::Start,
            unit::Mode::Replace,
        )
        .await
        {
            error!("failed to start reboot.target: {e:#}");
        }
    });

    Ok(())
}

pub async fn wait_for_system_running() -> Result<()> {
    let connection = system_connection().await?;
    // here we use manager which explicitly doesn't cache the system state
    let manager = ManagerProxy::builder(&connection)
        .uncached_properties(&["SystemState"])
        .build()
        .await
        .context("wait_for_system_running: failed to create manager")?;

    if manager.system_state().await? != "running" {
        manager
            .receive_system_state_changed()
            .await
            .filter(|p| p.name() == "running")
            .next()
            .await;
    }

    Ok(())
}

#[cfg(feature = "mock")]
pub async fn reboot(_reason: &str, _extra_info: &str) -> Result<()> {
    Ok(())
}

#[allow(dead_code)]
const CRASH_LOOP_RESTART_THRESHOLD: u32 = 3;

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub(crate) struct UnitHealth {
    name: String,
    active: ActiveState,
    sub_state: SubState,
    n_restarts: u32,
}

#[derive(Debug, PartialEq)]
#[allow(dead_code)]
enum SystemHealth {
    Healthy,
    Starting(String),
    Degraded(Vec<String>),
    CrashLooping(Vec<String>),
}

#[allow(dead_code)]
fn crash_looping_units(units: &[UnitHealth]) -> Vec<String> {
    let mut looping: Vec<String> = units
        .iter()
        .filter(|u| {
            (u.active == ActiveState::Activating && u.sub_state == SubState::AutoRestart)
                || (u.n_restarts >= CRASH_LOOP_RESTART_THRESHOLD && u.active != ActiveState::Active)
        })
        .map(|u| u.name.clone())
        .collect();
    looping.sort();
    looping
}

#[allow(dead_code)]
fn rate_system_health(system_state: &str, units: &[UnitHealth]) -> SystemHealth {
    match system_state {
        "running" | "degraded" => {
            let looping = crash_looping_units(units);
            if !looping.is_empty() {
                return SystemHealth::CrashLooping(looping);
            }
            if system_state == "degraded" {
                let mut failed: Vec<String> = units
                    .iter()
                    .filter(|u| u.active == ActiveState::Failed)
                    .map(|u| u.name.clone())
                    .collect();
                failed.sort();
                return SystemHealth::Degraded(failed);
            }
            SystemHealth::Healthy
        }
        other => SystemHealth::Starting(other.to_string()),
    }
}

#[allow(dead_code)]
fn degraded_extra_info(units: &[String]) -> String {
    format!("system degraded, failed units: {}", units.join(" "))
}

#[allow(dead_code)]
fn crash_loop_extra_info(units: &[String]) -> String {
    format!("crash-looping units: {}", units.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use systemd_zbus::{ActiveState, SubState};

    fn unit(name: &str, active: ActiveState, sub_state: SubState, n_restarts: u32) -> UnitHealth {
        UnitHealth {
            name: name.to_string(),
            active,
            sub_state,
            n_restarts,
        }
    }

    #[test]
    fn healthy_when_running_without_crash_loops() {
        let units = vec![unit("a.service", ActiveState::Active, SubState::Running, 0)];
        assert_eq!(rate_system_health("running", &units), SystemHealth::Healthy);
    }

    #[test]
    fn non_final_states_keep_polling() {
        assert_eq!(
            rate_system_health("starting", &[]),
            SystemHealth::Starting("starting".to_string())
        );
    }

    #[test]
    fn degraded_lists_failed_units_sorted() {
        let units = vec![
            unit("b.service", ActiveState::Failed, SubState::Failed, 0),
            unit("a.service", ActiveState::Failed, SubState::Failed, 0),
        ];
        assert_eq!(
            rate_system_health("degraded", &units),
            SystemHealth::Degraded(vec!["a.service".to_string(), "b.service".to_string()])
        );
    }

    #[test]
    fn auto_restart_is_a_crash_loop_even_when_running() {
        let units = vec![unit(
            "loop.service",
            ActiveState::Activating,
            SubState::AutoRestart,
            1,
        )];
        assert_eq!(
            rate_system_health("running", &units),
            SystemHealth::CrashLooping(vec!["loop.service".to_string()])
        );
    }

    #[test]
    fn restart_threshold_is_a_crash_loop() {
        let units = vec![unit(
            "loop.service",
            ActiveState::Inactive,
            SubState::Dead,
            CRASH_LOOP_RESTART_THRESHOLD,
        )];
        assert_eq!(
            rate_system_health("running", &units),
            SystemHealth::CrashLooping(vec!["loop.service".to_string()])
        );
    }

    #[test]
    fn recovered_unit_with_restart_history_is_not_a_crash_loop() {
        let units = vec![unit("a.service", ActiveState::Active, SubState::Running, 5)];
        assert_eq!(rate_system_health("running", &units), SystemHealth::Healthy);
    }

    // exact strings are a contract with omnect-os CI
    // (TEST_REBOOT_REASON_CHECK_EXTRA_INFO does an exact match)
    #[test]
    fn extra_info_strings_match_ci_contract() {
        assert_eq!(
            degraded_extra_info(&["dummy-failed.service".to_string()]),
            "system degraded, failed units: dummy-failed.service"
        );
        assert_eq!(
            crash_loop_extra_info(&["dummy-crash-loop.service".to_string()]),
            "crash-looping units: dummy-crash-loop.service"
        );
    }
}
