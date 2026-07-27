pub mod networkd;
pub mod unit;
pub mod watchdog;

use anyhow::{Context, Result};
use log::info;
use sd_notify::NotifyState;
use std::sync::Once;
use systemd_zbus::{ActiveState, ManagerProxy, SubState};

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

const SYSTEM_HEALTHY_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
// a single clean poll can race a crash loop's short start window
const HEALTHY_CONFIRMATION_POLLS: u32 = 3;

pub async fn wait_for_system_healthy(deadline: std::time::Duration) -> Result<()> {
    let connection = system_connection().await?;
    // we poll SystemState explicitly; the property cache must not hide changes
    let manager = ManagerProxy::builder(&connection)
        .uncached_properties(&["SystemState"])
        .build()
        .await
        .context("wait_for_system_healthy: failed to create manager")?;

    let start = std::time::Instant::now();
    let mut healthy_polls = 0u32;

    loop {
        let state = manager
            .system_state()
            .await
            .context("wait_for_system_healthy: failed to get system state")?;

        let health = match state.as_str() {
            "running" | "degraded" => {
                let units = collect_unit_health(&connection, &manager).await?;
                rate_system_health(&state, &units)
            }
            _ => SystemHealth::Starting(state.clone()),
        };

        match health {
            SystemHealth::Healthy => {
                healthy_polls += 1;
                if healthy_polls >= HEALTHY_CONFIRMATION_POLLS {
                    return Ok(());
                }
            }
            SystemHealth::Starting(_) => healthy_polls = 0,
            SystemHealth::Degraded(units) => anyhow::bail!(degraded_extra_info(&units)),
            SystemHealth::CrashLooping(units) => anyhow::bail!(crash_loop_extra_info(&units)),
        }

        if start.elapsed() >= deadline {
            anyhow::bail!("system not healthy within deadline, last state: {state}");
        }

        tokio::time::sleep(SYSTEM_HEALTHY_POLL_INTERVAL).await;
    }
}

async fn collect_unit_health(
    connection: &zbus::Connection,
    manager: &ManagerProxy<'_>,
) -> Result<Vec<UnitHealth>> {
    let mut units = vec![];

    for unit in manager
        .list_units()
        .await
        .context("collect_unit_health: failed to list units")?
    {
        if !unit.name.ends_with(".service") {
            continue;
        }

        // NRestarts is only relevant for units that are not active
        let n_restarts = if unit.active == ActiveState::Active {
            0
        } else {
            systemd_zbus::ServiceProxy::builder(connection)
                .path(unit.path.clone())?
                .build()
                .await?
                .n_restarts()
                .await
                .unwrap_or(0)
        };

        units.push(UnitHealth {
            name: unit.name,
            active: unit.active,
            sub_state: unit.sub_state,
            n_restarts,
        });
    }

    Ok(units)
}

#[cfg(feature = "mock")]
pub async fn reboot(_reason: &str, _extra_info: &str) -> Result<()> {
    Ok(())
}

const CRASH_LOOP_RESTART_THRESHOLD: u32 = 3;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct UnitHealth {
    name: String,
    active: ActiveState,
    sub_state: SubState,
    n_restarts: u32,
}

#[derive(Debug, PartialEq)]
enum SystemHealth {
    Healthy,
    Starting(String),
    Degraded(Vec<String>),
    CrashLooping(Vec<String>),
}

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

fn degraded_extra_info(units: &[String]) -> String {
    format!("system degraded, failed units: {}", units.join(" "))
}

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
