pub mod networkd;
pub mod unit;
pub mod watchdog;

use anyhow::{Context, Result};
use log::{error, info, warn};
use sd_notify::NotifyState;
use std::{
    future::Future,
    mem::Discriminant,
    sync::Once,
    time::{Duration, Instant},
};
use systemd_zbus::{ActiveState, ManagerProxy};
use zbus::proxy::CacheProperties;

const SYSTEM_STATE_RUNNING: &str = "running";
const SYSTEM_STATE_DEGRADED: &str = "degraded";
const SYSTEM_HEALTHY_POLL_INTERVAL: Duration = Duration::from_secs(2);
// a single poll can land in a restart window in either direction, so a healthy
// and an unhealthy verdict both need the same number of consecutive observations
const HEALTH_CONFIRMATION_POLLS: u32 = 3;
const CRASH_LOOP_RESTART_THRESHOLD_DEFAULT: u32 = 3;
// the unit list ends up in extra_info, which is written to a fixed size pmsg
// record shared by several reboot reasons
const MAX_REPORTED_UNITS: usize = 10;

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

pub async fn wait_for_system_healthy(deadline: Duration) -> Result<()> {
    let connection = system_connection().await?;
    // we poll SystemState explicitly; the property cache must not hide changes
    let manager = ManagerProxy::builder(&connection)
        .uncached_properties(&["SystemState"])
        .build()
        .await
        .context("wait_for_system_healthy: failed to create manager")?;

    watch_system_health(
        SYSTEM_HEALTHY_POLL_INTERVAL,
        deadline,
        crash_loop_restart_threshold(),
        || poll_system_health(&connection, &manager),
    )
    .await
}

// the poll is injected so the decision can be tested without a system bus
async fn watch_system_health<F, Fut>(
    poll_interval: Duration,
    deadline: Duration,
    threshold: u32,
    mut poll: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(SystemState, Vec<UnitHealth>)>>,
{
    let start = Instant::now();
    let mut same_health_polls = 0u32;
    let mut last_health: Option<Discriminant<SystemHealth>> = None;

    loop {
        let (state, units) = poll().await?;
        let health = rate_system_health(&state, &units, threshold);

        let current = std::mem::discriminant(&health);
        same_health_polls = if last_health == Some(current) {
            same_health_polls + 1
        } else {
            1
        };
        last_health = Some(current);

        if same_health_polls >= HEALTH_CONFIRMATION_POLLS {
            match &health {
                SystemHealth::Healthy => return Ok(()),
                SystemHealth::Degraded(units) => anyhow::bail!(degraded_extra_info(units)),
                SystemHealth::CrashLooping(units) => anyhow::bail!(crash_loop_extra_info(units)),
                // no final verdict, so these keep polling until the deadline
                SystemHealth::Restarting(_) | SystemHealth::Starting(_) => {}
            }
        }

        if start.elapsed() >= deadline {
            return match &health {
                // reaching the crash loop threshold takes threshold x RestartSec,
                // much longer than the confirmation polls, so a pending restart
                // is no proof of a loop and must not roll back the update
                SystemHealth::Restarting(units) => {
                    warn!(
                        "deadline reached while units were still restarting: {}",
                        report_units(units)
                    );
                    Ok(())
                }
                SystemHealth::Healthy => Ok(()),
                SystemHealth::Degraded(units) => Err(anyhow::anyhow!(degraded_extra_info(units))),
                SystemHealth::CrashLooping(units) => {
                    Err(anyhow::anyhow!(crash_loop_extra_info(units)))
                }
                SystemHealth::Starting(state) => Err(anyhow::anyhow!(
                    "system not healthy within deadline, last state: {state}"
                )),
            };
        }

        tokio::time::sleep(poll_interval).await;
    }
}

async fn poll_system_health(
    connection: &zbus::Connection,
    manager: &ManagerProxy<'_>,
) -> Result<(SystemState, Vec<UnitHealth>)> {
    let state = SystemState::parse(
        &manager
            .system_state()
            .await
            .context("poll_system_health: failed to get system state")?,
    );

    let units = if matches!(state, SystemState::Other(_)) {
        vec![]
    } else {
        collect_unit_health(connection, manager).await?
    };

    Ok((state, units))
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
        // a transient per-unit D-Bus error must not abort the validation, so it
        // counts as 0
        let n_restarts = if unit.name.ends_with(".service") && in_restart_cycle(&unit.active) {
            service_n_restarts(connection, &unit).await.unwrap_or(0)
        } else {
            0
        };

        units.push(UnitHealth {
            name: unit.name,
            active: unit.active,
            n_restarts,
        });
    }

    Ok(units)
}

async fn service_n_restarts(
    connection: &zbus::Connection,
    unit: &systemd_zbus::Unit,
) -> Result<u32> {
    Ok(systemd_zbus::ServiceProxy::builder(connection)
        .path(unit.path.clone())?
        // a single read per poll: the default cache would subscribe to
        // PropertiesChanged for this unit and be dropped right after
        .cache_properties(CacheProperties::No)
        .build()
        .await?
        .n_restarts()
        .await?)
}

#[cfg(feature = "mock")]
pub async fn reboot(_reason: &str, _extra_info: &str) -> Result<()> {
    Ok(())
}

// overridable: how many retries are normal varies per deployment
fn crash_loop_restart_threshold() -> u32 {
    let mut threshold = CRASH_LOOP_RESTART_THRESHOLD_DEFAULT;
    if let Ok(value) = std::env::var("CRASH_LOOP_RESTART_THRESHOLD") {
        match value.parse::<u32>() {
            // 0 would rate every service in a restart cycle a crash loop
            Ok(0) | Err(_) => error!(
                "ignore invalid crash loop restart threshold {value} and use default {threshold}"
            ),
            Ok(value) => threshold = value,
        };
    }
    threshold
}

#[derive(Debug, Clone, PartialEq)]
struct UnitHealth {
    name: String,
    active: ActiveState,
    n_restarts: u32,
}

// the systemd system states this check distinguishes
#[derive(Debug, PartialEq)]
enum SystemState {
    Running,
    Degraded,
    Other(String),
}

impl SystemState {
    fn parse(state: &str) -> Self {
        match state {
            SYSTEM_STATE_RUNNING => Self::Running,
            SYSTEM_STATE_DEGRADED => Self::Degraded,
            other => Self::Other(other.to_string()),
        }
    }
}

#[derive(Debug, PartialEq)]
enum SystemHealth {
    Healthy,
    Starting(String),
    Restarting(Vec<String>),
    Degraded(Vec<String>),
    CrashLooping(Vec<String>),
}

// systemd keeps a unit 'activating' between a failed start and the next attempt,
// so only there is a restart pending; a unit that recovered or gave up is not
fn in_restart_cycle(active: &ActiveState) -> bool {
    *active == ActiveState::Activating
}

fn restart_cycle_units(units: &[UnitHealth], matches: impl Fn(u32) -> bool) -> Vec<String> {
    let mut names: Vec<String> = units
        .iter()
        .filter(|u| in_restart_cycle(&u.active) && matches(u.n_restarts))
        .map(|u| u.name.clone())
        .collect();
    names.sort();
    names
}

fn crash_looping_units(units: &[UnitHealth], threshold: u32) -> Vec<String> {
    restart_cycle_units(units, |n_restarts| n_restarts >= threshold)
}

fn restarting_units(units: &[UnitHealth], threshold: u32) -> Vec<String> {
    restart_cycle_units(units, |n_restarts| (1..threshold).contains(&n_restarts))
}

fn failed_units(units: &[UnitHealth]) -> Vec<String> {
    let mut failed: Vec<String> = units
        .iter()
        .filter(|u| u.active == ActiveState::Failed)
        .map(|u| u.name.clone())
        .collect();
    failed.sort();
    failed
}

fn rate_system_health(state: &SystemState, units: &[UnitHealth], threshold: u32) -> SystemHealth {
    if let SystemState::Other(state) = state {
        return SystemHealth::Starting(state.clone());
    }

    let looping = crash_looping_units(units, threshold);
    if !looping.is_empty() {
        return SystemHealth::CrashLooping(looping);
    }

    if *state == SystemState::Degraded {
        let failed = failed_units(units);
        return if failed.is_empty() {
            // the state was read before the unit list, so the failed unit may
            // already be gone; without a name there is nothing to report
            SystemHealth::Starting(SYSTEM_STATE_DEGRADED.to_string())
        } else {
            SystemHealth::Degraded(failed)
        };
    }

    let restarting = restarting_units(units, threshold);
    if !restarting.is_empty() {
        return SystemHealth::Restarting(restarting);
    }

    SystemHealth::Healthy
}

fn report_units(units: &[String]) -> String {
    if units.len() <= MAX_REPORTED_UNITS {
        return units.join(" ");
    }

    format!(
        "{} (+{} more)",
        units[..MAX_REPORTED_UNITS].join(" "),
        units.len() - MAX_REPORTED_UNITS
    )
}

fn degraded_extra_info(units: &[String]) -> String {
    format!("system degraded, failed units: {}", report_units(units))
}

fn crash_loop_extra_info(units: &[String]) -> String {
    format!("crash-looping units: {}", report_units(units))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(name: &str, active: ActiveState, n_restarts: u32) -> UnitHealth {
        UnitHealth {
            name: name.to_string(),
            active,
            n_restarts,
        }
    }

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    // drives the decision loop over a scripted poll sequence; an exhausted
    // script is an error, so a test can prove the loop did not stop early
    async fn watch(
        script: Vec<(SystemState, Vec<UnitHealth>)>,
        deadline: Duration,
    ) -> (Result<()>, usize) {
        let mut script = script.into_iter();
        let mut polls = 0usize;
        let result = watch_system_health(
            Duration::ZERO,
            deadline,
            CRASH_LOOP_RESTART_THRESHOLD_DEFAULT,
            || {
                polls += 1;
                std::future::ready(script.next().context("poll script exhausted"))
            },
        )
        .await;
        (result, polls)
    }

    fn healthy_poll() -> (SystemState, Vec<UnitHealth>) {
        (
            SystemState::Running,
            vec![unit("a.service", ActiveState::Active, 0)],
        )
    }

    fn degraded_poll() -> (SystemState, Vec<UnitHealth>) {
        (
            SystemState::Degraded,
            vec![unit("a.service", ActiveState::Failed, 0)],
        )
    }

    fn crash_loop_poll() -> (SystemState, Vec<UnitHealth>) {
        (
            SystemState::Running,
            vec![unit(
                "loop.service",
                ActiveState::Activating,
                CRASH_LOOP_RESTART_THRESHOLD_DEFAULT,
            )],
        )
    }

    fn restarting_poll() -> (SystemState, Vec<UnitHealth>) {
        (
            SystemState::Running,
            vec![unit("loop.service", ActiveState::Activating, 1)],
        )
    }

    #[test]
    fn healthy_when_running_without_crash_loops() {
        let units = vec![unit("a.service", ActiveState::Active, 0)];
        assert_eq!(
            rate_system_health(
                &SystemState::Running,
                &units,
                CRASH_LOOP_RESTART_THRESHOLD_DEFAULT
            ),
            SystemHealth::Healthy
        );
    }

    #[test]
    fn non_final_states_keep_polling() {
        assert_eq!(
            rate_system_health(
                &SystemState::parse("initializing"),
                &[],
                CRASH_LOOP_RESTART_THRESHOLD_DEFAULT
            ),
            SystemHealth::Starting("initializing".to_string())
        );
    }

    #[test]
    fn degraded_lists_failed_units_sorted() {
        let units = vec![
            unit("b.service", ActiveState::Failed, 0),
            unit("a.service", ActiveState::Failed, 0),
        ];
        assert_eq!(
            rate_system_health(
                &SystemState::Degraded,
                &units,
                CRASH_LOOP_RESTART_THRESHOLD_DEFAULT
            ),
            SystemHealth::Degraded(names(&["a.service", "b.service"]))
        );
    }

    #[test]
    fn degraded_lists_failed_non_service_units() {
        let units = vec![unit("data.mount", ActiveState::Failed, 0)];
        assert_eq!(
            rate_system_health(
                &SystemState::Degraded,
                &units,
                CRASH_LOOP_RESTART_THRESHOLD_DEFAULT
            ),
            SystemHealth::Degraded(names(&["data.mount"]))
        );
    }

    // the state is read before the unit list, so the failed unit can be gone by
    // then and there is nothing to name in the reboot reason
    #[test]
    fn degraded_without_failed_units_keeps_polling() {
        let units = vec![unit("a.service", ActiveState::Active, 0)];
        assert_eq!(
            rate_system_health(
                &SystemState::Degraded,
                &units,
                CRASH_LOOP_RESTART_THRESHOLD_DEFAULT
            ),
            SystemHealth::Starting(SYSTEM_STATE_DEGRADED.to_string())
        );
    }

    // the threshold takes threshold x RestartSec to be reached, which is longer
    // than the confirmation polls take, so health must not be confirmed while a
    // restart is pending
    #[test]
    fn restart_below_threshold_is_not_yet_healthy() {
        for n_restarts in 1..CRASH_LOOP_RESTART_THRESHOLD_DEFAULT {
            let units = vec![unit("loop.service", ActiveState::Activating, n_restarts)];
            assert_eq!(
                rate_system_health(
                    &SystemState::Running,
                    &units,
                    CRASH_LOOP_RESTART_THRESHOLD_DEFAULT
                ),
                SystemHealth::Restarting(names(&["loop.service"])),
                "{n_restarts} restarts should keep the check polling"
            );
        }
    }

    #[test]
    fn system_without_restarts_is_healthy() {
        let units = vec![
            unit("a.service", ActiveState::Active, 0),
            unit("b.timer", ActiveState::Inactive, 0),
        ];
        assert_eq!(
            rate_system_health(
                &SystemState::Running,
                &units,
                CRASH_LOOP_RESTART_THRESHOLD_DEFAULT
            ),
            SystemHealth::Healthy
        );
    }

    #[test]
    fn restart_threshold_is_a_crash_loop() {
        let units = vec![unit(
            "loop.service",
            ActiveState::Activating,
            CRASH_LOOP_RESTART_THRESHOLD_DEFAULT,
        )];
        assert_eq!(
            rate_system_health(
                &SystemState::Running,
                &units,
                CRASH_LOOP_RESTART_THRESHOLD_DEFAULT
            ),
            SystemHealth::CrashLooping(names(&["loop.service"]))
        );
    }

    #[test]
    fn custom_threshold_is_honored() {
        let units = vec![unit("loop.service", ActiveState::Activating, 1)];
        assert_eq!(
            rate_system_health(&SystemState::Running, &units, 1),
            SystemHealth::CrashLooping(names(&["loop.service"]))
        );
    }

    #[test]
    fn zero_threshold_falls_back_to_default() {
        crate::common::set_env_var("CRASH_LOOP_RESTART_THRESHOLD", "0");
        assert_eq!(
            crash_loop_restart_threshold(),
            CRASH_LOOP_RESTART_THRESHOLD_DEFAULT
        );
        crate::common::set_env_var("CRASH_LOOP_RESTART_THRESHOLD", "5");
        assert_eq!(crash_loop_restart_threshold(), 5);
        crate::common::remove_env_var("CRASH_LOOP_RESTART_THRESHOLD");
    }

    #[test]
    fn recovered_unit_with_restart_history_is_not_a_crash_loop() {
        let units = vec![unit("a.service", ActiveState::Active, 5)];
        assert_eq!(
            rate_system_health(
                &SystemState::Running,
                &units,
                CRASH_LOOP_RESTART_THRESHOLD_DEFAULT
            ),
            SystemHealth::Healthy
        );
    }

    // a unit that gave up restarting is a failed unit, which the degraded state
    // already reports, so it must not be counted as a loop
    #[test]
    fn unit_that_gave_up_restarting_is_not_a_crash_loop() {
        let units = vec![unit("loop.service", ActiveState::Failed, 5)];
        assert_eq!(
            rate_system_health(
                &SystemState::Degraded,
                &units,
                CRASH_LOOP_RESTART_THRESHOLD_DEFAULT
            ),
            SystemHealth::Degraded(names(&["loop.service"]))
        );
    }

    #[test]
    fn unparseable_threshold_falls_back_to_default() {
        for value in ["", "no", "-1"] {
            crate::common::set_env_var("CRASH_LOOP_RESTART_THRESHOLD", value);
            assert_eq!(
                crash_loop_restart_threshold(),
                CRASH_LOOP_RESTART_THRESHOLD_DEFAULT,
                "\"{value}\" should fall back to the default"
            );
        }
        crate::common::remove_env_var("CRASH_LOOP_RESTART_THRESHOLD");
    }

    #[test]
    fn reported_units_are_capped() {
        let units: Vec<String> = (0..MAX_REPORTED_UNITS + 3)
            .map(|i| format!("u{i}.service"))
            .collect();
        let reported = report_units(&units);
        assert!(reported.ends_with("(+3 more)"), "{reported}");
        assert_eq!(reported.matches(".service").count(), MAX_REPORTED_UNITS);
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

    #[tokio::test(flavor = "multi_thread")]
    async fn health_is_confirmed_by_consecutive_polls() {
        let script = (0..HEALTH_CONFIRMATION_POLLS)
            .map(|_| healthy_poll())
            .collect();
        let (result, polls) = watch(script, Duration::from_secs(60)).await;
        result.expect("healthy system should validate");
        assert_eq!(polls, HEALTH_CONFIRMATION_POLLS as usize);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn fewer_healthy_polls_do_not_confirm() {
        let script = (0..HEALTH_CONFIRMATION_POLLS - 1)
            .map(|_| healthy_poll())
            .collect();
        let (result, _) = watch(script, Duration::from_secs(60)).await;
        assert!(result.is_err(), "health confirmed too early");
    }

    // one poll can land between a unit failing and something restarting it, so a
    // single observation must not roll back the update
    #[tokio::test(flavor = "multi_thread")]
    async fn single_degraded_poll_does_not_roll_back() {
        let mut script = vec![degraded_poll()];
        script.extend((0..HEALTH_CONFIRMATION_POLLS).map(|_| healthy_poll()));
        let (result, _) = watch(script, Duration::from_secs(60)).await;
        result.expect("a single degraded poll should not fail the validation");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn confirmed_degraded_rolls_back_with_the_failed_units() {
        let script = (0..HEALTH_CONFIRMATION_POLLS)
            .map(|_| degraded_poll())
            .collect();
        let (result, _) = watch(script, Duration::from_secs(60)).await;
        assert_eq!(
            result.expect_err("degraded system should fail").to_string(),
            degraded_extra_info(&names(&["a.service"]))
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn confirmed_crash_loop_rolls_back_with_the_looping_units() {
        let script = (0..HEALTH_CONFIRMATION_POLLS)
            .map(|_| crash_loop_poll())
            .collect();
        let (result, _) = watch(script, Duration::from_secs(60)).await;
        assert_eq!(
            result.expect_err("crash loop should fail").to_string(),
            crash_loop_extra_info(&names(&["loop.service"]))
        );
    }

    // alternating failures never confirm one class, so only the deadline ends the
    // wait - it must not poll forever
    #[tokio::test(flavor = "multi_thread")]
    async fn alternating_failures_end_at_the_deadline() {
        let script = vec![degraded_poll(), crash_loop_poll()];
        let (result, polls) = watch(script, Duration::ZERO).await;
        assert!(result.is_err());
        assert_eq!(
            polls, 1,
            "the deadline should end the wait on the first poll"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pending_restart_at_the_deadline_is_accepted() {
        let (result, _) = watch(vec![restarting_poll()], Duration::ZERO).await;
        result.expect("a pending restart is no proof of a crash loop");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn still_starting_at_the_deadline_fails() {
        let script = vec![(SystemState::parse("initializing"), vec![])];
        let (result, _) = watch(script, Duration::ZERO).await;
        assert_eq!(
            result
                .expect_err("a system that never starts should fail")
                .to_string(),
            "system not healthy within deadline, last state: initializing"
        );
    }
}
