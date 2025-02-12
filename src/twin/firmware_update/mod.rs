mod adu_types;
mod osversion;

use super::{feature::*, system_info::*, Feature};
use super::{
    systemd,
    systemd::{unit::UnitAction, watchdog::WatchdogManager},
};
use adu_types::{DeviceUpdateConfig, ImportManifest};
use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use log::{error, info};
use osversion::OmnectOsVersion;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Duration,
};
use tar::Archive;

static IOT_HUB_DEVICE_UPDATE_SERVICE: &str = "deviceupdate-agent.service";

macro_rules! update_path {
    () => {{
        static UPDATE_FILE_PATH_DEFAULT: &'static str =
            "/var/lib/omnect-device-service/local_update/update.tar";
        std::env::var("UPDATE_FILE_PATH").unwrap_or(UPDATE_FILE_PATH_DEFAULT.to_string())
    }};
}

macro_rules! du_config_path {
    () => {{
        static DEVICE_UPDATE_PATH_DEFAULT: &'static str = "/etc/adu/du-config.json";
        std::env::var("DEVICE_UPDATE_PATH").unwrap_or(DEVICE_UPDATE_PATH_DEFAULT.to_string())
    }};
}

struct RunGuard<'a> {
    succeeded: &'a std::sync::Mutex<bool>,
    wdt: Option<Duration>,
}

impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        let Ok(succeeded) = self.succeeded.lock() else {
            error!("RunGuard::drop: failed to lock succeeded");
            return;
        };

        let wdt = self.wdt.take();

        if !(*succeeded) {
            tokio::spawn(async move {
                if let Some(wdt) = wdt {
                    if let Err(e) = WatchdogManager::interval(wdt).await {
                        error!("RunGuard::drop set wdt: {e}")
                    }
                }

                if let Err(e) = systemd::unit::unit_action(
                    IOT_HUB_DEVICE_UPDATE_SERVICE,
                    UnitAction::Start,
                    Duration::from_secs(30),
                )
                .await
                {
                    error!("RunGuard::drop start unit: {e}")
                }
            });
        }
    }
}

#[derive(Default)]
pub struct FirmwareUpdate {
    swu_file_path: Option<String>,
}

impl Drop for FirmwareUpdate {
    fn drop(&mut self) {
        // ToDo: clean directory
    }
}

#[async_trait(?Send)]
impl Feature for FirmwareUpdate {
    fn name(&self) -> String {
        Self::ID.to_string()
    }

    fn version(&self) -> u8 {
        Self::FIRMWARE_UPDATE_VERSION
    }

    fn is_enabled(&self) -> bool {
        env::var("SUPPRESS_NETWORK_STATUS") != Ok("true".to_string())
    }

    async fn command(&mut self, cmd: Command) -> CommandResult {
        match cmd {
            Command::LoadFirmwareUpdate => self.load(),
            Command::RunFirmwareUpdate => self.run().await,
            _ => bail!("unexpected command"),
        }
    }
}

impl FirmwareUpdate {
    const FIRMWARE_UPDATE_VERSION: u8 = 1;
    const ID: &'static str = "firmware_update";

    fn load(&mut self) -> CommandResult {
        self.swu_file_path = None;

        let du_config: DeviceUpdateConfig = Self::json_from_file(&du_config_path!())?;
        let current_version = OmnectOsVersion::from_sw_versions_file()?;
        let mut ar = Archive::new(fs::File::open(update_path!()).context("")?);
        let mut swu_path = None;
        let mut swu_sha = String::from("");
        let mut manifest_path = None;
        let mut manifest_sha1 = String::from("");
        let mut manifest_sha2 = String::from("");

        // ToDo: clean everything but update_path!() in /var/lib/omnect-device-service/local_update/

        for file in ar.entries().context("")? {
            let mut file = file.context("")?;
            let path = file.path().context("")?;

            ensure!(path.parent().is_some_and(|p| p == Path::new("")), "");

            let Ok(path) = Path::new(&update_path!())
                .parent()
                .context("")?
                .join(path.display().to_string())
                .into_os_string()
                .into_string()
            else {
                bail!("")
            };

            if path.ends_with(".swu") {
                file.unpack(&path).context("")?;
                swu_sha = base64::encode_config(
                    Sha256::digest(std::fs::read(&path).context("")?),
                    base64::STANDARD,
                );
                swu_path = Some(path);
            } else if path.ends_with(".swu.importManifest.json") {
                file.unpack(&path).context("")?;
                manifest_sha1 = format!("{:X}", Sha256::digest(std::fs::read(&path).context("")?));
                manifest_path = Some(path.clone());
            } else if path.ends_with(".swu.importManifest.json.sha256") {
                file.unpack(&path).context("")?;
                manifest_sha2 = fs::read_to_string(path).context("")?;
            } else {
                error!("");
            }
        }

        // ensure manifest hash matches
        ensure!(manifest_sha1.eq_ignore_ascii_case(manifest_sha2.trim()), "");

        let Some(manifest_path) = manifest_path else {
            bail!("");
        };

        let Some(swu_path) = swu_path else {
            bail!("");
        };

        let swu_filename = PathBuf::from(&swu_path);
        let Some(swu_filename) = swu_filename.file_name() else {
            bail!("");
        };

        // read manifest
        let manifest: ImportManifest = Self::json_from_file(&manifest_path)?;

        // ensure swu hash
        let Some(file) = manifest
            .files
            .iter()
            .find(|f| swu_filename.eq(f.filename.as_str()))
        else {
            bail!("")
        };

        ensure!(
            file.hashes["sha256"].eq_ignore_ascii_case(swu_sha.trim()),
            ""
        );

        ensure!(
            du_config.agents[0].manufacturer == manifest.compatibility[0].manufacturer,
            ""
        );
        ensure!(
            du_config.agents[0].model == manifest.compatibility[0].model,
            ""
        );
        ensure!(
            du_config.agents[0]
                .additional_device_properties
                .compatibilityid
                == manifest.compatibility[0].compatibilityid,
            ""
        );

        let new_version = OmnectOsVersion::from_string(&manifest.update_id.version)?;

        if current_version == new_version {
            bail!("")
        }

        if current_version > new_version {
            bail!("")
        }

        info!("successfully loaded update: current version: {current_version} new version: {new_version}");

        self.swu_file_path = Some(swu_path);

        Ok(Some(serde_json::to_value(manifest).context("")?))
    }

    async fn run(&mut self) -> CommandResult {
        ensure!(self.swu_file_path.is_some(), "no update loaded");

        let succeeded = std::sync::Mutex::new(false);

        let wdt = WatchdogManager::interval(Duration::from_secs(600)).await?;
        systemd::unit::unit_action(
            IOT_HUB_DEVICE_UPDATE_SERVICE,
            UnitAction::Stop,
            Duration::from_secs(30),
        )
        .await?;

        let _guard = RunGuard {
            succeeded: &succeeded,
            wdt,
        };

        let target_root = match RootPartition::current()? {
            RootPartition::A => RootPartition::B,
            RootPartition::B => RootPartition::A,
        };

        systemd::reboot().await?;

        *succeeded
            .lock()
            .map_err(|_| anyhow::anyhow!("run: cannot lock succeeded"))? = true;

        Ok(None)
    }

    fn json_from_file<P, T>(path: P) -> Result<T>
    where
        P: AsRef<Path>,
        P: std::fmt::Display,
        T: DeserializeOwned,
    {
        serde_json::from_reader(
            fs::OpenOptions::new()
                .read(true)
                .create(false)
                .open(&path)
                .context(format!("failed to open {path}"))?,
        )
        .context(format!("failed to read {path}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_executor::block_on;
    use tempfile;

    #[test]
    fn load_ok() {
        let mut firmware_update = FirmwareUpdate::default();
        let tmp_dir = tempfile::tempdir().unwrap();
        let tar_file = tmp_dir.path().join("update.tar");
        let du_config_file = tmp_dir.path().join("du-config.json");
        let sw_versions_file = tmp_dir.path().join("sw-versions");
        std::fs::copy("testfiles/positive/update.tar", &tar_file).unwrap();
        std::fs::copy("testfiles/positive/du-config.json", &du_config_file).unwrap();
        std::fs::copy("testfiles/positive/sw-versions", &sw_versions_file).unwrap();
        std::env::set_var("UPDATE_FILE_PATH", tar_file);
        std::env::set_var("DEVICE_UPDATE_PATH", du_config_file);
        std::env::set_var("SW_VERSIONS_PATH", sw_versions_file);

        assert!(
            block_on(async { firmware_update.command(Command::LoadFirmwareUpdate).await }).is_ok()
        );
    }
}
