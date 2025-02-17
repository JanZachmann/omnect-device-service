mod adu_types;
mod osversion;

use crate::{
    bootloader_env, systemd,
    systemd::{unit::UnitAction, watchdog::WatchdogManager},
    twin::{feature::*, system_info::RootPartition, Feature},
    update_validation::UpdateValidationConfig,
    update_validation_config_path,
};
use adu_types::{DeviceUpdateConfig, ImportManifest};
use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use log::{error, info};
use osversion::OmnectOsVersion;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Duration,
};
use tar::Archive;

static IOT_HUB_DEVICE_UPDATE_SERVICE: &str = "deviceupdate-agent.service";

macro_rules! update_folder_path {
    () => {{
        static UPDATE_FOLDER_PATH_DEFAULT: &'static str =
            "/var/lib/omnect-device-service/local_update";
        std::env::var("UPDATE_FOLDER_PATH").unwrap_or(UPDATE_FOLDER_PATH_DEFAULT.to_string())
    }};
}

macro_rules! du_config_path {
    () => {{
        static DEVICE_UPDATE_PATH_DEFAULT: &'static str = "/etc/adu/du-config.json";
        std::env::var("DEVICE_UPDATE_PATH").unwrap_or(DEVICE_UPDATE_PATH_DEFAULT.to_string())
    }};
}

macro_rules! log_file_path {
    () => {{
        static SWUPDATE_LOG_PATH_DEFAULT: &'static str = "/var/log/aduc-logs/swupdate.log";
        std::env::var("SWUPDATE_LOG_PATH").unwrap_or(SWUPDATE_LOG_PATH_DEFAULT.to_string())
    }};
}

#[cfg(not(feature = "mock"))]
macro_rules! pubkey_file_path {
    () => {{
        static SWUPDATE_PUBKEY_PATH_DEFAULT: &'static str = "/usr/share/swupdate/public.pem";
        std::env::var("SWUPDATE_PUBKEY_PATH").unwrap_or(SWUPDATE_PUBKEY_PATH_DEFAULT.to_string())
    }};
}

macro_rules! no_bootloader_updated_file_path {
    () => {{
        static NO_BOOTLOADER_UPDATE_PATH_DEFAULT: &'static str =
            "/run/omnect-bootloader-update-not-necessary";
        std::env::var("NO_BOOTLOADER_UPDATE_PATH")
            .unwrap_or(NO_BOOTLOADER_UPDATE_PATH_DEFAULT.to_string())
    }};
}

macro_rules! bootloader_updated_file_path {
    () => {{
        static BOOTLOADER_UPDATE_PATH_DEFAULT: &'static str = "/run/omnect-bootloader-update";
        std::env::var("BOOTLOADER_UPDATE_PATH")
            .unwrap_or(BOOTLOADER_UPDATE_PATH_DEFAULT.to_string())
    }};
}

struct RunGuard {
    succeeded: bool,
    wdt: Option<Duration>,
}

impl RunGuard {
    async fn new() -> Result<Self> {
        let succeeded = false;
        let wdt = WatchdogManager::interval(Duration::from_secs(600)).await?;

        systemd::unit::unit_action(
            IOT_HUB_DEVICE_UPDATE_SERVICE,
            UnitAction::Stop,
            Duration::from_secs(30),
        )
        .await?;

        Ok(RunGuard { succeeded, wdt })
    }

    fn finalize(&mut self) {
        self.succeeded = true;
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        if !(self.succeeded) {
            let wdt = self.wdt.take();
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

#[derive(Debug, Deserialize, PartialEq)]
pub struct LoadUpdateCommand {
    pub update_file_path: PathBuf,
}

#[derive(Default)]
pub struct FirmwareUpdate {
    swu_file_path: Option<String>,
}

impl Drop for FirmwareUpdate {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&update_folder_path!());
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
            Command::LoadFirmwareUpdate(cmd) => self.load(cmd.update_file_path),
            Command::RunFirmwareUpdate => self.run().await,
            _ => bail!("unexpected command"),
        }
    }
}

impl FirmwareUpdate {
    const FIRMWARE_UPDATE_VERSION: u8 = 1;
    const ID: &'static str = "firmware_update";

    fn load<P>(&mut self, path: P) -> CommandResult
    where
        P: AsRef<Path>,
    {
        self.swu_file_path = None;

        let du_config: DeviceUpdateConfig = Self::json_from_file(&du_config_path!())?;
        let current_version = OmnectOsVersion::from_sw_versions_file()?;
        let mut ar = Archive::new(fs::File::open(path).context("")?);
        let mut swu_path = None;
        let mut swu_sha = String::from("");
        let mut manifest_path = None;
        let mut manifest_sha1 = String::from("");
        let mut manifest_sha2 = String::from("");

        // clean our working folder by 1st removing and 2nd recreating
        let _ = fs::remove_dir_all(&update_folder_path!());
        fs::create_dir_all(&update_folder_path!()).context("")?;

        for file in ar.entries().context("")? {
            let mut file = file.context("")?;
            let path = file.path().context("")?;

            ensure!(path.parent().is_some_and(|p| p == Path::new("")), "");

            let Ok(path) = Path::new(&update_folder_path!())
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
        let Some(ref swu_file_path) = self.swu_file_path else {
            bail!("no update loaded")
        };

        let target_partition = RootPartition::current()?.other();

        let mut guard = RunGuard::new().await?;

        Self::swupdate(swu_file_path, target_partition.root_update_params()).context(format!(
            "failed to update root partition: swupdate logs at {}",
            log_file_path!()
        ))?;

        let _ = fs::remove_file(no_bootloader_updated_file_path!());

        if Self::swupdate(swu_file_path, target_partition.bootloader_update_params()).is_ok() {
            ensure!(
                Path::new(&bootloader_updated_file_path!())
                    .try_exists()
                    .is_ok_and(|result| result),
                format!(
                    "failed to update bootloader: expected {} to be present. (swupdate logs at {})",
                    bootloader_updated_file_path!(),
                    log_file_path!()
                )
            );

            bootloader_env::set("omnect_bootloader_updated", "1")?;
            bootloader_env::set("omnect_os_bootpart", &target_partition.index().to_string())?;
        } else {
            ensure!(
                Path::new(&no_bootloader_updated_file_path!())
                    .try_exists()
                    .is_ok_and(|result| result),
                format!(
                    "failed to update bootloader: expected {} to be present. (swupdate logs at {})",
                    no_bootloader_updated_file_path!(),
                    log_file_path!()
                )
            );

            bootloader_env::set(
                "omnect_validate_update_part",
                &target_partition.index().to_string(),
            )?;
        }

        let update_validation_conf = UpdateValidationConfig { local: true };

        serde_json::to_writer_pretty(
            fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(update_validation_config_path!())
                .context(format!(
                    "failed to open {}",
                    update_validation_config_path!()
                ))?,
            &update_validation_conf,
        )
        .context(format!(
            "failed to serialize to {}",
            update_validation_config_path!()
        ))?;

        systemd::reboot().await?;

        guard.finalize();

        Ok(None)
    }

    #[cfg(not(feature = "mock"))]
    fn swupdate(swu_file_path: &str, selection: &str) -> Result<()> {
        std::process::Command::new("swupdate")
            .arg("-v")
            .arg("-i")
            .arg(swu_file_path)
            .arg("-k")
            .arg(pubkey_file_path!())
            .arg("-e")
            .arg(selection)
            .arg("&>>")
            .arg(log_file_path!())
            .status()?;
        Ok(())
    }
    #[cfg(feature = "mock")]
    fn swupdate(_swu_file_path: &str, _selection: &str) -> Result<()> {
        Ok(())
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
        let update_folder = tmp_dir.path().join("local_update");
        let du_config_file = tmp_dir.path().join("du-config.json");
        let sw_versions_file = tmp_dir.path().join("sw-versions");
        std::fs::copy("testfiles/positive/du-config.json", &du_config_file).unwrap();
        std::fs::copy("testfiles/positive/sw-versions", &sw_versions_file).unwrap();
        std::env::set_var("UPDATE_FOLDER_PATH", update_folder);
        std::env::set_var("DEVICE_UPDATE_PATH", du_config_file);
        std::env::set_var("SW_VERSIONS_PATH", sw_versions_file);

        assert!(block_on(async { firmware_update.load("testfiles/positive/update.tar") }).is_ok());
    }
}
