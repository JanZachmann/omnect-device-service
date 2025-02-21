mod adu_types;
mod common;
mod os_version;
pub mod update_validation;

use crate::{
    bootloader_env, systemd,
    systemd::{unit::UnitAction, watchdog::WatchdogManager},
    twin::{
        feature::*,
        firmware_update::{adu_types::*, common::*, os_version::*},
        system_info::RootPartition,
        Feature,
    },
};
use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use log::{debug, error, info};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Duration,
};
use tar::Archive;

static UPDATE_WDT_INTERVAL_SECS: u64 = 600;

struct RunGuard {
    succeeded: bool,
    wdt: Option<Duration>,
}

impl RunGuard {
    async fn new() -> Result<Self> {
        let succeeded = false;
        let wdt = WatchdogManager::interval(Duration::from_secs(UPDATE_WDT_INTERVAL_SECS)).await?;

        debug!("changed wdt to {UPDATE_WDT_INTERVAL_SECS}s and saved old one ({wdt:?})");

        systemd::unit::unit_action(
            IOT_HUB_DEVICE_UPDATE_SERVICE,
            UnitAction::Stop,
            Duration::from_secs(30),
        )
        .await?;

        debug!("stopped {IOT_HUB_DEVICE_UPDATE_SERVICE}");

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

            debug!("update failed: restore old wdt ({wdt:?}) and restart {IOT_HUB_DEVICE_UPDATE_SERVICE}");

            tokio::spawn(async move {
                if let Some(wdt) = wdt {
                    if let Err(e) = WatchdogManager::interval(wdt).await {
                        error!("failed to restore wdt interval: {e:#}")
                    }
                }

                if let Err(e) = systemd::unit::unit_action(
                    IOT_HUB_DEVICE_UPDATE_SERVICE,
                    UnitAction::Start,
                    Duration::from_secs(30),
                )
                .await
                {
                    error!("failed to restart {IOT_HUB_DEVICE_UPDATE_SERVICE}: {e:#}")
                }
            });
        }
    }
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct LoadUpdateCommand {
    pub update_file_path: PathBuf,
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct RunUpdateCommand {
    pub validate_iothub_connection: bool,
}

#[derive(Default)]
pub struct FirmwareUpdate {
    swu_file_path: Option<String>,
}

impl Drop for FirmwareUpdate {
    fn drop(&mut self) {
        if let Err(e) = Self::clean_working_dir() {
            error!("failed to clean working directory: {e}")
        }
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
        env::var("SUPPRESS_FIRMWARE_UPDATE") != Ok("true".to_string())
    }

    async fn command(&mut self, cmd: Command) -> CommandResult {
        match cmd {
            Command::LoadFirmwareUpdate(cmd) => self.load(cmd.update_file_path),
            Command::RunFirmwareUpdate(cmd) => self.run(cmd.validate_iothub_connection).await,
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

        let du_config: DeviceUpdateConfig = json_from_file(&du_config_path!())?;
        let current_version = OmnectOsVersion::from_sw_versions_file()?;
        let mut ar = Archive::new(fs::File::open(path).context("failed to open archive")?);
        let mut swu_path = None;
        let mut swu_sha = String::from("");
        let mut manifest_path = None;
        let mut manifest_sha1 = String::from("");
        let mut manifest_sha2 = String::from("");

        Self::clean_working_dir().context("failed to clean working directory")?;

        for file in ar.entries().context("failed to get archive entries")? {
            let mut file = file.context("failed to get archive entry")?;
            let path = file.path().context("failed to get entry path")?;

            debug!("extract entry: {path:?}");

            ensure!(
                path.parent().is_some_and(|p| p == Path::new("")),
                "entry path expected at root of archive"
            );

            let Ok(path) = Path::new(&update_folder_path!())
                .join(path.display().to_string())
                .into_os_string()
                .into_string()
            else {
                bail!("failed to create target path for entry")
            };

            if path.ends_with(".swu") {
                file.unpack(&path).context("failed to unpack *.swu")?;
                swu_sha = base64::encode_config(
                    Sha256::digest(std::fs::read(&path).context("failed to read *.swu for hash")?),
                    base64::STANDARD,
                );
                swu_path = Some(path);
            } else if path.ends_with(".swu.importManifest.json") {
                file.unpack(&path)
                    .context("failed to unpack *.swu.importManifest.json")?;
                manifest_sha1 = format!(
                    "{:X}",
                    Sha256::digest(
                        std::fs::read(&path)
                            .context("failed to read *.swu.importManifest.json for hash")?
                    )
                );
                manifest_path = Some(path.clone());
            } else if path.ends_with(".swu.importManifest.json.sha256") {
                file.unpack(&path)
                    .context("failed to unpack *.swu.importManifest.json.sha256")?;
                manifest_sha2 = fs::read_to_string(path)
                    .context("failed to read *.swu.importManifest.json.sha256")?
                    .split_whitespace()
                    .next()
                    .context("failed to read first string of *.swu.importManifest.json.sha256")?
                    .to_owned();
            } else {
                error!("found unexpected entry");
            }
        }

        // ensure manifest hash matches
        ensure!(
            manifest_sha1.eq_ignore_ascii_case(manifest_sha2.trim()),
            "failed to verify *.swu.importManifest.json hash"
        );

        let Some(manifest_path) = manifest_path else {
            bail!("*.swu.importManifest.json missing");
        };

        let Some(swu_path) = swu_path else {
            bail!("*.swu missing");
        };

        let swu_filename = PathBuf::from(&swu_path);
        let Some(swu_filename) = swu_filename.file_name() else {
            bail!("failed to get *.swu filename from path");
        };

        // read manifest
        let manifest: ImportManifest = json_from_file(&manifest_path)?;

        // ensure swu hash
        let Some(file) = manifest
            .files
            .iter()
            .find(|f| swu_filename.eq(f.filename.as_str()))
        else {
            bail!("failed to find *.swu in manifest")
        };

        ensure!(
            file.hashes["sha256"].eq_ignore_ascii_case(swu_sha.trim()),
            "failed to verify *.swu hash"
        );

        ensure!(
            du_config.agents[0].manufacturer == manifest.compatibility[0].manufacturer,
            "failed to verify compatibility: manufacturer"
        );
        ensure!(
            du_config.agents[0].model == manifest.compatibility[0].model,
            "failed to verify compatibility: model"
        );
        ensure!(
            du_config.agents[0]
                .additional_device_properties
                .compatibilityid
                == manifest.compatibility[0].compatibilityid,
            "failed to verify compatibility: compatibilityid"
        );

        let new_version = OmnectOsVersion::from_string(&manifest.update_id.version)?;

        if current_version == new_version {
            bail!("version {current_version} already installed")
        }

        if current_version > new_version {
            bail!("downgrades not allowed ({new_version} < {current_version} )")
        }

        info!("successfully loaded update (current version: {current_version} new version: {new_version})");

        self.swu_file_path = Some(swu_path);

        Ok(Some(
            serde_json::to_value(manifest).context("failed to serialize manifest")?,
        ))
    }

    async fn run(&mut self, validate_iothub_connection: bool) -> CommandResult {
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

        json_to_file(
            &UpdateValidationConfig {
                local: !validate_iothub_connection,
            },
            update_validation_config_path!(),
            true,
        )?;

        if let Err(e) = systemd::reboot().await {
            error!("reboot failed with: {e}");
            return Err(e);
        }

        info!("update succeeded");

        guard.finalize();

        Ok(None)
    }

    #[cfg(not(feature = "mock"))]
    fn swupdate(swu_file_path: &str, selection: &str) -> Result<()> {
        ensure!(
            std::process::Command::new("sudo")
                .arg("-u")
                .arg("adu")
                .arg("swupdate")
                .arg("-v")
                .arg("-i")
                .arg(swu_file_path)
                .arg("-k")
                .arg(pubkey_file_path!())
                .arg("-e")
                .arg(selection)
                /*                 .arg("&>>")
                .arg(log_file_path!()) */
                .current_dir("/usr/bin")
                .status()?
                .success(),
            "failed to run swupdate command"
        );
        Ok(())
    }
    #[cfg(feature = "mock")]
    fn swupdate(_swu_file_path: &str, _selection: &str) -> Result<()> {
        Ok(())
    }

    fn clean_working_dir() -> Result<()> {
        for entry in fs::read_dir(update_folder_path!())? {
            let entry = entry?;
            let path = entry.path();

            if entry.file_type()?.is_dir() {
                fs::remove_dir_all(path)?;
            } else {
                fs::remove_file(path)?;
            }
        }
        Ok(())
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
