use super::super::systemd::networkd;
use super::web_service;
use super::{feature::*, Feature};
use super::{systemd, systemd::unit::UnitAction};
use anyhow::{anyhow, bail, ensure, Context, Result};
use async_trait::async_trait;
use azure_iot_sdk::client::IotMessage;
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use regex::Regex;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fmt::Display;
use std::{
    borrow::Cow,
    cmp::Ordering,
    collections::HashMap,
    env, fmt, fs, io,
    path::{Path, PathBuf},
    time::Duration,
};
use tar::Archive;
use tokio::{sync::mpsc::Sender, time::interval};

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

macro_rules! sw_versions_path {
    () => {{
        static SW_VERSIONS_PATH_DEFAULT: &'static str = "/etc/sw-versions";
        std::env::var("SW_VERSIONS_PATH").unwrap_or(SW_VERSIONS_PATH_DEFAULT.to_string())
    }};
}

#[derive(Deserialize)]
struct UpdateId {
    provider: String,
    name: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserConsentHandlerProperties {
    installed_criteria: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SWUpdateHandlerProperties {
    installed_criteria: String,
    swu_file_name: String,
    arguments: String,
    script_file_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
enum HandlerProperties {
    UserConsent(UserConsentHandlerProperties),
    SWUpdate(SWUpdateHandlerProperties),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Step {
    #[serde(rename = "type")]
    step_type: String,
    description: String,
    handler: String,
    files: Vec<String>,
    handler_properties: HandlerProperties,
}

#[derive(Deserialize)]
struct Instructions {
    steps: Vec<Step>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct File {
    filename: String,
    size_in_bytes: u64,
    hashes: HashMap<String, String>,
}

#[derive(Deserialize)]
struct Compatibility {
    manufacturer: String,
    model: String,
    compatibilityid: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportManifest {
    update_id: UpdateId,
    is_deployable: bool,
    compatibility: Vec<Compatibility>,
    instructions: Instructions,
    files: Vec<File>,
    created_date_time: String,
    manifest_version: String,
}

#[derive(Deserialize)]
struct AdditionalDeviceProperties {
    compatibilityid: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Agent {
    manufacturer: String,
    model: String,
    additional_device_properties: AdditionalDeviceProperties,
}

#[derive(Deserialize)]
struct DeviceUpdateConfig {
    agents: Vec<Agent>,
}

struct OmnectOsVersion {
    major: u32,
    minor: u32,
    patch: u32,
    build: u32,
}

impl PartialOrd for OmnectOsVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OmnectOsVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        let mut order = self.major.cmp(&other.major);

        if order == Ordering::Equal {
            order = self.minor.cmp(&other.minor);
        }

        if order == Ordering::Equal {
            order = self.patch.cmp(&other.patch);
        }

        if order == Ordering::Equal {
            order = self.build.cmp(&other.build);
        }

        order
    }
}

impl PartialEq for OmnectOsVersion {
    fn eq(&self, other: &Self) -> bool {
        self.major == other.major
            && self.minor == other.minor
            && self.patch == other.patch
            && self.build == other.build
    }
}

impl Eq for OmnectOsVersion {}

impl Display for OmnectOsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({}, {},{}, {})",
            self.major, self.minor, self.patch, self.build
        )
    }
}

impl OmnectOsVersion {
    fn from_string(version: &str) -> Result<OmnectOsVersion> {
        let regex = Regex::new(r#"^(\d*).(\d*).(\d*).(\d*)$"#).context("")?;

        let c = regex.captures(&version).context("")?;

        Ok(OmnectOsVersion {
            major: c[1].to_string().parse().context("")?,
            minor: c[2].to_string().parse().context("")?,
            patch: c[3].to_string().parse().context("")?,
            build: c[4].to_string().parse().context("")?,
        })
    }

    fn from_sw_versions_file() -> Result<OmnectOsVersion> {
        let sw_versions = fs::read_to_string(sw_versions_path!()).context("")?;
        let regex = Regex::new(r#"^.* (\d*).(\d*).(\d*).(\d*)$"#).context("")?;

        let c = regex.captures(&sw_versions).context("")?;

        Ok(OmnectOsVersion {
            major: c[1].to_string().parse().context("")?,
            minor: c[2].to_string().parse().context("")?,
            patch: c[3].to_string().parse().context("")?,
            build: c[4].to_string().parse().context("")?,
        })
    }
}

#[derive(Default)]
pub struct FirmwareUpdate {}

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
            Command::LoadFirmwareUpdate => self.load().await?,
            _ => bail!("unexpected command"),
        }

        Ok(None)
    }
}

impl FirmwareUpdate {
    const FIRMWARE_UPDATE_VERSION: u8 = 1;
    const ID: &'static str = "firmware_update";

    async fn load(&mut self) -> Result<()> {
        // ToDo: a guard to clean update dir in case of erros
        // let guard = ...
        let du_config: DeviceUpdateConfig = Self::json_from_file(&du_config_path!())?;
        let current_version = OmnectOsVersion::from_sw_versions_file()?;
        let mut ar = Archive::new(fs::File::open(update_path!()).context("")?);
        let mut swu_path = None;
        let mut swu_sha = String::from("");
        let mut manifest_path = None;
        let mut manifest_sha1 = String::from("");
        let mut manifest_sha2 = String::from("");

        for (_, file) in ar.entries().context("")?.enumerate() {
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
                // read manifest hash
                manifest_sha2 = fs::read_to_string(path).context("")?;
            } else {
                error!("");
            }
        }

        // ensure manifest hash matches
        ensure!(
            manifest_sha1.eq_ignore_ascii_case(&manifest_sha2.trim()),
            ""
        );

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
            file.hashes["sha256"].eq_ignore_ascii_case(&swu_sha.trim()),
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
        let mut firmware_update = FirmwareUpdate {};
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
