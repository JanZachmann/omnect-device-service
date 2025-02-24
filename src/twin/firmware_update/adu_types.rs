use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
pub(crate) struct UpdateId {
    pub(crate) provider: String,
    pub(crate) name: String,
    pub(crate) version: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UserConsentHandlerProperties {
    pub(crate) installed_criteria: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SWUpdateHandlerProperties {
    pub(crate) installed_criteria: String,
    pub(crate) swu_file_name: String,
    pub(crate) arguments: String,
    pub(crate) script_file_name: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub(crate) enum HandlerProperties {
    UserConsent(UserConsentHandlerProperties),
    SWUpdate(SWUpdateHandlerProperties),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Step {
    #[serde(rename = "type")]
    pub(crate) step_type: String,
    pub(crate) description: String,
    pub(crate) handler: String,
    pub(crate) files: Vec<String>,
    pub(crate) handler_properties: HandlerProperties,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Instructions {
    pub(crate) steps: Vec<Step>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct File {
    pub(crate) filename: String,
    pub(crate) size_in_bytes: u64,
    pub(crate) hashes: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Compatibility {
    pub(crate) manufacturer: String,
    pub(crate) model: String,
    pub(crate) compatibilityid: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ImportManifest {
    pub(crate) update_id: UpdateId,
    pub(crate) is_deployable: bool,
    pub(crate) compatibility: Vec<Compatibility>,
    pub(crate) instructions: Instructions,
    pub(crate) files: Vec<File>,
    pub(crate) created_date_time: String,
    pub(crate) manifest_version: String,
}

#[derive(Deserialize)]
pub(crate) struct AdditionalDeviceProperties {
    pub(crate) compatibilityid: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Agent {
    pub(crate) manufacturer: String,
    pub(crate) model: String,
    pub(crate) additional_device_properties: AdditionalDeviceProperties,
}

#[derive(Deserialize)]
pub(crate) struct DeviceUpdateConfig {
    pub(crate) agents: Vec<Agent>,
}
