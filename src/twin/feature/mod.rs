use crate::twin::{
    consent, factory_reset, firmware_update, network, reboot, ssh_tunnel, TwinUpdate,
    TwinUpdateState,
};
use anyhow::{bail, ensure, Result};
use async_trait::async_trait;
use azure_iot_sdk::client::{DirectMethod, IotMessage};
use futures::Stream;
use futures::StreamExt;
use log::{debug, error, info, warn};
use notify_debouncer_full::{new_debouncer, notify::*, DebounceEventResult, Debouncer, NoCache};
use std::{
    any::TypeId,
    path::{Path, PathBuf},
    pin::Pin,
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot},
    time::{Instant, Interval},
};

#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    CloseSshTunnel(ssh_tunnel::CloseSshTunnelCommand),
    DesiredGeneralConsent(consent::DesiredGeneralConsentCommand),
    DesiredUpdateDeviceSshCa(ssh_tunnel::UpdateDeviceSshCaCommand),
    FactoryReset(factory_reset::FactoryResetCommand),
    FileCreated(FileCommand),
    FileModified(FileCommand),
    GetSshPubKey(ssh_tunnel::GetSshPubKeyCommand),
    Interval(IntervalCommand),
    LoadFirmwareUpdate(firmware_update::LoadUpdateCommand),
    OpenSshTunnel(ssh_tunnel::OpenSshTunnelCommand),
    Reboot,
    ReloadNetwork,
    RunFirmwareUpdate(firmware_update::RunUpdateCommand),
    SetWaitOnlineTimeout(reboot::SetWaitOnlineTimeoutCommand),
    ValidateUpdateAuthenticated(bool),
    UserConsent(consent::UserConsentCommand),
}

impl Command {
    pub fn feature_id(&self) -> TypeId {
        use Command::*;

        match self {
            CloseSshTunnel(_) => TypeId::of::<ssh_tunnel::SshTunnel>(),
            DesiredGeneralConsent(_) => TypeId::of::<consent::DeviceUpdateConsent>(),
            DesiredUpdateDeviceSshCa(_) => TypeId::of::<ssh_tunnel::SshTunnel>(),
            FactoryReset(_) => TypeId::of::<factory_reset::FactoryReset>(),
            FileCreated(cmd) => cmd.feature_id,
            FileModified(cmd) => cmd.feature_id,
            GetSshPubKey(_) => TypeId::of::<ssh_tunnel::SshTunnel>(),
            Interval(cmd) => cmd.feature_id,
            LoadFirmwareUpdate(_) => TypeId::of::<firmware_update::FirmwareUpdate>(),
            OpenSshTunnel(_) => TypeId::of::<ssh_tunnel::SshTunnel>(),
            Reboot => TypeId::of::<reboot::Reboot>(),
            ReloadNetwork => TypeId::of::<network::Network>(),
            RunFirmwareUpdate(_) => TypeId::of::<firmware_update::FirmwareUpdate>(),
            SetWaitOnlineTimeout(_) => TypeId::of::<reboot::Reboot>(),
            ValidateUpdateAuthenticated(_) => TypeId::of::<firmware_update::FirmwareUpdate>(),
            UserConsent(_) => TypeId::of::<consent::DeviceUpdateConsent>(),
        }
    }

    pub fn from_direct_method(name: &str, payload: serde_json::Value) -> Result<Command> {
        info!("direct method: {name}");

        // ToDo: write macro or fn for match arms
        match name {
            "factory_reset" => match serde_json::from_value(payload) {
                Ok(c) => Ok(Command::FactoryReset(c)),
                Err(e) => {
                    bail!("cannot parse FactoryReset from direct method payload {e}")
                }
            },
            "user_consent" => match serde_json::from_value(payload) {
                Ok(c) => Ok(Command::UserConsent(consent::UserConsentCommand {
                    user_consent: c,
                })),
                Err(e) => {
                    bail!("cannot parse UserConsent from direct method payload {e}")
                }
            },
            "get_ssh_pub_key" => match serde_json::from_value(payload) {
                Ok(c) => Ok(Command::GetSshPubKey(c)),
                Err(e) => {
                    bail!("cannot parse GetSshPubKey from direct method payload {e}")
                }
            },
            "open_ssh_tunnel" => match serde_json::from_value(payload) {
                Ok(c) => Ok(Command::OpenSshTunnel(c)),
                Err(e) => {
                    bail!("cannot parse OpenSshTunnel from direct method payload {e}")
                }
            },
            "close_ssh_tunnel" => match serde_json::from_value(payload) {
                Ok(c) => Ok(Command::CloseSshTunnel(c)),
                Err(e) => {
                    bail!("cannot parse CloseSshTunnel from direct method payload {e}")
                }
            },
            "reboot" => Ok(Command::Reboot),
            "set_wait_online_timeout" => match serde_json::from_value(payload) {
                Ok(c) => Ok(Command::SetWaitOnlineTimeout(c)),
                Err(e) => {
                    bail!("cannot parse CloseSshTunnel from direct method payload {e}")
                }
            },
            _ => {
                bail!("unknown direct method {} with payload {}", name, payload)
            }
        }
    }

    // we only log errors and don't fail in this function if input cannot be parsed
    pub fn from_desired_property(name: &str, value: serde_json::Value) -> Result<Option<Command>> {
        info!("desired property: {name}");

        match name {
            "ssh_tunnel_ca_pub" => match serde_json::from_value(value) {
                Ok(c) => Ok(Some(Command::DesiredUpdateDeviceSshCa(c))),
                Err(e) => {
                    bail!("from_desired_property: cannot parse DesiredUpdateDeviceSshCa {e:#}")
                }
            },
            "general_consent" => match serde_json::from_value(value) {
                Ok(c) => Ok(Some(Command::DesiredGeneralConsent(c))),
                Err(e) => {
                    bail!("from_desired_property: cannot parse DesiredGeneralConsentCommand {e:#}")
                }
            },
            "$version" => {
                /*ignore*/
                Ok(None)
            }
            _ => {
                warn!("from_desired_property: unhandled desired property {name}");
                Ok(None)
            }
        }
    }
}

#[derive(Debug)]
pub struct CommandRequest {
    pub command: Command,
    pub reply: Option<oneshot::Sender<CommandResult>>,
}

impl CommandRequest {
    pub fn from_direct_method(direct_method: DirectMethod) -> Option<CommandRequest> {
        match Command::from_direct_method(&direct_method.name, direct_method.payload) {
            Ok(command) => Some(CommandRequest {
                command,
                reply: Some(direct_method.responder),
            }),
            Err(e) => {
                error!("{e:#}");
                if direct_method.responder.send(Err(e)).is_err() {
                    error!("direct method response receiver dropped")
                }
                None
            }
        }
    }

    // we only log errors and don't fail in this function if input cannot be parsed
    pub fn from_desired_property(update: TwinUpdate) -> Vec<CommandRequest> {
        info!("desired property: {update:?}");
        let mut cmds = vec![];

        let value = match update.state {
            TwinUpdateState::Partial => &update.value,
            TwinUpdateState::Complete => &update.value["desired"],
        };

        if let Some(map) = value.as_object() {
            for k in map.keys() {
                match Command::from_desired_property(k.as_str(), value.clone()) {
                    Ok(Some(command)) => cmds.push(CommandRequest {
                        command,
                        reply: None,
                    }),
                    Ok(None) => { /* ignore */ }
                    Err(e) => error!("{e}"),
                }
            }
        }

        cmds
    }
}

pub type CommandResult = Result<Option<serde_json::Value>>;
pub type CommandRequestStream = Pin<Box<dyn Stream<Item = CommandRequest> + Send>>;
pub type CommandRequestStreamResult = Result<Option<CommandRequestStream>>;

#[async_trait(?Send)]
pub trait Feature {
    fn name(&self) -> String;
    fn version(&self) -> u8;
    fn is_enabled(&self) -> bool;

    async fn connect_twin(
        &mut self,
        _tx_reported_properties: mpsc::Sender<serde_json::Value>,
        _tx_outgoing_message: mpsc::Sender<IotMessage>,
    ) -> Result<()> {
        Ok(())
    }

    async fn connect_web_service(&self) -> Result<()> {
        Ok(())
    }

    fn command_request_stream(&mut self) -> CommandRequestStreamResult {
        Ok(None)
    }

    async fn command(&mut self, _cmd: &Command) -> CommandResult {
        unimplemented!();
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct FileCommand {
    pub feature_id: TypeId,
    pub path: PathBuf,
}

#[derive(Clone, Debug, PartialEq)]
pub struct IntervalCommand {
    pub feature_id: TypeId,
    pub instant: Instant,
}

pub fn interval_stream<T>(interval: Interval) -> CommandRequestStream
where
    T: 'static,
{
    tokio_stream::wrappers::IntervalStream::new(interval)
        .map(|i| CommandRequest {
            command: Command::Interval(IntervalCommand {
                feature_id: TypeId::of::<T>(),
                instant: i,
            }),
            reply: None,
        })
        .boxed()
}

pub fn file_created_stream<T>(paths: Vec<&Path>) -> CommandRequestStream
where
    T: 'static,
{
    let (tx, rx) = mpsc::channel(2);
    let inner_paths: Vec<PathBuf> = paths.into_iter().map(|p| p.to_path_buf()).collect();

    tokio::task::spawn_blocking(move || loop {
        for p in &inner_paths {
            if matches!(p.try_exists(), Ok(true)) {
                let _ = tx.blocking_send(CommandRequest {
                    command: Command::FileCreated(FileCommand {
                        feature_id: TypeId::of::<T>(),
                        path: p.clone(),
                    }),
                    reply: None,
                });
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    });

    tokio_stream::wrappers::ReceiverStream::new(rx).boxed()
}

pub fn file_modified_stream<T>(
    paths: Vec<&Path>,
) -> Result<(Debouncer<INotifyWatcher, NoCache>, CommandRequestStream)>
where
    T: 'static,
{
    let (tx, rx) = mpsc::channel(2);
    let mut debouncer = new_debouncer(
        Duration::from_secs(2),
        None,
        move |res: DebounceEventResult| match res {
            Ok(debounced_events) => {
                for de in debounced_events {
                    if let EventKind::Modify(_) = de.event.kind {
                        debug!("notify-event: {de:?}");
                        for p in &de.paths {
                            let _ = tx.blocking_send(CommandRequest {
                                command: Command::FileModified(FileCommand {
                                    feature_id: TypeId::of::<T>(),
                                    path: p.clone(),
                                }),
                                reply: None,
                            });
                        }
                    }
                }
            }
            Err(errors) => errors.iter().for_each(|e| error!("notify-error: {e:?}")),
        },
    )?;

    for p in paths {
        ensure!(p.is_file(), "{p:?} is not a regular existing file");
        debug!("watch {p:?}");
        debouncer.watch(p, RecursiveMode::NonRecursive)?;
    }

    Ok((
        debouncer,
        tokio_stream::wrappers::ReceiverStream::new(rx).boxed(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::twin::factory_reset;
    use reboot::SetWaitOnlineTimeoutCommand;
    use serde_json::json;
    use std::str::FromStr;

    #[test]
    fn from_direct_method_test() {
        assert!(Command::from_direct_method("unknown", json!({})).is_err());

        assert!(Command::from_direct_method("factory_reset", json!({})).is_err());

        assert!(Command::from_direct_method(
            "factory_reset",
            json!({
                "mode": 0,
                "preserve": ["1"],
            }),
        )
        .is_err());

        assert_eq!(
            Command::from_direct_method(
                "factory_reset",
                json!({
                    "mode": 1,
                    "preserve": ["1"],
                }),
            )
            .unwrap(),
            Command::FactoryReset(factory_reset::FactoryResetCommand {
                mode: factory_reset::FactoryResetMode::Mode1,
                preserve: vec!["1".to_string()]
            })
        );

        assert_eq!(
            Command::from_direct_method(
                "factory_reset",
                json!({
                    "mode": 1,
                    "preserve": [],
                }),
            )
            .unwrap(),
            Command::FactoryReset(factory_reset::FactoryResetCommand {
                mode: factory_reset::FactoryResetMode::Mode1,
                preserve: vec![]
            })
        );

        assert!(Command::from_direct_method("user_consent", json!({"foo": 1}),).is_err());

        assert_eq!(
            Command::from_direct_method("user_consent", json!({"foo": "bar"}),).unwrap(),
            Command::UserConsent(consent::UserConsentCommand {
                user_consent: std::collections::HashMap::from([(
                    "foo".to_string(),
                    "bar".to_string()
                )]),
            })
        );

        assert!(
            Command::from_direct_method("close_ssh_tunnel", json!({"tunnel_id": "no-uuid"}),)
                .is_err()
        );

        assert_eq!(
            Command::from_direct_method(
                "close_ssh_tunnel",
                json!({"tunnel_id": "3015d09d-b5e5-4c47-91d1-72460fd67b5d"}),
            )
            .unwrap(),
            Command::CloseSshTunnel(ssh_tunnel::CloseSshTunnelCommand {
                tunnel_id: "3015d09d-b5e5-4c47-91d1-72460fd67b5d".to_string(),
            })
        );

        assert!(
            Command::from_direct_method("get_ssh_pub_key", json!({"tunnel_id": "no-uuid"}),)
                .is_err()
        );

        assert_eq!(
            Command::from_direct_method(
                "get_ssh_pub_key",
                json!({"tunnel_id": "3015d09d-b5e5-4c47-91d1-72460fd67b5d"})
            )
            .unwrap(),
            Command::GetSshPubKey(ssh_tunnel::GetSshPubKeyCommand {
                tunnel_id: "3015d09d-b5e5-4c47-91d1-72460fd67b5d".to_string(),
            })
        );

        assert_eq!(
            Command::from_direct_method(
                "open_ssh_tunnel",
                json!({
                    "tunnel_id": "3015d09d-b5e5-4c47-91d1-72460fd67b5d",
                    "certificate": "cert",
                    "host": "my-host",
                    "port": 22,
                    "user": "usr",
                    "socket_path": "/socket",
                }),
            )
            .unwrap(),
            Command::OpenSshTunnel(ssh_tunnel::OpenSshTunnelCommand {
                tunnel_id: "3015d09d-b5e5-4c47-91d1-72460fd67b5d".to_string(),
                certificate: "cert".to_string(),
                bastion_config: ssh_tunnel::BastionConfig {
                    host: "my-host".to_string(),
                    port: 22,
                    user: "usr".to_string(),
                    socket_path: PathBuf::from_str("/socket").unwrap(),
                }
            })
        );

        assert_eq!(
            Command::from_direct_method(
                "get_ssh_pub_key",
                json!({"tunnel_id": "3015d09d-b5e5-4c47-91d1-72460fd67b5d"}),
            )
            .unwrap(),
            Command::GetSshPubKey(ssh_tunnel::GetSshPubKeyCommand {
                tunnel_id: "3015d09d-b5e5-4c47-91d1-72460fd67b5d".to_string(),
            })
        );

        assert_eq!(
            Command::from_direct_method("reboot", json!({}),).unwrap(),
            Command::Reboot
        );

        assert_eq!(
            Command::from_direct_method("set_wait_online_timeout", json!({}),).unwrap(),
            Command::SetWaitOnlineTimeout(SetWaitOnlineTimeoutCommand { timeout_secs: None })
        );

        assert_eq!(
            Command::from_direct_method("set_wait_online_timeout", json!({"timeout_secs": 1}),)
                .unwrap(),
            Command::SetWaitOnlineTimeout(SetWaitOnlineTimeoutCommand {
                timeout_secs: Some(1),
            })
        );

        assert!(Command::from_direct_method(
            "set_wait_online_timeout",
            json!({"timeout_secs": "1"}),
        )
        .is_err());
    }

    #[test]
    fn from_desired_property_test() {
        assert_eq!(
            CommandRequest::from_desired_property(TwinUpdate {
                state: TwinUpdateState::Partial,
                value: json!({})
            }),
            vec![]
        );

        assert_eq!(
            Command::from_desired_property(TwinUpdate {
                state: TwinUpdateState::Partial,
                value: json!({
                    "$version": 1,
                    "general_consent": ["swupdate"]})
            }),
            vec![Command::DesiredGeneralConsent(
                consent::DesiredGeneralConsentCommand {
                    general_consent: vec!["swupdate".to_string()]
                }
            )]
        );

        assert_eq!(
            Command::from_desired_property(TwinUpdate {
                state: TwinUpdateState::Partial,
                value: json!({"general_consent": []})
            }),
            vec![Command::DesiredGeneralConsent(
                consent::DesiredGeneralConsentCommand {
                    general_consent: vec![]
                }
            )]
        );

        assert_eq!(
            Command::from_desired_property(TwinUpdate {
                state: TwinUpdateState::Partial,
                value: json!({"general_consent": ["one", "two"]})
            }),
            vec![Command::DesiredGeneralConsent(
                consent::DesiredGeneralConsentCommand {
                    general_consent: vec!["one".to_string(), "two".to_string()]
                }
            )]
        );

        assert_eq!(
            Command::from_desired_property(TwinUpdate {
                state: TwinUpdateState::Complete,
                value: json!({})
            }),
            vec![]
        );

        assert_eq!(
            Command::from_desired_property(TwinUpdate {
                state: TwinUpdateState::Complete,
                value: json!({"desired": {}})
            }),
            vec![]
        );

        assert_eq!(
            Command::from_desired_property(TwinUpdate {
                state: TwinUpdateState::Complete,
                value: json!({"desired": {"general_consent": []}})
            }),
            vec![Command::DesiredGeneralConsent(
                consent::DesiredGeneralConsentCommand {
                    general_consent: vec![]
                }
            )]
        );

        assert_eq!(
            Command::from_desired_property(TwinUpdate {
                state: TwinUpdateState::Complete,
                value: json!({"desired": {"general_consent": ["one", "two"]}})
            }),
            vec![Command::DesiredGeneralConsent(
                consent::DesiredGeneralConsentCommand {
                    general_consent: vec!["one".to_string(), "two".to_string()]
                }
            )]
        );

        assert_eq!(
            Command::from_desired_property(TwinUpdate {
                state: TwinUpdateState::Complete,
                value: json!({"desired": {"key": "value"}})
            }),
            vec![]
        );

        assert_eq!(
            Command::from_desired_property(TwinUpdate {
                state: TwinUpdateState::Complete,
                value: json!({"desired": {"general_consent": ""}})
            }),
            vec![]
        );
    }
}
