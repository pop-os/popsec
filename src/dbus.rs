use dbus::{ffidisp::Connection, Message};
use std::error::Error as _;
use thiserror::Error;

use crate::tpm2_totp::*;

pub const DBUS_DEST: &str = "com.system76.PopSec";
pub const DBUS_IFACE: &str = DBUS_DEST;
pub const DBUS_PATH: &str = "/com/system76/PopSec";

pub const METHOD_TPM2_TOTP_SHOW: &str = "Tpm2TotpShow";

/// An error that may occur when interacting with the popsec daemon.
#[derive(Debug, Error)]
pub enum Error {
    /// Received an unexpected arrangement of DBus arguments.
    #[error("argument mismatch in {} method", _0)]
    ArgumentMismatch(&'static str, #[source] dbus::arg::TypeMismatchError),
    /// Failed to call one of the daemon's methods.
    #[error("calling {} method failed", _0)]
    Call(&'static str, #[source] dbus::Error),
    /// Failed to establish a DBus connection to the system.
    #[error("unable to establish dbus connection")]
    Connection(#[source] dbus::Error),
    /// Failed to create a new method call.
    #[error("failed to create {} method call: {}", _0, _1)]
    NewMethodCall(&'static str, Box<str>),
}

impl From<TotpError> for dbus::Error {
    fn from(err: TotpError) -> dbus::Error {
        let name = match err {
            TotpError::NoPasswordProvided => {
                "com.system76.PopSec.Error.NoPasswordProvided"
            },
            TotpError::SecretHasNoPassword => {
                "com.system76.PopSec.Error.SecretHasNoPassword"
            },
            TotpError::SecretAlreadyExists => {
                "com.system76.PopSec.Error.SecretAlreadyExists"
            },
            TotpError::SecretNotFound => {
                "com.system76.PopSec.Error.SecretNotFound"
            },
            TotpError::SystemStateChanged => {
                "com.system76.PopSec.Error.SystemStateChanged"
            },
            TotpError::WrongPassword => {
                "com.system76.PopSec.Error.WrongPassword"
            },
            TotpError::Lockout => {
                "com.system76.PopSec.Error.Lockout"
            },
            TotpError::Other(_) => {
                "com.system76.PopSec.Error.Other"
            },
        };
        dbus::Error::new_custom(name, &err.to_string())
    }
}

impl From<TotpError> for dbus::MethodErr {
    fn from(err: TotpError) -> dbus::MethodErr {
        dbus::MethodErr::from(dbus::Error::from(err))
    }
}

impl TryFrom<dbus::Error> for TotpError {
    type Error = dbus::Error;
    fn try_from(dbus: dbus::Error) -> Result<TotpError, dbus::Error> {
        let dbus_name = match dbus.name() {
            Some(some) => some,
            None => return Err(dbus),
        };
        match dbus_name {
            "com.system76.PopSec.Error.NoPasswordProvided" => Ok(
                TotpError::NoPasswordProvided,
            ),
            "com.system76.PopSec.Error.SecretHasNoPassword" => Ok(
                TotpError::SecretHasNoPassword,
            ),
            "com.system76.PopSec.Error.SecretAlreadyExists" => Ok(
                TotpError::SecretAlreadyExists,
            ),
            "com.system76.PopSec.Error.SecretNotFound" => Ok(
                TotpError::SecretNotFound,
            ),
            "com.system76.PopSec.Error.SystemStateChanged" => Ok(
                TotpError::SystemStateChanged,
            ),
            "com.system76.PopSec.Error.WrongPassword" => Ok(
                TotpError::WrongPassword,
            ),
            "com.system76.PopSec.Error.Lockout" => Ok(
                TotpError::Lockout,
            ),
            "com.system76.PopSec.Error.Other" => Ok(
                TotpError::Other(
                    dbus.message().map_or(String::new(), |x| x.to_string())
                ),
            ),
            _ => Err(dbus),
        }
    }
}

/// DBus client connection for interacting with the system76-firmware daemon.
pub struct Client(Connection);

impl Client {
    pub fn new() -> Result<Self, Error> {
        Connection::new_system()
            .map_err(Error::Connection)
            .map(Self)
    }

    /// Convenience method for calling a DBus method.
    fn call_method<F: FnMut(Message) -> Message>(
        &self,
        method: &'static str,
        mut append_args: F,
    ) -> Result<Message, Error> {
        let mut m = Message::new_method_call(DBUS_DEST, DBUS_PATH, DBUS_IFACE, method)
            .map_err(|why| Error::NewMethodCall(method, why.into()))?;

        m = append_args(m);

        self.0
            .send_with_reply_and_block(m, -1)
            .map_err(|why| Error::Call(method, why))
    }

    pub fn tpm2_totp_show(&self) -> Result<TotpCode, Error> {
        self.call_method(METHOD_TPM2_TOTP_SHOW, |m| m)?
            .read1::<u64>()
            .map_err(|why| Error::ArgumentMismatch(METHOD_TPM2_TOTP_SHOW, why))
            .map(TotpCode)
    }
}
