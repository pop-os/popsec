use std::{
    io::Read,
    process,
};

pub struct TotpAuth(pub String);
pub struct TotpError(pub String);
pub struct TotpCode(pub String);
pub struct TotpPass(pub String);

pub struct Tpm2Totp;

impl Tpm2Totp {
    // We have chosen by default to measure PCR 0, 2, and 7. This allows for changes to firmware,
    // option roms, or the secure boot state to be detected. Changes to the OS are intended to
    // be verified with secure boot.
    const PCRS: &'static str = "0,2,7";

    pub fn new() -> Self {
        Self
    }

    fn command(&mut self, args: &[&str]) -> Result<String, TotpError> {
        let mut child = process::Command::new("tpm2-totp")
            .args(args)
            .stdout(process::Stdio::piped())
            .spawn()
            .map_err(|err| TotpError(format!(
                "tpm2-totp: failed to spawn: {}", err
            )))?;

        let mut stdout = String::new();
        child.stdout.take().unwrap()
            .read_to_string(&mut stdout)
            .map_err(|err| TotpError(format!(
                "tpm2-totp: failed to read output: {}", err
            )))?;

        let status = child.wait()
            .map_err(|err| TotpError(format!(
                "tpm2-totp: failed to wait: {}", err
            )))?;
        if status.success() {
            Ok(stdout)
        } else {
            Err(TotpError(format!(
                "tpm2-totp: exited with status {}", status
            )))
        }
    }

    fn label(&self) -> Result<String, TotpError> {
        let hostname = sys_info::hostname().map_err(|err| TotpError(format!(
            "tpm2-totp: failed to read hostname: {}", err
        )))?;
        Ok(format!("{} TPM2-TOTP", hostname))
    }

    pub fn clean(&mut self) -> Result<(), TotpError> {
        self.command(&["clean"])?;
        Ok(())
    }

    pub fn init(&mut self, password: &TotpPass) -> Result<TotpAuth, TotpError> {
        let label = self.label()?;
        self.command(&[
            "--label", &label,
            "--pcrs", Self::PCRS,
            "--password", &password.0,
            "init",
        ]).map(TotpAuth)
    }

    pub fn recover(&mut self, password: &TotpPass) -> Result<TotpAuth, TotpError> {
        let label = self.label()?;
        self.command(&[
            "--label", &label,
            "--password", &password.0,
            "recover",
        ]).map(TotpAuth)
    }

    pub fn reseal(&mut self, password: &TotpPass) -> Result<(), TotpError> {
        self.command(&[
            "--pcrs", Self::PCRS,
            "--password", &password.0,
            "reseal",
        ])?;
        Ok(())
    }

    pub fn show(&mut self) -> Result<TotpCode, TotpError> {
        self.command(&["show"]).map(TotpCode)
    }
}
