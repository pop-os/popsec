use std::{
    ffi::CString,
    ptr,
};
use thiserror::Error;
use tss_esapi::{
    tcti_ldr::{
        DeviceConfig,
        TctiContext,
        TctiNameConf
    },
};
use tpm2_totp_sys::*;

struct AutoFree<T>(*mut T);

impl<T> Drop for AutoFree<T> {
    fn drop(&mut self) {
        if ! self.0.is_null() {
            unsafe { libc::free(self.0 as *mut libc::c_void); }
            self.0 = ptr::null_mut();
        }
    }
}

pub struct TotpAuth(pub String);

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("No recovery password for the TOTP secret was given")]
    NoPasswordProvided,
    #[error("The TOTP secret has not been stored with a recovery password and thus cannot be retrieved")]
    SecretHasNoPassword,
    #[error("A TOTP secret is already stored")]
    SecretAlreadyExists,
    #[error("No TOTP secret is currently stored")]
    SecretNotFound,
    #[error("The system state has changed, no TOTP could be calculated")]
    SystemStateChanged,
    #[error("Wrong recovery password for the TOTP secret")]
    WrongPassword,
    #[error("The password has been entered wrongly too many times and the TPM is in lockout mode")]
    Lockout,
    //TODO: wrap this up too
    #[error("{0}")]
    Other(String),
}

pub struct TotpCode(pub u64);

pub struct TotpPass(pub String);

impl TotpError {
    fn from_rc(rc: libc::c_int) -> Self {
        use tss_esapi::constants::tss::*;
        const RC_NO_PASSWORD_PROVIDED: libc::c_int = -10;
        const RC_SECRET_HAS_NO_PASSWORD: libc::c_int = -20;
        const RC_SECRET_ALREADY_EXISTS: libc::c_int = TPM2_RC_NV_DEFINED as _;
        const RC_SECRET_NOT_FOUND: libc::c_int = (TPM2_RC_HANDLE | TPM2_RC_1) as _;
        const RC_SYSTEM_STATE_CHANGED: libc::c_int = (TPM2_RC_POLICY_FAIL | TPM2_RC_9) as _;
        const RC_WRONG_PASSWORD: libc::c_int = (TPM2_RC_AUTH_FAIL | TPM2_RC_9) as _;
        const RC_LOCKOUT: libc::c_int = TPM2_RC_LOCKOUT as _;
        println!("{:x}", rc);
        match rc {
            RC_NO_PASSWORD_PROVIDED => Self::NoPasswordProvided,
            RC_SECRET_HAS_NO_PASSWORD => Self::SecretHasNoPassword,
            RC_SECRET_ALREADY_EXISTS => Self::SecretAlreadyExists,
            RC_SECRET_NOT_FOUND => Self::SecretNotFound,
            RC_SYSTEM_STATE_CHANGED => Self::SystemStateChanged,
            RC_WRONG_PASSWORD => Self::WrongPassword,
            RC_LOCKOUT => Self::Lockout,
            _ => Self::Other(format!("unknown (0x{:x}", rc)),
        }
    }
}

pub struct Tpm2Totp {
    context: TctiContext,
}

impl Tpm2Totp {
    // We have chosen by default to measure PCR 0, 2, and 7. This allows for changes to firmware,
    // option roms, or the secure boot state to be detected. Changes to the OS are intended to
    // be verified with secure boot.
    const PCRS: u32 = (1 << 0) | (1 << 2) | (1 << 7);

    // Choose bank 0 and 1, which are SHA1 and SHA256
    const BANKS: u32 = (1 << 0) | (1 << 1);

    // Use the same default NVRAM index as tpm2-totp command line
    const NVRAM_INDEX: u32 = 0x018094AF;

    pub fn new() -> Result<Self, TotpError> {
        let context = TctiContext::initialize(TctiNameConf::Device(
            DeviceConfig::default()
        )).map_err(|err| TotpError::Other(format!(
            "tpm2-totp: failed to initialize TCTI context: {}", err
        )))?;
        Ok(Self {
            context
        })
    }

    fn label(&self) -> Result<String, TotpError> {
        let hostname = sys_info::hostname().map_err(|err| TotpError::Other(format!(
            "tpm2-totp: failed to read hostname: {}", err
        )))?;
        Ok(format!("{} TPM2-TOTP", hostname))
    }

    pub fn clean(&mut self) -> Result<(), TotpError> {
        unimplemented!();
    }

    pub fn init(&mut self, password: &TotpPass) -> Result<TotpAuth, TotpError> {
        unimplemented!();
    }

    pub fn recover(&mut self, password: &TotpPass) -> Result<TotpAuth, TotpError> {
        unimplemented!();
    }

    pub fn reseal(&mut self, password: &TotpPass) -> Result<(), TotpError> {
        unsafe {
            let mut key_blob = AutoFree(ptr::null_mut());
            let mut key_blob_size = 0;
            let mut rc = tpm2totp_loadKey_nv(
                Self::NVRAM_INDEX,
                self.context.tcti_context_ptr() as *mut TSS2_TCTI_CONTEXT,
                &mut key_blob.0,
                &mut key_blob_size
            );
            if rc != 0 {
                return Err(TotpError::from_rc(rc));
            }

            let password_c = CString::new(password.0.as_str()).map_err(|err| {
                TotpError::Other(format!(
                    "failed to convert password to C string: {}", err
                ))
            })?;
            let mut new_blob = AutoFree(ptr::null_mut());
            let mut new_blob_size = 0;
            rc = tpm2totp_reseal(
                key_blob.0,
                key_blob_size,
                password_c.as_ptr(),
                Self::PCRS,
                Self::BANKS,
                self.context.tcti_context_ptr() as *mut TSS2_TCTI_CONTEXT,
                &mut new_blob.0,
                &mut new_blob_size
            );
            if rc != 0 {
                return Err(TotpError::from_rc(rc));
            }

            rc = tpm2totp_deleteKey_nv(
                Self::NVRAM_INDEX,
                self.context.tcti_context_ptr() as *mut TSS2_TCTI_CONTEXT
            );
            if rc != 0 {
                return Err(TotpError::from_rc(rc));
            }

            rc = tpm2totp_storeKey_nv(
                new_blob.0,
                new_blob_size,
                Self::NVRAM_INDEX,
                self.context.tcti_context_ptr() as *mut TSS2_TCTI_CONTEXT
            );
            if rc != 0 {
                return Err(TotpError::from_rc(rc));
            }

            Ok(())
        }
    }

    pub fn show(&mut self) -> Result<TotpCode, TotpError> {
        unsafe {
            let mut key_blob = AutoFree(ptr::null_mut());
            let mut key_blob_size = 0;
            let mut rc = tpm2totp_loadKey_nv(
                Self::NVRAM_INDEX,
                self.context.tcti_context_ptr() as *mut TSS2_TCTI_CONTEXT,
                &mut key_blob.0,
                &mut key_blob_size
            );
            if rc != 0 {
                return Err(TotpError::from_rc(rc));
            }

            let mut now = 0;
            let mut totp = 0;
            rc = tpm2totp_calculate(
                key_blob.0,
                key_blob_size,
                self.context.tcti_context_ptr() as *mut TSS2_TCTI_CONTEXT,
                &mut now,
                &mut totp
            );
            if rc != 0 {
                return Err(TotpError::from_rc(rc));
            }

            Ok(TotpCode(totp))
        }
    }
}
