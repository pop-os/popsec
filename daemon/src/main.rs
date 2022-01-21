use dbus::blocking::Connection;
use dbus_crossroads::{Crossroads, Context, MethodErr};
use popsec::{
    dbus::*,
    tpm2_totp::*,
};
use std::{process};


fn err_str<E: ::std::fmt::Display>(err: E) -> String {
    format!("{}", err)
}

fn daemon() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("must be run as root".into());
    }

    struct State;

    let state = State;

    let c = Connection::new_system().map_err(err_str)?;

    c.request_name(DBUS_DEST, false, true, false).map_err(err_str)?;

    let mut cr = Crossroads::new();

    let iface_token = cr.register(DBUS_IFACE, |b| {
        b.method(
            METHOD_TPM2_TOTP_SHOW,
            (),
            ("code",),
            |_ctx: &mut Context, _state: &mut State, _inputs: ()| {
                let mut tpm2_totp = Tpm2Totp::new().map_err(MethodErr::from)?;
                tpm2_totp.show()
                    .map(|v| (v.0,))
                    .map_err(MethodErr::from)
            }
        );
    });

    cr.insert(DBUS_PATH, &[iface_token], state);

    cr.serve(&c).map_err(err_str)
}

fn main() {
    match daemon() {
        Ok(()) => (),
        Err(err) => {
            eprintln!("popsec-daemon: {}", err);
            process::exit(1);
        }
    }
}
