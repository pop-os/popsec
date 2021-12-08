use cascade::cascade;
use chrono::prelude::*;
use gtk::prelude::*;
use i18n_embed::DesktopLanguageRequester;
use libhandy::prelude::*;
use popsec::tpm2_totp::{
    TotpCode,
    TotpError,
    Tpm2Totp
};
use std::{
    fs,
    str,
    sync::{Arc, Mutex},
    thread,
    time
};

mod localize;

pub fn localize() {
    let localizer = crate::localize::localizer();
    let requested_languages = DesktopLanguageRequester::requested_languages();

    if let Err(error) = localizer.select(&requested_languages) {
        eprintln!("failed to language for popsec-gtk: {}", error);
    }
}

fn header_func(row: &gtk::ListBoxRow, before: Option<&gtk::ListBoxRow>) {
    if before.is_none() {
        row.set_header::<gtk::Widget>(None)
    } else if row.header().is_none() {
        row.set_header(Some(&cascade! {
            gtk::Separator::new(gtk::Orientation::Horizontal);
            ..show();
        }));
    }
}

fn label_row<C: ContainerExt>(container: &C, title: &str) -> gtk::Label {
    let label = cascade! {
        gtk::Label::new(None);
    };
    let row = cascade! {
        libhandy::ActionRow::new();
        ..set_title(Some(title));
        ..add(&label);
    };
    container.add(&row);
    label
}

fn switch_row<C: ContainerExt>(container: &C, title: &str) -> gtk::Switch {
    let switch = cascade! {
        gtk::Switch::new();
        ..set_valign(gtk::Align::Center);
    };
    let row = cascade! {
        libhandy::ActionRow::new();
        ..set_title(Some(title));
        ..add(&switch);
    };
    container.add(&row);
    switch
}

fn settings_list_box<C: ContainerExt>(container: &C, title: &str) -> gtk::ListBox {
    let vbox = gtk::Box::new(gtk::Orientation::Vertical, 12);
    container.add(&vbox);

    let label = cascade! {
        gtk::Label::new(Some(&format!("<b>{}</b>", title)));
        ..set_use_markup(true);
        ..set_xalign(0.0);
    };
    vbox.add(&label);

    let list_box = cascade! {
        gtk::ListBox::new();
        ..style_context().add_class("frame");
        ..set_header_func(Some(Box::new(header_func)));
        ..set_selection_mode(gtk::SelectionMode::None);
    };

    vbox.add(&list_box);

    list_box
}

fn secure_boot<C: ContainerExt>(container: &C) {
    let list_box = settings_list_box(container, &fl!("secure-boot"));

    let secure_boot = fs::read(
        "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    ).ok().map_or(false, |x| x.get(4).map_or(false, |x| *x > 0));

    let label = label_row(&list_box, &fl!("secure-boot"));
    label.set_text(&if secure_boot { fl!("enabled") } else { fl!("disabled") });

    let setup_mode = fs::read(
        "/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    ).ok().map_or(false, |x| x.get(4).map_or(false, |x| *x > 0));

    let label = label_row(&list_box, &fl!("setup-mode"));
    label.set_text(&if setup_mode { fl!("enabled") } else { fl!("disabled") });
}

fn tpm<C: ContainerExt>(container: &C) {
    let list_box = settings_list_box(container, &fl!("tpm"));

    let tpm2_totp = Arc::new(Mutex::new(
        //TODO: better error handling
        Tpm2Totp::new().unwrap()
    ));

    enum Message {
        Code(TotpCode),
        Error(TotpError),
        Timeout(f64),
    }
    let (sender, receiver) = glib::MainContext::channel(glib::PRIORITY_DEFAULT);
    {
        let tpm2_totp = tpm2_totp.clone();
        thread::spawn(move || {
            loop {
                let result = tpm2_totp.lock().unwrap().show();
                match result {
                    Ok(ok) => {
                        sender.send(Message::Code(ok))
                            .expect("failed to send tpm2-totp code");
                    },
                    Err(err) => {
                        sender.send(Message::Error(err))
                            .expect("failed to send tpm2-totp error");
                        thread::sleep(time::Duration::new(1, 0));
                    },
                }

                // Sleep until next TOTP window
                let start = chrono::Utc::now().with_nanosecond(0).unwrap();
                let end = if start.second() < 30 {
                    start.with_second(30).unwrap()
                } else {
                    start.with_second(0).unwrap() + chrono::Duration::minutes(1)
                };
                loop {
                    let current = chrono::Utc::now().with_nanosecond(0).unwrap();
                    let remaining = end.signed_duration_since(current).num_seconds();
                    sender.send(Message::Timeout(
                        remaining as f64 / 30.0
                    )).expect("failed to send tpm2-totp timeout");
                    if remaining <= 0 {
                        break;
                    }
                    thread::sleep(time::Duration::new(1, 0));
                }
            }
        });
    }

    let label = gtk::Label::new(None);
    let progress_bar = cascade! {
        gtk::ProgressBar::new();
        ..set_no_show_all(true);
        ..set_valign(gtk::Align::Center);
        ..set_visible(false);
    };
    let init_button = cascade! {
        gtk::Button::with_label(&fl!("tpm2-totp-init-button"));
        ..set_no_show_all(true);
        ..set_valign(gtk::Align::Center);
        ..set_visible(false);
    };
    let reseal_button = cascade! {
        gtk::Button::with_label(&fl!("tpm2-totp-reseal-button"));
        ..set_no_show_all(true);
        ..set_valign(gtk::Align::Center);
        ..set_visible(false);
    };
    let row = cascade! {
        libhandy::ActionRow::new();
        ..set_title(Some(&fl!("tpm2-totp")));
        ..add(&label);
        ..add(&progress_bar);
        ..add(&init_button);
        ..add(&reseal_button);
    };
    list_box.add(&row);


    receiver.attach(None, move |message| {
        match message {
            Message::Code(code) => {
                label.set_text(&format!("{:06}", code.0));
                progress_bar.set_visible(true);
                init_button.set_visible(false);
                reseal_button.set_visible(false);
            },
            Message::Error(error) => {
                progress_bar.set_visible(false);
                init_button.set_visible(false);
                reseal_button.set_visible(false);
                match error {
                    TotpError::SecretNotFound => {
                        label.set_text(&fl!("tpm2-totp-init"));
                        init_button.set_visible(true);
                    },
                    TotpError::SystemStateChanged => {
                        label.set_text(&fl!("tpm2-totp-reseal"));
                        reseal_button.set_visible(true);
                    },
                    _ => {
                        label.set_text(&format!("{}", error));
                    }
                }
            },
            Message::Timeout(timeout) => {
                progress_bar.set_fraction(timeout);
            },
        }
        glib::Continue(true)
    });
}

pub struct PopSecWidget;

impl PopSecWidget {
    pub fn new<C: ContainerExt>(container: &C) -> Self {
        let vbox = gtk::Box::new(gtk::Orientation::Vertical, 48);
        let clamp = cascade! {
            libhandy::Clamp::new();
            ..set_margin_top(32);
            ..set_margin_bottom(32);
            ..set_margin_start(12);
            ..set_margin_end(12);
            ..add(&vbox);
        };
        let scrolled_window = cascade! {
            gtk::ScrolledWindow::new::<gtk::Adjustment, gtk::Adjustment>(None, None);
            ..add(&clamp);
        };
        container.add(&scrolled_window);

        secure_boot(&vbox);
        tpm(&vbox);

        Self
    }
}
