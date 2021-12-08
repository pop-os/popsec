use cascade::cascade;
use gtk::prelude::*;
use i18n_embed::DesktopLanguageRequester;
use libhandy::prelude::*;
use std::{fs, process, str, thread, time};

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

    //TODO: serious cleanup, sync with 30 second interval
    let (sender, receiver) = glib::MainContext::channel(glib::PRIORITY_DEFAULT);
    thread::spawn(move || {
        loop {
            let output = process::Command::new("sudo")
                .arg("tpm2-totp")
                .arg("show")
                .output()
                .unwrap();
            let stdout = String::from_utf8(output.stdout).unwrap();
            sender.send(stdout);
            thread::sleep(time::Duration::from_secs(5));
        }
    });

    let label = label_row(&list_box, &fl!("tpm2-totp"));
    receiver.attach(None, move |stdout| {
        label.set_text(&stdout);
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
