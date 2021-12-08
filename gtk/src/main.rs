use gtk::prelude::*;
use popsec_gtk::PopSecWidget;

fn main() {
    let app = gtk::Application::builder()
        .application_id("com.system76.PopSec")
        .build();

    app.connect_activate(|app| {
        let window = gtk::ApplicationWindow::builder()
            .application(app)
            .default_width(768)
            .default_height(576)
            .window_position(gtk::WindowPosition::Center)
            .build();

        PopSecWidget::new(&window);

        window.show_all();
    });

    app.run();
}
