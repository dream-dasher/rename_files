use sample_crate::{Result, TemplateApp};

fn main() -> Result<()> {
        // #[cfg(debug_assertions)]
        use sample_crate::activate_global_default_tracing_subscriber;
        let _writer_guard: tracing_appender::non_blocking::WorkerGuard = activate_global_default_tracing_subscriber()
                .maybe_env_default_level(None)
                .maybe_trace_error_level(None)
                .call()?;

        let native_options = eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default()
                        .with_inner_size([400.0, 300.0])
                        .with_min_inner_size([300.0, 220.0]),
                // .with_icon(
                //         // NOTE: Adding an icon is optional
                //         eframe::icon_data::from_png_bytes(&include_bytes!("../assets/icon-256.png")[..])
                //                 .expect("Failed to load icon"),
                // ),
                ..Default::default()
        };
        eframe::run_native("Egui Xp", native_options, Box::new(|cc| Ok(Box::new(TemplateApp::new(cc)))))?;
        Ok(())
}
