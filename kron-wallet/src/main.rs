//! Native KRON Network wallet (eframe / egui).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod amount;
mod app;
mod explorer;
mod mnemonic;
mod persist;

use app::KronWalletApp;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1024.0, 760.0])
            .with_min_inner_size([860.0, 620.0])
            .with_title("KRON Wallet"),
        ..Default::default()
    };
    eframe::run_native(
        "KRON Wallet",
        options,
        Box::new(|cc| Ok(Box::new(KronWalletApp::new(cc)))),
    )
}
