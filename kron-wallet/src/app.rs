//! KRON desktop wallet UI. English labels; comments in English.

use std::time::Instant;

use eframe::egui::{
    self, Align, Color32, CornerRadius, FontId, Frame, Layout, Margin, RichText, Stroke, StrokeKind,
    TextStyle, Ui, Vec2,
};
use new_blockchain::dag::{DagTransaction, KronDAG};
use new_blockchain::kron::{
    derive_kron_address, sign_transaction_natively, KronAddress, KronKeypair,
};
use new_blockchain::{
    broadcast_wallet_tx, default_gateway_addr, FIXED_TRANSACTION_FEE, NETWORK_NAME, TICKER,
};

use crate::amount::{format_kron_amount, parse_kron_amount};
use crate::explorer::{self, ExplorerView};
use crate::mnemonic::{self, RecoveryPhrase, QUIZ_LEN};
use crate::persist::{self, LoadedWallet};

const BG: Color32 = Color32::from_rgb(0x0a, 0x0a, 0x0c);
const BG_CARD: Color32 = Color32::from_rgb(0x12, 0x12, 0x18);
const BG_ELEVATED: Color32 = Color32::from_rgb(0x16, 0x16, 0x1c);
const BG_INPUT: Color32 = Color32::from_rgb(0x08, 0x08, 0x0c);
const ACCENT: Color32 = Color32::from_rgb(0x00, 0xe5, 0xff);
const ACCENT_DIM: Color32 = Color32::from_rgb(0x00, 0x6e, 0x7a);
const ACCENT_SOFT: Color32 = Color32::from_rgb(0x00, 0x3a, 0x44);
const TEXT: Color32 = Color32::from_rgb(0xe8, 0xf7, 0xfa);
const MUTED: Color32 = Color32::from_rgb(0x7d, 0x8b, 0x92);
const DANGER: Color32 = Color32::from_rgb(0xff, 0x5c, 0x7a);
const WARN: Color32 = Color32::from_rgb(0xff, 0xb0, 0x20);
const WARN_BG: Color32 = Color32::from_rgb(0x2a, 0x1c, 0x0a);
const OK: Color32 = Color32::from_rgb(0x3d, 0xf5, 0xc0);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Home,
    Receive,
    Send,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    SavePhrase,
    ConfirmPhrase,
    Wallet,
}

pub struct KronWalletApp {
    keypair: KronKeypair,
    address: String,
    nonce: u64,
    entropy: [u8; 32],
    mnemonic_backed_up: bool,
    archived_legacy: bool,
    screen: Screen,
    tab: Tab,
    send_to: String,
    send_amount: String,
    receipt: Option<String>,
    flash: Option<(String, Instant)>,
    persist_error: Option<String>,
    wrote_it_down: bool,
    quiz_indices: [usize; QUIZ_LEN],
    quiz_inputs: [String; QUIZ_LEN],
    quiz_error: Option<String>,
    reveal_ack: bool,
    reveal_open: bool,
    watch_address: String,
    explorer: ExplorerView,
    last_poll: Instant,
}

impl KronWalletApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        apply_theme(&cc.egui_ctx);
        match persist::load_or_create() {
            Ok(loaded) => Self::from_loaded(loaded, None),
            Err(e) => {
                let phrase = RecoveryPhrase::generate();
                let address = derive_kron_address(phrase.keypair().public_key());
                Self {
                    keypair: phrase.keypair(),
                    address,
                    nonce: 0,
                    entropy: phrase.entropy(),
                    mnemonic_backed_up: false,
                    archived_legacy: false,
                    screen: Screen::SavePhrase,
                    tab: Tab::Home,
                    send_to: String::new(),
                    send_amount: String::new(),
                    receipt: None,
                    flash: None,
                    persist_error: Some(e.to_string()),
                    wrote_it_down: false,
                    quiz_indices: mnemonic::quiz_indices(),
                    quiz_inputs: std::array::from_fn(|_| String::new()),
                    quiz_error: None,
                    reveal_ack: false,
                    reveal_open: false,
                    watch_address: String::new(),
                    explorer: ExplorerView::default(),
                    last_poll: Instant::now() - std::time::Duration::from_secs(2),
                }
            }
        }
    }

    fn from_loaded(loaded: LoadedWallet, persist_error: Option<String>) -> Self {
        let address = derive_kron_address(loaded.keypair.public_key());
        let screen = if loaded.needs_onboarding {
            Screen::SavePhrase
        } else {
            Screen::Wallet
        };
        Self {
            keypair: loaded.keypair,
            address,
            nonce: loaded.nonce,
            entropy: loaded.entropy,
            mnemonic_backed_up: !loaded.needs_onboarding,
            archived_legacy: loaded.archived_legacy,
            screen,
            tab: Tab::Home,
            send_to: String::new(),
            send_amount: String::new(),
            receipt: None,
            flash: None,
            persist_error,
            wrote_it_down: false,
            quiz_indices: mnemonic::quiz_indices(),
            quiz_inputs: std::array::from_fn(|_| String::new()),
            quiz_error: None,
            reveal_ack: false,
            reveal_open: false,
            watch_address: String::new(),
            explorer: ExplorerView::default(),
            last_poll: Instant::now() - std::time::Duration::from_secs(2),
        }
    }

    fn phrase(&self) -> RecoveryPhrase {
        RecoveryPhrase::from_entropy(self.entropy).expect("stored entropy is valid BIP39")
    }

    fn persist(&mut self) {
        if let Err(e) = persist::save(
            &self.keypair,
            self.nonce,
            &self.entropy,
            self.mnemonic_backed_up,
        ) {
            self.persist_error = Some(e.to_string());
        }
    }

    fn copy_address(&mut self, ctx: &egui::Context) {
        ctx.copy_text(self.address.clone());
        self.flash = Some(("Address copied".into(), Instant::now()));
    }

    fn copy_phrase(&mut self, ctx: &egui::Context) {
        ctx.copy_text(self.phrase().phrase());
        self.flash = Some(("Recovery phrase copied".into(), Instant::now()));
    }

    fn confirm_quiz(&mut self) {
        let phrase = self.phrase();
        let words = phrase.words();
        let ok = self
            .quiz_indices
            .iter()
            .zip(self.quiz_inputs.iter())
            .all(|(idx, typed)| mnemonic::words_match(&words[*idx], typed));
        if !ok {
            self.quiz_error = Some(
                "Those words do not match. Check your backup and try again.".into(),
            );
            return;
        }
        self.mnemonic_backed_up = true;
        self.persist();
        self.screen = Screen::Wallet;
        self.reveal_ack = false;
        self.reveal_open = false;
        self.flash = Some(("Wallet ready. Recovery phrase saved offline.".into(), Instant::now()));
    }

    fn sign_send(&mut self) {
        self.receipt = None;
        let dest = match KronAddress::parse(self.send_to.trim()) {
            Ok(a) => a,
            Err(e) => {
                self.flash = Some((format!("Invalid address: {e}"), Instant::now()));
                return;
            }
        };
        let amount = match parse_kron_amount(&self.send_amount) {
            Ok(v) if v > 0 => v,
            Ok(_) => {
                self.flash = Some(("Amount must be positive".into(), Instant::now()));
                return;
            }
            Err(e) => {
                self.flash = Some((e.to_string(), Instant::now()));
                return;
            }
        };

        let hint = explorer::fetch_compose(&self.address);
        let (p1, p2, nonce) = if let Some(h) = &hint {
            self.nonce = h.nonce;
            (h.parent_1, h.parent_2, h.nonce)
        } else {
            let genesis = KronDAG::with_genesis();
            (genesis.genesis_id(), genesis.genesis_id(), self.nonce)
        };
        let mut tx = match DagTransaction::user_transfer(
            p1,
            p2,
            &self.keypair,
            *dest.as_bytes(),
            amount,
            nonce,
        ) {
            Ok(tx) => tx,
            Err(e) => {
                self.flash = Some((format!("Signing failed: {e}"), Instant::now()));
                return;
            }
        };

        let native_sig =
            sign_transaction_natively(&tx.unsigned_bytes(), &self.keypair.private_key());
        tx.signature = native_sig;

        if !tx.verify_signature() {
            self.flash = Some(("Signature verification failed".into(), Instant::now()));
            return;
        }

        let hex_tx = hex::encode(tx.canonical_bytes());
        let digest = hex::encode(tx.id);
        let gateway = default_gateway_addr();
        match broadcast_wallet_tx(gateway, &tx) {
            Ok(()) => {
                self.nonce = nonce.saturating_add(1);
                self.persist();
                self.receipt = Some(format!(
                    "Broadcast to {gateway} (kron-mesh/1).\n\
                     Recipient: {}\n\
                     Amount: {} {TICKER}\n\
                     Native fee: {} {TICKER}\n\
                     Nonce: {nonce}\n\
                     Digest: {digest}\n\
                     Hex: {hex_tx}",
                    dest.as_str(),
                    format_kron_amount(amount),
                    format_kron_amount(FIXED_TRANSACTION_FEE),
                ));
                self.flash = Some((format!("Transaction broadcast to {gateway}"), Instant::now()));
            }
            Err(e) => {
                self.receipt = Some(format!(
                    "Signed but broadcast to {gateway} failed: {e}\n\
                     Start kron-node on port 8000 (or set KRON_GATEWAY).\n\
                     Digest: {digest}\n\
                     Hex: {hex_tx}"
                ));
                self.flash = Some((format!("Broadcast failed: {e}"), Instant::now()));
            }
        }
    }
}

impl eframe::App for KronWalletApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(std::time::Duration::from_millis(1500));
        if self.last_poll.elapsed() >= std::time::Duration::from_millis(1500) {
            let query = if self.watch_address.trim().is_empty() {
                self.address.clone()
            } else {
                self.watch_address.trim().to_string()
            };
            self.explorer = explorer::fetch_view(&query);
            self.last_poll = Instant::now();
        }
        if let Some((_, at)) = self.flash {
            if at.elapsed().as_secs() >= 4 {
                self.flash = None;
            }
        }

        egui::TopBottomPanel::top("top")
            .frame(
                Frame::new()
                    .fill(BG)
                    .inner_margin(Margin::symmetric(28, 18))
                    .stroke(Stroke::new(1.0, ACCENT_DIM)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    draw_kron_k(ui, 48.0);
                    ui.add_space(14.0);
                    ui.vertical(|ui| {
                        ui.add_space(2.0);
                        ui.label(
                            RichText::new(NETWORK_NAME)
                                .color(ACCENT)
                                .font(FontId::proportional(24.0))
                                .strong(),
                        );
                        ui.label(
                            RichText::new(format!("Desktop wallet  ·  {TICKER}"))
                                .color(MUTED)
                                .size(13.0),
                        );
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        Frame::new()
                            .fill(ACCENT_SOFT)
                            .stroke(Stroke::new(1.0, ACCENT_DIM))
                            .inner_margin(Margin::symmetric(12, 6))
                            .corner_radius(CornerRadius::same(8))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new(TICKER)
                                        .color(ACCENT)
                                        .font(FontId::monospace(16.0))
                                        .strong(),
                                );
                            });
                    });
                });
            });

        egui::TopBottomPanel::bottom("bottom")
            .frame(Frame::new().fill(BG).inner_margin(Margin::symmetric(24, 10)))
            .show(ctx, |ui| {
                if let Some((msg, _)) = &self.flash {
                    ui.colored_label(OK, msg);
                } else if let Some(err) = &self.persist_error {
                    ui.colored_label(DANGER, format!("Wallet save: {err}"));
                } else {
                    ui.colored_label(
                        MUTED,
                        "Local keys stay in AppData. Home polls the local explorer at 127.0.0.1:8080.",
                    );
                }
            });

        egui::CentralPanel::default()
            .frame(Frame::new().fill(BG).inner_margin(Margin::symmetric(28, 22)))
            .show(ctx, |ui| match self.screen {
                Screen::SavePhrase => self.ui_save_phrase(ui, ctx),
                Screen::ConfirmPhrase => self.ui_confirm_phrase(ui),
                Screen::Wallet => self.ui_wallet(ui, ctx),
            });
    }
}

impl KronWalletApp {
    fn ui_save_phrase(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        ui.label(
            RichText::new("Save your recovery phrase")
                .color(TEXT)
                .font(FontId::proportional(26.0))
                .strong(),
        );
        ui.add_space(6.0);
        ui.label(
            RichText::new("Write these 24 words down and keep them offline. This is the only backup.")
                .color(MUTED)
                .size(14.0),
        );
        ui.add_space(16.0);

        if self.archived_legacy {
            warn_banner(
                ui,
                "A previous wallet without a recovery phrase was archived as wallet.json.bak. \
                 This new wallet uses a fresh key. The old address can no longer spend from this file.",
            );
            ui.add_space(12.0);
        }

        warn_banner(
            ui,
            "Anyone with this phrase can spend your KRON. Never share it, screenshot it, or store it in the cloud. \
             KRON cannot recover a lost phrase.",
        );
        ui.add_space(16.0);

        let phrase = self.phrase();
        let words = phrase.words();
        card(ui, |ui| {
            word_grid(ui, &words);
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                if primary_button(ui, "Copy").clicked() {
                    self.copy_phrase(ctx);
                }
                ui.add_space(8.0);
                ui.colored_label(MUTED, "Copied text stays on this device clipboard.");
            });
        });

        ui.add_space(18.0);
        ui.horizontal(|ui| {
            ui.checkbox(
                &mut self.wrote_it_down,
                RichText::new("I have written down my recovery phrase and stored it offline.")
                    .color(TEXT)
                    .size(14.0),
            );
        });
        ui.add_space(12.0);
        ui.add_enabled_ui(self.wrote_it_down, |ui| {
            if primary_button(ui, "Continue").clicked() {
                self.quiz_error = None;
                self.quiz_inputs = std::array::from_fn(|_| String::new());
                self.screen = Screen::ConfirmPhrase;
            }
        });
    }

    fn ui_confirm_phrase(&mut self, ui: &mut Ui) {
        ui.label(
            RichText::new("Confirm your recovery phrase")
                .color(TEXT)
                .font(FontId::proportional(26.0))
                .strong(),
        );
        ui.add_space(6.0);
        ui.label(
            RichText::new("Enter the requested words to prove you saved the backup.")
                .color(MUTED)
                .size(14.0),
        );
        ui.add_space(18.0);

        card(ui, |ui| {
            for (slot, idx) in self.quiz_indices.iter().enumerate() {
                ui.label(
                    RichText::new(format!("Word {}", idx + 1))
                        .color(MUTED)
                        .size(12.0),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut self.quiz_inputs[slot])
                        .desired_width(280.0)
                        .font(FontId::monospace(16.0))
                        .hint_text("word"),
                );
                ui.add_space(10.0);
            }
            if let Some(err) = &self.quiz_error {
                ui.colored_label(DANGER, err);
                ui.add_space(8.0);
            }
        });

        ui.add_space(16.0);
        ui.horizontal(|ui| {
            if ghost_button(ui, "Back").clicked() {
                self.screen = Screen::SavePhrase;
                self.quiz_error = None;
            }
            ui.add_space(10.0);
            if primary_button(ui, "Continue").clicked() {
                self.confirm_quiz();
            }
        });
    }

    fn ui_wallet(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        ui.horizontal(|ui| {
            tab_button(ui, &mut self.tab, Tab::Home, "Home");
            ui.add_space(8.0);
            tab_button(ui, &mut self.tab, Tab::Receive, "Receive");
            ui.add_space(8.0);
            tab_button(ui, &mut self.tab, Tab::Send, "Send");
        });
        ui.add_space(20.0);

        match self.tab {
            Tab::Home => self.ui_home(ui, ctx),
            Tab::Receive => self.ui_receive(ui, ctx),
            Tab::Send => self.ui_send(ui),
        }
    }

    fn ui_home(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        card(ui, |ui| {
            ui.label(RichText::new("Your address").color(MUTED).size(12.0));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.add(
                    egui::Label::new(
                        RichText::new(&self.address)
                            .color(TEXT)
                            .font(FontId::monospace(14.0)),
                    )
                    .wrap(),
                );
                ui.add_space(8.0);
                if primary_button(ui, "Copy").clicked() {
                    self.copy_address(ctx);
                }
            });
            ui.add_space(22.0);
            ui.label(RichText::new("Balance").color(MUTED).size(12.0));
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!("{} {TICKER}", self.explorer.balance_text))
                    .color(ACCENT)
                    .font(FontId::proportional(36.0))
                    .strong(),
            );
            ui.add_space(8.0);
            if self.explorer.online {
                ui.label(
                    RichText::new(format!(
                        "DAG txs {}  ·  circulating {}",
                        self.explorer.dag_tx_count, self.explorer.circulating
                    ))
                    .color(MUTED)
                    .size(13.0),
                );
            } else {
                ui.colored_label(
                    WARN,
                    "Node/explorer offline — start KRON Node",
                );
            }
            ui.add_space(12.0);
            ui.label(RichText::new("Watch address (optional)").color(MUTED).size(12.0));
            ui.add(
                egui::TextEdit::singleline(&mut self.watch_address)
                    .desired_width(f32::INFINITY)
                    .font(FontId::monospace(13.0))
                    .hint_text("Paste a miner payout kron1… to watch"),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "Mine to this wallet address in KRON Miner, or watch the payout address you pasted there.",
                )
                .color(MUTED)
                .size(13.0),
            );
        });

        if !self.explorer.txs.is_empty() {
            ui.add_space(16.0);
            card(ui, |ui| {
                ui.label(
                    RichText::new("Recent activity")
                        .color(TEXT)
                        .size(16.0)
                        .strong(),
                );
                ui.add_space(8.0);
                for tx in &self.explorer.txs {
                    ui.label(
                        RichText::new(format!(
                            "h{}  {}  {} → {}",
                            tx.dag_tx_index, tx.amount, tx.from, tx.to
                        ))
                        .color(TEXT)
                        .font(FontId::monospace(12.0)),
                    );
                }
            });
        }

        ui.add_space(16.0);
        card(ui, |ui| {
            ui.label(
                RichText::new("Recovery phrase")
                    .color(TEXT)
                    .size(16.0)
                    .strong(),
            );
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "Your 24-word backup is stored only on this device. Reveal it only in private.",
                )
                .color(MUTED)
                .size(13.0),
            );
            ui.add_space(12.0);
            ui.checkbox(
                &mut self.reveal_ack,
                RichText::new("I am in a private place and understand this phrase is secret.")
                    .color(TEXT)
                    .size(13.0),
            );
            ui.add_space(10.0);
            ui.add_enabled_ui(self.reveal_ack, |ui| {
                let label = if self.reveal_open {
                    "Hide recovery phrase"
                } else {
                    "Reveal recovery phrase"
                };
                if ghost_button(ui, label).clicked() {
                    self.reveal_open = !self.reveal_open;
                }
            });
            if self.reveal_open && self.reveal_ack {
                ui.add_space(14.0);
                let phrase = self.phrase();
                let words = phrase.words();
                word_grid(ui, &words);
                ui.add_space(12.0);
                if primary_button(ui, "Copy").clicked() {
                    self.copy_phrase(ctx);
                }
            }
        });
    }

    fn ui_receive(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        card(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(8.0);
                draw_kron_k(ui, 104.0);
                ui.add_space(16.0);
                ui.label(
                    RichText::new(format!("Receive {TICKER}"))
                        .color(ACCENT)
                        .font(FontId::proportional(22.0))
                        .strong(),
                );
                ui.add_space(8.0);
                ui.label(
                    RichText::new("Send funds to this Bech32 address.")
                        .color(MUTED)
                        .size(14.0),
                );
                ui.add_space(16.0);
                Frame::new()
                    .fill(BG_INPUT)
                    .stroke(Stroke::new(1.0, ACCENT_DIM))
                    .inner_margin(Margin::symmetric(16, 12))
                    .corner_radius(CornerRadius::same(8))
                    .show(ui, |ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(&self.address)
                                    .color(TEXT)
                                    .font(FontId::monospace(15.0)),
                            )
                            .wrap(),
                        );
                    });
                ui.add_space(16.0);
                if primary_button(ui, "Copy address").clicked() {
                    self.copy_address(ctx);
                }
                ui.add_space(8.0);
            });
        });
    }

    fn ui_send(&mut self, ui: &mut Ui) {
        card(ui, |ui| {
            ui.label(
                RichText::new("Send KRON")
                    .color(TEXT)
                    .font(FontId::proportional(20.0))
                    .strong(),
            );
            ui.add_space(6.0);
            ui.colored_label(
                MUTED,
                "Signs with ML-DSA-44 and broadcasts the vertex to 127.0.0.1:8000 (KRON_GATEWAY).",
            );
            ui.add_space(16.0);

            ui.label(RichText::new("Recipient (kron1…)").color(MUTED).size(12.0));
            ui.add(
                egui::TextEdit::singleline(&mut self.send_to)
                    .desired_width(f32::INFINITY)
                    .font(FontId::monospace(14.0))
                    .hint_text("kron1…"),
            );
            ui.add_space(12.0);

            ui.label(RichText::new("Amount (KRON)").color(MUTED).size(12.0));
            ui.add(
                egui::TextEdit::singleline(&mut self.send_amount)
                    .desired_width(240.0)
                    .font(FontId::monospace(16.0))
                    .hint_text("1.5"),
            );
            ui.add_space(12.0);

            ui.horizontal(|ui| {
                ui.label(RichText::new("Native fee").color(MUTED));
                ui.label(
                    RichText::new(format!(
                        "{} {TICKER}  ({} units)",
                        format_kron_amount(FIXED_TRANSACTION_FEE),
                        FIXED_TRANSACTION_FEE
                    ))
                    .color(ACCENT),
                );
            });
            ui.add_space(16.0);

            if primary_button(ui, "Send").clicked() {
                self.sign_send();
            }
        });

        if let Some(receipt) = &self.receipt {
            ui.add_space(16.0);
            card(ui, |ui| {
                ui.label(
                    RichText::new("Receipt")
                        .color(OK)
                        .size(16.0)
                        .strong(),
                );
                ui.add_space(8.0);
                ui.add(
                    egui::Label::new(
                        RichText::new(receipt.clone())
                            .color(TEXT)
                            .font(FontId::monospace(12.0)),
                    )
                    .wrap(),
                );
            });
        }
    }
}

fn apply_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.override_text_color = Some(TEXT);
    visuals.panel_fill = BG;
    visuals.window_fill = BG;
    visuals.extreme_bg_color = BG_INPUT;
    visuals.faint_bg_color = BG_CARD;
    visuals.widgets.noninteractive.bg_fill = BG_CARD;
    visuals.widgets.inactive.bg_fill = BG_ELEVATED;
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(0x1a, 0x2a, 0x32);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, ACCENT);
    visuals.widgets.active.bg_fill = Color32::from_rgb(0x00, 0x3a, 0x44);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, ACCENT);
    visuals.selection.bg_fill = Color32::from_rgb(0x00, 0x5a, 0x66);
    visuals.hyperlink_color = ACCENT;
    visuals.widgets.inactive.corner_radius = CornerRadius::same(8);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(8);
    visuals.widgets.active.corner_radius = CornerRadius::same(8);
    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = Vec2::new(10.0, 8.0);
    style.spacing.button_padding = Vec2::new(16.0, 8.0);
    style.spacing.interact_size.y = 32.0;
    style.text_styles.insert(
        TextStyle::Heading,
        FontId::proportional(22.0),
    );
    style.text_styles.insert(
        TextStyle::Body,
        FontId::proportional(14.0),
    );
    ctx.set_style(style);
}

fn card(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    Frame::new()
        .fill(BG_CARD)
        .stroke(Stroke::new(1.0, ACCENT_DIM))
        .inner_margin(Margin::same(22))
        .corner_radius(CornerRadius::same(14))
        .show(ui, add);
}

fn warn_banner(ui: &mut Ui, text: &str) {
    Frame::new()
        .fill(WARN_BG)
        .stroke(Stroke::new(1.0, WARN))
        .inner_margin(Margin::symmetric(14, 10))
        .corner_radius(CornerRadius::same(10))
        .show(ui, |ui| {
            ui.label(RichText::new(text).color(WARN).size(13.0));
        });
}

fn word_grid(ui: &mut Ui, words: &[String]) {
    let cols = 4;
    egui::Grid::new("mnemonic_grid")
        .num_columns(cols)
        .spacing([10.0, 10.0])
        .min_col_width(140.0)
        .show(ui, |ui| {
            for (i, word) in words.iter().enumerate() {
                Frame::new()
                    .fill(BG_INPUT)
                    .stroke(Stroke::new(1.0, ACCENT_DIM))
                    .inner_margin(Margin::symmetric(10, 8))
                    .corner_radius(CornerRadius::same(8))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!("{:02}", i + 1))
                                    .color(MUTED)
                                    .font(FontId::monospace(11.0)),
                            );
                            ui.label(
                                RichText::new(word)
                                    .color(TEXT)
                                    .font(FontId::monospace(14.0))
                                    .strong(),
                            );
                        });
                    });
                if (i + 1) % cols == 0 {
                    ui.end_row();
                }
            }
        });
}

fn tab_button(ui: &mut Ui, current: &mut Tab, tab: Tab, label: &str) {
    let selected = *current == tab;
    let fill = if selected {
        Color32::from_rgb(0x00, 0x3a, 0x44)
    } else {
        BG_ELEVATED
    };
    let stroke = if selected {
        Stroke::new(1.4, ACCENT)
    } else {
        Stroke::new(1.0, ACCENT_DIM)
    };
    let text = RichText::new(label)
        .color(if selected { ACCENT } else { TEXT })
        .size(14.0)
        .strong();
    let btn = egui::Button::new(text)
        .fill(fill)
        .stroke(stroke)
        .corner_radius(CornerRadius::same(8))
        .min_size(Vec2::new(118.0, 36.0));
    if ui.add(btn).clicked() {
        *current = tab;
    }
}

fn primary_button(ui: &mut Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(label).color(BG).strong().size(14.0))
            .fill(ACCENT)
            .stroke(Stroke::new(1.0, ACCENT))
            .corner_radius(CornerRadius::same(8))
            .min_size(Vec2::new(148.0, 34.0)),
    )
}

fn ghost_button(ui: &mut Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(label).color(ACCENT).strong().size(14.0))
            .fill(BG_ELEVATED)
            .stroke(Stroke::new(1.0, ACCENT_DIM))
            .corner_radius(CornerRadius::same(8))
            .min_size(Vec2::new(148.0, 34.0)),
    )
}

/// Geometric K from the official KRON icon descriptor (lattice basis strokes).
fn draw_kron_k(ui: &mut Ui, size: f32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), egui::Sense::hover());
    let painter = ui.painter();
    painter.rect_filled(rect, CornerRadius::same(10), BG);
    painter.rect_stroke(
        rect,
        CornerRadius::same(10),
        Stroke::new(1.0, ACCENT_DIM),
        StrokeKind::Inside,
    );
    let map = |x: f32, y: f32| {
        egui::pos2(
            rect.left() + x / 32.0 * rect.width(),
            rect.top() + y / 32.0 * rect.height(),
        )
    };
    let glow = Stroke::new((size / 32.0) * 4.2, ACCENT_SOFT);
    let stroke = Stroke::new((size / 32.0) * 2.4, ACCENT);
    for s in [glow, stroke] {
        painter.line_segment([map(7.0, 3.0), map(16.0, 16.0)], s);
        painter.line_segment([map(16.0, 16.0), map(7.0, 29.0)], s);
        painter.line_segment([map(16.0, 16.0), map(26.0, 4.0)], s);
        painter.line_segment([map(16.0, 16.0), map(26.0, 28.0)], s);
    }
}
