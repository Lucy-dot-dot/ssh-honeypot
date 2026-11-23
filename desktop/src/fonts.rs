use eframe::egui;

/// Inter variable font bundled with the package (opsz/wght axes, defaults to
/// optical size 14 at regular weight, which suits egui's UI text sizes).
const INTER_FONT: &[u8] = include_bytes!("../assets/Inter-VariableFont_opsz,wght.ttf");

/// Register Inter as the primary proportional font. Installed with highest
/// priority so every proportional text renders in Inter, while the built-in
/// fonts stay as fallbacks for glyphs and icons Inter does not cover.
/// The monospace family (report output) keeps the built-in Hack font.
pub fn install(ctx: &egui::Context) {
    ctx.add_font(egui::FontInsert::new(
        "Inter",
        egui::FontData::from_static(INTER_FONT),
        vec![egui::InsertFontFamily {
            family: egui::FontFamily::Proportional,
            priority: egui::FontPriority::Highest,
        }],
    ));
}
