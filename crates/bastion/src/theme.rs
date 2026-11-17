//! Visual identity: a calm dark theme with a single accent colour.

use egui::{Color32, CornerRadius, FontFamily, FontId, Stroke, TextStyle, Visuals};

pub const ACCENT: Color32 = Color32::from_rgb(0x4C, 0x8D, 0xFF);
pub const DANGER: Color32 = Color32::from_rgb(0xF0, 0x5A, 0x5A);
pub const WARN: Color32 = Color32::from_rgb(0xF5, 0xB0, 0x41);
pub const OK: Color32 = Color32::from_rgb(0x4C, 0xC3, 0x8A);
pub const MUTED: Color32 = Color32::from_rgb(0x8A, 0x93, 0xA6);

const BG: Color32 = Color32::from_rgb(0x14, 0x17, 0x1C);
const PANEL: Color32 = Color32::from_rgb(0x1B, 0x1F, 0x26);
const WIDGET: Color32 = Color32::from_rgb(0x25, 0x2A, 0x33);
const HOVER: Color32 = Color32::from_rgb(0x2E, 0x34, 0x3F);

pub fn apply(ctx: &egui::Context) {
    let mut v = Visuals::dark();
    v.panel_fill = PANEL;
    v.window_fill = PANEL;
    v.extreme_bg_color = BG;
    v.faint_bg_color = Color32::from_rgb(0x20, 0x25, 0x2D);
    v.selection.bg_fill = ACCENT.linear_multiply(0.45);
    v.selection.stroke = Stroke::new(1.0, ACCENT);
    v.hyperlink_color = ACCENT;
    v.window_corner_radius = CornerRadius::same(10);
    v.window_stroke = Stroke::new(1.0, Color32::from_rgb(0x2C, 0x32, 0x3C));
    for w in [&mut v.widgets.inactive, &mut v.widgets.hovered, &mut v.widgets.active, &mut v.widgets.open] {
        w.corner_radius = CornerRadius::same(6);
    }
    v.widgets.inactive.weak_bg_fill = WIDGET;
    v.widgets.inactive.bg_fill = WIDGET;
    v.widgets.hovered.weak_bg_fill = HOVER;
    v.widgets.hovered.bg_fill = HOVER;
    v.widgets.active.weak_bg_fill = ACCENT.linear_multiply(0.6);
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(0x2A, 0x2F, 0x38));
    ctx.set_visuals(v);

    ctx.global_style_mut(|s| {
        s.spacing.item_spacing = egui::vec2(8.0, 8.0);
        s.spacing.button_padding = egui::vec2(12.0, 6.0);
        s.spacing.interact_size.y = 30.0;
        s.text_styles = [
            (TextStyle::Heading, FontId::new(20.0, FontFamily::Proportional)),
            (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
            (TextStyle::Button, FontId::new(14.0, FontFamily::Proportional)),
            (TextStyle::Small, FontId::new(12.0, FontFamily::Proportional)),
            (TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace)),
        ]
        .into();
    });
}

/// Primary call-to-action button.
pub fn primary_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Button::new(egui::RichText::new(text).color(Color32::WHITE).strong())
            .fill(ACCENT)
            .min_size(egui::vec2(96.0, 32.0)),
    )
}

pub fn danger_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(egui::Button::new(egui::RichText::new(text).color(Color32::WHITE)).fill(DANGER.linear_multiply(0.85)))
}

pub fn section(ui: &mut egui::Ui, title: &str) {
    ui.add_space(6.0);
    ui.label(egui::RichText::new(title.to_uppercase()).small().strong().color(MUTED));
}

/// Bastion's mark: a shield-like diamond with an inner "window", drawn as vectors.
pub fn logo(ui: &mut egui::Ui, size: f32) -> egui::Response {
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let p = ui.painter_at(rect);
    let c = rect.center();
    let r = size * 0.48;
    let outer = vec![c + egui::vec2(0.0, -r), c + egui::vec2(r, 0.0), c + egui::vec2(0.0, r), c + egui::vec2(-r, 0.0)];
    p.add(egui::Shape::convex_polygon(outer, ACCENT, Stroke::NONE));
    let w = size * 0.34;
    let inner = egui::Rect::from_center_size(c, egui::vec2(w, w * 0.72));
    p.rect_filled(inner, size * 0.04, Color32::from_rgb(0x14, 0x17, 0x1C));
    p.rect_filled(
        egui::Rect::from_min_size(inner.min, egui::vec2(w, w * 0.16)),
        size * 0.04,
        Color32::WHITE.linear_multiply(0.85),
    );
    resp
}
