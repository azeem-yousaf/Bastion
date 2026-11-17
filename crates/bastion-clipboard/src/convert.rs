//! Pure format conversions between local MIME data and CLIPRDR clipboard formats.
//!
//! Nothing in here touches the OS or the network, so everything is unit tested.

use std::io::Cursor;

use ironrdp_cliprdr_format::{bitmap, html};

/// Canonical local text type.
pub(crate) const MIME_TEXT_UTF8: &str = "text/plain;charset=utf-8";
pub(crate) const MIME_TEXT_PLAIN: &str = "text/plain";
pub(crate) const MIME_UTF8_STRING: &str = "UTF8_STRING";
pub(crate) const MIME_STRING: &str = "STRING";
pub(crate) const MIME_TEXT_X11: &str = "TEXT";
pub(crate) const MIME_HTML: &str = "text/html";
pub(crate) const MIME_PNG: &str = "image/png";
pub(crate) const MIME_JPEG: &str = "image/jpeg";
pub(crate) const MIME_BMP: &str = "image/bmp";
pub(crate) const MIME_URI_LIST: &str = "text/uri-list";
pub(crate) const MIME_GNOME_FILES: &str = "x-special/gnome-copied-files";
/// Set to `secret` by password managers (KeePassXC, KWallet, ...) on selections that must not
/// be recorded or forwarded. Clipboard managers honour it; so do we.
pub(crate) const MIME_PASSWORD_HINT: &str = "x-kde-passwordManagerHint";
/// Carried by every remote clipboard a Bastion session offers locally, so other sessions (in
/// this process or another) recognise it and do not pass it on to their own remote.
pub(crate) const MIME_BASTION_REMOTE: &str = "application/x-bastion-remote-clipboard";

/// Text types we read locally, best first.
pub(crate) const LOCAL_TEXT_TYPES: &[&str] =
    &[MIME_TEXT_UTF8, MIME_UTF8_STRING, MIME_TEXT_PLAIN, MIME_STRING, MIME_TEXT_X11];
/// Image types we read locally, best first.
pub(crate) const LOCAL_IMAGE_TYPES: &[&str] = &[MIME_PNG, MIME_BMP, MIME_JPEG];

/// What a local MIME type maps to on the RDP side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum LocalKind {
    Text,
    Html,
    Png,
    UriList,
    GnomeFiles,
}

impl LocalKind {
    /// Classifies a MIME type requested by a local paste.
    pub(crate) fn from_mime(mime: &str) -> Option<Self> {
        let base = mime.split(';').next().unwrap_or("").trim();
        match base {
            "text/plain" | MIME_UTF8_STRING | MIME_STRING | MIME_TEXT_X11 => Some(Self::Text),
            MIME_HTML => Some(Self::Html),
            MIME_PNG => Some(Self::Png),
            MIME_URI_LIST => Some(Self::UriList),
            MIME_GNOME_FILES => Some(Self::GnomeFiles),
            _ => None,
        }
    }

    pub(crate) fn is_files(self) -> bool {
        matches!(self, Self::UriList | Self::GnomeFiles)
    }
}

#[derive(Debug)]
pub(crate) struct ConvertError(pub(crate) String);

impl core::fmt::Display for ConvertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::error::Error for ConvertError {}

fn err(e: impl core::fmt::Display) -> ConvertError {
    ConvertError(e.to_string())
}

// ---------------------------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------------------------

/// Decodes local text bytes offered as `mime` into a Rust string.
///
/// `STRING` is ISO-8859-1 per ICCCM; everything else is treated as UTF-8 (invalid sequences are
/// replaced). A leading BOM is dropped.
pub(crate) fn local_text_to_string(mime: &str, data: &[u8]) -> String {
    if mime == MIME_STRING {
        return data.iter().map(|&b| char::from(b)).collect();
    }
    let data = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data);
    String::from_utf8_lossy(data).into_owned()
}

/// Converts text to `CF_UNICODETEXT`: UTF-16LE, CRLF line endings, NUL terminated.
///
/// Text after an embedded NUL is dropped (Windows would treat the NUL as the end anyway).
pub(crate) fn text_to_cf_unicodetext(text: &str) -> Vec<u8> {
    let text = text.split('\0').next().unwrap_or("");
    let normalized = lf_to_crlf(text);
    let mut out = Vec::with_capacity(normalized.len() * 2 + 2);
    for unit in normalized.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    out
}

/// Converts `CF_UNICODETEXT` to UTF-8 text with LF line endings.
///
/// Stops at the first NUL code unit; an odd trailing byte is ignored; unpaired surrogates become
/// U+FFFD.
pub(crate) fn cf_unicodetext_to_text(data: &[u8]) -> String {
    let units: Vec<u16> =
        data.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
    crlf_to_lf(&String::from_utf16_lossy(&units))
}

/// Converts `CF_TEXT` (ANSI, assumed Windows-1252/Latin-1) to UTF-8 with LF line endings.
pub(crate) fn cf_text_to_text(data: &[u8]) -> String {
    let s: String = data.iter().take_while(|&&b| b != 0).map(|&b| char::from(b)).collect();
    crlf_to_lf(&s)
}

/// LF -> CRLF, leaving existing CRLF pairs untouched.
pub(crate) fn lf_to_crlf(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + text.len() / 32);
    let mut prev = '\0';
    for c in text.chars() {
        if c == '\n' && prev != '\r' {
            out.push('\r');
        }
        out.push(c);
        prev = c;
    }
    out
}

/// CRLF -> LF. Lone CRs are kept.
pub(crate) fn crlf_to_lf(text: &str) -> String {
    text.replace("\r\n", "\n")
}

// ---------------------------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------------------------

/// Decodes local `text/html` bytes. Firefox/Chromium sometimes hand out UTF-16 with a BOM.
pub(crate) fn decode_local_html(data: &[u8]) -> String {
    if let Some(rest) = data.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = rest.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        return String::from_utf16_lossy(&units);
    }
    if let Some(rest) = data.strip_prefix(&[0xFE, 0xFF]) {
        let units: Vec<u16> = rest.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
        return String::from_utf16_lossy(&units);
    }
    let data = data.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(data);
    String::from_utf8_lossy(data).into_owned()
}

fn find_ascii_ci(haystack: &str, needle: &str) -> Option<usize> {
    let hay = haystack.as_bytes();
    let needle = needle.as_bytes();
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| hay[i..i + needle.len()].eq_ignore_ascii_case(needle))
}

/// Extracts the part of an HTML document that belongs between the CF_HTML fragment markers:
/// the `<body>` contents of a full document, otherwise the input minus a leading
/// `<meta charset>` tag (which Chromium prepends to copied fragments).
pub(crate) fn html_fragment(doc: &str) -> &str {
    let doc = doc.trim_end_matches('\0');
    if let Some(body) = find_ascii_ci(doc, "<body")
        && let Some(open_end) = doc.get(body..).and_then(|s| s.find('>'))
    {
        let start = body + open_end + 1;
        let end = doc.get(start..).and_then(|s| find_ascii_ci(s, "</body")).map_or(doc.len(), |e| start + e);
        if let Some(inner) = doc.get(start..end) {
            return inner;
        }
    }
    let trimmed = doc.trim_start();
    if find_ascii_ci(trimmed.get(..5).unwrap_or(""), "<meta") == Some(0)
        && let Some(end) = trimmed.find('>')
    {
        return trimmed.get(end + 1..).unwrap_or("");
    }
    doc
}

/// Local `text/html` -> CF_HTML ("HTML Format"), NUL terminated.
pub(crate) fn local_html_to_cf_html(data: &[u8]) -> Vec<u8> {
    let doc = decode_local_html(data);
    let mut out = html::plain_html_to_cf_html(html_fragment(&doc)).into_bytes();
    out.push(0);
    out
}

/// CF_HTML -> UTF-8 HTML fragment suitable for `text/html`.
pub(crate) fn cf_html_to_local_html(data: &[u8]) -> Result<Vec<u8>, ConvertError> {
    html::validate_cf_html(data).map_err(err)?;
    let fragment = html::cf_html_to_plain_html(data).map_err(err)?;
    // A meta charset makes consumers that sniff (e.g. LibreOffice) decode it as UTF-8.
    let mut out = String::with_capacity(fragment.len() + 64);
    out.push_str("<meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\">");
    out.push_str(fragment);
    Ok(out.into_bytes())
}

// ---------------------------------------------------------------------------------------------
// Images
// ---------------------------------------------------------------------------------------------

/// Largest side of an image the DIB conversion accepts.
const MAX_IMAGE_SIDE: u32 = 10_000;
/// Largest decoded (RGBA) image the DIB conversion accepts.
const MAX_IMAGE_RGBA_BYTES: u64 = 64 * 1024 * 1024;

/// Converts a local image (`image/png`, `image/bmp`, `image/jpeg`) to PNG.
///
/// An image the DIB conversion would refuse anyway (more than 64 MiB of RGBA, or a side over
/// 10,000 pixels) is refused from its header, before anything is decoded. `max_bytes` further
/// bounds the decoder's allocations so a crafted image cannot exhaust memory.
pub(crate) fn local_image_to_png(mime: &str, data: &[u8], max_bytes: usize) -> Result<Vec<u8>, ConvertError> {
    let format = match mime {
        MIME_PNG => return Ok(data.to_vec()),
        MIME_BMP => image::ImageFormat::Bmp,
        MIME_JPEG => image::ImageFormat::Jpeg,
        other => return Err(ConvertError(format!("unsupported image type {other}"))),
    };
    let (width, height) = image::ImageReader::with_format(Cursor::new(data), format).into_dimensions().map_err(err)?;
    if width > MAX_IMAGE_SIDE
        || height > MAX_IMAGE_SIDE
        || u64::from(width) * u64::from(height) * 4 > MAX_IMAGE_RGBA_BYTES
    {
        return Err(ConvertError(format!("image is too large for the clipboard ({width}x{height})")));
    }
    let mut reader = image::ImageReader::with_format(Cursor::new(data), format);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_SIDE);
    limits.max_image_height = Some(MAX_IMAGE_SIDE);
    // The decoded image fits in 64 MiB (checked above); allow the decoder some working memory.
    let max_alloc = u64::try_from(max_bytes.saturating_mul(4)).unwrap_or(u64::MAX).min(MAX_IMAGE_RGBA_BYTES * 2);
    limits.max_alloc = Some(max_alloc);
    reader.limits(limits);
    let img = reader.decode().map_err(err)?;
    let rgba = img.to_rgba8();
    let mut out = Vec::new();
    rgba.write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png).map_err(err)?;
    Ok(out)
}

pub(crate) fn png_to_dib(png: &[u8]) -> Result<Vec<u8>, ConvertError> {
    bitmap::png_to_cf_dib(png).map_err(err)
}

pub(crate) fn png_to_dibv5(png: &[u8]) -> Result<Vec<u8>, ConvertError> {
    bitmap::png_to_cf_dibv5(png).map_err(err)
}

pub(crate) fn dib_to_png(dib: &[u8]) -> Result<Vec<u8>, ConvertError> {
    bitmap::dib_to_png(dib).map_err(err)
}

pub(crate) fn dibv5_to_png(dib: &[u8]) -> Result<Vec<u8>, ConvertError> {
    bitmap::dibv5_to_png(dib).map_err(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mime_classification() {
        assert_eq!(LocalKind::from_mime("text/plain;charset=utf-8"), Some(LocalKind::Text));
        assert_eq!(LocalKind::from_mime("text/plain"), Some(LocalKind::Text));
        assert_eq!(LocalKind::from_mime("UTF8_STRING"), Some(LocalKind::Text));
        assert_eq!(LocalKind::from_mime("text/html"), Some(LocalKind::Html));
        assert_eq!(LocalKind::from_mime("image/png"), Some(LocalKind::Png));
        assert_eq!(LocalKind::from_mime("text/uri-list"), Some(LocalKind::UriList));
        assert_eq!(LocalKind::from_mime("x-special/gnome-copied-files"), Some(LocalKind::GnomeFiles));
        assert_eq!(LocalKind::from_mime("application/x-foo"), None);
    }

    #[test]
    fn text_to_unicodetext_crlf_and_terminator() {
        let out = text_to_cf_unicodetext("a\nb\r\nc");
        let expected: Vec<u8> = "a\r\nb\r\nc".encode_utf16().flat_map(|u| u.to_le_bytes()).chain([0, 0]).collect();
        assert_eq!(out, expected);
    }

    #[test]
    fn text_to_unicodetext_truncates_at_nul() {
        let out = text_to_cf_unicodetext("abc\0secret");
        assert_eq!(out, vec![b'a', 0, b'b', 0, b'c', 0, 0, 0]);
    }

    #[test]
    fn text_to_unicodetext_non_bmp() {
        let s = "h\u{e9}llo \u{1F600} \u{4e16}\u{754c}";
        let out = text_to_cf_unicodetext(s);
        assert_eq!(cf_unicodetext_to_text(&out), s);
    }

    #[test]
    fn unicodetext_to_text_stops_at_nul_and_converts_crlf() {
        let mut data: Vec<u8> = "line1\r\nline2".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        data.extend_from_slice(&[0, 0, b'x', 0, b'y', 0]);
        assert_eq!(cf_unicodetext_to_text(&data), "line1\nline2");
    }

    #[test]
    fn unicodetext_handles_odd_length_and_lone_surrogate() {
        let mut data = vec![b'a', 0, 0x00, 0xD8, b'b', 0];
        data.push(0x41); // odd trailing byte
        assert_eq!(cf_unicodetext_to_text(&data), "a\u{FFFD}b");
        assert_eq!(cf_unicodetext_to_text(&[]), "");
    }

    #[test]
    fn text_round_trip_preserves_lf() {
        let s = "one\ntwo\n\nthree\n";
        assert_eq!(cf_unicodetext_to_text(&text_to_cf_unicodetext(s)), s);
    }

    #[test]
    fn cf_text_latin1() {
        assert_eq!(cf_text_to_text(b"caf\xe9\r\nx\0junk"), "caf\u{e9}\nx");
    }

    #[test]
    fn local_text_decoding() {
        assert_eq!(local_text_to_string(MIME_STRING, b"\xe9"), "\u{e9}");
        assert_eq!(local_text_to_string(MIME_TEXT_UTF8, b"\xEF\xBB\xBFhi"), "hi");
        assert_eq!(local_text_to_string(MIME_TEXT_UTF8, b"a\xffb"), "a\u{FFFD}b");
    }

    #[test]
    fn html_round_trip() {
        let fragment = "<b>bold</b> &amp; <i>\u{e9}t\u{e9}</i>";
        let cf = local_html_to_cf_html(fragment.as_bytes());
        assert_eq!(cf.last(), Some(&0));
        assert!(html::validate_cf_html(&cf).is_ok());
        let back = cf_html_to_local_html(&cf).expect("valid CF_HTML");
        let back = String::from_utf8(back).expect("utf8");
        assert!(back.ends_with(fragment), "{back}");
        assert!(back.starts_with("<meta"));
    }

    #[test]
    fn html_full_document_uses_body() {
        let doc = "<html><head><title>t</title></head><BODY class=x><p>hi</p></BODY></html>";
        assert_eq!(html_fragment(doc), "<p>hi</p>");
        let cf = local_html_to_cf_html(doc.as_bytes());
        let back = String::from_utf8(cf_html_to_local_html(&cf).expect("valid")).expect("utf8");
        assert!(back.ends_with("<p>hi</p>"));
    }

    #[test]
    fn html_strips_chromium_meta_prefix() {
        let doc = "<meta charset='utf-8'><span>x</span>";
        assert_eq!(html_fragment(doc), "<span>x</span>");
    }

    #[test]
    fn html_utf16_bom_decoding() {
        let mut data = vec![0xFF, 0xFE];
        data.extend("<b>\u{e9}</b>".encode_utf16().flat_map(|u| u.to_le_bytes()));
        assert_eq!(decode_local_html(&data), "<b>\u{e9}</b>");
    }

    #[test]
    fn invalid_cf_html_is_rejected() {
        assert!(cf_html_to_local_html(b"garbage").is_err());
        assert!(cf_html_to_local_html(b"Version:0.9\r\nStartHTML:999\r\n").is_err());
    }

    fn sample_png(w: u32, h: u32) -> (Vec<u8>, image::RgbaImage) {
        let img = image::RgbaImage::from_fn(w, h, |x, y| {
            image::Rgba([(x * 40) as u8, (y * 60) as u8, ((x + y) * 20) as u8, if x == 0 { 128 } else { 255 }])
        });
        let mut png = Vec::new();
        img.write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png).expect("encode png");
        (png, img)
    }

    fn decode_png(data: &[u8]) -> image::RgbaImage {
        image::load_from_memory_with_format(data, image::ImageFormat::Png).expect("decode").to_rgba8()
    }

    #[test]
    fn png_dib_round_trip_pixels() {
        let (png, img) = sample_png(5, 3);
        let dib = png_to_dib(&png).expect("to dib");
        let back = decode_png(&dib_to_png(&dib).expect("from dib"));
        assert_eq!(back.dimensions(), (5, 3));
        // CF_DIB has no reliable alpha; compare colour channels.
        for (a, b) in img.pixels().zip(back.pixels()) {
            assert_eq!(a.0[..3], b.0[..3]);
        }
    }

    #[test]
    fn png_dibv5_round_trip_pixels_with_alpha() {
        let (png, img) = sample_png(4, 4);
        let dib = png_to_dibv5(&png).expect("to dibv5");
        let back = decode_png(&dibv5_to_png(&dib).expect("from dibv5"));
        assert_eq!(back.dimensions(), (4, 4));
        for (a, b) in img.pixels().zip(back.pixels()) {
            assert_eq!(a.0, b.0);
        }
    }

    #[test]
    fn bmp_and_jpeg_to_png() {
        let (_, img) = sample_png(3, 2);
        let mut bmp = Vec::new();
        image::DynamicImage::ImageRgba8(img.clone())
            .to_rgb8()
            .write_to(&mut Cursor::new(&mut bmp), image::ImageFormat::Bmp)
            .expect("bmp");
        let png = local_image_to_png(MIME_BMP, &bmp, 1 << 20).expect("bmp -> png");
        let back = decode_png(&png);
        assert_eq!(back.dimensions(), (3, 2));
        assert_eq!(back.get_pixel(1, 1).0[..3], img.get_pixel(1, 1).0[..3]);

        let mut jpg = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .to_rgb8()
            .write_to(&mut Cursor::new(&mut jpg), image::ImageFormat::Jpeg)
            .ok();
        if !jpg.is_empty() {
            // Encoder availability depends on features; decoding is what we ship.
            let png = local_image_to_png(MIME_JPEG, &jpg, 1 << 20).expect("jpeg -> png");
            assert_eq!(decode_png(&png).dimensions(), (3, 2));
        }
        assert!(local_image_to_png(MIME_JPEG, b"not a jpeg", 1 << 20).is_err());
    }

    /// A valid BMP header (24 bpp) for a `width` x `height` image, with no pixel data.
    fn bmp_header(width: u32, height: u32) -> Vec<u8> {
        let mut bmp = Vec::new();
        bmp.extend_from_slice(b"BM");
        bmp.extend_from_slice(&0u32.to_le_bytes()); // file size (ignored)
        bmp.extend_from_slice(&0u32.to_le_bytes()); // reserved
        bmp.extend_from_slice(&54u32.to_le_bytes()); // pixel data offset
        bmp.extend_from_slice(&40u32.to_le_bytes()); // BITMAPINFOHEADER
        bmp.extend_from_slice(&width.to_le_bytes());
        bmp.extend_from_slice(&height.to_le_bytes());
        bmp.extend_from_slice(&1u16.to_le_bytes()); // planes
        bmp.extend_from_slice(&24u16.to_le_bytes()); // bits per pixel
        bmp.extend_from_slice(&[0u8; 24]); // no compression, sizes, resolution, palette
        bmp
    }

    #[test]
    fn oversized_local_images_are_refused_from_the_header() {
        // What the DIB conversion could never send must be refused before decoding, whatever the
        // transfer limit: 18,000 x 18,000 would need 1.2 GiB of RGBA.
        for (width, height) in [(18_000, 18_000), (9_000, 9_000), (10_001, 1), (1, 10_001), (4_097, 4_097)] {
            let error = local_image_to_png(MIME_BMP, &bmp_header(width, height), 256 << 20).expect_err("refused");
            assert!(error.to_string().contains("too large"), "{width}x{height}: {error}");
        }
        // Within the cap the header is accepted and decoding proceeds (and fails: no pixels).
        let error = local_image_to_png(MIME_BMP, &bmp_header(4_096, 4_096), 256 << 20).expect_err("truncated");
        assert!(!error.to_string().contains("too large"), "{error}");
    }

    #[test]
    fn corrupt_dib_is_rejected() {
        assert!(dib_to_png(&[1, 2, 3]).is_err());
        assert!(dibv5_to_png(&[0; 10]).is_err());
        assert!(png_to_dib(b"not a png").is_err());
    }
}
