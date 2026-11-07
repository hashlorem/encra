//! Reading a 2FA QR code from a screenshot, so the setup key never has to be
//! found and typed. Everything happens here; the image is never sent anywhere.

use image::{GrayImage, ImageReader, Limits};
use std::io::Cursor;

/// Bigger than any screenshot; refuses a file picked by mistake.
pub const MAX_IMAGE_BYTES: usize = 25 * 1024 * 1024;
const MAX_SIDE: u32 = 10_000;

/// Decode PNG or JPEG bytes, refusing anything oversized before it is
/// allocated.
pub fn from_encoded(bytes: &[u8]) -> Result<GrayImage, String> {
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err("that image is too large".into());
    }
    let mut reader = ImageReader::new(Cursor::new(bytes)).with_guessed_format().map_err(|_| "could not read that image")?;
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_SIDE);
    limits.max_image_height = Some(MAX_SIDE);
    limits.max_alloc = Some(512 * 1024 * 1024);
    reader.limits(limits);
    let image = reader.decode().map_err(|_| "could not read that image (use a PNG or JPEG)")?;
    Ok(image.to_luma8())
}

/// An RGBA buffer, as the clipboard hands it over.
pub fn from_rgba(width: usize, height: usize, rgba: &[u8]) -> Result<GrayImage, String> {
    if width == 0 || height == 0 || width > MAX_SIDE as usize || height > MAX_SIDE as usize || rgba.len() != width * height * 4 {
        return Err("could not read that image".into());
    }
    let grey = rgba
        .chunks_exact(4)
        .map(|p| ((p[0] as u32 * 299 + p[1] as u32 * 587 + p[2] as u32 * 114) / 1000) as u8)
        .collect();
    GrayImage::from_raw(width as u32, height as u32, grey).ok_or_else(|| "could not read that image".into())
}

/// The text of the one-time-code QR in the image.
pub fn read_code_link(image: &GrayImage) -> Result<String, String> {
    // Full resolution: shrinking a screenshot blurs the modules enough that
    // small QR codes stop reading.
    let (w, h) = image.dimensions();
    // The decoder sees untrusted pixels; a panic in it is a failed read, not
    // a stuck dialog.
    let texts = std::panic::catch_unwind(|| {
        let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(w as usize, h as usize, |x, y| image.get_pixel(x as u32, y as u32)[0]);
        prepared.detect_grids().iter().filter_map(|grid| grid.decode().ok().map(|(_, text)| text)).collect::<Vec<String>>()
    })
    .unwrap_or_default();
    if texts.is_empty() {
        return Err("no QR code found in that image".into());
    }
    texts
        .into_iter()
        .find(|text| text.to_ascii_lowercase().starts_with("otpauth"))
        .ok_or_else(|| "that QR code is not a 2FA setup code".into())
}

/// Whatever image is on the clipboard.
pub fn from_clipboard() -> Result<GrayImage, String> {
    let mut clipboard = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    let image = clipboard.get_image().map_err(|_| "there is no image on the clipboard")?;
    from_rgba(image.width, image.height, &image.bytes)
}

/// Clear the clipboard after reading a QR from it: the screenshot holds the
/// secret, and clipboard history apps would keep it.
pub fn clear_clipboard() {
    if let Ok(mut clipboard) = arboard::Clipboard::new() {
        let _ = clipboard.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A QR for `text`, drawn black on white at `scale` pixels per module,
    /// placed at (x, y) on a canvas, encoded as PNG.
    fn qr_png(text: &str, scale: u32, canvas: (u32, u32), at: (u32, u32)) -> Vec<u8> {
        let code = qrcode::QrCode::new(text).unwrap();
        let width = code.width() as u32;
        let colors = code.to_colors();
        let mut image = GrayImage::from_pixel(canvas.0, canvas.1, image::Luma([255]));
        for (i, color) in colors.iter().enumerate() {
            if *color != qrcode::Color::Dark {
                continue;
            }
            let (mx, my) = (i as u32 % width, i as u32 / width);
            for dy in 0..scale {
                for dx in 0..scale {
                    image.put_pixel(at.0 + mx * scale + dx, at.1 + my * scale + dy, image::Luma([0]));
                }
            }
        }
        let mut png = Vec::new();
        image.write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png).unwrap();
        png
    }

    const LINK: &str = "otpauth://totp/Example:me@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&period=60";

    #[test]
    fn test_reads_a_2fa_qr_from_a_screenshot() {
        let png = qr_png(LINK, 6, (400, 400), (60, 60));
        assert_eq!(read_code_link(&from_encoded(&png).unwrap()).unwrap(), LINK);

        // A full Retina screenshot with the QR off to one side.
        let big = qr_png(LINK, 8, (5120, 2880), (3800, 900));
        assert_eq!(read_code_link(&from_encoded(&big).unwrap()).unwrap(), LINK);
    }

    #[test]
    fn test_refuses_images_that_are_not_a_2fa_qr() {
        assert!(from_encoded(b"not an image at all").is_err());
        assert!(from_encoded(&[0u8; MAX_IMAGE_BYTES + 1]).unwrap_err().contains("too large"));

        let blank = GrayImage::from_pixel(300, 200, image::Luma([255]));
        assert!(read_code_link(&blank).unwrap_err().contains("no QR"));

        let website = qr_png("https://example.com", 6, (400, 400), (60, 60));
        assert!(read_code_link(&from_encoded(&website).unwrap()).unwrap_err().contains("not a 2FA"));

        // Wider than any screen: refused by the decoder's limits.
        let wide = GrayImage::from_pixel(MAX_SIDE + 1, 1, image::Luma([255]));
        let mut png = Vec::new();
        wide.write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png).unwrap();
        assert!(from_encoded(&png).is_err());

        assert!(from_rgba(2, 2, &[0u8; 15]).is_err(), "buffer shorter than its size");
        assert!(from_rgba(0, 0, &[]).is_err());
    }
}
