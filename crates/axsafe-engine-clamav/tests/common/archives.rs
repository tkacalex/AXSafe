//! Harmlose Container zur Laufzeit (auch für die Tests des ClamAV-Workers).
#![allow(dead_code)]

use std::io::{Cursor, Write};
use std::path::Path;

pub fn zip_with(entries: &[(&str, &[u8])], password: Option<&str>) -> Vec<u8> {
    use zip::unstable::write::FileOptionsExt;
    use zip::write::SimpleFileOptions;
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in entries {
        let mut opts =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        if let Some(pw) = password {
            opts = opts.with_deprecated_encryption(pw.as_bytes()).unwrap();
        }
        w.start_file(*name, opts).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

pub fn ooxml_with(payload: &[u8]) -> Vec<u8> {
    let ct = br#"<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>"#;
    zip_with(
        &[
            ("[Content_Types].xml", ct),
            ("word/embeddings/oleObject1.bin", payload),
        ],
        None,
    )
}

pub fn gzip_with(payload: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(payload).unwrap();
    e.finish().unwrap()
}

pub fn cfb_with(payload: &[u8]) -> Vec<u8> {
    let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    {
        let mut s = comp.create_stream("/Inhalt").unwrap();
        s.write_all(payload).unwrap();
    }
    comp.flush().unwrap();
    comp.into_inner().into_inner()
}

pub fn cab_with(payload: &[u8]) -> Vec<u8> {
    let mut b = cab::CabinetBuilder::new();
    b.add_folder(cab::CompressionType::MsZip)
        .add_file("inhalt.bin");
    let mut w = b.build(Cursor::new(Vec::new())).unwrap();
    while let Some(mut f) = w.next_file().unwrap() {
        f.write_all(payload).unwrap();
    }
    w.finish().unwrap().into_inner()
}

pub fn sevenz_with(dir: &Path, payload: &[u8]) -> Vec<u8> {
    let src = dir.join("7z-src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("inhalt.bin"), payload).unwrap();
    sevenz_rust2::compress(&src, Cursor::new(Vec::new()))
        .unwrap()
        .into_inner()
}

/// Minimales PDF mit einem FlateDecode-Stream, der `payload` enthält.
pub fn pdf_with(payload: &[u8]) -> Vec<u8> {
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    z.write_all(payload).unwrap();
    let stream = z.finish().unwrap();
    let mut pdf = Vec::new();
    let mut offs = Vec::new();
    pdf.extend_from_slice(b"%PDF-1.4\n");
    offs.push(pdf.len());
    pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    offs.push(pdf.len());
    pdf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n");
    offs.push(pdf.len());
    pdf.extend_from_slice(
        format!(
            "3 0 obj\n<< /Length {} /Filter /FlateDecode >>\nstream\n",
            stream.len()
        )
        .as_bytes(),
    );
    pdf.extend_from_slice(&stream);
    pdf.extend_from_slice(b"\nendstream\nendobj\n");
    let xref = pdf.len();
    pdf.extend_from_slice(b"xref\n0 4\n0000000000 65535 f \n");
    for o in offs {
        pdf.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!("trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
    );
    pdf
}

/// Minimales ISO-9660-Abbild mit genau einer Datei im Wurzelverzeichnis
/// (ohne externes Werkzeug, damit es unter Linux und Windows gleich ist).
pub fn iso_with(name: &str, payload: &[u8]) -> Vec<u8> {
    const S: usize = 2048;
    fn both32(v: u32) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&v.to_le_bytes());
        b[4..].copy_from_slice(&v.to_be_bytes());
        b
    }
    fn both16(v: u16) -> [u8; 4] {
        let mut b = [0u8; 4];
        b[..2].copy_from_slice(&v.to_le_bytes());
        b[2..].copy_from_slice(&v.to_be_bytes());
        b
    }
    fn record(lba: u32, len: u32, dir: bool, ident: &[u8]) -> Vec<u8> {
        let mut r = vec![0u8; 33];
        r[2..10].copy_from_slice(&both32(lba));
        r[10..18].copy_from_slice(&both32(len));
        r[18..25].copy_from_slice(&[126, 10, 27, 12, 0, 0, 0]);
        r[25] = if dir { 2 } else { 0 };
        r[28..32].copy_from_slice(&both16(1));
        r[32] = ident.len() as u8;
        r.extend_from_slice(ident);
        if r.len() % 2 == 1 {
            r.push(0);
        }
        r[0] = r.len() as u8;
        r
    }
    let file_lba = 21u32;
    let file_sectors = payload.len().div_ceil(S).max(1);
    let total = 21 + file_sectors;
    let mut img = vec![0u8; total * S];
    let ident = format!("{};1", name.to_ascii_uppercase());
    // Primärer Datenträgerdeskriptor (Sektor 16)
    let p = &mut img[16 * S..17 * S];
    p[0] = 1;
    p[1..6].copy_from_slice(b"CD001");
    p[6] = 1;
    p[8..40].fill(b' ');
    p[40..72].fill(b' ');
    p[40..46].copy_from_slice(b"AXSAFE");
    p[80..88].copy_from_slice(&both32(total as u32));
    p[120..124].copy_from_slice(&both16(1));
    p[124..128].copy_from_slice(&both16(1));
    p[128..132].copy_from_slice(&both16(S as u16));
    p[132..140].copy_from_slice(&both32(10));
    p[140..144].copy_from_slice(&18u32.to_le_bytes());
    p[148..152].copy_from_slice(&19u32.to_be_bytes());
    let root = record(20, S as u32, true, &[0]);
    p[156..156 + root.len()].copy_from_slice(&root);
    p[190..813].fill(b' ');
    for o in [813, 830, 847, 864] {
        p[o..o + 16].fill(b'0');
    }
    p[881] = 1;
    // Abschluss (Sektor 17)
    let t = &mut img[17 * S..18 * S];
    t[0] = 255;
    t[1..6].copy_from_slice(b"CD001");
    t[6] = 1;
    // Pfadtabellen (18: little endian, 19: big endian)
    let mut l = vec![1u8, 0];
    l.extend_from_slice(&20u32.to_le_bytes());
    l.extend_from_slice(&1u16.to_le_bytes());
    l.extend_from_slice(&[0, 0]);
    img[18 * S..18 * S + 10].copy_from_slice(&l);
    let mut m = vec![1u8, 0];
    m.extend_from_slice(&20u32.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&[0, 0]);
    img[19 * S..19 * S + 10].copy_from_slice(&m);
    // Wurzelverzeichnis (Sektor 20)
    let mut dir = record(20, S as u32, true, &[0]);
    dir.extend(record(20, S as u32, true, &[1]));
    dir.extend(record(
        file_lba,
        payload.len() as u32,
        false,
        ident.as_bytes(),
    ));
    img[20 * S..20 * S + dir.len()].copy_from_slice(&dir);
    img[21 * S..21 * S + payload.len()].copy_from_slice(payload);
    img
}

/// RAR 2.x/4.x mit einer unkomprimiert gespeicherten Datei (Methode
/// „store“), nach der öffentlichen Formatbeschreibung; Prüfsummen wie im
/// Format vorgesehen (Kopf: untere 16 Bit von CRC-32).
pub fn rar_with(name: &str, payload: &[u8]) -> Vec<u8> {
    fn crc32(d: &[u8]) -> u32 {
        let mut c = 0xFFFF_FFFFu32;
        for &b in d {
            c ^= u32::from(b);
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    (c >> 1) ^ 0xEDB8_8320
                } else {
                    c >> 1
                };
            }
        }
        !c
    }
    fn block(htype: u8, flags: u16, body: &[u8], data: &[u8]) -> Vec<u8> {
        let mut h = vec![htype];
        h.extend_from_slice(&flags.to_le_bytes());
        h.extend_from_slice(&((7 + body.len()) as u16).to_le_bytes());
        h.extend_from_slice(body);
        let mut out = ((crc32(&h) & 0xFFFF) as u16).to_le_bytes().to_vec();
        out.extend(h);
        out.extend_from_slice(data);
        out
    }
    let mut out = b"Rar!\x1a\x07\x00".to_vec();
    out.extend(block(0x73, 0, &[0u8; 6], &[]));
    let mut fh = Vec::new();
    fh.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // gepackt
    fh.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // entpackt
    fh.push(2); // Windows
    fh.extend_from_slice(&crc32(payload).to_le_bytes());
    fh.extend_from_slice(&0x5B5A_0000u32.to_le_bytes()); // DOS-Zeit
    fh.push(20); // benötigte Version 2.0
    fh.push(0x30); // Methode: speichern
    fh.extend_from_slice(&(name.len() as u16).to_le_bytes());
    fh.extend_from_slice(&0x20u32.to_le_bytes());
    fh.extend_from_slice(name.as_bytes());
    out.extend(block(0x74, 0x8000, &fh, payload));
    out.extend(block(0x7B, 0x4000, &[], &[]));
    out
}
