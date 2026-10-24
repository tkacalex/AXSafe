//! Gemeinsame Testhilfen: harmlose Testdaten und Container zur Laufzeit.
#![allow(dead_code)]

use md5::{Digest, Md5};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

/// EICAR wird zur Laufzeit zusammengesetzt (Quelltext enthält ihn nicht am Stück).
pub fn eicar() -> Vec<u8> {
    let a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$";
    let b = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    format!("{a}{b}").into_bytes()
}

/// ClamAV-Hashsignatur (.hdb) für EICAR, nur AXSafe-Testsignatur.
pub fn test_hdb(dir: &Path) -> PathBuf {
    let e = eicar();
    let p = dir.join("axsafe-test.hdb");
    std::fs::write(
        &p,
        format!(
            "{}:{}:AXSafe.Test.EICAR.HDB\n",
            hex::encode(Md5::digest(&e)),
            e.len()
        ),
    )
    .unwrap();
    p
}

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

/// Kopiert den Testhelfer als `clamscan-<modus>` in `dir`.
pub fn fake_clamscan(dir: &Path, mode: &str) -> PathBuf {
    let src = PathBuf::from(env!("CARGO_BIN_EXE_axsafe-clamav-testhelper"));
    let dst = dir.join(format!("clamscan-{mode}{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(src, &dst).unwrap();
    wait_executable(&dst);
    dst
}

/// Linux kann eine frisch geschriebene Datei kurz mit ETXTBSY („Text file
/// busy“) ablehnen, wenn parallel ein anderer Test einen Prozess startet und
/// dabei den Schreib-Handle erbt. Warten, bis die Kopie startbar ist.
pub fn wait_executable(p: &Path) {
    for _ in 0..200 {
        match std::process::Command::new(p).arg("--version").output() {
            Ok(o) if o.status.success() => return,
            _ => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
    panic!("Testhelfer {} nicht startbar", p.display());
}

pub fn clamscan_available() -> bool {
    std::process::Command::new("clamscan")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Pflicht-Vorbedingung: ohne clamscan schlägt der Test fehl statt still zu bestehen.
pub fn require_clamscan() {
    assert!(
        clamscan_available(),
        "Vorbedingung fehlt: clamscan ist nicht installiert. Dieser Test ist als #[ignore] \
         markiert und darf nur dort mit --include-ignored laufen, wo ClamAV installiert ist."
    );
}
