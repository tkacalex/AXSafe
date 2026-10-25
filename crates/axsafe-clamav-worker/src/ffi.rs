//! Dynamisches Laden von libclamav (keine Bindung zur Übersetzungszeit).
//!
//! Signaturen nach `libclamav/clamav.h` (ClamAV 1.5.4). Nur die hier
//! genannten Funktionen werden benutzt.

#![allow(unsafe_code)]

use std::ffi::{c_char, c_int, c_ulong, c_void, CStr, CString};

pub const CL_INIT_DEFAULT: u32 = 0;
pub const CL_SUCCESS: c_int = 0;
pub const CL_VIRUS: c_int = 1;
pub const CL_DB_STDOPT: u32 = 0x2 | 0x8 | 0x2000;

// enum cl_engine_field (Reihenfolge laut clamav.h 1.5.4)
pub const CL_ENGINE_MAX_SCANSIZE: c_int = 0;
pub const CL_ENGINE_MAX_FILESIZE: c_int = 1;
pub const CL_ENGINE_MAX_RECURSION: c_int = 2;
pub const CL_ENGINE_MAX_FILES: c_int = 3;
pub const CL_ENGINE_DB_VERSION: c_int = 8;
pub const CL_ENGINE_DB_TIME: c_int = 9;
pub const CL_ENGINE_TMPDIR: c_int = 13;
pub const CL_ENGINE_CVDCERTSDIR: c_int = 37;
pub const CL_ENGINE_MAX_SCANTIME: c_int = 31;

// struct cl_scan_options
pub const CL_SCAN_GENERAL_HEURISTICS: u32 = 0x4;
pub const CL_SCAN_HEURISTIC_EXCEEDS_MAX: u32 = 0x4;
pub const CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE: u32 = 0x40;
pub const CL_SCAN_HEURISTIC_ENCRYPTED_DOC: u32 = 0x80;

#[repr(C)]
pub struct ScanOptions {
    pub general: u32,
    pub parse: u32,
    pub heuristic: u32,
    pub mail: u32,
    pub dev: u32,
}

impl ScanOptions {
    /// Entspricht `clamscan --alert-encrypted=yes --alert-exceeds-max=yes`
    /// mit allen Parsern (wie bisher über clamscan).
    pub fn axsafe() -> Self {
        ScanOptions {
            general: CL_SCAN_GENERAL_HEURISTICS,
            parse: !0,
            heuristic: CL_SCAN_HEURISTIC_EXCEEDS_MAX
                | CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE
                | CL_SCAN_HEURISTIC_ENCRYPTED_DOC,
            mail: 0,
            dev: 0,
        }
    }
}

type FnInit = unsafe extern "C" fn(u32) -> c_int;
type FnEngineNew = unsafe extern "C" fn() -> *mut c_void;
type FnEngineFree = unsafe extern "C" fn(*mut c_void) -> c_int;
type FnSetNum = unsafe extern "C" fn(*mut c_void, c_int, i64) -> c_int;
type FnGetNum = unsafe extern "C" fn(*const c_void, c_int, *mut c_int) -> i64;
type FnSetStr = unsafe extern "C" fn(*mut c_void, c_int, *const c_char) -> c_int;
type FnLoad = unsafe extern "C" fn(*const c_char, *mut c_void, *mut u32, u32) -> c_int;
type FnCompile = unsafe extern "C" fn(*mut c_void) -> c_int;
type FnFmapOpen = unsafe extern "C" fn(*const c_void, usize) -> *mut c_void;
type FnFmapClose = unsafe extern "C" fn(*mut c_void);
type FnScanMap = unsafe extern "C" fn(
    *mut c_void,
    *const c_char,
    *mut *const c_char,
    *mut c_ulong,
    *const c_void,
    *mut ScanOptions,
    *mut c_void,
) -> c_int;
type FnRetVer = unsafe extern "C" fn() -> *const c_char;
type FnRetFlevel = unsafe extern "C" fn() -> u32;
type FnStrError = unsafe extern "C" fn(c_int) -> *const c_char;

/// Geladene Bibliothek mit den benötigten Funktionen.
pub struct LibClamav {
    _handle: Handle,
    init: FnInit,
    engine_new: FnEngineNew,
    engine_free: FnEngineFree,
    set_num: FnSetNum,
    get_num: FnGetNum,
    set_str: FnSetStr,
    load: FnLoad,
    compile: FnCompile,
    fmap_open: FnFmapOpen,
    fmap_close: FnFmapClose,
    scanmap: FnScanMap,
    retver: FnRetVer,
    retflevel: FnRetFlevel,
    strerror: FnStrError,
}

/// Plattform-Handle der Bibliothek (wird nie entladen, solange der Worker lebt).
struct Handle(*mut c_void);

#[cfg(windows)]
fn open(path: &str) -> Result<Handle, String> {
    use windows_sys::Win32::System::LibraryLoader::{
        LoadLibraryExW, LOAD_WITH_ALTERED_SEARCH_PATH,
    };
    let w: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: nullterminierter Pfad; LOAD_WITH_ALTERED_SEARCH_PATH lädt die
    // Abhängigkeiten aus dem Ordner der Bibliothek (ClamAV-Installation).
    let h = unsafe {
        LoadLibraryExW(
            w.as_ptr(),
            std::ptr::null_mut(),
            LOAD_WITH_ALTERED_SEARCH_PATH,
        )
    };
    if h.is_null() {
        Err(format!(
            "{path} nicht ladbar: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(Handle(h))
    }
}

#[cfg(windows)]
fn sym(h: &Handle, name: &str) -> Result<*const c_void, String> {
    use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
    let c = CString::new(name).map_err(|e| e.to_string())?;
    // SAFETY: gültiges Modul-Handle, nullterminierter Name.
    match unsafe { GetProcAddress(h.0 as _, c.as_ptr() as *const u8) } {
        Some(f) => Ok(f as *const c_void),
        None => Err(format!("Funktion {name} fehlt in libclamav")),
    }
}

#[cfg(unix)]
fn open(path: &str) -> Result<Handle, String> {
    let c = CString::new(path).map_err(|e| e.to_string())?;
    // SAFETY: nullterminierter Pfad.
    let h = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if h.is_null() {
        // SAFETY: dlerror liefert eine Zeichenkette oder NULL.
        let e = unsafe { libc::dlerror() };
        let msg = if e.is_null() {
            String::new()
        } else {
            // SAFETY: von dlerror geliefert, nullterminiert.
            unsafe { CStr::from_ptr(e) }.to_string_lossy().into_owned()
        };
        Err(format!("{path} nicht ladbar: {msg}"))
    } else {
        Ok(Handle(h))
    }
}

#[cfg(unix)]
fn sym(h: &Handle, name: &str) -> Result<*const c_void, String> {
    let c = CString::new(name).map_err(|e| e.to_string())?;
    // SAFETY: gültiges Handle aus dlopen.
    let p = unsafe { libc::dlsym(h.0, c.as_ptr()) };
    if p.is_null() {
        Err(format!("Funktion {name} fehlt in libclamav"))
    } else {
        Ok(p as *const c_void)
    }
}

macro_rules! load_fn {
    ($h:expr, $name:literal, $ty:ty) => {{
        let p = sym(&$h, $name)?;
        // SAFETY: Symbol aus libclamav mit der in clamav.h dokumentierten Signatur.
        unsafe { std::mem::transmute::<*const c_void, $ty>(p) }
    }};
}

fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        // SAFETY: libclamav liefert nullterminierte, statische Zeichenketten.
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

impl LibClamav {
    pub fn open(path: &str) -> Result<Self, String> {
        let h = open(path)?;
        Ok(LibClamav {
            init: load_fn!(h, "cl_init", FnInit),
            engine_new: load_fn!(h, "cl_engine_new", FnEngineNew),
            engine_free: load_fn!(h, "cl_engine_free", FnEngineFree),
            set_num: load_fn!(h, "cl_engine_set_num", FnSetNum),
            get_num: load_fn!(h, "cl_engine_get_num", FnGetNum),
            set_str: load_fn!(h, "cl_engine_set_str", FnSetStr),
            load: load_fn!(h, "cl_load", FnLoad),
            compile: load_fn!(h, "cl_engine_compile", FnCompile),
            fmap_open: load_fn!(h, "cl_fmap_open_memory", FnFmapOpen),
            fmap_close: load_fn!(h, "cl_fmap_close", FnFmapClose),
            scanmap: load_fn!(h, "cl_scanmap_callback", FnScanMap),
            retver: load_fn!(h, "cl_retver", FnRetVer),
            retflevel: load_fn!(h, "cl_retflevel", FnRetFlevel),
            strerror: load_fn!(h, "cl_strerror", FnStrError),
            _handle: h,
        })
    }

    pub fn version(&self) -> String {
        // SAFETY: Funktion ohne Argumente.
        cstr(unsafe { (self.retver)() })
    }

    pub fn flevel(&self) -> u32 {
        // SAFETY: Funktion ohne Argumente.
        unsafe { (self.retflevel)() }
    }

    pub fn strerror(&self, code: c_int) -> String {
        // SAFETY: liefert eine statische Zeichenkette.
        cstr(unsafe { (self.strerror)(code) })
    }

    fn check(&self, what: &str, rc: c_int) -> Result<(), String> {
        if rc == CL_SUCCESS {
            Ok(())
        } else {
            Err(format!("{what}: {} ({rc})", self.strerror(rc)))
        }
    }
}

/// Eine geladene und kompilierte Engine.
pub struct Engine<'a> {
    lib: &'a LibClamav,
    ptr: *mut c_void,
}

/// Grenzen und Arbeitsordner der Engine.
pub struct EngineSettings<'s> {
    pub tempdir: &'s str,
    pub max_filesize: u64,
    pub max_scansize: u64,
    pub max_recursion: u32,
    pub max_files: u32,
    pub max_scantime_ms: u32,
    pub certsdir: Option<&'s str>,
}

impl<'a> Engine<'a> {
    /// `cl_init`, `cl_engine_new`, Grenzen setzen, `cl_load`, `cl_engine_compile`.
    /// Rückgabe: Engine und Anzahl geladener Signaturen.
    pub fn load(
        lib: &'a LibClamav,
        database: &str,
        s: &EngineSettings<'_>,
    ) -> Result<(Self, u64), String> {
        // SAFETY: Aufrufe nach clamav.h; alle Zeiger leben bis zum Ende des Aufrufs.
        unsafe {
            lib.check("cl_init", (lib.init)(CL_INIT_DEFAULT))?;
            let ptr = (lib.engine_new)();
            if ptr.is_null() {
                return Err("cl_engine_new: kein Speicher".into());
            }
            let e = Engine { lib, ptr };
            let num = |f: c_int, v: i64, n: &str| lib.check(n, (lib.set_num)(ptr, f, v));
            num(
                CL_ENGINE_MAX_FILESIZE,
                s.max_filesize as i64,
                "MAX_FILESIZE",
            )?;
            num(
                CL_ENGINE_MAX_SCANSIZE,
                s.max_scansize as i64,
                "MAX_SCANSIZE",
            )?;
            num(
                CL_ENGINE_MAX_RECURSION,
                i64::from(s.max_recursion),
                "MAX_RECURSION",
            )?;
            num(CL_ENGINE_MAX_FILES, i64::from(s.max_files), "MAX_FILES")?;
            num(
                CL_ENGINE_MAX_SCANTIME,
                i64::from(s.max_scantime_ms),
                "MAX_SCANTIME",
            )?;
            let tmp = CString::new(s.tempdir).map_err(|e| e.to_string())?;
            lib.check("TMPDIR", (lib.set_str)(ptr, CL_ENGINE_TMPDIR, tmp.as_ptr()))?;
            if let Some(c) = s.certsdir {
                let c = CString::new(c).map_err(|e| e.to_string())?;
                lib.check(
                    "CVDCERTSDIR",
                    (lib.set_str)(ptr, CL_ENGINE_CVDCERTSDIR, c.as_ptr()),
                )?;
            }
            let db = CString::new(database).map_err(|e| e.to_string())?;
            let mut sigs: u32 = 0;
            lib.check(
                "cl_load",
                (lib.load)(db.as_ptr(), ptr, &mut sigs, CL_DB_STDOPT),
            )?;
            lib.check("cl_engine_compile", (lib.compile)(ptr))?;
            Ok((e, u64::from(sigs)))
        }
    }

    pub fn get_num(&self, field: c_int) -> i64 {
        let mut err: c_int = 0;
        // SAFETY: gültige Engine.
        unsafe { (self.lib.get_num)(self.ptr, field, &mut err) }
    }

    /// Prüft genau diese Bytes (Speicherabbild, kein Pfad).
    pub fn scan(&self, data: &[u8]) -> Result<Option<String>, (c_int, String)> {
        // SAFETY: `data` lebt bis nach cl_fmap_close; libclamav liest nur.
        unsafe {
            let map = (self.lib.fmap_open)(data.as_ptr() as *const c_void, data.len());
            if map.is_null() {
                return Err((-1, "cl_fmap_open_memory fehlgeschlagen".into()));
            }
            let mut virname: *const c_char = std::ptr::null();
            let mut scanned: c_ulong = 0;
            let mut opts = ScanOptions::axsafe();
            let rc = (self.lib.scanmap)(
                map,
                std::ptr::null(),
                &mut virname,
                &mut scanned,
                self.ptr,
                &mut opts,
                std::ptr::null_mut(),
            );
            let name = cstr(virname);
            (self.lib.fmap_close)(map);
            match rc {
                CL_SUCCESS => Ok(None),
                CL_VIRUS => Ok(Some(name)),
                other => Err((other, self.lib.strerror(other))),
            }
        }
    }
}

impl Drop for Engine<'_> {
    fn drop(&mut self) {
        // SAFETY: Engine wurde von cl_engine_new geliefert.
        unsafe {
            (self.lib.engine_free)(self.ptr);
        }
    }
}
