//! Plattformspezifische Prozesskontrolle.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(crate) use unix::Contained;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::Contained;
#[cfg(windows)]
pub use windows::{
    appcontainer_folder, appcontainer_grant, restricted_grant_execute, restricted_grant_read,
    restricted_work_dir,
};

#[cfg(not(any(unix, windows)))]
compile_error!("axsafe-proc unterstützt nur Unix und Windows");
