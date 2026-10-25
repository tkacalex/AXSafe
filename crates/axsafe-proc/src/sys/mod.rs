//! Plattformspezifische Prozesskontrolle.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::children_peak_rss;
#[cfg(unix)]
pub(crate) use unix::Contained;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::Contained;
#[cfg(windows)]
pub use windows::{
    appcontainer_folder, appcontainer_grant, create_probe_file, mitigation_summary,
    restricted_grant_execute, restricted_grant_read, restricted_work_dir,
    running_as_service_account, ProbeOwner,
};

#[cfg(not(any(unix, windows)))]
compile_error!("axsafe-proc unterstützt nur Unix und Windows");
