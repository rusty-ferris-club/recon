use chrono::{DateTime, Local, Utc};
use std::{fs::Metadata, io, time::SystemTime};

#[cfg(unix)]
#[must_use]
pub fn user_and_group(
    meta: &Metadata,
) -> (Option<String>, Option<String>, Option<u32>, Option<u32>) {
    use std::os::unix::fs::MetadataExt;
    use users::{get_group_by_gid, get_user_by_uid};

    let uid = meta.uid();
    let user = get_user_by_uid(uid).map(|res| res.name().to_string_lossy().to_string());

    let gid = meta.gid();
    let group = get_group_by_gid(gid).map(|res| res.name().to_string_lossy().to_string());
    (user, group, Some(uid), Some(gid))
}

#[cfg(not(unix))]
#[must_use]
pub fn user_and_group(m: &Metadata) -> (Option<String>, Option<String>, Option<u32>, Option<u32>) {
    (None, None, None, None)
}

pub fn ftime(t: io::Result<SystemTime>) -> Option<DateTime<Utc>> {
    t.ok()
        .map(DateTime::<Local>::from)
        .map(DateTime::<Utc>::from)
}

#[cfg(unix)]
#[must_use]
pub fn mode(m: &Metadata) -> u32 {
    use std::os::unix::prelude::MetadataExt;
    m.mode()
}

#[cfg(not(unix))]
#[must_use]
pub fn mode(_m: &Metadata) -> u32 {
    0
}
