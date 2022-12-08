use nix::sched::{unshare, CloneFlags};
use nix::unistd::Pid;
use nix::unistd::{setgroups, setresgid, setresuid};
use nix::unistd::{Gid, Uid};
use std::fs::File;
use std::io::Write;
use std::os::unix::io::RawFd;

use crate::errors::Errcode;
use crate::ipc::{recv_boolean, send_boolean};

// The general user namespace configuration is the following:

// Child process tries to unshare its user resources
// If it suceeds, then user namespace isolation is supported
// If it fails, then user namespace isolation isn’t supported
// Child process tells parent process if it supports user namespace isolation
// If it supported user namespace isolation, parent process maps UID / GID of the user namespace
// Parent process tells child process to continue
// Then child process switches his UID / GID to the one provided by the user as a parameter.

pub fn userns(fd: RawFd, uid: u32) -> Result<(), Errcode> {
    log::debug!("Setting up user namespace with UID {}", uid);

    let has_userns = match unshare(CloneFlags::CLONE_NEWUSER) {
        Ok(_) => true,
        Err(_) => false,
    };
    send_boolean(fd, has_userns)?;

    if recv_boolean(fd)? {
        return Err(Errcode::NamespacesError(0));
    }

    if has_userns {
        log::info!("User namespaces set up");
    } else {
        log::info!("User namespaces not supported, continuing...");
    }

    log::debug!("Switching to uid {} / gid {}...", uid, uid);
    let gid = Gid::from_raw(uid);
    let uid = Uid::from_raw(uid);

    if let Err(_) = setgroups(&[gid]) {
        return Err(Errcode::NamespacesError(1));
    }

    //We use the setresuid and setresgid to set the UID and GID (respectively) of the process.
    // This will set the real user ID
    if let Err(_) = setresgid(gid, gid, gid) {
        return Err(Errcode::NamespacesError(2));
    }

    if let Err(_) = setresuid(uid, uid, uid) {
        return Err(Errcode::NamespacesError(3));
    }
    Ok(())
}

const USERNS_OFFSET: u64 = 10000;
const USERNS_COUNT: u64 = 2000;

// The file /proc/<pid>/uidmap is used by the Linux kernel to map the user IDs inside and outside the namespace of a process.
// The format is the following:

// `ID-inside-ns ID-outside-ns length`
// So if the file /proc/<pid>/uidmap contains 0 1000 5, a user having the UID 0
// inside the container will have a UID 1000 outside the container.
// In the same way, a UID of 1 inside maps to a UID of 1001 outside, but a UID of 6
// inside doesn’t map to 1006 outside as only 5 UID are allowed to be mapped.
pub fn handle_child_uid_map(pid: Pid, fd: RawFd) -> Result<(), Errcode> {
    if recv_boolean(fd)? {
        if let Ok(mut uid_map) = File::create(format!("/proc/{}/{}", pid.as_raw(), "uid_map")) {
            if let Err(_) =
                uid_map.write_all(format!("0 {} {}", USERNS_OFFSET, USERNS_COUNT).as_bytes())
            {
                return Err(Errcode::NamespacesError(4));
            }
        } else {
            return Err(Errcode::NamespacesError(5));
        }

        if let Ok(mut gid_map) = File::create(format!("/proc/{}/{}", pid.as_raw(), "gid_map")) {
            if let Err(_) =
                gid_map.write_all(format!("0 {} {}", USERNS_OFFSET, USERNS_COUNT).as_bytes())
            {
                return Err(Errcode::NamespacesError(6));
            }
        } else {
            return Err(Errcode::NamespacesError(7));
        }
    } else {
        log::info!("No user namespace set up from child process");
    }

    log::debug!("Child UID/GID map done, sending signal to child to continue...");
    send_boolean(fd, false)
}
