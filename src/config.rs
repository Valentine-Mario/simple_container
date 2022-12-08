use crate::errors::Errcode;
use crate::hostname::generate_hostname;

use crate::ipc::generate_socket_pair;
use std::ffi::CString;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ContainerOpts {
    // The path of the binary / executable / script to execute inside the container
    pub path: CString,
    pub argv: Vec<CString>,
    pub fd: RawFd,

    //The ID of the user inside the container. An ID of 0 means it’s root (administrator)
    pub uid: u32,
    pub mount_dir: PathBuf,
    pub hostname: String,
}

impl ContainerOpts {
    pub fn new(
        command: String,
        uid: u32,
        mount_dir: PathBuf,
    ) -> Result<(ContainerOpts, (RawFd, RawFd)), Errcode> {
        let argv: Vec<CString> = command
            .split_ascii_whitespace()
            .map(|s| CString::new(s).expect("Cannot read arg"))
            .collect();
        let path = argv[0].clone();
        let sockets = generate_socket_pair()?;

        Ok((
            ContainerOpts {
                path,
                argv,
                fd: sockets.1.clone(),
                uid,
                mount_dir,
                hostname: generate_hostname()?,
            },
            sockets,
        ))
    }
}
