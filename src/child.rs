use crate::capabilities::setcapabilities;
use crate::config::ContainerOpts;
use crate::errors::Errcode;
use crate::hostname::set_container_hostname;
use crate::mounts::setmountpoint;
use crate::namespaces::userns;
use crate::syscalls::setsyscalls;

use nix::sched::clone;
use nix::sched::CloneFlags;
use nix::sys::signal::Signal;
use nix::unistd::{close, Pid};

//stack size of 1KiB
const STACK_SIZE: usize = 1024 * 1024;

fn child(config: ContainerOpts) -> isize {
    match setup_container_configurations(&config) {
        Ok(_) => log::info!("Container set up successfully"),
        Err(e) => {
            log::error!("Error while configuring container: {:?}", e);
            return -1;
        }
    }

    if let Err(_) = close(config.fd) {
        log::error!("Error while closing socket ...");
        return -1;
    }
    log::info!(
        "Starting container with command {} and args {:?}",
        config.path.to_str().unwrap(),
        config.argv
    );
    0
}

pub fn generate_child_process(config: ContainerOpts) -> Result<Pid, Errcode> {
    //hold the stack of the child process
    let mut tmp_stack: [u8; STACK_SIZE] = [0; STACK_SIZE];
    let mut flags = CloneFlags::empty();
    //insert name spece into the clone flag
    //will start the cloned child in a new mount namespace
    flags.insert(CloneFlags::CLONE_NEWNS);
    //will start the cloned child in a new cgroup namespace
    flags.insert(CloneFlags::CLONE_NEWCGROUP);
    //will start the cloned child in a new pid namespace
    flags.insert(CloneFlags::CLONE_NEWPID);
    //will start the cloned child in a new ipc namespace
    flags.insert(CloneFlags::CLONE_NEWIPC);
    //will start the cloned child in a new network namespace
    flags.insert(CloneFlags::CLONE_NEWNET);
    //will start the cloned child in a new uts namespace
    //it will allow the contained process to set its own hostname and NIS domain name in the namespace
    flags.insert(CloneFlags::CLONE_NEWUTS);

    //`clone` create a child process
    match clone(
        Box::new(|| child(config.clone())),
        &mut tmp_stack,
        flags,
        Some(Signal::SIGCHLD as i32),
    ) {
        Ok(pid) => Ok(pid),
        Err(_) => Err(Errcode::ChildProcessError(0)),
    }
}

fn setup_container_configurations(config: &ContainerOpts) -> Result<(), Errcode> {
    set_container_hostname(&config.hostname)?;
    setmountpoint(&config.mount_dir)?;
    userns(config.fd, config.uid)?;
    setcapabilities()?;
    setsyscalls()?;
    Ok(())
}

//cgroupfs-mount
//sudo ./target/debug/crabcan  --mount ./ --uid 0 --command bash --debug
