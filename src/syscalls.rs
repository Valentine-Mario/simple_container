// seccomp (short for secure computing mode) is a computer security facility in the Linux kernel.
// seccomp allows a process to make a one-way transition into a “secure” state where it cannot make
// any system calls except exit(), sigreturn(), read() and write() to already-open file descriptors.
// Should it attempt any other system calls, the kernel will terminate the process with SIGKILL or SIGSYS.
// In this sense, it does not virtualize the system’s resources but isolates the process from them entirely.
use syscallz::{Context, Action, Syscall, Comparator, Cmp};
use crate::errors::Errcode;
use libc::TIOCSTI;
use nix::sys::stat::Mode;
use nix::sched::CloneFlags;


const EPERM: u16=1;


pub fn setsyscalls()->Result<(), Errcode>{
    let s_isuid: u64 = Mode::S_ISUID.bits().into();
    let s_isgid: u64 = Mode::S_ISGID.bits().into();
    let clone_new_user: u64 = CloneFlags::CLONE_NEWUSER.bits() as u64;

    // Unconditionnal syscall deny
    let syscalls_refused = [
        Syscall::keyctl,
        Syscall::add_key,
        Syscall::request_key,
        Syscall::mbind,
        Syscall::migrate_pages,
        Syscall::move_pages,
        Syscall::set_mempolicy,
        Syscall::userfaultfd,
        Syscall::perf_event_open,
    ];

    // Conditionnal syscall deny
    let syscalls_refuse_ifcomp = [
        (Syscall::chmod, 1, s_isuid),
        (Syscall::chmod, 1, s_isgid),

        (Syscall::fchmod, 1, s_isuid),
        (Syscall::fchmod, 1, s_isgid),

        (Syscall::fchmodat, 2, s_isuid),
        (Syscall::fchmodat, 2, s_isgid),

        (Syscall::unshare, 0, clone_new_user),
        (Syscall::clone, 0, clone_new_user),

        (Syscall::ioctl, 1, TIOCSTI),
    ];

    // Initialize seccomp profile with all syscalls allowed by default
    if let Ok(mut ctx) = Context::init_with_action(Action::Allow) {

        // Configure profile here
        for sc in syscalls_refused.iter() {
            refuse_syscall(&mut ctx, sc)?;
        }

        for (sc, ind, biteq) in syscalls_refuse_ifcomp.iter(){
            refuse_if_comp(&mut ctx, *ind, sc, *biteq)?;
        }

        if let Err(_) = ctx.load(){
            return Err(Errcode::SyscallsError(0));
        }

        Ok(())
    } else {
        Err(Errcode::SyscallsError(1))
    }
}

//this would refuse the call to certain sys calls
fn refuse_syscall(ctx: &mut Context, sc: &Syscall)-> Result<(), Errcode>{
    match ctx.set_action_for_syscall(Action::Errno(EPERM), *sc){
        Ok(_) => Ok(()),
        Err(_) => Err(Errcode::SyscallsError(2)),
    }
}

//Syscalls can be restricted when a particular condition is met
//What this Comparator will do is to take the argument number ind passed to the syscall, and compare it using the mask biteq to the value biteq.
//This is equivalent to testing if the bit biteq is set.
fn refuse_if_comp(ctx: &mut Context, ind: u32, sc: &Syscall, biteq: u64)-> Result<(), Errcode>{
    match ctx.set_rule_for_syscall(Action::Errno(EPERM), *sc,
            &[Comparator::new(ind, Cmp::MaskedEq, biteq, Some(biteq))]){
        Ok(_) => Ok(()),
        Err(_) => Err(Errcode::SyscallsError(3)),
    }
}