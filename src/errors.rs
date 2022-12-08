use std::fmt;
use std::process::exit;

#[derive(Debug)]
// Contains all possible errors in our tool
pub enum Errcode {
    ArgumentInvalid(&'static str),
    ContainerError(u8),
    ChildProcessError(u8),
    NotSupported(u8),
    SocketError(u8),
    HostnameError(u8),
    RngError,
    MountsError(u8),
    NamespacesError(u8),
    CapabilitiesError(u8),
    SyscallsError(u8),
    ResourcesError(u8),
}

#[allow(unreachable_patterns)]
// trait Display, allows Errcode enum to be displayed by:
//      println!("{}", error);
impl fmt::Display for Errcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Define what behaviour for each variant of the enum
        match &self {
            Errcode::ArgumentInvalid(ele) => write!(f, "ArgumentInvalid: {}", ele),
            _ => write!(f, "{:?}", self), // For any variant not previously covered
        }
    }
}

impl Errcode {
    // Translate an Errcode::X into a number to return (the Unix way)
    pub fn get_retcode(&self) -> i32 {
        1 // Everything != 0 will be treated as an error
    }
}

pub fn exit_with_retcode(res: Result<(), Errcode>) {
    match res {
        Ok(_) => {
            log::debug!("Exit without any error, returning 0");
            exit(0);
        }
        Err(e) => {
            let retcode = e.get_retcode();
            log::error!("Error on exit:\n\t{}\n\tReturning {}", e, retcode);
            exit(retcode);
        }
    }
}
