#![feature(thread_id_value)]

use std::convert::TryInto;
use std::ffi::CStr;
use std::ffi::CString;
use std::io::Write;
use std::os::raw::{c_long, c_int};
use std::iter::FromIterator;

use log::debug;
use log::error;
use log::info;
use log::warn;

use std::collections::HashMap;

fn libc_error<I: Copy + TryInto<i32>>(context: &str, error_code: I) -> I
    where <I as TryInto<i32>>::Error: std::fmt::Debug
{
    let error_code_i32 = error_code.try_into().unwrap();
    if error_code_i32 < 0 {
        panic!("{} failed, code {}", context, error_code_i32);
    }
    error_code
}

fn libc_strerror<I: Copy + TryInto<i32>, F: Fn() -> I>(context: &str, f: F) -> I
    where <I as TryInto<i32>>::Error: std::fmt::Debug
{
    let errno_location = unsafe { libc::__errno_location() };
    if errno_location == std::ptr::null_mut() {
        panic!("errno location NULL");
    }
    unsafe { *errno_location = 0; }
    let error_code = f();
    if unsafe { *errno_location } != 0 {
        let error_message = unsafe {
            let strerror = libc::strerror(*errno_location);
            if strerror == std::ptr::null_mut() {
                panic!("strerror NULL");
            }
            CString::from(CStr::from_ptr(strerror))
        };
        panic!("{} failed, strerror {:?}", context, error_message.to_str());
    } else {
        error_code
    }
}

fn trace_fork_execve(command: &str, args: Vec<&str>) {
    info!("Trace/forking command={:?} args={:?}", command, args);
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // TRACEE
        info!("Tracee forked");
        libc_error("traceme", unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) });
        libc_error("initial SIGSTOP", unsafe { libc::raise(libc::SIGSTOP) });
        info!("Tracee about to exec");
        let command_cstr = CString::new(command).unwrap();
        let mut args_cstrs = Vec::with_capacity(args.len());
        for arg in &args {
            args_cstrs.push(CString::new(*arg).unwrap());
        }

        let mut argv = Vec::with_capacity(args.len() + 2);
        argv.push(command_cstr.as_ptr());
        for arg_cstr in &args_cstrs {
            argv.push(arg_cstr.as_ptr());
        }
        argv.push(std::ptr::null());
        libc_strerror("tracee execvp", || unsafe { libc::execvp(command_cstr.as_ptr(), argv.as_ptr()) });
    } else {
        info!("Tracer forked tracee");
        let mut tracee_status = 0;
        libc_error("initial waitpid", unsafe { libc::waitpid(pid, &mut tracee_status, 0) });
        if !libc::WIFSTOPPED(tracee_status) || libc::WSTOPSIG(tracee_status) != libc::SIGSTOP {
            panic!("Tracee didn't SIGSTOP as expected");
        }

        libc_error("ptrace_setoptions", unsafe {
            libc::ptrace(
                libc::PTRACE_SETOPTIONS, pid, 0,
                libc::PTRACE_O_TRACECLONE
                    | libc::PTRACE_O_TRACEFORK
                    | libc::PTRACE_O_TRACEVFORK
                    | libc::PTRACE_O_TRACESYSGOOD
            )
        });

        libc_error("continuting ptrace", unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) });

        let initial_tracer_state = TracerState {
            child_process_states: HashMap::from_iter(vec![(pid, ProcessState::default())])
        };
        event_loop(initial_tracer_state);
    }
}

#[derive(Debug)]
struct EnteredSyscall {
    orig_rax: u64,
}


#[derive(Debug, Default)]
struct ProcessState {
    in_syscall: Option<EnteredSyscall>,
}

#[derive(Debug)]
struct TracerState {
    child_process_states: HashMap<libc::pid_t, ProcessState>
}

fn event_loop(mut tracer_state: TracerState) {
    info!("Entering tracer event loop");
    loop {
        debug!("Tracer state {:#?}", tracer_state);
        if tracer_state.child_process_states.is_empty() {
            break;
        }

        let mut tracee_status = 0;
        let pid = libc_error("event loop wait", unsafe { libc::waitpid(-1, &mut tracee_status, 0) });
        if libc::WIFEXITED(tracee_status) {
            let exit_code = libc::WEXITSTATUS(tracee_status);
            debug!("Tracee {} exited with status {}", pid, exit_code);
            if let Some(child_state) = tracer_state.child_process_states.remove(&pid) {
                debug!("Tracee {} state {:#?} removed ", pid, child_state);
            } else {
                panic!("PID {} not found in child_process_states", pid);
            }
        } else if libc::WIFSIGNALED(tracee_status) {
            debug!("Tracee {} signalled with {}", pid, libc::WTERMSIG(tracee_status));
        } else if libc::WIFSTOPPED(tracee_status) {
            let signal = libc::WSTOPSIG(tracee_status);
            let signal_cstr = unsafe { CString::from(CStr::from_ptr(libc::strsignal(signal))) };

            const SIGTRAP_SYSCALL: c_int = libc::SIGTRAP | 0x80;

            match signal {
                libc::SIGTRAP => {
                    let ptrace_event = tracee_status >> 16;
                    match ptrace_event {
                        libc::PTRACE_EVENT_CLONE | libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK => {
                            let event_str = match ptrace_event {
                                libc::PTRACE_EVENT_CLONE => "CLONE",
                                libc::PTRACE_EVENT_FORK => "FORK",
                                libc::PTRACE_EVENT_VFORK => "VFORK",
                                _ => "???",
                            };

                            debug!("Ptrace event {}!", event_str);
                            let mut child_pid = 0;
                            libc_error("event get_event_msg", unsafe { libc::ptrace(libc::PTRACE_GETEVENTMSG, pid, 0, &mut child_pid)});
                            debug!("Event child pid {}", child_pid);
                            tracer_state.child_process_states.entry(child_pid).or_insert_with(ProcessState::default);
                        }
                        _ => {
                            warn!("Unknown ptrace event {}", ptrace_event);
                        }
                    }
                }
                SIGTRAP_SYSCALL => {
                    let process_state = tracer_state.child_process_states.get_mut(&pid).unwrap();
                    match &process_state.in_syscall {
                        None => {
                            let orig_rax_value = libc_strerror("ORIG_RAX poke", || unsafe { libc::ptrace(libc::PTRACE_PEEKUSER, pid, 8 * libc::ORIG_RAX, 0) });
                            info!("Entering syscall {}", orig_rax_value);
                            process_state.in_syscall = Some(EnteredSyscall {
                                orig_rax: orig_rax_value as u64
                            });
                        }
                        Some(entered_syscall) => {
                            let rax_value = libc_strerror("RAX poke", || unsafe { libc::ptrace(libc::PTRACE_PEEKUSER, pid, 8 * libc::RAX, 0) });
                            info!("Leaving syscall {}, return value {}", entered_syscall.orig_rax, rax_value);
                            process_state.in_syscall = None;
                        }
                    }
                }
                _ => {
                    debug!("Tracee {} stopped with {:?}", pid, signal_cstr);
                }
            }

            libc_error("event_loop ptrace_cont", unsafe { libc::ptrace(libc::PTRACE_SYSCALL, pid, 0, 0) });
            continue;
        } else {
            debug!("Tracee {} returned with unhandled status {}", pid, tracee_status);
            break;
        }
    }
}

fn main() {
    init_logging();
    let matches = clap::App::new("optimistic universal cache")
        .version("0.1.0")
        .about("https://github.com/exfalso/opticache")
        .setting(clap::AppSettings::ArgRequiredElseHelp)
        .subcommands(vec![
            clap::SubCommand::with_name("run")
                .arg(clap::Arg::with_name("COMMAND")
                    .required(true))
                .arg(clap::Arg::with_name("ARGS")
                    .multiple(true))
        ])
        .get_matches();
    match matches.subcommand() {
        ("run", Some(matches)) => {
            let command = matches.value_of("COMMAND").ok_or("COMMAND required").unwrap();
            let args = matches.values_of("ARGS").map(|values| values.collect()).unwrap_or(vec![]);
            trace_fork_execve(command, args);
        }
        _ => {
            panic!("No command specified");
        }
    }
}

pub fn init_logging() {
    env_logger::Builder::from_default_env()
        .target(env_logger::Target::Stderr)
        .format(|buf, record| {
            writeln!(
                buf,
                "{:30} {:5} [p#{}][t#{:02x}] {}",
                format!("{:?}", chrono::Utc::now()),
                record.level(),
                std::process::id(),
                std::thread::current().id().as_u64(),
                record.args()
            )
        })
        .init();
}
