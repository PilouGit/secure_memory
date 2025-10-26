// anti_debug.rs
// Anti-debugging utilities (no TPM involved).
// Usage: call `harden_process()` early in your program startup (before secrets loaded).
//
// NOTE: None of these measures are foolproof against a privileged attacker or kernel compromise.
// They raise the bar for casual debugging and many standard attack tools (gdb/ptrace/LD_PRELOAD).

use std::fs;
use std::io::Read;
use std::os::raw::c_int;
use std::env;
use std::time::Duration;
use std::thread;

use libc::{
    prctl, PR_SET_DUMPABLE, PR_SET_PTRACER, PR_SET_NO_NEW_PRIVS, setrlimit, rlimit, RLIMIT_CORE,
};
use libc::{syscall, SYS_ptrace, PTRACE_TRACEME};

/// Try to make process non-dumpable and disallow ptrace attach.
/// Returns Ok(()) on success (best-effort) or Err(String) with message.
pub fn disable_debugger_attach() -> Result<(), String> {
    unsafe {
        // 1) disable core dumps (also prevents some memory leaks via core)
        let rlim = rlimit { rlim_cur: 0, rlim_max: 0 };
        if setrlimit(RLIMIT_CORE, &rlim) != 0 {
            // non-fatal
        }

        // 2) mark non-dumpable
        if prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            // non-fatal
        }

        // 3) disallow new privileges (helps seccomp and prevents some ptrace tricks)
        // ignore errors - best-effort
        let _ = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

        // 4) set PR_SET_PTRACER to -1 to prevent other processes using PR_SET_PTRACER to allow themselves
        // Note: not all kernels support PR_SET_PTRACER; ignore errors
        let _ = prctl(PR_SET_PTRACER, -1, 0, 0, 0);
    }
    Ok(())
}

/// Check /proc/self/status TracerPid.
/// Return true if tracer pid != 0.
pub fn is_debugger_attached() -> bool {
    if let Ok(mut f) = fs::File::open("/proc/self/status") {
        let mut s = String::new();
        if f.read_to_string(&mut s).is_ok() {
            for line in s.lines() {
                if line.starts_with("TracerPid:") {
                    if let Some(pid_str) = line.split(':').nth(1) {
                        if let Ok(pid) = pid_str.trim().parse::<i32>() {
                            return pid != 0;
                        }
                    }
                }
            }
        }
    }
    false
}

/// Very small anti-debug self-test using ptrace(PTRACE_TRACEME).
/// Returns true if it appears that we are being traced/ptraced already.
/// This is a destructive small test: it may leave the process in a state if it fails.
/// We call ptrace(PTRACE_TRACEME) and expect it to succeed (return 0). If it fails with -1,
/// it's likely that someone else is tracing us.
pub fn anti_debug_self_test() -> bool {
    unsafe {
        // syscall(PTRACE_TRACEME, 0, 0, 0)
        let ret = syscall(SYS_ptrace as _, PTRACE_TRACEME as c_int, 0, 0, 0);
        if ret == -1 {
            return true; // already being traced or insufficient privileges
        }
        // detach (best-effort) - many kernels will have detached automatically on exec of child
        // Try to call ptrace(PTRACE_DETACH, 0, 0, 0)
        // NOTE: if PTRACE_TRACEME succeeded, we should actually either raise SIGSTOP then continue;
        // but here we only attempt a minimal best-effort detach to restore state.
        // We ignore errors on detach.
        libc::ptrace(libc::PTRACE_DETACH, 0, 0, 0);
        false
    }
}

/// Check common dangerous environment variables (LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT, LD_DEBUG).
/// If any are set, returns Err with the variable; otherwise Ok(()).
pub fn check_env_safety() -> Result<(), String> {
    const DANGEROUS: [&str; 4] = ["LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG"];
    for var in &DANGEROUS {
        if env::var_os(var).is_some() {
            return Err(format!("Unsafe environment variable detected: {}", var));
        }
    }
    Ok(())
}

#[cfg(feature = "seccomp")]
mod seccomp_support {
    use super::*;
    use seccomp::{SeccompAction, SeccompFilter, SeccompRule};
    use seccomp::syscall::Syscall;

    /// Try to install a minimal seccomp filter that returns EPERM on ptrace syscall.
    /// Requires the `seccomp` crate and Linux with libseccomp.
    pub fn install_ptrace_blocker() -> Result<(), String> {
        // Create filter that by default allows, but blocks ptrace.
        let mut filter = SeccompFilter::new(SeccompAction::Allow)
            .map_err(|e| format!("seccomp filter create failed: {:?}", e))?;

        // Block the ptrace syscall
        let sc = Syscall::from_name("ptrace").map_err(|_| "ptrace syscall not found".to_string())?;
        // Add a rule to cause errno(EPERM) on ptrace invocation
        filter.add_rule(sc, SeccompAction::Errno(libc::EPERM.into()), Vec::<SeccompRule>::new())
            .map_err(|e| format!("seccomp add rule failed: {:?}", e))?;

        filter.load().map_err(|e| format!("seccomp load failed: {:?}", e))?;
        Ok(())
    }
}

/// Install a minimal seccomp filter to block ptrace (best-effort).
/// This function is a no-op unless compiled with `--features seccomp`.
pub fn try_install_seccomp_blocker() -> Result<(), String> {
    #[cfg(feature = "seccomp")]
    {
        return seccomp_support::install_ptrace_blocker();
    }
    #[cfg(not(feature = "seccomp"))]
    {
        return Err("seccomp feature not enabled at compile time".into());
    }
}

/// Top-level convenience function to harden process against trivial debugging.
/// Call this early in startup (before loading secrets). It returns Err if a high-risk
/// condition is detected (e.g. LD_PRELOAD present, or debugger attached).
///
/// Behavior is best-effort: it attempts to set several protections and will return Err
/// for important detections. It does NOT kill the process automatically; caller decides.
pub fn harden_process() -> Result<(), String> {
    // 1) Quick env check
    check_env_safety()?;

    // 2) Disable core dumps / ptrace attach as best-effort
    disable_debugger_attach().ok();

    // 3) Install seccomp blocker (optional)
    let _ = try_install_seccomp_blocker(); // ignore seccomp errors

    // 4) Detect if already traced
    if is_debugger_attached() {
        return Err("Debugger already attached (TracerPid != 0)".into());
    }

    // 5) ptrace self-test
    if anti_debug_self_test() {
        return Err("Ptrace/self-test indicates we are traced".into());
    }

    // small sleep to give attackers little time to attach? not necessary, but you can do quick re-check
    thread::sleep(Duration::from_millis(10));
    if is_debugger_attached() {
        return Err("Debugger attached after self-test".into());
    }

    Ok(())
}
