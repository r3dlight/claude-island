// SPDX-FileCopyrightText: 2026 Stephane N
// SPDX-License-Identifier: GPL-3.0-or-later

// PTY overlay: run the sandboxed command inside a pseudo-terminal and sit in
// the middle as a transparent byte pump, so claude-island can draw an inline
// approval prompt over the terminal and read the answer, exactly like Claude
// Code's own permission prompts.
//
// The pump is a single poll() event loop over three fds: the real stdin, the
// PTY master, and a self-pipe woken by the proxy when it needs to ask. While
// a prompt is on screen the master output is buffered (so it does not scribble
// over the question) and flushed once the user answers. The real terminal is
// put in raw mode and restored on every exit path (including panics) by a Drop
// guard.
//
// Requires a real controlling terminal on both stdin and stdout; the caller
// falls back to the asynchronous pending-file flow otherwise.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode, Stdio};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::mpsc::{Receiver, Sender};

/// A pending approval question from the proxy/broker to the pump.
pub struct Request {
    /// The full question shown in the prompt (may contain SGR colors); the
    /// pump appends ` ?  [y/N]`.
    pub question: String,
    /// Short text echoed in the confirmation line.
    pub label: String,
    /// Draw the bar in red (a security alert, e.g. a leak) rather than blue.
    pub alert: bool,
    pub reply: Sender<bool>,
}

/// Handle given to the proxy/broker to ask the pump a question (blocking).
#[derive(Clone)]
pub struct Prompter {
    tx: Sender<Request>,
    wake_w: i32,
}

impl Prompter {
    /// Asks the user (via the pump) whether to allow `domain`. Blocks until
    /// answered; defaults to deny after a timeout so a stuck connection does
    /// not hang forever.
    pub fn ask(&self, domain: &str) -> bool {
        self.ask_question(
            format!("allow network to \x1b[1;97m{domain}\x1b[0m"),
            domain.to_string(),
            false,
        )
    }

    /// Asks whether to allow a detected leak (`what` heading to `host`).
    /// Defaults to deny (block the leak) on timeout.
    pub fn ask_leak(&self, what: &str, host: &str) -> bool {
        self.ask_question(
            format!("allow LEAK of \x1b[1;97m{what}\x1b[0m to \x1b[1;97m{host}\x1b[0m"),
            format!("{what} -> {host}"),
            true,
        )
    }

    fn ask_question(&self, question: String, label: String, alert: bool) -> bool {
        let (rtx, rrx) = std::sync::mpsc::channel();
        if self
            .tx
            .send(Request {
                question,
                label,
                alert,
                reply: rtx,
            })
            .is_err()
        {
            return false;
        }
        // Wake the pump's poll().
        let byte = [1u8];
        unsafe {
            libc::write(self.wake_w, byte.as_ptr() as *const libc::c_void, 1);
        }
        rrx.recv_timeout(std::time::Duration::from_secs(120))
            .unwrap_or(false)
    }
}

/// True if both stdin and stdout are real terminals.
pub fn have_tty() -> bool {
    unsafe { libc::isatty(0) == 1 && libc::isatty(1) == 1 }
}

/// Original terminal attributes, saved for the signal handlers below. Leaked
/// (lives for the process); set once before the handlers are installed.
static SAVED_TERMIOS: AtomicPtr<libc::termios> = AtomicPtr::new(ptr::null_mut());

/// Signal handler: restore the terminal, then exit. Covers the case where the
/// wrapper is killed (SIGTERM/SIGHUP/SIGQUIT) and Drop would not run, which
/// would otherwise leave the terminal stuck in raw mode.
extern "C" fn on_term(sig: libc::c_int) {
    let p = SAVED_TERMIOS.load(Ordering::Acquire);
    if !p.is_null() {
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, p);
        }
    }
    unsafe {
        libc::_exit(128 + sig);
    }
}

/// Restores the terminal's original attributes when dropped (normal exit and
/// panic unwinding); the signal handlers cover kill.
struct RawGuard {
    orig: libc::termios,
}

impl RawGuard {
    fn enter() -> Option<Self> {
        unsafe {
            let mut orig: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(0, &mut orig) != 0 {
                return None;
            }
            // Publish the original attributes and install restore-on-kill
            // handlers before switching to raw mode.
            let leaked = Box::into_raw(Box::new(orig));
            SAVED_TERMIOS.store(leaked, Ordering::Release);
            let handler = on_term as extern "C" fn(libc::c_int) as libc::sighandler_t;
            for sig in [libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
                libc::signal(sig, handler);
            }
            let mut raw = orig;
            libc::cfmakeraw(&mut raw);
            if libc::tcsetattr(0, libc::TCSANOW, &raw) != 0 {
                return None;
            }
            Some(RawGuard { orig })
        }
    }
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &self.orig);
        }
    }
}

static WINCH: AtomicBool = AtomicBool::new(false);

extern "C" fn on_winch(_: libc::c_int) {
    WINCH.store(true, Ordering::SeqCst);
}

/// Copies the real terminal's window size onto the PTY master.
fn copy_winsize(master: i32) {
    unsafe {
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) == 0 {
            libc::ioctl(master, libc::TIOCSWINSZ, &ws);
        }
    }
}

/// Opens a PTY master/slave pair (System V style, no libutil dependency).
fn open_pty() -> std::io::Result<(OwnedFd, OwnedFd)> {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if master < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let master = OwnedFd::from_raw_fd(master);
        if libc::grantpt(master.as_raw_fd()) != 0 || libc::unlockpt(master.as_raw_fd()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut buf = [0i8; 128];
        if libc::ptsname_r(master.as_raw_fd(), buf.as_mut_ptr(), buf.len()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let slave = libc::open(buf.as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
        if slave < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((master, OwnedFd::from_raw_fd(slave)))
    }
}

/// Runs `argv` inside a PTY, pumping I/O and servicing approval requests from
/// `rx` (woken via `wake_r`). `configure` applies env scrubbing to the child.
pub fn run(
    argv: &[String],
    configure: impl FnOnce(&mut Command),
    rx: Receiver<Request>,
    wake_r: i32,
) -> std::io::Result<ExitCode> {
    let (master, slave) = open_pty()?;
    copy_winsize(master.as_raw_fd());

    // Child: slave becomes the controlling terminal, then exec argv.
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    configure(&mut cmd);
    let slave_in = slave.try_clone()?;
    let slave_out = slave.try_clone()?;
    let slave_err = slave.try_clone()?;
    cmd.stdin(Stdio::from(slave_in))
        .stdout(Stdio::from(slave_out))
        .stderr(Stdio::from(slave_err));
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // fd 0 is the slave (dup2'd by Command); make it our ctty.
            if libc::ioctl(0, libc::TIOCSCTTY as libc::c_ulong, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    drop(slave); // only the child keeps the slave open

    unsafe {
        // Cast the fn item to a fn pointer first, then to sighandler_t;
        // a direct item-to-integer cast would produce a bogus value.
        let handler = on_winch as extern "C" fn(libc::c_int) as libc::sighandler_t;
        libc::signal(libc::SIGWINCH, handler);
    }
    let _raw = RawGuard::enter();

    let master_fd = master.as_raw_fd();
    let mut master_file = std::fs::File::from(master);
    let mut stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    let mut queue: VecDeque<Request> = VecDeque::new();
    let mut asking: Option<Request> = None;
    let mut buffered: Vec<u8> = Vec::new();
    let mut stdin_open = true;
    let mut buf = [0u8; 8192];
    let mut reaped: Option<std::process::ExitStatus> = None;

    loop {
        if WINCH.swap(false, Ordering::SeqCst) {
            copy_winsize(master_fd);
        }

        // Start the next prompt if one is queued and none is on screen.
        if asking.is_none() {
            if let Some(req) = queue.pop_front() {
                // Discard input typed before the prompt appeared (e.g. the
                // Enter that submitted the request to the agent, or the
                // keystroke that approved the agent's own tool prompt), so a
                // stale byte cannot auto-answer this prompt.
                unsafe {
                    libc::tcflush(0, libc::TCIFLUSH);
                }
                // A distinct line drawn over the agent's TUI: a colored bar
                // and name (red for a security alert, else light blue), the
                // question, clear [y/N]. \x1b[2K erases the line first so no
                // leftover from the TUI overlaps it.
                let bar = if req.alert {
                    "\x1b[1;91m"
                } else {
                    "\x1b[1;94m"
                };
                let prompt = format!(
                    "\r\n\x1b[2K{bar}\u{258c} claude-island\x1b[0m  {} ?  {bar}[y/N]\x1b[0m ",
                    req.question
                );
                stdout.write_all(prompt.as_bytes()).ok();
                stdout.flush().ok();
                asking = Some(req);
            }
        }

        let mut fds = [
            libc::pollfd {
                fd: master_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: wake_r,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if stdin_open { 0 } else { -1 },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 3, 500) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }

        // Drain approval requests woken via the self-pipe.
        if fds[1].revents & libc::POLLIN != 0 {
            let mut d = [0u8; 64];
            unsafe {
                libc::read(wake_r, d.as_mut_ptr() as *mut libc::c_void, d.len());
            }
            while let Ok(req) = rx.try_recv() {
                queue.push_back(req);
            }
        }

        // PTY master -> screen (or buffer while a prompt is up). POLLERR is
        // included so a hangup that surfaces as an error still triggers a
        // read (which then returns EIO and breaks).
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            match master_file.read(&mut buf) {
                Ok(0) => break,
                Ok(k) => {
                    if asking.is_some() {
                        buffered.extend_from_slice(&buf[..k]);
                    } else {
                        stdout.write_all(&buf[..k]).ok();
                        stdout.flush().ok();
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break, // EIO on child exit
            }
        }

        // Real stdin -> child, or -> answer while a prompt is up.
        if fds[2].revents & libc::POLLIN != 0 {
            match stdin.read(&mut buf) {
                Ok(0) => {
                    stdin_open = false;
                }
                Ok(k) => {
                    if let Some(req) = asking.take() {
                        let answer = buf[..k].iter().any(|&b| b == b'y' || b == b'Y');
                        // Replace the prompt line in place (\r + erase) with a
                        // colored confirmation so the decision stays visible
                        // and is not lost under the agent's next redraw.
                        let echo = if answer {
                            format!(
                                "\r\x1b[2K\x1b[1;92m\u{258c} allowed\x1b[0m {}\r\n",
                                req.label
                            )
                        } else {
                            format!(
                                "\r\x1b[2K\x1b[1;91m\u{258c} denied\x1b[0m {}\r\n",
                                req.label
                            )
                        };
                        stdout.write_all(echo.as_bytes()).ok();
                        req.reply.send(answer).ok();
                        // Flush any output that arrived during the prompt.
                        if !buffered.is_empty() {
                            stdout.write_all(&buffered).ok();
                            buffered.clear();
                        }
                        stdout.flush().ok();
                    } else {
                        master_file.write_all(&buf[..k]).ok();
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => stdin_open = false,
            }
        }

        // Guaranteed exit detection: even if the master never reports EOF
        // (the bug that once left a zombie and a stuck terminal), reap the
        // child directly. Checked every iteration (poll wakes at least every
        // 500 ms), so the loop always ends shortly after the child does.
        if let Ok(Some(st)) = child.try_wait() {
            reaped = Some(st);
            break;
        }
    }

    // Answer any outstanding prompts with deny so proxy threads unblock.
    if let Some(req) = asking.take() {
        req.reply.send(false).ok();
    }
    for req in queue.drain(..) {
        req.reply.send(false).ok();
    }

    let status = match reaped {
        Some(s) => s,
        None => child.wait()?,
    };
    drop(_raw);
    match status.code() {
        Some(c) => Ok(ExitCode::from(u8::try_from(c).unwrap_or(1))),
        None => Ok(ExitCode::from(1)),
    }
}

/// Creates the prompter/pump endpoints: the self-pipe plus the request
/// channel. Returns (prompter for the proxy, receiver + read-fd for the pump).
pub fn channel() -> std::io::Result<(Prompter, Receiver<Request>, i32)> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let (tx, rx) = std::sync::mpsc::channel();
    Ok((Prompter { tx, wake_w: fds[1] }, rx, fds[0]))
}
