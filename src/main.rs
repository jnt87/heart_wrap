use std::{env, process::{Command, Stdio, Child}, thread, time::{Duration, SystemTime}, path::{Path, PathBuf}, fs, io::{self, Read}};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use chrono::Local;
use procfs::process::Process;
use log::{info, error};
use signal_hook::consts::signal::*;
use signal_hook::flag;
use std::process::exit;
use libc;

macro_rules! trust_me_bro {
    ($code:expr) => {{
        unsafe { $code }
    }};
}

#[derive(Debug)]
struct ProcTime {
    utime: u64,
    stime: u64,
}

impl ProcTime {
    fn from_stat(statb: &procfs::process::Stat) -> Self {
        Self {
            utime: statb.utime,
            stime: statb.stime,
        }
    }

    fn has_changed(&self, other: &ProcTime) -> bool {
        self.utime != other.utime || self.stime != other.stime
    }

    fn update_time(&mut self, other: &ProcTime) {
        self.utime = other.utime;
        self.stime = other.stime;
    }

    fn uninitialized() -> Self {
        Self {
            utime: 0,
            stime: 0,
        }
    }
}

fn time_check(mut old_time: ProcTime, statb: procfs::process::Stat) -> bool {
    let time = ProcTime::from_stat(&statb);
    let changed = old_time.has_changed(&time);
    old_time.update_time(&time);
    return changed;

}

fn is_process_running(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

fn get_threads(pid: u32) -> Vec<u32> {
    let path = format!("/proc/{}/task/", pid);
    if let Ok(entries) = fs::read_dir(path) {
        return entries
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
            .collect();
    }
    Vec::new()
}

fn print_threads(pid: u32) {
    let tids = get_threads(pid);
    println!("Threads (TIDs) of process {}: {:?}", pid, tids);
}

fn send_pulse() -> std::io::Result<()> {
    let now = SystemTime::now();
    fs::write("/tmp/heartbeat.txt", format!("{:?}", now))?;
    log::debug!("Heartbeat updated: {:?}", now);
    Ok(())
}

fn get_child_pids(parent_pid: u32) -> io::Result<Vec<u32>> {
    let mut child_pids = Vec::new();
    
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let path = entry.path();
        
        if !path.is_dir() {
            continue;
        }

        if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
            let stat_path = format!("/proc/{}/stat", filename);
            let path_copy = String::from(&stat_path);
            let path = PathBuf::from(path_copy);
            if !path.is_file() {
                continue;
            }
            if let Ok(mut file) = fs::File::open(&stat_path) {
                let mut contents = String::new();
                file.read_to_string(&mut contents)?;
                let fields: Vec<&str> = contents.split_whitespace().collect();
                if let Some(ppid) = fields.get(3).and_then(|s| s.parse::<u32>().ok()) {
                    if ppid == parent_pid {
                        if let Ok(pid) = filename.parse::<u32>() {
                            child_pids.push(pid);
                        }
                    }
                }
            }
        }
    }
    Ok(child_pids)
}

fn print_child_pids(parent_pid: u32) {
    match get_child_pids(parent_pid) {
        Ok(children) => {
            if children.is_empty() {
                println!("No child processes found for PID {}", parent_pid);
            } else {
                println!("Child PIDs of {}: {:?}", parent_pid, children);
            }
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn print_stat_block(statb: procfs::process::Stat, pid: u32) {
    println!("Process ID: {}", pid);
    println!("Command: {:?}", statb.comm);
    println!("State: {:?}", statb.state);
    println!("Parent PID: {}", statb.ppid);
    println!("CPU Time: user={}s, system={}s", statb.utime, statb.stime);
    println!("Memory Usage: {} bytes", statb.vsize);
    println!("Resident Set Size (RSS): {} pages", statb.rss);
}


fn is_good_state(statb: procfs::process::Stat) -> bool {
    return match statb.state {
        'R' | 'S' => true,
        'D' => false,
        'Z' | 'T' => false,
        _ => false,
    };
}


fn spawn_process(command: &str, args: &[String]) -> Result<Child, std::io::Error> {
    info!("Spawning process: {} {:?}", command, args);

    let child = Command::new(command)
        .args(args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn();
    match child {
        Ok(child) => {
            info!("Successfully spawned process with PID: {}", child.id());
            Ok(child)
        }
        Err(e) => {
            error!("Failed to start process '{}': {}", command, e);
            Err(e)
        }
    }
}

fn monitor_process(pid: u32, running: Arc<AtomicBool>) {
    info!("Starting process monitoring for PID: {}", pid);
    while running.load(Ordering::SeqCst) && is_process_running(pid) {
        let mut time_tracker = ProcTime::uninitialized();
        match Process::new(pid as i32) {
            Ok(proc) => {
                match proc.stat() {
                    Ok(stat) => {
                        let healthy_state = is_good_state(stat.clone());
                        let new_time = ProcTime::from_stat(&stat);
                        let time_changed = time_tracker.has_changed(&new_time);
                        time_tracker.update_time(&new_time);
                        if healthy_state && time_changed {
                            println!("In the Clurb, we all fam");
                            send_pulse();
                        } else {
                            println!("What are you racist?");
                        }
                        print_stat_block(stat, pid);
                        print_threads(pid);
                        print_child_pids(pid);
                    }
                    Err(e) => error!("Failed to retrieve process stat for PID {}: {}", pid, e),
                }
            }
            Err(e) => error!("Failed to read process info for PID {}: {}", pid, e),
        }

        info!("[{}] Heartbeat... Monitoring PID: {}", Local::now().format("%H:%M:%S"), pid);
        thread::sleep(Duration::from_secs(2));
    }
    info!("Process {} has exited or monitoring was stopped.", pid);
}


fn handle_exit_status(mut child: Child) -> i32 {
    match child.wait() {
        Ok(status) => {
            if let Some(code) = status.code() {
                info!("Process {} exited with statues code {}", child.id(), code);
                code
            } else {
                error!("Process {} terminated by signal", child.id());
                1 // Return non-zero if terminated by a signal
            }
        }
        Err(e) => {
            error!("Failed to retrieve exit status for process {}: {}", child.id(), e);
            1 // Return non-zero on error
        }
    }
}

fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <command> [args...]", args[0]);
        std::process::exit(1);
    }

    let command = &args[1];
    let command_args = &args[2..];

    let child = match spawn_process(command, command_args) {
        Ok(child) => child,
        Err(_) => {
            eprintln!("Error: Failed to spawn process.");
            std::process::exit(1);
        }
    };
    
    let child_id = child.id() as u32;
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = Arc::clone(&running);

    let signals = [SIGINT, SIGTERM, SIGHUP];
    for &sig in &signals {
        let child_pid = child.id() as i32;
        flag::register(sig, Arc::clone(&running)).expect("Failed to register signal handler");
        trust_me_bro!( libc::signal(sig, libc::SIG_DFL) );
    }

    let monitor_handle = thread::spawn(move || {
        monitor_process(child_id, running_clone);
    });

    let exit_code = handle_exit_status(child);

    running.store(false, Ordering::SeqCst);
    let _ = monitor_handle.join();

    exit(exit_code);

}
