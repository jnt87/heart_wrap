use std::{env, process::{Command, Stdio, Child}, thread, time::Duration, path::{Path, PathBuf}, fs, io::{self, Read}};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use chrono::Local;
use procfs::process::Process;
use log::{info, error};

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

//fn spawn_process(command: &str, args: &[String]) -> Result<Child, std::io::Error>
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

//fn monitor_process(pid: u32)
fn monitor_process(pid: u32, running: Arc<AtomicBool>) {
    info!("Starting process monitoring for PID: {}", pid);

    while running.load(Ordering::SeqCst) && is_process_running(pid) {
        match Process::new(pid as i32) {
            Ok(proc) => {
                match proc.stat() {
                    Ok(stat) => {
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

//fn handle_exit_status(child: Child) -> i32
fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <command> [args...]", args[0]);
        std::process::exit(1);
    }

    let command = &args[1];
    let command_args = &args[2..];

    let mut child = match spawn_process(command, command_args) {
        Ok(child) => child,
        Err(_) => {
            eprintln!("Error: Failed to spawn process.");
            std::process::exit(1);
        }
    };
    
    let child_id = child.id() as u32;
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = Arc::clone(&running);

    let monitor_handle = thread::spawn(move || {
        monitor_process(child_id, running_clone);
    });

    let exit_status = child.wait().expect("Failed to wait on child process");

    running.store(false, Ordering::SeqCst);
    let _ = monitor_handle.join();

    std::process::exit(exit_status.code().unwrap_or(1));

}
