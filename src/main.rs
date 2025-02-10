use std::{env, process::{Command, Stdio}, thread, time::Duration, path::{Path, PathBuf}, fs, io::{self, Read}};
use chrono::Local;
use procfs::process::Process;

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

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <command> [args...]", args[0]);
        std::process::exit(1);
    }

    let command = &args[1];
    let command_args = &args[2..];

    let mut child = match Command::new(command)
        .args(command_args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!("Failed to start cmd: {}", e);
            std::process::exit(1);
        }
    };
    
    let child_id = child.id() as u32;
    let heartbeat_handle = thread::spawn(move || {
        while is_process_running(child_id) {
            match Process::new(child_id as i32) {
                Ok(proc) => {
                    if let Ok(stat) = proc.stat() {
                        print_stat_block(stat, child_id);
                        print_threads(child_id);
                        print_child_pids(child_id);
                    } else {
                        eprintln!("Failed to retrieve process stat.");
                    }
                }
                Err(e) => eprintln!("Failed to read process info: {}", e),
            }
            println!("[{}] Heartbeat...", Local::now().format("%H:%M:%S"));
            thread::sleep(Duration::from_secs(2));
        }
    });

    let exit_status = child.wait().expect("Failed to wait on child process");
    let _ = heartbeat_handle.join();

    std::process::exit(exit_status.code().unwrap_or(1));

}
