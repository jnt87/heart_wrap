use std::{env, process::{Command, Stdio}, thread, time::Duration, path::Path};
use chrono::Local;
use procfs::process::Process;

fn is_process_running(pid: i32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
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
    
    let child_id = child.id() as i32;
    let heartbeat_handle = thread::spawn(move || {
        while is_process_running(child_id) {
            match Process::new(child_id) {
                Ok(proc) => {
                    if let Ok(stat) = proc.stat() {
                        println!("Process ID: {}", proc.pid);
                        println!("Command: {:?}", stat.comm);
                        println!("State: {:?}", stat.state);
                        println!("Parent PID: {}", stat.ppid);
                        println!("CPU Time: user={}s, system={}s", stat.utime, stat.stime);
                        println!("Memory Usage: {} bytes", stat.vsize);
                        println!("Resident Set Size (RSS): {} pages", stat.rss);
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
