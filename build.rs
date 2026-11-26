use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/trace/linux.bpf.c");
    println!("cargo:rerun-if-changed=src/net/macos_socket.c");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("src/net/macos_socket.c")
            .compile("tcptui_socket");
    }
    println!("cargo:rerun-if-env-changed=BPF_CLANG");
    println!("cargo:rerun-if-env-changed=BPF_INCLUDE_DIR");
    if env::var_os("CARGO_FEATURE_LINUX_TRACE").is_none()
        || env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
    {
        return;
    }
    let target = match env::var("CARGO_CFG_TARGET_ENDIAN").as_deref() {
        Ok("big") => "bpfeb",
        _ => "bpfel",
    };
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR")).join("tcptui.bpf.o");
    let compiler = env::var_os("BPF_CLANG").unwrap_or_else(|| "clang".into());
    let mut command = Command::new(compiler);
    command.args(["-target", target, "-O2", "-g", "-Wall", "-Werror"]);
    if let Some(path) = env::var_os("BPF_INCLUDE_DIR") {
        command.arg("-I").arg(path);
    }
    let status = command
        .args(["-c", "src/trace/linux.bpf.c", "-o"])
        .arg(output)
        .status()
        .expect("linux-trace requires Clang with the BPF backend and libbpf headers");
    assert!(
        status.success(),
        "failed to compile the Linux TCP trace program"
    );
}
