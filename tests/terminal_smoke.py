"""Exercise interactive startup and restoration through a real Unix PTY."""

import fcntl
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time


def supervise(status_fd, release_fd, command):
    result = subprocess.run(command, check=False)
    os.write(status_fd, f"{result.returncode}\n".encode())
    # On macOS the controlling PTY is revoked when its session leader exits.
    # Hold the session open until the parent has inspected the restored state.
    os.read(release_fd, 1)
    return result.returncode


def run(binary, options):
    with tempfile.TemporaryDirectory(prefix="tcptui-pty-") as config:
        master, slave = pty.openpty()
        status_read, status_write = os.pipe()
        release_read, release_write = os.pipe()
        before = termios.tcgetattr(slave)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 120, 0, 0))

        def attach_terminal():
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

        proc = subprocess.Popen(
            [
                sys.executable, __file__, "--supervise", str(status_write), str(release_read),
                binary, "--no-resolve", *options,
            ],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=dict(os.environ, TERM="xterm-256color", XDG_CONFIG_HOME=config, HOME=config),
            preexec_fn=attach_terminal,
            pass_fds=(status_write, release_read),
        )
        os.close(status_write)
        os.close(release_read)
        output = bytearray()
        sent_quit = False
        status = None
        deadline = time.monotonic() + 15
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master, status_read], [], [], 0.1)
                if master in ready:
                    output.extend(os.read(master, 65536))
                if not sent_quit and b"endpoint(s)" in output:
                    os.write(master, b"q")
                    sent_quit = True
                if status_read in ready:
                    status = os.read(status_read, 32)
                    break
                if proc.poll() is not None:
                    break
            while select.select([master], [], [], 0)[0]:
                chunk = os.read(master, 65536)
                if not chunk:
                    break
                output.extend(chunk)
            assert sent_quit, f"interactive table never rendered: {output[-2000:]!r}"
            assert status == b"0\n", f"failed to exit ({status!r}): {output[-2000:]!r}"
            assert b"\x1b[?1049l" in output, "alternate screen was not restored"
            assert termios.tcgetattr(slave) == before, "PTY termios state changed"
            os.write(release_write, b"1")
            assert proc.wait(timeout=2) == 0
            print("Interactive table rendered, exited and restored the terminal.")
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
            for descriptor in (master, slave, status_read, release_write):
                os.close(descriptor)


if __name__ == "__main__":
    if sys.argv[1] == "--supervise":
        sys.exit(supervise(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4:]))
    run(sys.argv[1], sys.argv[2:])
