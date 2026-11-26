"""Exercise interactive startup and restoration through a real Unix PTY."""

import fcntl
import os
import pty
import select
import struct
import subprocess
import sys
import tempfile
import termios
import time


def run(binary, options):
    with tempfile.TemporaryDirectory(prefix="tcptui-pty-") as config:
        master, slave = pty.openpty()
        before = termios.tcgetattr(slave)
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 120, 0, 0))

        def attach_terminal():
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

        proc = subprocess.Popen(
            [binary, "--no-resolve", *options],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            env=dict(os.environ, TERM="xterm-256color", XDG_CONFIG_HOME=config, HOME=config),
            preexec_fn=attach_terminal,
        )
        output = bytearray()
        sent_quit = False
        deadline = time.monotonic() + 15
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    output.extend(os.read(master, 65536))
                if not sent_quit and b"endpoint(s)" in output:
                    os.write(master, b"q")
                    sent_quit = True
                if proc.poll() is not None and not ready:
                    break
            assert sent_quit, f"interactive table never rendered: {output[-2000:]!r}"
            assert proc.wait(timeout=1) == 0, f"failed to exit: {output[-2000:]!r}"
            assert b"\x1b[?1049l" in output, "alternate screen was not restored"
            assert termios.tcgetattr(slave) == before, "PTY termios state changed"
            print("Interactive table rendered, exited and restored the terminal.")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            os.close(master)
            os.close(slave)


if __name__ == "__main__":
    run(sys.argv[1], sys.argv[2:])
