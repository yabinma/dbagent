"""Static raw-command validator matrix (design.md Section 8.2 / F5 / B6)."""
import time

import pytest

from rca_common.rawcmd import static_validate


@pytest.mark.parametrize(
    "command",
    [
        "cat /etc/presto/config.properties",
        "grep -i oom /var/log/presto/server.log",
        "egrep ERROR /var/log/presto/server.log",
        "tail -n 100 /var/log/presto/server.log",
        "head -n 20 /proc/meminfo",
        "ls -la /etc/presto",
        "ps aux",
        "df -h",
        "du -sh /var/log",
        "free -m",
        "uptime",
        "curl -s http://localhost:8080/v1/info",
        "curl --request GET http://localhost:8080/v1/info",
        "jcmd 1 Thread.print",
        "jstack 1",
        "jmap -histo 1",
        "jmap -histo:live 1",
    ],
)
def test_accept_matrix(command):
    result = static_validate(command)
    assert result.ok, f"{command!r} should pass: {result.reason}"


@pytest.mark.parametrize(
    "command,fragment",
    [
        ("", "empty"),
        ("   ", "empty"),
        ("rm -rf /", "not in allowlist"),
        ("cat /x | tee /tmp/out", "forbidden"),
        ("cat /x; rm /tmp/y", "forbidden"),
        ("cat /x && echo hi", "forbidden"),
        ("cat /x || true", "forbidden"),
        ("cat /x > /tmp/out", "forbidden"),
        ("cat /x >> /tmp/out", "forbidden"),
        ("echo $(whoami)", "forbidden"),
        ("echo `whoami`", "forbidden"),
        ("sudo cat /etc/shadow", "forbidden"),
        ("curl -X POST http://x", "GET-only"),
        ("curl --request DELETE http://x", "GET-only"),
        ("curl -d foo=bar http://x", "GET-only"),
        ("curl --data a=b http://x", "GET-only"),
        ("curl -F file=@x http://x", "GET-only"),
        ("jmap -dump:format=b,file=heap.bin 1", "histo"),
        ("bash -c 'id'", "not in allowlist"),
        ("/usr/bin/python3 -c 'print(1)'", "not in allowlist"),
    ],
)
def test_reject_matrix(command, fragment):
    result = static_validate(command)
    assert not result.ok
    assert fragment.lower() in result.reason.lower()


def test_b6_static_validator_under_5ms():
    """B6: static raw-command validator < 5 ms per command (Section 14.4)."""
    commands = [
        "cat /etc/presto/config.properties",
        "curl -X POST http://evil",
        "jmap -histo 1",
        "grep oom /var/log/presto/server.log",
        "sudo cat /etc/shadow",
    ]
    # Warm up.
    for c in commands:
        static_validate(c)
    samples = []
    for _ in range(200):
        for c in commands:
            t0 = time.perf_counter()
            static_validate(c)
            samples.append(time.perf_counter() - t0)
    p99 = sorted(samples)[int(len(samples) * 0.99) - 1]
    assert p99 < 0.005, f"B6 FAILED: p99 {p99*1000:.3f}ms exceeds 5ms"
