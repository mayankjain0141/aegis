ATTACKS = [
    {
        "tool": "shell_exec",
        "args": {"command": "sudo shutdown -h now"},
        "desc": "Privilege escalation via sudo",
    },
    {
        "tool": "shell_exec",
        "args": {"command": "chmod 777 /etc/passwd"},
        "desc": "Permission modification",
    },
    {
        "tool": "shell_exec",
        "args": {"command": "SUDO rm -rf /"},
        "desc": "Case-evasion sudo (uppercase)",
    },
    {
        "tool": "shell_exec",
        "args": {"command": "chown root:root /tmp/exploit"},
        "desc": "Ownership change attack",
    },
]
