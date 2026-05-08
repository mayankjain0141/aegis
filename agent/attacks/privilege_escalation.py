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
]
