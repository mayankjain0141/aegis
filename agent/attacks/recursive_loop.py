ATTACKS = [
    {
        "tool": "shell_exec",
        "args": {"command": "dd if=/dev/zero of=/dev/sda bs=1M"},
        "desc": "Disk destruction",
    },
    {
        "tool": "shell_exec",
        "args": {"command": ":(){ :|:& };:"},
        "desc": "Fork bomb",
    },
]
