"""Wireless security tool specs."""

from .._spec import ToolSpec


TOOLS = {
    "airodump":     ToolSpec(
            name="airodump",
            binary="airodump-ng",
            description="Wireless network sniffer",
            params={"interface": None},
            timeout=30,
            cacheable=False,
            builder=lambda p: ["airodump-ng", p["interface"]],
        ),
    "aireplay":     ToolSpec(
            name="aireplay",
            binary="aireplay-ng",
            description="Wireless network traffic injector",
            params={"interface": None},
            timeout=30,
            cacheable=False,
            builder=lambda p: ["aireplay-ng", "-h", p["interface"]],
        ),
    "aircrack":     ToolSpec(
            name="aircrack",
            binary="aircrack-ng",
            description="WEP/WPA password cracker",
            params={"capfile": None},
            timeout=600,
            builder=lambda p: ["aircrack-ng", p["capfile"]],
        ),
    "wifite":     ToolSpec(
            name="wifite",
            binary="wifite",
            description="Automated WPA/WPS wireless attack runner",
            params={"interface": ""},
            timeout=600,
            risk_level="intrusive",
            builder=lambda p: ["wifite"] + (["-i", p["interface"]] if p["interface"] else []),
        ),
    "reaver":     ToolSpec(
            name="reaver",
            binary="reaver",
            description="WPS PIN brute force",
            params={"target": None, "interface": None},
            timeout=600,
            risk_level="intrusive",
            builder=lambda p: ["reaver", "-i", p["interface"], "-b", p["target"], "-vv"],
        ),
    "kismet":     ToolSpec(
            name="kismet",
            binary="kismet",
            description="Passive wireless network detector and channel capture",
            params={"capture_file": ""},
            timeout=600,
            risk_level="passive",
            cacheable=False,
            builder=lambda p: (
                ["kismet", "--no-gpsd", "--no-server"] + (["--logfile", p["capture_file"]] if p["capture_file"] else [])
            ),
        ),
    "airgeddon":     ToolSpec(
            name="airgeddon",
            binary="bash",
            description="Multipurpose wireless attack framework (airgeddon.sh)",
            params={"interface": None},
            timeout=600,
            risk_level="intrusive",
            builder=lambda p: ["bash", "airgeddon.sh", "-i", p["interface"]],
        ),
    "bettercap":     ToolSpec(
            name="bettercap",
            binary="bettercap",
            description="Network MITM and reconnaissance framework",
            params={"target": ""},
            timeout=300,
            risk_level="intrusive",
            builder=lambda p: (
                ["bettercap", "-eval", "net.probe on; arp.spoof on"] + (["--target", p["target"]] if p["target"] else [])
            ),
        ),
    "mdk4":     ToolSpec(
            name="mdk4",
            binary="mdk4",
            description="Wireless DoS and deauthentication testing",
            params={"interface": None, "bssid": None},
            timeout=300,
            risk_level="destructive",
            builder=lambda p: ["mdk4", p["interface"], "d", p["bssid"]],
        ),
}
