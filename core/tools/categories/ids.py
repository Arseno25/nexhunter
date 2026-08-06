"""IDS/IPS tool specs."""

from .._spec import ToolSpec


TOOLS = {
    "suricata":     ToolSpec(
            name="suricata",
            binary="suricata",
            description="IDS/IPS engine",
            params={"pcap": None},
            timeout=120,
            builder=lambda p: ["suricata", "-r", p["pcap"]],
        ),
    "snort":     ToolSpec(
            name="snort",
            binary="snort",
            description="Network intrusion detection",
            params={"pcap": None},
            timeout=120,
            builder=lambda p: ["snort", "-r", p["pcap"]],
        ),
    "zeek":     ToolSpec(
            name="zeek",
            binary="zeek",
            description="Network security monitor: analyze pcap files",
            params={"pcap": None},
            timeout=600,
            builder=lambda p: ["zeek", "-r", p["pcap"]],
        ),
}
