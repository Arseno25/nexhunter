"""Mobile app security tool specs."""

from .._spec import ToolSpec


TOOLS = {
    "adb_list_devices":     ToolSpec(
            name="adb_list_devices",
            binary="adb",
            description="List connected Android devices (read-only)",
            params={},
            timeout=30,
            risk_level="passive",
            category="mobile",
            builder=lambda p: ["adb", "devices", "-l"],
        ),
    "adb_list_packages":     ToolSpec(
            name="adb_list_packages",
            binary="adb",
            description="List packages on the connected device (read-only)",
            params={},
            timeout=30,
            risk_level="passive",
            category="mobile",
            builder=lambda p: ["adb", "shell", "pm", "list", "packages"],
        ),
    "apktool":     ToolSpec(
            name="apktool",
            binary="apktool",
            description="APK analyzer",
            params={"apk": None},
            timeout=60,
            builder=lambda p: ["apktool", "d", p["apk"]],
        ),
    "jadx":     ToolSpec(
            name="jadx",
            binary="jadx",
            description="Android decompiler",
            params={"apk": None},
            timeout=120,
            builder=lambda p: ["jadx", p["apk"]],
        ),
    "objection":     ToolSpec(
            name="objection",
            binary="objection",
            description="Runtime mobile application exploration and frida gadget control",
            params={"device_id": None, "action": "explore"},
            timeout=300,
            builder=lambda p: ["objection", "--id", p["device_id"], p["action"]],
        ),
    "androguard":     ToolSpec(
            name="androguard",
            binary="androguard",
            description="Android APK analysis",
            params={"file": None},
            timeout=120,
            builder=lambda p: ["androguard", "axml", p["file"]],
        ),
}
