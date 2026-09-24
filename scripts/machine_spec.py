"""Machine specification captured next to every published number.

Standard library only, so it runs on the demo box without extra installs.
Hostname and user name are deliberately NOT recorded.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def _cpu_model() -> str:
    system = platform.system()
    try:
        if system == "Windows":
            import winreg  # type: ignore[import-not-found]

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
                return str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).strip()
        if system == "Linux":
            for line in Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
        if system == "Darwin":
            return subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
    except Exception:  # pragma: no cover - best effort only
        pass
    return platform.processor() or platform.machine()


def _ram_bytes() -> int | None:
    system = platform.system()
    try:
        if system == "Windows":
            import ctypes

            class _MemStatus(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong), ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong), ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong), ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

            status = _MemStatus(); status.dwLength = ctypes.sizeof(_MemStatus)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))  # type: ignore[attr-defined]
            return int(status.ullTotalPhys)
        if system == "Linux":
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
        if system == "Darwin":
            return int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True).strip())
    except Exception:  # pragma: no cover
        pass
    return None


def _power_state() -> dict[str, object] | None:
    """AC vs battery and Windows battery saver, so throttled runs are labelled as such."""
    try:
        if platform.system() == "Windows":
            import ctypes

            class _SPS(ctypes.Structure):
                _fields_ = [("ACLineStatus", ctypes.c_ubyte), ("BatteryFlag", ctypes.c_ubyte), ("BatteryLifePercent", ctypes.c_ubyte),
                            ("SystemStatusFlag", ctypes.c_ubyte), ("BatteryLifeTime", ctypes.c_ulong), ("BatteryFullLifeTime", ctypes.c_ulong)]

            status = _SPS()
            if not ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(status)):  # type: ignore[attr-defined]
                return None
            ac = {0: "battery", 1: "ac", 255: "unknown"}.get(status.ACLineStatus, "unknown")
            plan = None
            try:
                out = subprocess.check_output(["powercfg", "/getactivescheme"], text=True, stderr=subprocess.DEVNULL)
                plan = out.split("(")[-1].rstrip(")\n ") if "(" in out else out.strip()
            except Exception:
                pass
            return {"power_source": ac, "battery_percent": None if status.BatteryLifePercent == 255 else status.BatteryLifePercent,
                    "battery_saver_on": bool(status.SystemStatusFlag & 1), "power_plan": plan}
        if platform.system() == "Linux":
            supply = Path("/sys/class/power_supply")
            online = [p for p in supply.glob("A*/online")] if supply.exists() else []
            if online:
                return {"power_source": "ac" if online[0].read_text().strip() == "1" else "battery"}
    except Exception:  # pragma: no cover
        pass
    return None


def _git_commit(root: Path) -> str | None:
    try:
        return subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=root, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return None


def machine_spec() -> dict[str, object]:
    ram = _ram_bytes()
    root = Path(__file__).resolve().parents[1]
    return {
        "captured_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "os": platform.platform(),
        "cpu_model": _cpu_model(),
        "logical_cpus": os.cpu_count(),
        "ram_gb": round(ram / 2**30, 1) if ram else None,
        "python": platform.python_version(),
        "python_impl": platform.python_implementation(),
        "power": _power_state(),
        "git_commit": _git_commit(root),
        "command": " ".join([Path(sys.executable).name, *sys.argv]),
    }


def spec_markdown(spec: dict[str, object]) -> str:
    return "\n".join(f"| {key} | `{value}` |" for key, value in spec.items())


if __name__ == "__main__":
    import json

    print(json.dumps(machine_spec(), indent=2))
