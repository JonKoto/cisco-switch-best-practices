"""Netmiko SSH connector to pull running-config from Cisco devices."""

from __future__ import annotations

from netmiko import ConnectHandler


def fetch_running_config(
    host: str,
    username: str,
    password: str,
    port: int = 22,
    enable_secret: str | None = None,
    timeout: int = 30,
) -> str:
    """Connect to a Cisco IOS device via SSH and return the running configuration."""
    device = {
        "device_type": "cisco_ios",
        "host": host,
        "username": username,
        "password": password,
        "port": port,
        "timeout": timeout,
    }
    if enable_secret:
        device["secret"] = enable_secret

    with ConnectHandler(**device) as conn:
        if enable_secret:
            conn.enable()
        output = conn.send_command("show running-config")
    return output
