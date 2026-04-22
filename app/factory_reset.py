import os
import platform
import subprocess
import logging
from typing import Dict, List

import app.device_password as device_password
import app.wifi_manager as wifi_manager

logger = logging.getLogger(__name__)


def _project_base_dir() -> str:
    import app.config as config_module

    return os.path.dirname(os.path.dirname(os.path.abspath(config_module.__file__)))


def _get_system_username() -> str:
    return os.environ.get("USER") or os.environ.get("USERNAME") or "admin"


def _sync_system_password(new_password: str) -> None:
    if platform.system() != "Linux":
        logger.info("Factory reset: skipping system password sync on non-Linux host")
        return

    username = _get_system_username()
    result = subprocess.run(
        ["sudo", "chpasswd"],
        input=f"{username}:{new_password}\n",
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        stderr = (result.stderr or result.stdout or "unknown chpasswd error").strip()
        raise RuntimeError(stderr)


def _reset_device_password(errors: List[str]) -> bool:
    try:
        previous_password = device_password.get_device_password()
        new_password = device_password.reset_device_password()
    except PermissionError as exc:
        logger.info("Factory reset: skipping Device Password reset: %s", exc)
        return False
    except Exception as exc:
        errors.append(f"Device Password reset failed: {exc}")
        logger.warning("Factory reset: Device Password reset failed", exc_info=True)
        return False

    try:
        _sync_system_password(new_password)
    except Exception as exc:
        errors.append(f"Device Password system sync failed: {exc}")
        logger.warning(
            "Factory reset: Device Password changed but system sync failed",
            exc_info=True,
        )
        try:
            device_password.set_device_password(previous_password)
        except Exception:
            errors.append("Failed to restore previous Device Password after sync failure")
            logger.warning(
                "Factory reset: failed to restore previous Device Password",
                exc_info=True,
            )
        return False

    return True


def perform_factory_reset() -> Dict[str, object]:
    """
    Clear local config/WiFi/password state and request reboot.

    Returns a structured result so callers can provide user-visible fallback behavior
    if reboot cannot be requested.
    """
    errors: List[str] = []
    base_dir = _project_base_dir()
    config_path = os.path.join(base_dir, "config.json")
    backup_path = os.path.join(base_dir, "config.json.bak")
    welcome_marker = os.path.join(base_dir, ".welcome_printed")

    config_cleared = True
    for path in (config_path, backup_path, welcome_marker):
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception as e:
            config_cleared = False
            errors.append(f"Failed to remove {path}: {e}")
            logger.warning("Factory reset: failed to remove %s", path, exc_info=True)

    device_password_reset = _reset_device_password(errors)

    wifi_cleared = False
    try:
        wifi_cleared = bool(wifi_manager.forget_all_wifi())
        if not wifi_cleared:
            errors.append("Failed to forget one or more saved WiFi networks")
            logger.warning("Factory reset: forget_all_wifi returned False")
    except Exception as e:
        errors.append(f"WiFi reset failed: {e}")
        logger.warning("Factory reset: WiFi reset failed", exc_info=True)

    reboot_requested = False
    try:
        result = subprocess.run(
            ["sudo", "reboot"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        reboot_requested = result.returncode == 0
        if not reboot_requested:
            stderr = (result.stderr or result.stdout or "unknown reboot error").strip()
            errors.append(f"Reboot command failed: {stderr}")
            logger.error("Factory reset: reboot command failed: %s", stderr)
    except Exception as e:
        errors.append(f"Reboot command exception: {e}")
        logger.error("Factory reset: reboot command raised exception", exc_info=True)

    return {
        "config_cleared": config_cleared,
        "device_password_reset": device_password_reset,
        "wifi_cleared": wifi_cleared,
        "reboot_requested": reboot_requested,
        "errors": errors,
    }
