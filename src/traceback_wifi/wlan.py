"""Read-only Native Wi-Fi API adapter. Never reads profiles or credentials.

Implements WLAN_CONNECTION_ATTRIBUTES per Microsoft's wlanapi.h. Native API
avoids depending on localized netsh field names. Some Windows versions restrict
Wi-Fi details behind location permission; errors are reported, not hidden.
"""
from __future__ import annotations

import ctypes as c
import os
from ctypes import wintypes as w


class WifiApiError(RuntimeError):
    pass


class GUID(c.Structure):
    _fields_ = [("Data1", w.DWORD), ("Data2", w.WORD), ("Data3", w.WORD),
                ("Data4", c.c_ubyte * 8)]


class DOT11_SSID(c.Structure):
    _fields_ = [("uSSIDLength", w.ULONG), ("ucSSID", c.c_ubyte * 32)]


class WLAN_ASSOCIATION_ATTRIBUTES(c.Structure):
    _fields_ = [("dot11Ssid", DOT11_SSID), ("dot11BssType", w.DWORD),
                ("dot11Bssid", c.c_ubyte * 6), ("dot11PhyType", w.DWORD),
                ("uDot11PhyIndex", w.ULONG), ("wlanSignalQuality", w.ULONG),
                ("ulRxRate", w.ULONG), ("ulTxRate", w.ULONG)]


class WLAN_SECURITY_ATTRIBUTES(c.Structure):
    _fields_ = [("bSecurityEnabled", w.BOOL), ("bOneXEnabled", w.BOOL),
                ("dot11AuthAlgorithm", w.DWORD), ("dot11CipherAlgorithm", w.DWORD)]


class WLAN_CONNECTION_ATTRIBUTES(c.Structure):
    _fields_ = [("isState", w.DWORD), ("strProfileName", w.WCHAR * 256),
                ("wlanAssociationAttributes", WLAN_ASSOCIATION_ATTRIBUTES),
                ("wlanSecurityAttributes", WLAN_SECURITY_ATTRIBUTES)]


class WLAN_INTERFACE_INFO(c.Structure):
    _fields_ = [("InterfaceGuid", GUID), ("strInterfaceDescription", w.WCHAR * 256),
                ("isState", w.DWORD)]


_AUTH = {1: "Open", 2: "Shared key", 3: "WPA Enterprise", 4: "WPA-PSK",
         5: "WPA-None", 6: "WPA2 Enterprise", 7: "WPA2-PSK", 8: "WPA3 SAE",
         9: "WPA3 Enterprise (192-bit)", 10: "WPA3 Enterprise", 11: "OWE"}


def _check(code: int, operation: str) -> None:
    if code != 0:
        raise WifiApiError(f"{operation} returned Windows error {code}")


def current_connection() -> dict:
    if os.name != "nt":
        raise WifiApiError("Native Wi-Fi observation requires Windows 10 or 11")

    try:
        dll = c.WinDLL("wlanapi", use_last_error=True)
    except OSError as exc:
        raise WifiApiError(f"Windows WLAN API unavailable: {exc}") from exc
    dll.WlanOpenHandle.argtypes = [w.DWORD, c.c_void_p, c.POINTER(w.DWORD), c.POINTER(w.HANDLE)]
    dll.WlanOpenHandle.restype = w.DWORD
    dll.WlanCloseHandle.argtypes = [w.HANDLE, c.c_void_p]
    dll.WlanCloseHandle.restype = w.DWORD
    dll.WlanEnumInterfaces.argtypes = [w.HANDLE, c.c_void_p, c.POINTER(c.c_void_p)]
    dll.WlanEnumInterfaces.restype = w.DWORD
    dll.WlanQueryInterface.argtypes = [w.HANDLE, c.POINTER(GUID), w.DWORD, c.c_void_p,
                                       c.POINTER(w.DWORD), c.POINTER(c.c_void_p), c.c_void_p]
    dll.WlanQueryInterface.restype = w.DWORD
    dll.WlanFreeMemory.argtypes = [c.c_void_p]
    dll.WlanFreeMemory.restype = None

    handle = w.HANDLE()
    negotiated = w.DWORD()
    _check(dll.WlanOpenHandle(2, None, c.byref(negotiated), c.byref(handle)), "WlanOpenHandle")
    interfaces_ptr = c.c_void_p()
    try:
        _check(dll.WlanEnumInterfaces(handle, None, c.byref(interfaces_ptr)), "WlanEnumInterfaces")
        try:
            if not interfaces_ptr.value:
                raise WifiApiError("WLAN enumeration returned no buffer")
            count = c.cast(interfaces_ptr, c.POINTER(w.DWORD)).contents.value
            if count > 128:
                raise WifiApiError("Unexpected WLAN interface count")
            if not count:
                return {"link": "no_adapter", "adapter": None}
            start = interfaces_ptr.value + 2 * c.sizeof(w.DWORD)
            entries = [c.cast(start + i * c.sizeof(WLAN_INTERFACE_INFO),
                              c.POINTER(WLAN_INTERFACE_INFO)).contents for i in range(count)]
            # Prefer an actually connected adapter when multiple wireless cards exist.
            entry = next((item for item in entries if item.isState == 1), entries[0])
            adapter = entry.strInterfaceDescription
            if entry.isState != 1:
                return {"link": "disconnected", "adapter": adapter}

            data_ptr = c.c_void_p()
            data_size = w.DWORD()
            _check(dll.WlanQueryInterface(handle, c.byref(entry.InterfaceGuid), 7, None,
                                           c.byref(data_size), c.byref(data_ptr), None),
                   "WlanQueryInterface(current_connection)")
            try:
                if data_size.value < c.sizeof(WLAN_CONNECTION_ATTRIBUTES):
                    raise WifiApiError("WLAN connection data is incomplete")
                attr = c.cast(data_ptr, c.POINTER(WLAN_CONNECTION_ATTRIBUTES)).contents
                assoc = attr.wlanAssociationAttributes
                security = attr.wlanSecurityAttributes
                ssid_bytes = bytes(assoc.dot11Ssid.ucSSID[:min(assoc.dot11Ssid.uSSIDLength, 32)])
                ssid = ssid_bytes.decode("utf-8", errors="replace") or "<hidden SSID>"
                bssid = ":".join(f"{part:02X}" for part in assoc.dot11Bssid)
                channel = None
                channel_ptr = c.c_void_p()
                channel_size = w.DWORD()
                if dll.WlanQueryInterface(handle, c.byref(entry.InterfaceGuid), 8, None,
                                          c.byref(channel_size), c.byref(channel_ptr), None) == 0:
                    try:
                        if channel_ptr.value and channel_size.value >= 4:
                            channel = c.cast(channel_ptr, c.POINTER(w.ULONG)).contents.value
                    finally:
                        if channel_ptr.value:
                            dll.WlanFreeMemory(channel_ptr)
                return {"link": "connected", "adapter": adapter, "ssid": ssid,
                        "bssid": bssid, "signal_pct": int(assoc.wlanSignalQuality),
                        "channel": channel, "security": (
                            _AUTH.get(security.dot11AuthAlgorithm,
                                      f"Auth type {security.dot11AuthAlgorithm}")
                            if security.bSecurityEnabled else "Open / unencrypted")}
            finally:
                if data_ptr.value:
                    dll.WlanFreeMemory(data_ptr)
        finally:
            if interfaces_ptr.value:
                dll.WlanFreeMemory(interfaces_ptr)
    finally:
        dll.WlanCloseHandle(handle, None)
