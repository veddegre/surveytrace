"""
SurveyTrace — fingerprinting helpers
Classifies hosts by category and maps to CPE strings using:
  - MAC OUI lookup
  - Hostname pattern heuristics
  - Open port profiles
  - Banner heuristics
"""

from __future__ import annotations
import re
from pathlib import Path
import json

# ---------------------------------------------------------------------------
# MAC OUI → (vendor_name, category_hint)
# Source: IEEE OUI registry — extend as needed
# ---------------------------------------------------------------------------
OUI_TABLE: dict[str, tuple[str, str]] = {
    # --- Ubiquiti / UniFi ---
    "74:AC:B9": ("Ubiquiti Networks",        "net"),  # UniFi MR Flex, USW etc
    "00:27:22": ("Ubiquiti Networks",        "net"),
    "04:18:D6": ("Ubiquiti Networks",        "net"),
    "0C:80:63": ("Ubiquiti Networks",        "net"),
    "18:E8:29": ("Ubiquiti Networks",        "net"),
    "24:A4:3C": ("Ubiquiti Networks",        "net"),
    "44:D9:E7": ("Ubiquiti Networks",        "net"),
    "60:22:32": ("Ubiquiti Networks",        "net"),
    "68:72:51": ("Ubiquiti Networks",        "net"),
    "74:83:C2": ("Ubiquiti Networks",        "net"),
    "78:8A:20": ("Ubiquiti Networks",        "net"),
    "80:2A:A8": ("Ubiquiti Networks",        "net"),
    "B4:FB:E4": ("Ubiquiti Networks",        "net"),
    "CC:32:E5": ("Ubiquiti Networks",        "net"),
    "DC:9F:DB": ("Ubiquiti Networks",        "net"),
    "E0:63:DA": ("Ubiquiti Networks",        "net"),
    "F0:9F:C2": ("Ubiquiti Networks",        "net"),
    "FC:EC:DA": ("Ubiquiti Networks",        "net"),

    # --- Cisco ---
    "00:00:0C": ("Cisco Systems",            "net"),
    "00:01:42": ("Cisco Systems",            "net"),
    "00:0E:84": ("Cisco Systems",            "net"),
    "00:17:94": ("Cisco Systems",            "net"),
    "00:1A:A1": ("Cisco Systems",            "net"),
    "00:1B:54": ("Cisco Systems",            "net"),
    "00:23:AC": ("Cisco Systems",            "net"),
    "2C:31:24": ("Cisco Systems",            "net"),
    "3C:08:F6": ("Cisco Systems",            "net"),
    "54:60:09": ("Cisco Systems",            "net"),
    "58:8D:09": ("Cisco Systems",            "net"),
    "70:10:5C": ("Cisco Systems",            "net"),
    "88:5A:92": ("Cisco Systems",            "net"),
    "A0:EC:F9": ("Cisco Systems",            "net"),
    "D0:72:DC": ("Cisco Systems",            "net"),
    "F8:7B:20": ("Cisco Systems",            "net"),

    # --- Juniper ---
    "00:05:85": ("Juniper Networks",         "net"),
    "00:10:DB": ("Juniper Networks",         "net"),
    "00:12:1E": ("Juniper Networks",         "net"),
    "00:19:E2": ("Juniper Networks",         "net"),
    "00:1F:12": ("Juniper Networks",         "net"),
    "28:8A:1C": ("Juniper Networks",         "net"),
    "2C:6B:F5": ("Juniper Networks",         "net"),
    "3C:61:04": ("Juniper Networks",         "net"),
    "40:B4:F0": ("Juniper Networks",         "net"),
    "5C:5E:AB": ("Juniper Networks",         "net"),
    "84:B5:9C": ("Juniper Networks",         "net"),
    "A8:D0:E5": ("Juniper Networks",         "net"),

    # --- Aruba / HPE networking ---
    "00:0B:86": ("Aruba Networks",           "net"),
    "00:1A:1E": ("Aruba Networks",           "net"),
    "18:64:72": ("Aruba Networks",           "net"),
    "20:4C:03": ("Aruba Networks",           "net"),
    "24:DE:C6": ("Aruba Networks",           "net"),
    "40:E3:D6": ("Aruba Networks",           "net"),
    "6C:F3:7F": ("Aruba Networks",           "net"),
    "84:D4:7E": ("Aruba Networks",           "net"),
    "94:B4:0F": ("Aruba Networks",           "net"),
    "AC:A3:1E": ("Aruba Networks",           "net"),
    "D8:C7:C8": ("Aruba Networks",           "net"),
    "F0:5C:19": ("Aruba Networks",           "net"),

    # --- TP-Link ---
    "14:EB:B6": ("TP-Link Technologies",     "net"),
    "50:C7:BF": ("TP-Link Technologies",     "net"),
    "54:AF:97": ("TP-Link Technologies",     "net"),
    "60:32:B1": ("TP-Link Technologies",     "net"),
    "80:8F:1D": ("TP-Link Technologies",     "net"),
    "98:DA:C4": ("TP-Link Technologies",     "net"),
    "B0:BE:76": ("TP-Link Technologies",     "net"),
    "C0:06:C3": ("TP-Link Technologies",     "net"),
    "E8:DE:27": ("TP-Link Technologies",     "net"),

    # --- Google / Chromecast / Nest ---
    "00:1A:11": ("Google",                   "iot"),
    "08:9E:08": ("Google",                   "iot"),
    "1C:F2:9A": ("Google",                   "iot"),
    "20:DF:B9": ("Google",                   "iot"),
    "3C:5A:B4": ("Google",                   "iot"),
    "48:D6:D5": ("Google",                   "iot"),
    "54:60:09": ("Google",                   "iot"),  # overlaps Cisco — banner wins
    "6C:AD:F8": ("Google",                   "iot"),
    "A4:77:33": ("Google",                   "iot"),
    "AC:67:B2": ("Google",                   "iot"),
    "D8:6C:63": ("Google",                   "iot"),
    "E4:F0:42": ("Google",                   "iot"),
    "F4:F5:D8": ("Google",                   "iot"),

    # --- Amazon / Echo / Kindle ---
    "00:FC:8B": ("Amazon",                   "iot"),
    "0C:47:C9": ("Amazon",                   "iot"),
    "18:74:2E": ("Amazon",                   "iot"),
    "28:EF:01": ("Amazon",                   "iot"),
    "34:D2:70": ("Amazon",                   "iot"),
    "40:B4:CD": ("Amazon",                   "iot"),
    "44:65:0D": ("Amazon",                   "iot"),
    "50:F5:DA": ("Amazon",                   "iot"),
    "68:37:E9": ("Amazon",                   "iot"),
    "74:75:48": ("Amazon",                   "iot"),
    "84:D6:D0": ("Amazon",                   "iot"),
    "A0:02:DC": ("Amazon",                   "iot"),
    "B4:7C:9C": ("Amazon",                   "iot"),
    "CC:9E:A2": ("Amazon",                   "iot"),
    "F0:27:2D": ("Amazon",                   "iot"),
    "FC:65:DE": ("Amazon",                   "iot"),

    # --- Apple ---
    "00:03:93": ("Apple",                    "ws"),
    "00:0A:27": ("Apple",                    "ws"),
    "00:17:F2": ("Apple",                    "ws"),
    "00:1C:B3": ("Apple",                    "ws"),
    "00:25:BC": ("Apple",                    "ws"),
    "04:54:53": ("Apple",                    "ws"),
    "08:66:98": ("Apple",                    "ws"),
    "0C:74:C2": ("Apple",                    "ws"),
    "10:40:F3": ("Apple",                    "ws"),
    "14:99:E2": ("Apple",                    "ws"),
    "18:20:32": ("Apple",                    "ws"),
    "1C:36:BB": ("Apple",                    "ws"),
    "20:C9:D0": ("Apple",                    "ws"),
    "24:A0:74": ("Apple",                    "ws"),
    "28:6A:B8": ("Apple",                    "ws"),
    "2C:BE:08": ("Apple",                    "ws"),
    "34:15:9E": ("Apple",                    "ws"),
    "38:C9:86": ("Apple",                    "ws"),
    "3C:15:C2": ("Apple",                    "ws"),
    "40:3C:FC": ("Apple",                    "ws"),
    "44:00:10": ("Apple",                    "ws"),
    "48:60:BC": ("Apple",                    "ws"),
    "4C:57:CA": ("Apple",                    "ws"),
    "50:DE:06": ("Apple",                    "ws"),
    "54:26:96": ("Apple",                    "ws"),
    "58:B0:35": ("Apple",                    "ws"),
    "5C:97:F3": ("Apple",                    "ws"),
    "60:03:08": ("Apple",                    "ws"),
    "64:B0:A6": ("Apple",                    "ws"),
    "68:96:7B": ("Apple",                    "ws"),
    "6C:40:08": ("Apple",                    "ws"),
    "70:56:81": ("Apple",                    "ws"),
    "74:E1:B6": ("Apple",                    "ws"),
    "78:7B:8A": ("Apple",                    "ws"),
    "7C:6D:62": ("Apple",                    "ws"),
    "80:00:6E": ("Apple",                    "ws"),
    "84:38:35": ("Apple",                    "ws"),
    "88:66:A5": ("Apple",                    "ws"),
    "8C:85:90": ("Apple",                    "ws"),
    "90:B0:ED": ("Apple",                    "ws"),
    "94:E9:6A": ("Apple",                    "ws"),
    "98:01:A7": ("Apple",                    "ws"),
    "9C:FC:01": ("Apple",                    "ws"),
    "A0:99:9B": ("Apple",                    "ws"),
    "A4:5E:60": ("Apple",                    "ws"),
    "A8:96:8A": ("Apple",                    "ws"),
    "AC:29:3A": ("Apple",                    "ws"),
    "B0:34:95": ("Apple",                    "ws"),
    "B4:F0:AB": ("Apple",                    "ws"),
    "B8:FF:61": ("Apple",                    "ws"),
    "BC:52:B7": ("Apple",                    "ws"),
    "C0:D0:12": ("Apple",                    "ws"),
    "C4:B3:01": ("Apple",                    "ws"),
    "C8:2A:14": ("Apple",                    "ws"),
    "CC:20:E8": ("Apple",                    "ws"),
    "D0:03:4B": ("Apple",                    "ws"),
    "D4:9A:20": ("Apple",                    "ws"),
    "D8:BB:2C": ("Apple",                    "ws"),
    "DC:2B:2A": ("Apple",                    "ws"),
    "E0:AC:CB": ("Apple",                    "ws"),
    "E4:CE:8F": ("Apple",                    "ws"),
    "E8:04:0B": ("Apple",                    "ws"),
    "EC:35:86": ("Apple",                    "ws"),
    "F0:18:98": ("Apple",                    "ws"),
    "F4:1B:A1": ("Apple",                    "ws"),
    "F8:27:93": ("Apple",                    "ws"),
    "FC:25:3F": ("Apple",                    "ws"),

    # --- Samsung ---
    "00:15:99": ("Samsung Electronics",      "ws"),
    "00:21:19": ("Samsung Electronics",      "ws"),
    "08:08:C2": ("Samsung Electronics",      "ws"),
    "10:D5:42": ("Samsung Electronics",      "ws"),
    "14:49:E0": ("Samsung Electronics",      "ws"),
    "18:3A:2D": ("Samsung Electronics",      "ws"),
    "1C:66:AA": ("Samsung Electronics",      "ws"),
    "20:64:32": ("Samsung Electronics",      "ws"),
    "24:4B:03": ("Samsung Electronics",      "ws"),
    "2C:AE:2B": ("Samsung Electronics",      "ws"),
    "34:14:5F": ("Samsung Electronics",      "ws"),
    "38:AA:3C": ("Samsung Electronics",      "ws"),
    "3C:BD:D8": ("Samsung Electronics",      "ws"),
    "40:0E:85": ("Samsung Electronics",      "ws"),
    "44:78:3E": ("Samsung Electronics",      "ws"),
    "48:13:7E": ("Samsung Electronics",      "ws"),
    "4C:3C:16": ("Samsung Electronics",      "ws"),
    "50:01:BB": ("Samsung Electronics",      "ws"),
    "54:92:BE": ("Samsung Electronics",      "ws"),
    "58:EF:68": ("Samsung Electronics",      "ws"),
    "5C:0A:5B": ("Samsung Electronics",      "ws"),
    "60:D0:A9": ("Samsung Electronics",      "ws"),
    "64:B3:10": ("Samsung Electronics",      "ws"),
    "68:EB:AE": ("Samsung Electronics",      "ws"),
    "6C:2F:2C": ("Samsung Electronics",      "ws"),
    "70:F9:27": ("Samsung Electronics",      "ws"),
    "74:45:8A": ("Samsung Electronics",      "ws"),
    "78:1F:DB": ("Samsung Electronics",      "ws"),
    "7C:64:56": ("Samsung Electronics",      "ws"),
    "80:65:6D": ("Samsung Electronics",      "ws"),
    "84:25:DB": ("Samsung Electronics",      "ws"),
    "88:32:9B": ("Samsung Electronics",      "ws"),
    "8C:77:12": ("Samsung Electronics",      "ws"),
    "90:18:7C": ("Samsung Electronics",      "ws"),
    "94:35:0A": ("Samsung Electronics",      "ws"),
    "98:52:B1": ("Samsung Electronics",      "ws"),
    "9C:02:98": ("Samsung Electronics",      "ws"),
    "A0:07:98": ("Samsung Electronics",      "ws"),
    "A4:23:05": ("Samsung Electronics",      "ws"),
    "A8:06:00": ("Samsung Electronics",      "ws"),
    "AC:5F:3E": ("Samsung Electronics",      "ws"),
    "B0:72:BF": ("Samsung Electronics",      "ws"),
    "B4:3A:28": ("Samsung Electronics",      "ws"),
    "B8:BC:1B": ("Samsung Electronics",      "ws"),
    "BC:20:A4": ("Samsung Electronics",      "ws"),
    "C0:BD:D1": ("Samsung Electronics",      "ws"),
    "C4:42:02": ("Samsung Electronics",      "ws"),
    "C8:14:79": ("Samsung Electronics",      "ws"),
    "CC:07:AB": ("Samsung Electronics",      "ws"),
    "D0:22:BE": ("Samsung Electronics",      "ws"),
    "D4:87:D8": ("Samsung Electronics",      "ws"),
    "D8:57:EF": ("Samsung Electronics",      "ws"),
    "DC:71:96": ("Samsung Electronics",      "ws"),
    "E0:99:71": ("Samsung Electronics",      "ws"),
    "E4:40:E2": ("Samsung Electronics",      "ws"),
    "E8:E5:D6": ("Samsung Electronics",      "ws"),
    "EC:1F:72": ("Samsung Electronics",      "ws"),
    "F0:25:B7": ("Samsung Electronics",      "ws"),
    "F4:42:8F": ("Samsung Electronics",      "ws"),
    "F8:04:2E": ("Samsung Electronics",      "ws"),
    "FC:00:12": ("Samsung Electronics",      "ws"),

    # --- Tuya / Smart home ---
    "68:57:2D": ("Tuya Technology",          "iot"),
    "DC:4F:22": ("Tuya Technology",          "iot"),
    "50:02:91": ("Tuya Technology",          "iot"),
    "84:CF:BF": ("Tuya Technology",          "iot"),
    "BC:FF:4D": ("Tuya Technology",          "iot"),

    # --- Espressif (ESP8266/ESP32) ---
    "10:52:1C": ("Espressif",                "iot"),
    "18:FE:34": ("Espressif",                "iot"),
    "24:6F:28": ("Espressif",                "iot"),
    "2C:F4:32": ("Espressif",                "iot"),
    "30:AE:A4": ("Espressif",                "iot"),
    "3C:61:05": ("Espressif",                "iot"),
    "3C:71:BF": ("Espressif",                "iot"),
    "40:F5:20": ("Espressif",                "iot"),
    "48:3F:DA": ("Espressif",                "iot"),
    "4C:11:AE": ("Espressif",                "iot"),
    "54:43:54": ("Espressif",                "iot"),
    "58:BF:25": ("Espressif",                "iot"),
    "5C:CF:7F": ("Espressif",                "iot"),
    "60:01:94": ("Espressif",                "iot"),
    "68:C6:3A": ("Espressif",                "iot"),
    "70:03:9F": ("Espressif",                "iot"),
    "7C:49:EB": ("Espressif",                "iot"),
    "80:7D:3A": ("Espressif",                "iot"),
    "84:0D:8E": ("Espressif",                "iot"),
    "84:CC:A8": ("Espressif",                "iot"),
    "84:F3:EB": ("Espressif",                "iot"),
    "8C:AA:B5": ("Espressif",                "iot"),
    "90:97:D5": ("Espressif",                "iot"),
    "94:B9:7E": ("Espressif",                "iot"),
    "98:CD:AC": ("Espressif",                "iot"),
    "A0:20:A6": ("Espressif",                "iot"),
    "A4:CF:12": ("Espressif",                "iot"),
    "A4:E5:7C": ("Espressif",                "iot"),
    "AC:67:B2": ("Espressif",                "iot"),
    "B4:E6:2D": ("Espressif",                "iot"),
    "B8:D6:1A": ("Espressif",                "iot"),
    "BC:DD:C2": ("Espressif",                "iot"),
    "C4:4F:33": ("Espressif",                "iot"),
    "C8:2B:96": ("Espressif",                "iot"),
    "CC:50:E3": ("Espressif",                "iot"),
    "D8:A0:1D": ("Espressif",                "iot"),
    "DC:4F:22": ("Espressif",                "iot"),
    "E8:DB:84": ("Espressif",                "iot"),
    "EC:62:60": ("Espressif",                "iot"),
    "F0:08:D1": ("Espressif",                "iot"),
    "F4:CF:A2": ("Espressif",                "iot"),

    # --- Raspberry Pi ---
    "B4:E6:2D": ("Raspberry Pi Foundation",  "iot"),
    "D8:3A:DD": ("Raspberry Pi Foundation",  "iot"),
    "DC:A6:32": ("Raspberry Pi Foundation",  "iot"),
    "E4:5F:01": ("Raspberry Pi Foundation",  "iot"),

    # --- Sonos ---
    "00:0E:58": ("Sonos",                    "iot"),
    "34:7E:5C": ("Sonos",                    "iot"),
    "48:A6:B8": ("Sonos",                    "iot"),
    "54:2A:1B": ("Sonos",                    "iot"),
    "5C:AA:FD": ("Sonos",                    "iot"),
    "78:28:CA": ("Sonos",                    "iot"),
    "94:9F:3E": ("Sonos",                    "iot"),
    "B8:E9:37": ("Sonos",                    "iot"),
    "D4:A9:28": ("Sonos",                    "iot"),

    # --- Roku ---
    "00:0D:4B": ("Roku",                     "iot"),
    "08:05:81": ("Roku",                     "iot"),
    "AC:3A:7A": ("Roku",                     "iot"),
    "B0:A7:37": ("Roku",                     "iot"),
    "CC:6D:A0": ("Roku",                     "iot"),
    "D4:E2:2F": ("Roku",                     "iot"),
    "DC:3A:5E": ("Roku",                     "iot"),

    # --- Nest / Nest Labs ---
    "00:0E:8F": ("Nest Labs",                "iot"),
    "18:B4:30": ("Nest Labs",                "iot"),
    "20:31:BB": ("Nest Labs",                "iot"),
    "64:16:66": ("Nest Labs",                "iot"),
    "D8:5D:E2": ("Nest Labs",                "iot"),

    # --- Ring ---
    "00:62:6E": ("Ring",                     "iot"),
    "2C:AA:8E": ("Ring",                     "iot"),
    "34:AB:95": ("Ring",                     "iot"),

    # --- Shelly ---
    "3C:61:05": ("Shelly (Allterco)",        "iot"),
    "C4:5B:BE": ("Shelly (Allterco)",        "iot"),
    "E0:98:06": ("Shelly (Allterco)",        "iot"),

    # --- Brother printers ---
    "00:04:1C": ("Brother Industries",       "prn"),
    "00:0C:8C": ("Brother Industries",       "prn"),
    "00:1B:A9": ("Brother Industries",       "prn"),
    "00:80:92": ("Brother Industries",       "prn"),
    "04:CD:82": ("Brother Industries",       "prn"),
    "14:2D:27": ("Brother Industries",       "prn"),
    "1C:87:74": ("Brother Industries",       "prn"),
    "20:43:A8": ("Brother Industries",       "prn"),
    "30:05:5C": ("Brother Industries",       "prn"),
    "30:C9:AB": ("Brother Industries",       "prn"),
    "3C:2A:F4": ("Brother Industries",       "prn"),
    "40:5B:D8": ("Brother Industries",       "prn"),
    "40:EE:DD": ("Brother Industries",       "prn"),
    "48:E7:DA": ("Brother Industries",       "prn"),
    "54:56:1B": ("Brother Industries",       "prn"),
    "58:40:4E": ("Brother Industries",       "prn"),
    "5C:C5:D4": ("Brother Industries",       "prn"),
    "64:70:02": ("Brother Industries",       "prn"),
    "70:77:81": ("Brother Industries",       "prn"),
    "74:27:EA": ("Brother Industries",       "prn"),
    "78:31:C1": ("Brother Industries",       "prn"),
    "7C:EB:52": ("Brother Industries",       "prn"),
    "84:CF:BF": ("Brother Industries",       "prn"),
    "AC:BD:4D": ("Brother Industries",       "prn"),
    "B0:42:17": ("Brother Industries",       "prn"),
    "C0:D3:91": ("Brother Industries",       "prn"),
    "D0:AB:D5": ("Brother Industries",       "prn"),
    "D4:20:B0": ("Brother Industries",       "prn"),

    # --- HP printers ---
    "00:01:E6": ("Hewlett-Packard",          "prn"),
    "00:11:0A": ("Hewlett-Packard",          "prn"),
    "00:17:08": ("Hewlett-Packard",          "prn"),
    "00:1E:0B": ("Hewlett-Packard",          "prn"),
    "00:24:81": ("Hewlett-Packard",          "prn"),
    "00:30:6E": ("Hewlett-Packard",          "prn"),
    "0C:96:E6": ("Hewlett-Packard",          "prn"),
    "1C:C1:DE": ("Hewlett-Packard",          "prn"),
    "3C:D9:2B": ("Hewlett-Packard",          "prn"),
    "40:B0:34": ("Hewlett-Packard",          "prn"),
    "48:96:B7": ("Hewlett-Packard",          "prn"),
    "54:28:F0": ("Hewlett-Packard",          "prn"),
    "70:5A:0F": ("Hewlett-Packard",          "prn"),
    "78:AC:C0": ("Hewlett-Packard",          "prn"),
    "80:C1:6E": ("Hewlett-Packard",          "prn"),
    "90:E7:C4": ("Hewlett-Packard",          "prn"),
    "A0:D3:C1": ("Hewlett-Packard",          "prn"),
    "AC:16:2D": ("Hewlett-Packard",          "prn"),
    "B0:5A:DA": ("Hewlett-Packard",          "prn"),
    "BC:85:56": ("Hewlett-Packard",          "prn"),
    "FC:3F:DB": ("Hewlett-Packard",          "srv"),  # servers/workstations

    # --- Grandstream VoIP ---
    "00:0B:82": ("Grandstream Networks",     "voi"),
    "A4:BF:01": ("Grandstream Networks",     "voi"),
    "C0:74:2B": ("Grandstream Networks",     "voi"),

    # --- Yealink VoIP ---
    "00:15:65": ("Yealink Network Technology","voi"),
    "00:1F:0A": ("Yealink Network Technology","voi"),
    "80:5E:C0": ("Yealink Network Technology","voi"),
    "C0:74:AD": ("Yealink Network Technology","voi"),

    # --- Polycom VoIP ---
    "00:04:F2": ("Polycom",                  "voi"),
    "00:E0:75": ("Polycom",                  "voi"),
    "64:16:7F": ("Polycom",                  "voi"),

    # --- Cisco VoIP (7900 series) ---
    "00:11:21": ("Cisco VoIP",               "voi"),
    "00:1E:13": ("Cisco VoIP",               "voi"),
    "00:1E:7A": ("Cisco VoIP",               "voi"),
    "00:25:B4": ("Cisco VoIP",               "voi"),
    "00:26:0B": ("Cisco VoIP",               "voi"),
    "10:BD:18": ("Cisco VoIP",               "voi"),
    "58:97:1E": ("Cisco VoIP",               "voi"),
    "88:75:56": ("Cisco VoIP",               "voi"),

    # --- VMware ---
    "00:0C:29": ("VMware",                   "srv"),  # VMware guest VM NIC
    "00:50:56": ("VMware",                   "srv"),  # VMware guest VM NIC
    "00:05:69": ("VMware",                   "hv"),

    # --- Microsoft Hyper-V ---
    "00:15:5D": ("Microsoft Hyper-V",        "srv"),  # guest VM NIC — host may or may not be hv

    # --- Proxmox / Virtual ---
    "08:00:27": ("VirtualBox",               "srv"),  # VirtualBox guest VM NIC

    # --- Siemens OT ---
    "00:0E:CF": ("Profibus (Siemens/Beckhoff)","ot"),
    "00:1B:78": ("Siemens",                  "ot"),
    "28:63:36": ("Siemens",                  "ot"),
    "50:4D:E1": ("Siemens",                  "ot"),
    "AC:64:17": ("Siemens",                  "ot"),

    # --- Dell ---
    "00:08:74": ("Dell Technologies",        "srv"),
    "14:18:77": ("Dell Technologies",        "srv"),
    "18:03:73": ("Dell Technologies",        "srv"),
    "18:66:DA": ("Dell Technologies",        "srv"),
    "34:17:EB": ("Dell Technologies",        "srv"),
    "44:A8:42": ("Dell Technologies",        "srv"),
    "54:9F:35": ("Dell Technologies",        "srv"),
    "74:86:E2": ("Dell Technologies",        "srv"),
    "84:7B:EB": ("Dell Technologies",        "srv"),
    "B0:83:FE": ("Dell Technologies",        "srv"),
    "B8:AC:6F": ("Dell Technologies",        "srv"),
    "F4:8E:38": ("Dell Technologies",        "srv"),
    "F8:DB:88": ("Dell Technologies",        "srv"),

    # --- Intel server NICs ---
    "00:1B:21": ("Intel",                    "srv"),
    "00:1E:67": ("Intel",                    "srv"),
    "68:05:CA": ("Intel",                    "srv"),
    "A4:BF:01": ("Intel",                    "srv"),

    # --- Supermicro ---
    "00:25:90": ("Supermicro",               "srv"),
    "0C:C4:7A": ("Supermicro",               "srv"),
    "AC:1F:6B": ("Supermicro",               "srv"),

    # --- Synology NAS ---
    "00:11:32": ("Synology",                 "srv"),
    "BC:5F:F4": ("Synology",                 "srv"),

    # --- QNAP NAS ---
    "00:08:9B": ("QNAP Systems",             "srv"),
    "24:5E:BE": ("QNAP Systems",             "srv"),

    # --- Apple (additional) ---
    "E8:FF:1E": ("Apple",                    "ws"),
    "A4:0E:2B": ("Apple",                    "ws"),
    "A8:4A:63": ("Apple",                    "ws"),
    "EC:8A:C4": ("Apple",                    "ws"),
    "7C:D5:66": ("Apple",                    "ws"),
    "14:7D:DA": ("Apple",                    "ws"),
    "3C:06:30": ("Apple",                    "ws"),
    "6C:96:CF": ("Apple",                    "ws"),
    "8C:8D:28": ("Apple",                    "ws"),
    "AC:BC:32": ("Apple",                    "ws"),
    "F0:DB:F8": ("Apple",                    "ws"),

    # --- Samsung (additional) ---
    "98:17:3C": ("Samsung Electronics",      "ws"),
    "04:99:B9": ("Samsung Electronics",      "ws"),
    "54:3A:D6": ("Samsung Electronics",      "ws"),

    # --- Intel laptop NICs ---
    "28:24:C9": ("Intel",                    "ws"),
    "B4:B0:24": ("Intel",                    "ws"),
    "8C:8D:28": ("Intel",                    "ws"),
    "94:65:9C": ("Intel",                    "ws"),
    "AC:E2:D3": ("Intel",                    "ws"),
    "D4:3B:04": ("Intel",                    "ws"),
    "F8:94:C2": ("Intel",                    "ws"),

    # --- Realtek (laptops/PCs) ---
    "E4:2A:AC": ("Realtek",                  "ws"),
    "00:E0:4C": ("Realtek",                  "ws"),

    # --- Liteon (laptop NICs, common in Lenovo/HP) ---
    "DC:A0:D0": ("Liteon Technology",        "ws"),
    "60:57:18": ("Liteon Technology",        "ws"),
    "74:E5:43": ("Liteon Technology",        "ws"),

    # --- Xiaomi ---
    "F0:A7:31": ("Xiaomi",                   "iot"),
    "28:6C:07": ("Xiaomi",                   "iot"),
    "34:CE:00": ("Xiaomi",                   "iot"),
    "50:64:2B": ("Xiaomi",                   "iot"),
    "64:09:80": ("Xiaomi",                   "iot"),
    "74:23:44": ("Xiaomi",                   "iot"),
    "8C:BE:BE": ("Xiaomi",                   "iot"),
    "AC:F7:F3": ("Xiaomi",                   "iot"),
    "D4:97:0B": ("Xiaomi",                   "iot"),
    "F8:A4:5F": ("Xiaomi",                   "iot"),

    # --- Shenzhen Bilian (generic IoT modules) ---
    "D4:AD:FC": ("Shenzhen Bilian",          "iot"),
    "C8:3A:35": ("Shenzhen Bilian",          "iot"),
    "4C:11:AE": ("Shenzhen Bilian",          "iot"),

    # --- Texas Instruments (embedded / IoT) ---
    "00:1C:C2": ("Texas Instruments",        "iot"),
    "00:12:37": ("Texas Instruments",        "iot"),
    "00:17:EC": ("Texas Instruments",        "iot"),
    "34:03:DE": ("Texas Instruments",        "iot"),
    "78:A5:04": ("Texas Instruments",        "iot"),

    # --- Murata (IoT modules — used by Sony, Nintendo, etc.) ---
    "00:D2:B1": ("Murata Manufacturing",     "iot"),
    "04:CB:88": ("Murata Manufacturing",     "iot"),
    "8C:CE:4E": ("Murata Manufacturing",     "iot"),
    "CC:43:E3": ("Murata Manufacturing",     "iot"),

    # --- LG Electronics ---
    "A0:92:08": ("LG Electronics",           "ws"),
    "10:68:3F": ("LG Electronics",           "ws"),
    "28:39:5E": ("LG Electronics",           "ws"),
    "48:59:29": ("LG Electronics",           "ws"),
    "64:99:5D": ("LG Electronics",           "ws"),
    "88:C9:D0": ("LG Electronics",           "ws"),
    "BC:F5:AC": ("LG Electronics",           "ws"),
    "CC:FA:00": ("LG Electronics",           "ws"),
    "E8:5D:86": ("LG Electronics",           "ws"),

    # --- Vivo Mobile ---
    "B0:4F:13": ("Vivo Mobile",              "ws"),
    "14:97:45": ("Vivo Mobile",              "ws"),
    "28:7F:CF": ("Vivo Mobile",              "ws"),

    # --- TP-Link smart plugs / extenders ---
    "DC:54:D7": ("TP-Link",                  "iot"),
    "50:91:E3": ("TP-Link",                  "iot"),
    "88:C3:97": ("TP-Link",                  "iot"),
    "C0:C9:E3": ("TP-Link",                  "iot"),

    # --- Buffalo NAS / routers ---
    "E8:48:B8": ("Buffalo Americas",         "net"),
    "1C:87:2C": ("Buffalo Americas",         "net"),
    "2C:FD:A1": ("Buffalo Americas",         "net"),

    # --- 1C:69:7A — appears to be Azurewave (common in thin clients / mini PCs) ---
    "1C:69:7A": ("AzureWave Technology",     "ws"),

    # --- Ubiquiti (additional) ---
    "74:AC:B9": ("Ubiquiti Networks",        "net"),
    "28:87:BA": ("Ubiquiti Networks",        "net"),
    "3C:A9:AB": ("Ubiquiti Networks",        "net"),
    "34:F1:50": ("Ubiquiti Networks",        "net"),
    "80:B6:55": ("Ubiquiti Networks",        "net"),
    "80:B5:4E": ("Ubiquiti Networks",        "net"),
    "44:3D:54": ("Ubiquiti Networks",        "net"),
}

# Loaded at runtime from data/oui_map.json (generated by sync_oui.py)
EXTERNAL_OUI_TABLE: dict[str, tuple[str, str]] = {}


def load_external_oui_map(path: str | Path) -> int:
    """
    Load external OUI mappings from JSON:
      {"AA:BB:CC": {"vendor": "Acme", "category": "srv"}, ...}
    Returns number of loaded entries.
    """
    global EXTERNAL_OUI_TABLE
    p = Path(path)
    if not p.exists():
        EXTERNAL_OUI_TABLE = {}
        return 0
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        parsed: dict[str, tuple[str, str]] = {}
        for k, v in raw.items():
            key = str(k).upper().replace("-", ":").strip()
            if not re.match(r"^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}$", key):
                continue
            vendor = ""
            cat = ""
            if isinstance(v, dict):
                vendor = str(v.get("vendor") or "").strip()
                cat = str(v.get("category") or "").strip()
            elif isinstance(v, str):
                vendor = v.strip()
            if vendor:
                parsed[key] = (vendor, cat if cat in {"net", "srv", "ws", "iot", "prn", "hv", "ot", "voi"} else "")
        EXTERNAL_OUI_TABLE = parsed
        return len(EXTERNAL_OUI_TABLE)
    except Exception:
        EXTERNAL_OUI_TABLE = {}
        return 0


# ---------------------------------------------------------------------------
# Hostname patterns → (category, vendor_hint)
# Matched against the hostname before port/banner analysis
# Gives us classification even when no ports are open
# ---------------------------------------------------------------------------
HOSTNAME_PATTERNS: list[tuple[str, str, str]] = [
    # pattern (case-insensitive),     category, vendor_hint
    # UniFi device naming conventions
    (r"^U[ADG]M",                     "net",   "Ubiquiti Networks"),
    (r"^USW[-_]",                     "net",   "Ubiquiti Networks"),
    (r"^UAP[-_]",                     "net",   "Ubiquiti Networks"),
    (r"^UDM[-_]?",                    "net",   "Ubiquiti Networks"),
    (r"^USG[-_]",                     "net",   "Ubiquiti Networks"),
    # Meraki device naming — require specific Meraki patterns, not just MR prefix
    # UniFi also uses MR prefix (MR Flex) so OUI should take priority
    (r"^MR\d{2}",                     "net",   "Cisco Meraki"),   # MR33, MR46 etc
    (r"Meraki",                       "net",   "Cisco Meraki"),
    (r"^unifi",                       "net",   "Ubiquiti Networks"),
    (r"^[Pp]ortal-[0-9a-fA-F]{12}",    "iot",   "Meta"),  # Meta Portal device (MAC-based hostname)
    (r"^U[A-Z]{2,}-",                  "net",   "Ubiquiti Networks"),  # UAP-, USW-, UDM- etc

    # Switch naming patterns
    (r"[Ss]witch",                    "net",   ""),
    (r"[-_][Ss][Ww]$",               "net",   ""),
    (r"^[A-Z]{2}[Ss]witch",          "net",   ""),  # FCSwitch, DRSwitch etc
    (r"^SW[-_\d]",                    "net",   ""),
    (r"router",                       "net",   ""),
    (r"gateway",                      "net",   ""),
    (r"firewall",                     "net",   ""),
    (r"^AP[-_\d]",                    "net",   ""),   # access point
    (r"[-_]AP[-_\d]",                "net",   ""),

    # Google / Chromecast / Home
    (r"Chromecast",                   "iot",   "Google"),
    (r"Google[-_]Home",               "iot",   "Google"),
    (r"Google[-_]Nest",               "iot",   "Google"),
    (r"Nest[-_]",                     "iot",   "Google / Nest"),
    (r"GoogleHome",                   "iot",   "Google"),

    # Meta / Facebook
    (r"^[Pp]ortal",                    "iot",   "Meta"),
    (r"Quest[-_]",                     "iot",   "Meta"),
    (r"Oculus",                        "iot",   "Meta"),

    # Amazon
    (r"Echo[-_]",                     "iot",   "Amazon"),
    (r"Fire[-_]TV",                   "iot",   "Amazon"),
    (r"Kindle",                       "iot",   "Amazon"),
    (r"^Amazon",                      "iot",   "Amazon"),

    # Smart TVs and streaming
    (r"Roku",                         "iot",   "Roku"),
    (r"Apple[-_]TV",                  "iot",   "Apple"),
    (r"Android[-_]TV",                "iot",   ""),
    (r"Pixel[-_]Tablet",              "iot",   "Google"),
    (r"Television",                   "iot",   ""),
    (r"[-_]TV$",                      "iot",   ""),

    # Wearables
    (r"[Aa]pple[-_]?[Ww]atch",         "iot",   "Apple"),
    (r"watch\.vedders",                "iot",   "Apple"),   # personal hostname pattern
    (r"[-_.]watch[-_.]",               "iot",   ""),
    (r"^watch\d*$",                   "iot",   ""),
    (r"Fitbit",                        "iot",   "Fitbit"),
    (r"Garmin",                        "iot",   "Garmin"),
    (r"[-_]watch$",                    "iot",   ""),

    # Phones / tablets / ChromeOS
    (r"iPhone",                       "ws",    "Apple"),
    (r"iPad|iPadOS",                  "ws",    "Apple"),
    (r"MacBook",                      "ws",    "Apple"),
    (r"Mac[-_]?(Studio|mini|Pro)\b",   "ws",    "Apple"),
    (r"iMac",                         "ws",    "Apple"),
    (r"Chromebook|Chrome[-_]OS|\bCrOS\b", "ws", ""),
    (r"Android_",                     "ws",    ""),
    (r"Pixel[-_]\d",                  "ws",    "Google"),
    (r"Galaxy",                       "ws",    "Samsung"),

    # Printers
    (r"^BRW",                         "prn",   "Brother Industries"),  # Brother default hostname
    (r"^HP",                          "prn",   "Hewlett-Packard"),
    (r"LaserJet",                     "prn",   "Hewlett-Packard"),
    (r"OfficeJet",                    "prn",   "Hewlett-Packard"),
    (r"EPSON",                        "prn",   "Epson"),
    (r"Canon",                        "prn",   "Canon"),
    (r"Ricoh",                        "prn",   "Ricoh"),
    (r"Xerox",                        "prn",   "Xerox"),
    (r"Lexmark",                      "prn",   "Lexmark"),

    # VoIP
    (r"SIP[-_]",                      "voi",   ""),
    (r"GXP\d",                        "voi",   "Grandstream Networks"),
    (r"rodecaster",                   "voi",   "Rode"),
    (r"polycom",                      "voi",   "Polycom"),
    (r"yealink",                      "voi",   "Yealink"),

    # NAS / storage
    (r"^DS\d{3}",                     "srv",   "Synology"),
    (r"Synology",                     "srv",   "Synology"),
    (r"QNAP",                         "srv",   "QNAP"),
    (r"^TS[-_]\d",                    "srv",   "QNAP"),
    (r"NAS",                          "srv",   ""),

    # Cameras / security
    (r"camera",                       "iot",   ""),
    (r"CAM[-_\d]",                    "iot",   ""),
    (r"doorbell",                     "iot",   ""),
    (r"^Ring",                        "iot",   "Ring"),

    # HDHomeRun tuner
    (r"^HDHR",                        "iot",   "SiliconDust"),

    # Common Linux server hostnames
    (r"surveytrace",                  "srv",   "SurveyTrace"),
    (r"grafana",                      "srv",   ""),
    (r"\bplex\b",                     "srv",   ""),
    (r"jellyfin",                     "srv",   ""),
    (r"pihole|adguard",               "srv",   ""),
    (r"homeassistant|home-assistant", "iot",   "Home Assistant"),
    (r"openhab",                      "iot",   ""),
    (r"mosquitto|mqtt",               "iot",   ""),
    (r"gitea|gitlab|github",          "srv",   ""),
    (r"nextcloud|owncloud",           "srv",   ""),
    (r"portainer",                    "srv",   ""),
    # Photon OS hostnames — category only; hardware vendor stays from OUI (e.g. HP mini)
    (r"\bphoton\b",                   "srv",   ""),
    (r"proxmox|pve\.|\.pve\b|pve-",    "hv",    "Proxmox"),
    (r"zabbix",                       "srv",   "Zabbix"),
    (r"kasm",                         "voi",   "Kasm Workspaces"),
    (r"ntfy",                         "srv",   "ntfy"),
    (r"mastodon",                     "srv",   "Mastodon"),
    (r"hyperv|hyper-v",               "hv",    "Microsoft Hyper-V"),
    (r"^hvhost",                       "hv",    ""),
    (r"esxi|vcenter|vsphere|vmhost|esx[-_]?\d", "hv",    "VMware"),
    (r"truenas|freenas",              "srv",   "TrueNAS"),
    (r"opnsense|pfsense",             "net",   ""),
    (r"vpn",                          "net",   ""),
]


# ---------------------------------------------------------------------------
# Port profiles → (required_ports, category, cpe_fragment, description)
# ---------------------------------------------------------------------------
PORT_PROFILES: list[tuple[set[int], str, str, str]] = [
    # OT / ICS — highest priority, check first
    ({102},              "ot",  "siemens:s7",           "Siemens S7 (ISO-TSAP)"),
    ({502},              "ot",  "modbus",                "Modbus TCP"),
    ({20000},            "ot",  "dnp3",                  "DNP3"),
    ({44818},            "ot",  "ethernet_ip",           "EtherNet/IP"),
    ({4840},             "ot",  "opc_ua",                "OPC-UA"),

    # Hypervisors
    ({902, 903},         "hv",  "vmware:esxi",           "VMware ESXi"),
    # vCenter Server Appliance / VAMI (distinctive vs generic 443 sites)
    ({5480},             "hv",  "vmware:vcenter",        "VMware vCenter Appliance (VAMI)"),
    # PVE web UI is 8006; 8007 is optional — match on either alone
    ({8006, 8007},       "hv",  "proxmox:ve",            "Proxmox VE"),

    # Monitoring / messaging (distinctive ports before generic DB rules)
    ({10051},            "srv", "zabbix:zabbix_server",  "Zabbix server (trapper)"),
    ({2375, 2376},       "srv", "docker:engine",         "Docker Engine API"),

    # VoIP
    ({5060},             "voi", "sip",                   "SIP / VoIP"),
    ({5061},             "voi", "sip",                   "SIP TLS / VoIP"),

    # Printers
    ({9100},             "prn", "printer",               "JetDirect / raw print"),
    ({631},              "prn", "ipp",                   "IPP printer"),

    # IoT / smart home
    ({1883},             "iot", "mqtt",                  "MQTT broker"),
    ({8883},             "iot", "mqtt",                  "MQTT TLS broker"),

    # Windows workstations / servers
    ({3389},             "ws",  "microsoft:windows",     "RDP → Windows"),
    ({5985, 5986},       "ws",  "microsoft:windows",     "WinRM → Windows"),
    ({135, 445},         "ws",  "microsoft:windows",     "SMB/RPC → Windows"),

    # Servers
    ({3306},             "srv", "mysql:mysql_server",    "MySQL"),
    ({5432},             "srv", "postgresql:postgresql", "PostgreSQL"),
    ({6379},             "srv", "redis:redis",           "Redis"),
    ({27017},            "srv", "mongodb:mongodb",       "MongoDB"),
    ({9200},             "srv", "elastic:elasticsearch", "Elasticsearch"),
    ({5900},             "srv", "vnc",                   "VNC"),
]


# ---------------------------------------------------------------------------
# Banner patterns → (regex, category, cpe_fragment)
# ---------------------------------------------------------------------------
BANNER_PATTERNS: list[tuple[str, str, str]] = [
    # Network gear — check before generic srv patterns
    (r"UniFi|Ubiquiti",              "net",  "ubiquiti:unifi"),
    (r"BIG.?IP",                     "net",  "f5:big_ip"),
    (r"Cisco IOS XE",                "net",  "cisco:ios_xe"),
    (r"Cisco IOS",                   "net",  "cisco:ios"),
    (r"Cisco Adaptive|Cisco ASA",    "net",  "cisco:asa"),
    (r"Cisco Meraki",                "net",  "cisco:meraki"),
    (r"Junos|JunOS",                 "net",  "juniper:junos"),
    (r"FortiOS|FortiGate",           "net",  "fortinet:fortios"),
    (r"pfsense",                     "net",  "netgate:pfsense"),
    (r"OPNsense",                    "net",  "opnsense:opnsense"),
    (r"MikroTik|RouterOS",           "net",  "mikrotik:routeros"),
    (r"pfSense",                     "net",  "netgate:pfsense"),
    (r"OpenWrt",                     "net",  "openwrt:openwrt"),
    (r"DD-WRT",                      "net",  "dd-wrt:dd-wrt"),

    # Hypervisors
    (r"VMware ESXi",                 "hv",   "vmware:esxi"),
    (r"vSphere\s+(Web\s+)?Client|VMware\s+vSphere|vCenter\s+Server|VMware\s+vCenter",
                                      "hv",   "vmware:vsphere"),
    (r"Proxmox",                     "hv",   "proxmox:ve"),
    (r"XenServer|XCP-ng",            "hv",   "xen:xenserver"),
    (r"Microsoft-HTTPAPI.*Hyper.?V", "hv",   "microsoft:hyper_v"),

    # OT / ICS
    (r"SIMATIC|S7-",                 "ot",   "siemens:simatic"),
    (r"Schneider|Modicon",           "ot",   "schneider_electric:modicon"),
    (r"Allen.?Bradley|ControlLogix", "ot",   "rockwell:controllogix"),
    (r"CODESYS",                     "ot",   "codesys:codesys"),

    # VoIP
    (r"Grandstream",                 "voi",  "grandstream:gxp"),
    (r"Polycom",                     "voi",  "polycom:realpresence"),
    (r"Yealink",                     "voi",  "yealink:sip"),
    (r"Cisco IP Phone|SEP[0-9A-F]{12}",  "voi",  "cisco:ip_phone"),
    (r"Asterisk",                    "voi",  "digium:asterisk"),
    (r"FreeSWITCH",                  "voi",  "freeswitch:freeswitch"),

    # VMware Photon OS — before printer patterns (some dashboards embed HPHTTP / LaserJet-like text)
    (r"VMware\s+Photon|Photon\s+OS|PHOTON_BUILD|photon-release",
                                     "srv",  "vmware:photon_os"),

    # Printers
    # Keep HP printer detection strict; broad "HP.*Jet" caused false positives
    # on non-printer hosts with unrelated banner text.
    (r"\bHP\s*LaserJet\b|\bHPHTTP\b", "prn",  "hp:laserjet"),
    (r"Brother",                     "prn",  "brother:mfc"),
    (r"Ricoh",                       "prn",  "ricoh:printer"),
    (r"Xerox",                       "prn",  "xerox:workcentre"),
    (r"Canon",                       "prn",  "canon:imagerunner"),
    (r"Epson",                       "prn",  "epson:printer"),
    (r"Lexmark",                     "prn",  "lexmark:printer"),
    (r"Kyocera",                     "prn",  "kyocera:printer"),

    # IoT / smart home
    (r"Shelly",                      "iot",  "allterco:shelly"),
    (r"Tasmota",                     "iot",  "tasmota:tasmota"),
    (r"Raspberry Pi",                "iot",  "raspberrypi:raspberry_pi"),
    (r"Home Assistant",              "iot",  "home_assistant:home_assistant"),
    (r"Tuya",                        "iot",  "tuya:tuya"),
    (r"Chromecast|Google Cast",      "iot",  "google:chromecast"),
    (r"Roku",                        "iot",  "roku:roku"),
    (r"Sonos",                       "iot",  "sonos:sonos"),
    (r"HDHomeRun|hdhomerun",         "iot",  "silicondust:hdhomerun"),
    # Keep this strict: plain "ring" appears in unrelated strings (e.g. "BoringSSL", "keyring")
    (r"\bRing\b|\bRing[- ]Doorbell\b", "iot",  "ring:ring"),

    # Servers — identifiable apps before generic nginx/Apache (first match wins).
    (r"Zabbix|zabbix\.js|zabbix-server", "srv", "zabbix:zabbix"),
    (r"\bntfy\b",                    "srv",  "ntfy:server"),
    (r"Kasm|kasmweb|KasmVNC",        "voi",  "kasm:workspace"),
    (r"Mastodon",                    "srv",  "mastodon:mastodon"),
    (r"Grafana",                     "srv",  "grafana:grafana"),
    (r"AdGuard",                     "srv",  "adguard:adguardhome"),
    # Pi-hole often banners as dnsmasq … pi-hole (no literal "Pi-hole" substring).
    (r"Pi[-\s]?hole|\bpihole\b|\bdnsmasq\b.{0,200}pi[-\s]?hole", "srv", "pi-hole:pi-hole"),
    (r"Nginx[-\s]?Proxy[-\s]?Manager|nginxproxymanager|NPM\s+reverse\s+proxy", "srv", "nginx_proxy_manager:nginx_proxy_manager"),
    (r"Portainer|\bportainer\b|\[?Vedorama\]?", "srv", "portainer:portainer"),
    (r"Uptime[\s_-]?Kuma",           "srv",  "uptime_kuma:uptime_kuma"),
    (r"Karakeep",                    "srv",  "karakeep:karakeep"),
    (r"Open\s*WebUI|OpenWebUI",      "srv",  "open_webui:open_webui"),
    (r"Homarr",                      "srv",  "homarr:homarr"),
    (r"Plex Media",                  "srv",  "plex:plex_media_server"),
    (r"Jellyfin",                    "srv",  "jellyfin:jellyfin"),
    (r"Nextcloud",                   "srv",  "nextcloud:nextcloud"),
    (r"Gitea",                       "srv",  "gitea:gitea"),
    (r"GitLab",                      "srv",  "gitlab:gitlab"),
    # Generic daemons (OpenResty / NPM still hits "nginx" — keep products above).
    (r"nginx",                       "srv",  "nginx:nginx"),
    (r"Apache",                      "srv",  "apache:http_server"),
    (r"OpenSSH.*Ubuntu",             "srv",  "canonical:ubuntu_linux"),
    (r"OpenSSH.*Debian",             "srv",  "debian:debian_linux"),
    (r"OpenSSH.*CentOS|OpenSSH.*Rocky|OpenSSH.*AlmaLinux",
                                     "srv",  "redhat:enterprise_linux"),
    (r"Microsoft-HTTPAPI|IIS",       "srv",  "microsoft:iis"),
    (r"Lighttpd",                    "srv",  "lighttpd:lighttpd"),
    (r"Caddy",                       "srv",  "caddyserver:caddy"),
]


# ---------------------------------------------------------------------------
# Lookup functions
# ---------------------------------------------------------------------------
def is_locally_administered(mac: str) -> bool:
    """
    Returns True if the MAC is locally-administered (randomized).
    The second hex digit being 2, 6, A, or E indicates LA bit is set.
    macOS, Android, and Windows all use randomized MACs by default on Wi-Fi.
    """
    if not mac:
        return False
    try:
        first_octet = int(mac.replace("-", ":").split(":")[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


def oui_lookup(mac: str) -> tuple[str, str]:
    """Return (vendor, category_hint) for a MAC address, or ('', '')."""
    if not mac:
        return "", ""
    # Locally-administered (randomized) MACs can't be OUI-identified
    if is_locally_administered(mac):
        return "", ""
    norm   = mac.upper().replace("-", ":").strip()
    prefix = ":".join(norm.split(":")[:3])

    # Manual overrides for vendors with stale/misattributed OUI entries
    OUI_OVERRIDES: dict[str, tuple[str, str]] = {
        # Meta / Facebook Portal and hardware
        "A4:0E:2B": ("Meta",    "iot"),
        "54:EF:44": ("Meta",    "iot"),
        "4C:3B:DF": ("Meta",    "iot"),
        "0C:98:38": ("Meta",    "iot"),
        "B0:CE:18": ("Meta",    "iot"),  # Quest VR
        # Sonos
        "5C:AA:FD": ("Sonos",   "iot"),
        "B8:E9:37": ("Sonos",   "iot"),
        "94:9F:3E": ("Sonos",   "iot"),
        "78:28:CA": ("Sonos",   "iot"),
    }
    if prefix in OUI_OVERRIDES:
        return OUI_OVERRIDES[prefix]

    # Runtime-fed map from IEEE sync takes precedence over hardcoded table
    ext = EXTERNAL_OUI_TABLE.get(prefix)
    if ext:
        return ext

    entry = OUI_TABLE.get(prefix)
    return entry if entry else ("", "")


def classify_from_hostname(hostname: str) -> tuple[str, str]:
    """
    Return (category, vendor_hint) based on hostname patterns.
    Returns ('', '') if no pattern matches.
    """
    if not hostname:
        return "", ""
    for pattern, cat, vendor in HOSTNAME_PATTERNS:
        if re.search(pattern, hostname, re.IGNORECASE):
            return cat, vendor
    return "", ""


def classify_from_ports(ports: list[int]) -> tuple[str, str, str]:
    """
    Return (category, cpe_fragment, description) based on open port set.
    Returns ('', '', '') if no profile matches.
    """
    port_set = set(ports)
    for required, cat, cpe, desc in PORT_PROFILES:
        if required & port_set:
            return cat, cpe, desc
    return "", "", ""


def vendor_hint_from_port_cpe(cpe_fragment: str) -> str:
    """Display vendor/product for known port-profile CPE fragments."""
    if not cpe_fragment:
        return ""
    low = cpe_fragment.lower()
    if "proxmox" in low:
        return "Proxmox"
    if "vmware" in low or "esxi" in low:
        return "VMware"
    if "zabbix" in low:
        return "Zabbix"
    if "docker" in low:
        return "Docker"
    return ""


def cpe_uri_from_port_fragment(cpe_fragment: str) -> str:
    """Build a full CPE URI from a port-profile fragment (uses correct a/h/o prefix)."""
    if not cpe_fragment:
        return ""
    return f"cpe:/{_cpe_type(cpe_fragment)}:{cpe_fragment}:*"


def _printer_banner_conflicts_with_homelab_ports(port_set: set[int]) -> bool:
    """SSH plus typical container-dashboard ports — not a JetDirect-style printer."""
    if 22 not in port_set:
        return False
    if 9443 in port_set:  # Portainer HTTPS
        return True
    # Many distinct app ports + SSH is almost never a single-function printer
    return len(port_set) >= 10


def _linux_distro_evidence_in_combined(combined: str) -> bool:
    """
    Strong Linux OS signal in banners (SSH distro string, etc.).
    Used to avoid treating RDP (3389) alone as Windows when xrdp/Kasm/Linux VDI is common.
    """
    if re.search(
        r"OpenSSH[^\n]{0,160}(Ubuntu|Debian|Rocky|AlmaLinux|CentOS|Fedora|Arch\s+Linux)\b",
        combined,
        re.IGNORECASE,
    ):
        return True
    if re.search(r"\b(ubuntu|debian)\s+linux\b", combined, re.IGNORECASE):
        return True
    if re.search(r"\bxrdp\b|\bx11vnc\b", combined, re.IGNORECASE):
        return True
    return False


def _ports_for_windows_endpoint_profile(ports: list[int], combined: str) -> list[int]:
    """
    Drop 3389 from port-profile classification when banners already show Linux.
    Port profile {3389}→ws/microsoft:windows is meant for real Windows endpoints; RDP on
    Linux VMs (xrdp, Kasm, Guacamole) should not force that classification.
    """
    norm: list[int] = []
    for p in ports:
        try:
            pi = int(p)
        except (TypeError, ValueError):
            continue
        if 1 <= pi <= 65535:
            norm.append(pi)
    if 3389 not in norm or not _linux_distro_evidence_in_combined(combined):
        return norm
    return [p for p in norm if p != 3389]


def classify_from_banners(banners: dict[str, str]) -> tuple[str, str]:
    """
    Scan all banner strings against BANNER_PATTERNS.
    Returns (category, cpe_fragment) for the first match.
    """
    combined = " ".join(banners.values())
    for pattern, cat, cpe in BANNER_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            return cat, cpe
    return "", ""


# ---------------------------------------------------------------------------
# CPE type helper — determines correct type prefix (a/h/o)
# ---------------------------------------------------------------------------
# Software/applications → a
_CPE_APP_PREFIXES = {
    "nginx", "apache", "lighttpd", "caddy", "mysql", "postgresql", "redis",
    "mongodb", "elastic", "openbsd", "canonical", "debian", "redhat",
    "microsoft:iis", "microsoft:windows_server", "cisco:ios", "cisco:ios_xe",
    "cisco:asa", "fortinet:fortios", "netgate:pfsense", "opnsense:opnsense",
    "mikrotik:routeros", "openwrt:openwrt", "dd-wrt:dd-wrt", "gitea:gitea",
    "gitlab:gitlab", "grafana:grafana", "adguard:adguardhome",
    "jellyfin:jellyfin", "nextcloud:nextcloud", "plex:plex_media_server",
    "digium:asterisk", "freeswitch:freeswitch", "xen:xenserver",
    "proxmox:ve", "vmware:esxi", "vmware:vsphere", "vmware:vcenter", "zabbix:zabbix", "zabbix:zabbix_server",
    "docker:engine", "ntfy:server", "kasm:workspace", "mastodon:mastodon",
    "pi-hole", "nginx_proxy_manager", "portainer", "uptime_kuma", "karakeep",
    "open_webui", "homarr",
}
# OS → o
_CPE_OS_PREFIXES = {
    "linux", "microsoft:windows", "apple:macos", "apple:ios",
    "android", "freebsd", "openbsd",
    "vmware:photon",  # VMware Photon OS (container host)
}

def _cpe_type(cpe_fragment: str) -> str:
    """Return the correct CPE type character (a, h, or o) for a fragment."""
    frag = cpe_fragment.lower()
    for prefix in _CPE_OS_PREFIXES:
        if frag.startswith(prefix):
            return "o"
    for prefix in _CPE_APP_PREFIXES:
        if frag.startswith(prefix):
            return "a"
    return "h"  # hardware default for physical devices


def fingerprint(
    mac: str,
    ports: list[int],
    banners: dict[str, str],
    hostname: str = "",
    snmp_sysdescr: str = "",
    routed_scan: bool = False,
) -> dict:
    """
    Combine all signals into a best-guess fingerprint dict.
    Priority (highest to lowest):
      1. Banner patterns (most specific — software/product identified)
      2. Port profiles (protocol-level identification)
      3. Hostname patterns (naming conventions)
      4. OUI lookup (manufacturer baseline)
    """
    result = {"category": "unk", "vendor": "", "cpe": "", "os_guess": ""}

    # 1. OUI baseline — vendor and rough category
    oui_vendor, oui_cat = oui_lookup(mac)
    if oui_vendor:
        result["vendor"]   = oui_vendor
        result["category"] = oui_cat

    # 2. Hostname patterns — refine category if OUI was generic or absent
    if hostname:
        h_cat, h_vendor = classify_from_hostname(hostname)
        if h_cat:
            result["category"] = h_cat
        if h_vendor and not result["vendor"]:
            result["vendor"] = h_vendor

    # For locally-administered (randomized) MACs, use hostname to guess vendor
    # macOS randomizes Wi-Fi MAC by default — hostname is the only reliable signal
    if is_locally_administered(mac) and not result["vendor"]:
        if hostname:
            hn_lower = hostname.lower()
            if any(x in hn_lower for x in ["mac", "iphone", "ipad", "imac", "macbook"]):
                result["vendor"]   = "Apple"
                result["category"] = result["category"] if result["category"] != "unk" else "ws"
            elif any(x in hn_lower for x in ["pixel", "android"]):
                result["vendor"]   = "Google"
                result["category"] = result["category"] if result["category"] != "unk" else "ws"
            elif any(x in hn_lower for x in ["galaxy", "samsung"]):
                result["vendor"]   = "Samsung"
                result["category"] = result["category"] if result["category"] != "unk" else "ws"

    # 3–4. Build banner text once; port profiles then banners (see docstring rationale in code below).
    combined = " ".join(banners.values())
    if snmp_sysdescr:
        combined += " " + snmp_sysdescr

    # 3. Port profiles — protocol-level classification (3389 may be ignored when Linux is proven)
    ports_for_profile = _ports_for_windows_endpoint_profile(ports, combined)
    port_cat, port_cpe, _ = classify_from_ports(ports_for_profile)
    if port_cat:
        result["category"] = port_cat
        if port_cpe:
            result["cpe"] = f"cpe:/{_cpe_type(port_cpe)}:{port_cpe}:*"

    # 4. Banner — highest confidence for category/CPE, but NOT for vendor
    # Network gear hostname takes priority over banner category
    # (e.g. 'unifi' hostname should beat nginx banner → net not srv)
    NETWORK_HOSTNAMES = re.compile(
        r"unifi|switch|router|gateway|firewall|USW|UAP|UDM|USG|MR[A-Z]|access.?point",
        re.IGNORECASE
    )
    port_set = set(ports)
    # PVE / ESXi often present nginx or Linux SSH banners — do not downgrade to generic srv
    _generic_srv_cpe = {
        "nginx:nginx", "apache:http_server", "lighttpd:lighttpd", "caddyserver:caddy",
        "canonical:ubuntu_linux", "debian:debian_linux", "redhat:enterprise_linux",
        "microsoft:iis",
    }
    banner_cat, banner_cpe = "", ""
    skip_generic_banner = False
    if hostname and NETWORK_HOSTNAMES.search(hostname):
        result["category"] = "net"
        # Don't let banner override net category for network devices
        banner_cat, banner_cpe = classify_from_banners({"all": combined})
        if banner_cpe:
            result["cpe"] = f"cpe:/h:{banner_cpe}:*"
    else:
        banner_cat, banner_cpe = classify_from_banners({"all": combined})
        if banner_cat:
            # Do not let a generic printer banner override stronger endpoint/server
            # protocol signals (e.g., RDP/SMB, hypervisor, OT).
            if banner_cat == "prn" and port_cat in ("ws", "srv", "hv", "ot"):
                skip_generic_banner = True
            elif banner_cat == "prn" and hostname and re.search(r"\bphoton\b", hostname, re.I):
                skip_generic_banner = True
            elif banner_cat == "prn" and _printer_banner_conflicts_with_homelab_ports(port_set):
                skip_generic_banner = True
            # If protocol signals already indicate Windows workstation/server traits,
            # avoid downgrading CPE to generic web stack software.
            elif port_cat == "ws" and banner_cat == "srv" and banner_cpe in _generic_srv_cpe:
                skip_generic_banner = True
            if port_set & {8006, 8007} and banner_cat == "srv" and banner_cpe in _generic_srv_cpe:
                skip_generic_banner = True  # keep hv + CPE from Proxmox port profile
            elif port_set & {902, 903, 5480} and banner_cat == "srv" and banner_cpe in _generic_srv_cpe:
                skip_generic_banner = True  # keep hv from ESXi / vCenter port profile

            if not skip_generic_banner:
                result["category"] = banner_cat
        if banner_cpe and not skip_generic_banner:
            result["cpe"] = f"cpe:/{_cpe_type(banner_cpe)}:{banner_cpe}:*"

    # Vendor from banner CPE — but skip generic web/infra software names
    # that are running ON the device, not the device manufacturer
    SKIP_AS_VENDOR = {
        "nginx", "apache", "lighttpd", "caddy", "iis", "microsoft-httpapi",
        "openbsd", "canonical", "debian", "redhat", "centos", "ubuntu",
        "sip", "mqtt", "http_alt", "printer", "ipp", "vnc",
    }
    if banner_cpe and not result["vendor"] and not skip_generic_banner:
        vendor_key = banner_cpe.split(":")[0].lower()
        if vendor_key not in SKIP_AS_VENDOR:
            result["vendor"] = banner_cpe.split(":")[0].replace("_", " ").title()

    # Skipped printer banner on SSH + Portainer-style stacks — classify as server, not unk
    if (
        skip_generic_banner
        and banner_cat == "prn"
        and _printer_banner_conflicts_with_homelab_ports(port_set)
        and result["category"] == "unk"
    ):
        result["category"] = "srv"

    # Kasm / browser VDI often exposes RDP (3389) — hostname is a stronger signal than "RDP → Windows"
    if hostname and re.search(r"kasm", hostname, re.I):
        if result["category"] in ("ws", "srv", "unk"):
            result["category"] = "voi"
        if not result["vendor"]:
            result["vendor"] = "Kasm Workspaces"

    # Photon OS hostname — keep srv + OS CPE; do not replace hardware OEM (e.g. HP) with VMware branding
    if hostname and re.search(r"\bphoton\b", hostname, re.I):
        result["category"] = "srv"
        low_cpe = (result.get("cpe") or "").lower()
        if not result["cpe"] or "laserjet" in low_cpe or ":hp:" in low_cpe:
            result["cpe"] = "cpe:/o:vmware:photon_os:*"
        if not result.get("os_guess"):
            result["os_guess"] = "Photon OS"

    # Hyper-V MAC (00:15:5D) means the VM runs ON Hyper-V, not that it IS Hyper-V.
    # Only classify as hv if hostname/banner confirms it's a hypervisor host.
    # Guest VMs keep category=srv from the OUI table above.

    # 5. OS guess from SSH banner or SNMP
    if m := re.search(
        r"(Ubuntu \d+\.\d+|Debian \d+|CentOS \d+|Rocky Linux \d+|"
        r"AlmaLinux \d+|Windows Server \d+|Windows \d+|macOS \d+)",
        combined, re.I
    ):
        result["os_guess"] = m.group(1)
    elif m := re.search(r"(VMware Photon|Photon OS|PHOTON_BUILD|photon-release)", combined, re.I):
        result["os_guess"] = "Photon OS"
    elif m := re.search(r"(Ubuntu|Debian|CentOS|Rocky|Alma|Fedora|Arch)", combined, re.I):
        result["os_guess"] = m.group(1)
    elif port_cat == "ws" and (3389 in port_set or 445 in port_set or 5985 in port_set or 5986 in port_set):
        result["os_guess"] = "Windows"

    # Routed scans often miss L2 identity (MAC/ARP/SNMP context), which can let
    # DNS + generic web/ssh signals drift toward "net". If we have a Linux app
    # server footprint and no explicit network-device indicators, prefer "srv".
    if routed_scan and result["category"] == "net":
        explicit_net_cpes = {
            "ubiquiti:unifi",
            "f5:big_ip",
            "cisco:ios_xe",
            "cisco:ios",
            "cisco:asa",
            "cisco:meraki",
            "juniper:junos",
            "fortinet:fortios",
            "netgate:pfsense",
            "opnsense:opnsense",
            "mikrotik:routeros",
            "openwrt:openwrt",
            "dd-wrt:dd-wrt",
        }
        has_explicit_net_signal = (
            (oui_cat == "net")
            or (hostname and NETWORK_HOSTNAMES.search(hostname) is not None)
            or (banner_cpe in explicit_net_cpes)
        )
        linux_app_cpes = _generic_srv_cpe | {"linux"}
        looks_like_linux_app_host = (
            22 in port_set
            and bool(port_set & {80, 443, 8080, 8443})
            and (
                any(s in combined.lower() for s in ("openssh", "nginx", "apache", "ubuntu", "debian", "centos", "rocky", "almalinux"))
                or (banner_cpe in linux_app_cpes)
            )
        )
        if looks_like_linux_app_host and not has_explicit_net_signal:
            result["category"] = "srv"
            result["_routed_net_override"] = {
                "from": "net",
                "to": "srv",
                "has_ssh_22": 22 in port_set,
                "has_web_port": bool(port_set & {80, 443, 8080, 8443}),
                "linux_banner_hint": any(
                    s in combined.lower()
                    for s in ("openssh", "nginx", "apache", "ubuntu", "debian", "centos", "rocky", "almalinux")
                ),
                "has_net_oui": oui_cat == "net",
                "has_net_hostname_pattern": bool(hostname and NETWORK_HOSTNAMES.search(hostname)),
                "has_net_cpe": banner_cpe in explicit_net_cpes,
            }

    return result
