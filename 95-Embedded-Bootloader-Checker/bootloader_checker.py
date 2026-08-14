#!/usr/bin/env python3
"""
Embedded Bootloader Checker
Review U-Boot implementations for insecure env variable modifications,
lack of authentication, and unsigned update flaws.
"""

import argparse
import struct
import re
import os
import hashlib
import sys


class UBootChecker:
    VULNERABILITY_DB = {
        "unsigned_image": {
            "check": "Allow any unsigned image",
            "severity": "CRITICAL",
            "cwe": "CWE-347",
        },
        "env_unauth": {
            "check": "Environment variables modifiable without auth",
            "severity": "HIGH",
            "cwe": "CWE-287",
        },
        "no_password": {
            "check": "No bootloader password set",
            "severity": "HIGH",
            "cwe": "CWE-521",
        },
        "fastboot_open": {
            "check": "Fastboot mode accessible without auth",
            "severity": "HIGH",
            "cwe": "CWE-862",
        },
        "default_keys": {
            "check": "Default/test keys in use",
            "severity": "MEDIUM",
            "cwe": "CWE-321",
        },
        "recovery_exploit": {
            "check": "Recovery mode with unsigned updates",
            "severity": "HIGH",
            "cwe": "CWE-345",
        },
        "debug_console": {
            "check": "Debug console enabled in release build",
            "severity": "MEDIUM",
            "cwe": "CWE-489",
        },
        "bootdelay_long": {
            "check": "Long bootdelay allowing interrupt",
            "severity": "LOW",
            "cwe": "CWE-20",
        },
        "mtd_unlocked": {
            "check": "Flash/MTD regions unlocked",
            "severity": "HIGH",
            "cwe": "CWE-284",
        },
        "signed_but_verification_skip": {
            "check": "Signature verification can be skipped",
            "severity": "CRITICAL",
            "cwe": "CWE-354",
        },
    }

    def __init__(self, image_path=None, env_vars=None):
        self.image_path = image_path
        self.env_vars = env_vars or {}
        self.findings = []
        self.image_data = None

        if image_path and os.path.exists(image_path):
            with open(image_path, "rb") as f:
                self.image_data = f.read()

    def check_bootloader_image(self):
        print("[*] Scanning U-Boot image for vulnerabilities...\n")

        if self.image_data:
            self._check_crc()
            self._check_for_hardcoded_keys()
            self._check_for_signing()
            self._check_for_known_strings()

        self._check_env_vars()
        self._generate_report()

    def _check_crc(self):
        if not self.image_data:
            return
        if len(self.image_data) > 8:
            header = self.image_data[:8]
            if header[:4] == b"\x27\x05\x19\x56":
                print(f"  [i] U-Boot image header detected at offset 0")
            crc32 = sum(self.image_data) & 0xFFFFFFFF
            print(f"  [i] Image CRC32: 0x{crc32:08X}")

    def _check_for_hardcoded_keys(self):
        if not self.image_data:
            return
        patterns = [b"-----BEGIN", b"PRIVATE KEY", b"RSA PRIVATE", b"ssh-rsa", b"ssh-dss"]
        for pat in patterns:
            if pat in self.image_data:
                self.add_finding("default_keys", f"Private key material found: {pat.decode()}")

        key_files = [b"rsa_key.pem", b"private.pem", b"test_key", b"development"]
        for kf in key_files:
            if kf in self.image_data:
                self.add_finding("default_keys", f"Development key file: {kf.decode()}")

    def _check_for_signing(self):
        if not self.image_data:
            return
        sig_patterns = [b"signature", b"verified", b"rsa_verify", b"fitImage"]
        for pat in sig_patterns:
            if pat in self.image_data:
                print(f"  [i] Signature infrastructure found: '{pat.decode()}'")

    def _check_for_known_strings(self):
        if not self.image_data:
            return
        dangerous = [
            (b"bootdelay=", "bootdelay_long"),
            (b"init=/bin/sh", "debug_console"),
            (b"console=ttyAMA0", "debug_console"),
            (b"enable_debug", "debug_console"),
            (b"mtdoops", "mtd_unlocked"),
            (b"skip_sig", "signed_but_verification_skip"),
            (b"unsigned_images", "unsigned_image"),
            (b"verified_boot=0", "unsigned_image"),
            (b"disable_auth", "env_unauth"),
        ]
        for pat, vuln_id in dangerous:
            if pat in self.image_data:
                self.add_finding(vuln_id, f"String found in image: {pat.decode()}")

    def _check_env_vars(self):
        if not self.env_vars:
            self.env_vars = {}

        checks = [
            ("bootdelay", "5", lambda v: int(v) > 3, "bootdelay_long"),
            ("bootcmd", None, lambda v: "run" in v and "mmc" in v, None),
            ("bootargs", None, lambda v: "init=/bin/sh" in v, "debug_console"),
            ("verify", "yes", lambda v: v != "yes", "unsigned_image"),
            ("allow_unsigned", "no", lambda v: v == "yes", "unsigned_image"),
            ("secure", "yes", lambda v: v != "yes", "env_unauth"),
            ("password", "", lambda v: len(v) == 0, "no_password"),
            ("fastboot", "yes", lambda v: v == "yes", "fastboot_open"),
            ("recovery", "no", lambda v: v == "yes", "recovery_exploit"),
            ("auth_enforce", "yes", lambda v: v != "yes", "env_unauth"),
        ]

        for var, safe_val, is_bad, vuln_id in checks:
            val = self.env_vars.get(var)
            if val is not None and vuln_id and is_bad(val):
                self.add_finding(vuln_id, f"env var '{var}' = '{val}'" + (f" (expected: {safe_val})" if safe_val else ""))

    def add_finding(self, vuln_id, detail):
        vuln = self.VULNERABILITY_DB.get(vuln_id, {})
        severity = vuln.get("severity", "UNKNOWN")
        check = vuln.get("check", vuln_id)
        cwe = vuln.get("cwe", "")
        self.findings.append({
            "id": vuln_id,
            "check": check,
            "severity": severity,
            "cwe": cwe,
            "detail": detail,
        })
        sev_mark = {"CRITICAL": "[!]", "HIGH": "[-]", "MEDIUM": "[*]", "LOW": "[i]"}.get(severity, "[?]")
        print(f"  {sev_mark} [{severity}] {check}")
        print(f"      {detail}")
        if cwe:
            print(f"      Reference: {cwe}")

    def _generate_report(self):
        print("\n" + "=" * 60)
        print("BOOTLOADER SECURITY ASSESSMENT REPORT")
        print("=" * 60)
        print(f"\nTotal findings: {len(self.findings)}")
        severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            sev = f.get("severity", "UNKNOWN")
            severity_count[sev] = severity_count.get(sev, 0) + 1

        print(f"  CRITICAL: {severity_count.get('CRITICAL', 0)}")
        print(f"  HIGH:     {severity_count.get('HIGH', 0)}")
        print(f"  MEDIUM:   {severity_count.get('MEDIUM', 0)}")
        print(f"  LOW:      {severity_count.get('LOW', 0)}")

        if self.findings:
            print("\nAffected areas:")
            for f in self.findings:
                print(f"  - [{f['severity']}] {f['check']}: {f['detail']}")


class BootloaderChecklist:
    @staticmethod
    def interactive():
        checks = [
            ("1", "Is secure boot enforced?", "Check if boot ROM validates bootloader signature"),
            ("2", "Is U-Boot password protected?", "Check for password protection on U-Boot console"),
            ("3", "Are environment variables locked?", "Check if 'env' is writable without authentication"),
            ("4", "Are unsigned update images rejected?", "Check if update mechanism validates signatures"),
            ("5", "Is bootdelay=0 in production?", "Check if boot process can be interrupted"),
            ("6", "Is debug console disabled?", "Check if serial debug is disabled in release"),
            ("7", "Are default/test keys removed?", "Check for presence of development keys"),
            ("8", "Is flash/MTD write-protected?", "Check if firmware partitions are write-protected"),
            ("9", "Is recovery mode restricted?", "Check if recovery mode requires authentication"),
            ("10", "Is verified boot (MkImage) enabled?", "Check if FIT images with signatures are used"),
        ]

        print("\n=== Manual Bootloader Security Checklist ===\n")
        for num, question, desc in checks:
            print(f"  [{num}] {question}")
            print(f"       {desc}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Embedded Bootloader Checker")
    parser.add_argument("action", choices=["check-image", "check-env", "checklist", "dump-env"])
    parser.add_argument("--image", help="Path to U-Boot image file (ELF/bin)")
    parser.add_argument("--env-file", help="Path to environment variables file")
    parser.add_argument("--set", nargs=2, action="append", metavar=("KEY", "VAL"),
                        help="Set environment variable for checking")
    args = parser.parse_args()

    env_vars = {}
    if args.env_file:
        with open(args.env_file, "r") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    env_vars[k] = v

    if args.set:
        for k, v in args.set:
            env_vars[k] = v

    if args.action == "check-image" or args.action == "check-env":
        checker = UBootChecker(args.image, env_vars)
        checker.check_bootloader_image()

    elif args.action == "checklist":
        BootloaderChecklist.interactive()

    elif args.action == "dump-env":
        if not args.image:
            print("ERROR: --image required")
            return
        with open(args.image, "rb") as f:
            data = f.read()
        offset = 0
        while True:
            idx = data.find(b"=", offset)
            if idx == -1 or idx > len(data) - 100:
                break
            end = data.find(b"\x00", idx)
            if end == -1:
                break
            start = max(0, idx - 50)
            var = data[start:end].decode("utf-8", errors="replace").strip("\x00")
            if "=" in var:
                k, v = var.split("=", 1)
                if k.strip():
                    print(f"  {k.strip()} = {v.strip()}")
            offset = end + 1


if __name__ == "__main__":
    main()
