#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CLI IZIN MANAGER.

Contoh:
  python cli.py list
  python cli.py check 1.2.3.4
  python cli.py add "admin" 2026-12-31 1.2.3.4
  python cli.py del 1.2.3.4

Pakai GITHUB_TOKEN untuk mode GitHub, atau IZIN_FILE untuk file lokal.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from izin_store import (
    add_or_update,
    check_ip,
    delete_ip,
    make_store,
    parse_entries,
    summary,
)


def print_table(entries) -> None:
    print("%-4s %-22s %-12s %-12s %-10s %s" % ("#", "NAMA", "IP", "EXPIRED", "STATUS", "SISA"))
    print("-" * 78)
    for e in entries:
        days = "∞" if e.status == "lifetime" else ("-" if e.days_left is None else "%d hari" % e.days_left)
        print("%-4s %-22s %-12s %-12s %-10s %s" % (
            e.line_no, (e.name or "-")[:22], e.ip or "-", e.expiry or "-", e.status, days
        ))


def main() -> int:
    parser = argparse.ArgumentParser(description="Kelola IP lisensi HITS SSH")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="tampilkan semua IP")
    p_list.add_argument("--q", default="", help="filter nama/IP")
    p_list.add_argument("--json", action="store_true")

    p_check = sub.add_parser("check", help="cek satu IP")
    p_check.add_argument("ip")
    p_check.add_argument("--json", action="store_true")

    p_add = sub.add_parser("add", help="tambah/update IP")
    p_add.add_argument("name")
    p_add.add_argument("expiry", help="YYYY-MM-DD atau lifetime")
    p_add.add_argument("ip")
    p_add.add_argument("--json", action="store_true")

    p_del = sub.add_parser("del", help="hapus IP")
    p_del.add_argument("ip")
    p_del.add_argument("--json", action="store_true")

    args = parser.parse_args()
    store = make_store()

    try:
        if args.cmd == "list":
            entries = parse_entries(store.read()[0])
            if args.q:
                q = args.q.lower()
                entries = [e for e in entries if q in e.name.lower() or q in e.ip.lower()]
            if args.json:
                print(json.dumps({
                    "ok": True,
                    "summary": summary(entries),
                    "entries": [e.__dict__ for e in entries],
                }, ensure_ascii=False, indent=2))
            else:
                print_table(entries)
                print("\nTotal: %(total)d | aktif: %(active)d | expired: %(expired)d | lifetime: %(lifetime)d | invalid: %(invalid)d" % summary(entries))
            return 0

        if args.cmd == "check":
            result = check_ip(store.read()[0], args.ip)
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                if not result["found"]:
                    print("IP %s tidak ditemukan." % args.ip)
                else:
                    print("IP      : %s" % result["ip"])
                    print("Nama    : %s" % result["name"])
                    print("Expired : %s" % result["expiry"])
                    print("Status  : %s" % result["status"])
                    print("Sisa    : %s" % ("∞" if result["status"] == "lifetime" else
                                            ("-" if result["days_left"] is None else "%d hari" % result["days_left"])))
            return 0

        if args.cmd == "add":
            _text, info = store.update(
                lambda current: add_or_update(current, args.name, args.expiry, args.ip),
                "izin: add %s (%s)" % (args.ip, args.name),
            )
            if args.json:
                print(json.dumps({"ok": True, **info}, ensure_ascii=False, indent=2))
            else:
                print("%s: %s (%s)" % ("Diperbarui" if info["action"] == "updated" else "Ditambahkan", args.ip, args.name))
            return 0

        if args.cmd == "del":
            _text, info = store.update(
                lambda current: delete_ip(current, args.ip),
                "izin: delete %s" % args.ip,
            )
            if args.json:
                print(json.dumps({"ok": True, **info}, ensure_ascii=False, indent=2))
            else:
                print("Dihapus: %s (%s baris)" % (args.ip, info.get("count", 1)))
            return 0
    except Exception as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
