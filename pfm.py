#!/usr/bin/env python

import time
import re
import subprocess
import yaml
import sys
import os
import signal
from datetime import datetime
from daemonize import Daemonize
from argparse import ArgumentParser


class Configuration:
    """
    PFM Configuration
    """

    def __init__(self):
        # Defaults:
        self.conf = {
            "pfm_pid_file": "pfm.pid",
            "pfm_home_dir": "/var/pfm",
            "pfm_log_file": "pfm.log",
            "log_file": "/var/log/postfix.log",
            "pf_table": "spammers",
            "process_all": False,
            "wait_count": 40,
        }

    @property
    def log_file(self):
        return self.conf["log_file"]

    @property
    def whitelist(self):
        return self.conf["whitelist"]

    @property
    def pfm_log_file(self):
        return self.conf["pfm_log_file"]

    @property
    def pfm_db(self):
        return self.conf["pfm_db"]

    @property
    def pfm_home_dir(self):
        return self.conf["pfm_home_dir"]

    @property
    def pfm_pid_file(self):
        pid_file = self.conf["pfm_pid_file"]
        if pid_file.startswith("/"):
            return pid_file
        else:
            return os.path.join(self.pfm_home_dir, pid_file)

        return self.conf["pfm_pid_file"]

    @property
    def process_all(self):
        return self.conf["process_all"]

    @property
    def wait_count(self):
        return self.conf["wait_count"]

    @property
    def pf_table(self):
        return self.conf["pf_table"]

    @property
    def rules(self):
        return self.conf["rules"]

    def read_from_file(self, filepath):
        with open(filepath, "r") as stream:
            try:
                self.conf.update(yaml.safe_load(stream))
            except yaml.YAMLError as e:
                print("config file error: {!s}".format(e))
                sys.exit(1)


class Blocker:
    def block(self, address):
        print("BLOCK", address)

    def expire(self):
        pass


class PFBlocker(Blocker):
    def __init__(self, pf_table):
        self.pf_table = pf_table
        self.expire_counter = 0

    def block(self, address):
        print("BLOCK", address)
        subprocess.call(["doas", "pfctl", "-t", self.pf_table, "-T", "add", address])

    def expire(self):
        if self.expire_counter % 100 == 0:
            subprocess.call(
                ["doas", "pfctl", "-t", self.pf_table, "-T", "expire", "86400"]
            )
        self.expire_counter += 1


class LogProcessor:
    """
	Postfix Log Processing
	"""

    def __init__(self, config, blocker):
        self.log_file = config.log_file
        self.config = config
        self.blocker = blocker
        self.process_all = config.process_all

        self.line = None
        self.last_lines = []
        self.number_of_last_lines = 20

        self.ip4_addr_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        self.ip6_addr_pattern = re.compile(r"\[([0-9a-f:]+:[0-9a-f]{1,4})\]")

        self.blocked_addr = dict()

        self.pfm_log_file_handle = None

        self.install_signal_handler()

    def install_signal_handler(self):
        signal.signal(signal.SIGHUP, self.signal_handler)

    def signal_handler(self, signum, frame):
        if self.pfm_log_file_handle:
            self.log_write("Signal received: {!s}".format(signum))
            self.reopen_log_file()

    def reopen_log_file(self):
        self.filehandle = open(self.log_file, "r")
        self.read_fail_count = 0
        self.skipping = True

    def open_log_file(self):
        self.filehandle = open(self.log_file, "r")
        self.skipping = True

    def open_pfm_log_file(self):
        self.pfm_log_file_handle = open(self.config.pfm_log_file, "a", buffering=1)

    def print(self, message):
        print("*--- {:s}".format(message))

    def print_stat(self):
        self.print("STAT: Monitored addresses: {:d}".format(len(self.blocked_addr)))

    def log_write(self, message):
        self.pfm_log_file_handle.write(
            "{!s}: {:s}\n".format(datetime.now(), message.strip())
        )

    def monitor(self):
        """
        The main monitoring loop
		"""
        self.open_log_file()
        self.open_pfm_log_file()

        self.log_write("PFM started, pid={:d}".format(os.getpid()))

        self.read_fail_count = 0

        while True:

            self.line = self.filehandle.readline()

            if self.line:
                self.line = self.line.strip()

            if not self.skipping and "log file turned over" in self.line:
                self.log_write("Log file turned over, reopening log file")
                time.sleep(1.5)
                self.reopen_log_file()

            if (not self.skipping or self.process_all) and self.line:
                self.handle_line()

            if not self.line:
                self.skipping = False
                self.read_fail_count += 1
                if self.read_fail_count > self.config.wait_count:
                    self.reopen_log_file()
                time.sleep(0.5)

    def handle_line(self):
        if not self.skipping:
            print("| {:s}".format(self.line), end="")
        self.last_lines = self.last_lines[-self.number_of_last_lines :]
        self.last_lines.append(self.line)

        self.blocker.expire()

        self.check_entry()

    def get_ip_address_from_current_line(self, occurence=0):
        """
        Tries to find an IP address in self.line

        For IPv6 we only attempt to find most of the IP addresses
        that appear inside of square brackets
        """
        try:
            res = self.ip4_addr_pattern.findall(self.line)[occurence]
        except IndexError:
            res = None

        if res is None:
            # try finding an IPv6 address
            try:
                res = self.ip6_addr_pattern.findall(self.line)[occurence]
            except IndexError:
                res = None

        return res

    def block(self, grace=5, reason="Unspecified"):
        ip_address = self.get_ip_address_from_current_line()

        if ip_address is None:
            self.log_write("NO IP ADDRESS EXTRACTED FROM: {:s}".format(self.line))
            return

        if ip_address in self.config.whitelist:
            self.log_write(
                "Ignoring whitelisted address: {!s} ({!s})".format(ip_address, reason)
            )
            return

        self.blocked_addr.setdefault(ip_address, 0)
        self.blocked_addr[ip_address] += 1

        if self.blocked_addr[ip_address] >= grace:
            log_msg = "Blocking: address={addr!s} reason={reason!s}".format(
                addr=ip_address, reason=reason
            )
            self.log_write(
                "{msg:s} (line: {line:s})".format(msg=log_msg, line=self.line)
            )
            self.blocker.block(ip_address)
        else:
            self.log_write(
                "Triggered: address={addr!s} reason={reason!s} (count={count:d}) (line: {line:s})".format(
                    addr=ip_address,
                    reason=reason,
                    count=self.blocked_addr[ip_address],
                    line=self.line,
                )
            )

        self.print_stat()

    def check_entry(self):
        for rule in self.config.rules:
            if rule["trigger"] in self.line:
                self.block(grace=rule["grace"], reason=rule["comment"])


def pfm_main():
    global cfg
    proc = LogProcessor(cfg, PFBlocker(cfg.pf_table))
    proc.monitor()


def main():
    """
    MAIN
    """
    parser = ArgumentParser()
    parser.add_argument(
        "--foreground", "-F", action="store_true", help="run in foreground"
    )
    parser.add_argument(
        "--config",
        "-c",
        action="store",
        help="configuration file",
        default="./pfm.conf",
    )
    parser.add_argument(
        "--process-all", "-a", action="store_true", help="process the entire log file"
    )
    args = parser.parse_args()

    global cfg
    cfg = Configuration()
    cfg.read_from_file(args.config)

    if args.process_all:
        # Overwrite the config file value
        cfg.conf["process_all"] = True

    if not args.foreground:
        daemon = Daemonize(
            app="pfm", pid=cfg.pfm_pid_file, action=pfm_main, chdir=cfg.pfm_home_dir
        )
        daemon.start()
    else:
        os.chdir(cfg.pfm_home_dir)
        pfm_main()


if __name__ == "__main__":
    main()

# EOF
