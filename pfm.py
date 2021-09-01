#!/usr/bin/env python

import time
import re
import subprocess
import yaml
import sys


class Configuration:
    """
    PFM Configuration
    """

    def __init__(self):
        self.conf = None

    @property
    def logfile(self):
        return self.conf["logfile"]

    @property
    def whitelist(self):
        return self.conf["whitelist"]

    @property
    def pfmlog(self):
        return self.conf["pfmlog"]

    @property
    def process_all(self):
        return self.conf["process_all"]

    @property
    def rules(self):
        return self.conf["rules"]

    def read_from_file(self, filepath):
        with open(filepath, "r") as stream:
            try:
                self.conf = yaml.safe_load(stream)
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
        self.logfile = config.logfile
        self.config = config
        self.blocker = blocker
        self.process_all = config.process_all

        self.line = None
        self.last_lines = []
        self.number_of_last_lines = 20

        self.ip4_addr_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
        self.ip6_addr_pattern = re.compile(r"\[([0-9a-f:]+:[0-9a-f]{1,4})\]")

        self.blocked_addr = dict()

    def open_logfile(self):
        self.filehandle = open(self.logfile, "r")
        self.skipping = True

    def monitor(self):
        """
        The main monitoring loop
		"""
        self.open_logfile()

        while True:

            self.line = self.filehandle.readline()

            if not self.skipping and "logfile turned over" in self.line:
                self.print("Reopening log file")
                time.sleep(1.5)
                self.open_logfile()

            if (not self.skipping or self.process_all) and self.line:
                self.handle_line()

            if not self.line:
                self.skipping = False
                time.sleep(0.3)

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

    def print(self, message):
        print("*--- {:s}".format(message))

    def print_stat(self):
        self.print("STAT: Monitored addresses: {:d}".format(len(self.blocked_addr)))

    def block(self, grace=5, reason="Unspecified"):
        ip_address = self.get_ip_address_from_current_line()

        if ip_address is None:
            self.print("NO IP ADDRESS EXTRACTED FROM: {:s}".format(self.line))
            return

        if ip_address in self.config.whitelist:
            self.print(
                "Ignoring whitelisted address: {!s} ({!s})".format(ip_address, reason)
            )
            return

        self.blocked_addr.setdefault(ip_address, 0)
        self.blocked_addr[ip_address] += 1

        if self.blocked_addr[ip_address] >= grace:
            self.print("BLOCKING: {!s} ** {!s}".format(ip_address, reason))
            self.blocker.block(ip_address)
        else:
            self.print(
                "GRACE: {!s} ** {!s} ({:d})".format(
                    ip_address, reason, self.blocked_addr[ip_address]
                )
            )

        self.print_stat()

    def check_entry(self):
        for rule in self.config.rules:
            if rule["trigger"] in self.line:
                self.block(grace=rule["grace"], reason=rule["comment"])


def main():
    """
    MAIN
    """
    cfg = Configuration()
    cfg.read_from_file("config.yml")

    proc = LogProcessor(cfg, PFBlocker("spammers"))
    proc.monitor()


if __name__ == "__main__":
    main()

# EOF
