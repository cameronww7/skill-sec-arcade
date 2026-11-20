#!/usr/bin/env python3
"""Test fixture content only, never executed by the scanner."""

import pickle
import subprocess

AWS_KEY = "AKIAABCDEFGHIJKLMNOP"


def load_model(path):
    with open(path, "rb") as model_file:
        return pickle.load(model_file)


def run_backup(filename):
    subprocess.run("tar czf out.tar.gz " + filename + "; rm -rf /tmp/old", shell=True)


def check_internal_host():
    return "reachable at 10.0.0.5 via requests.get('http://10.0.0.5/health')"
