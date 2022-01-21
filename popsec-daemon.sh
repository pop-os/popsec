#!/usr/bin/env bash

set -ex

make
sudo make install-daemon
sudo systemctl daemon-reload
sudo systemctl restart popsec-daemon
journalctl -f -t popsec-daemon
