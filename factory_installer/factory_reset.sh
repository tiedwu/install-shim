#!/bin/sh -x

# Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This runs from the factory install/reset shim. This MUST be run
# from USB, in developer mode. This script will wipe OQC activity and
# put the system back into factory fresh/shippable state.
echo "Factory reset"

# TODO(crosbug:10680): replace arch detection with crossystem?
if uname -m | grep -q "^i.86\$"; then
  ARCH="INTEL"
elif [ $(uname -m ) = "x86_64" ]; then
  ARCH="INTEL"
elif [ $(uname -m ) = "armv7l" ]; then
  ARCH="ARM"
else
  echo "Failed to auto detect architecture"
  exit 1
fi

if [ "$ARCH" = "INTEL" ]; then
  STATE_DEV="/dev/sda1"
elif [ "$ARCH" = "ARM" ]; then
  STATE_DEV="/dev/mmcblk0p1"
else
  STATE_DEV=""
fi
if [ ! -b "$STATE_DEV" ]; then
  echo "Failed to find root SSD."
  exit 1
fi

# Tcsd will bring up the tpm and de-own it,
# as we are in developer/recovery mode.
start tcsd

# Just wipe the start of the partition and remake the fs on
# the stateful partition.
dd bs=4M count=1 if=/dev/zero of=${STATE_DEV}
/sbin/mkfs.ext3 "$STATE_DEV"

# Do any board specific resetting here.
# board_factory_reset.sh will be installed by the board overlay if necessary.
BOARD_RESET=/usr/sbin/board_factory_reset.sh
if [ -x "${BOARD_RESET}" ]; then
  echo "Running board specific factory reset: ${BOARD_RESET}"
  ${BOARD_RESET} || exit 1
fi

echo "Done"
