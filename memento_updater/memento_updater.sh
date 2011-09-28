#!/bin/bash

# Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This is the autoupdater for Memento. When called it consults Omaha to see
# if there's an update available. If so, it downloads it to the other
# partition on the Memento USB stick, then alters the MBR and partitions
# as needed so the next reboot will boot into the newly installed partition.
# Care is taken to ensure that when this exits the USB stick is configured
# to boot into the same partition as before or into the new partition,
# however there may be a small time window when this is not the case. Such a
# window should be about 1 second or less, and we tolerate that since this
# is for testing and not a real autoupdate solution for the long run.

source `dirname "$0"`/memento_updater_logging.sh || exit 1
. /usr/lib/shflags || exit 1

DEFINE_boolean force_update $FLAGS_FALSE \
  "Force update"
DEFINE_string omaha_url "" \
  "Use target autoupdate server for Omaha protocol."
DEFINE_string install_url "" \
  "Skip Omaha; Install image at this URL."
DEFINE_string install_url_checksum "" \
  "When using --install_url, the corresponding checksum"
DEFINE_string dst_partition "" \
  "If set, force installation onto the partition given."
DEFINE_boolean allow_removable_boot $FLAGS_FALSE \
  "Run even if booted from removable media."
DEFINE_string force_track "" \
  "If set, force a given track to be sent to Omaha"
DEFINE_string kernel_partition "" \
  "If set, force a given kernel partition. If set to 'none', install \
the image directly into just the rootfs partition, rather than both. \
If not set, installs to kernel partition based on rootfs partition."
DEFINE_boolean skip_postinst $FLAGS_FALSE \
  "Skip running postinst script."
DEFINE_boolean check_block_device $FLAGS_TRUE \
  "Check if destination is a block device."
DEFINE_string board "" \
  "The board type to download from the server."

# Parse command line
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

# make sure we're root
if [ "root" != $(whoami) ]
then
  echo run this script as root
  exit 1
fi

# check that this script doesn't run concurrently
PID_FILE=/tmp/memento_updater_lock
if [[ -f "$PID_FILE" && ! -d /proc/`cat $PID_FILE` ]]
then
  # process holding lock file is dead. clean up lockfile
  rm -rf "$PID_FILE"
fi

# Make sure we're not booted from USB, unless allowed by the flag.
if [ "${FLAGS_allow_removable_boot}" = "${FLAGS_FALSE}" ]; then
  ROOTDEV=$(rootdev)
  # Remove numbers at end of rootfs device.
  SRC=$(echo $ROOTDEV | sed -re 's/p?[0-9]+$//')
  REMOVABLE=$(cat /sys/block/${SRC#/dev/}/removable)
  if [ "$REMOVABLE" = "1" ]; then
    log not updating because we booted from USB
    exit 1
  fi
fi

if [ -z "${FLAGS_dst_partition}" ]; then
  # make sure update hasn't already completed
  UPDATED_COMPLETED_FILE="/tmp/memento_autoupdate_completed"
  if [ -f "$UPDATED_COMPLETED_FILE" ]
  then
    exit 0
  fi
fi

if ( set -o noclobber; echo "$$" > "$PID_FILE") 2> /dev/null;
then
  true
else
  log "Failed to acquire lockfile: $PID_FILE."
  log "Held by $(cat $PID_FILE)"
  exit 1
fi
# remove lockfile when we exit
trap 'RC=$?; rm -f "$PID_FILE"; log Memento AutoUpdate terminating; exit $RC' \
    INT TERM EXIT

log Memento AutoUpdate starting

# See if we're forcing an update from a specific URL
if [ -z "$FLAGS_install_url" ]
then
  # abort if autoupdates have been disabled, but only when an update image
  # isn't forced
  UPDATES_DISABLED_FILE="/var/local/disable_software_update"
  if [ -f "$UPDATES_DISABLED_FILE" ]
  then
    log Updates disabled. Aborting.
    exit 0
  fi

  # check w/ omaha to see if there's an update
  EXTRA_PING_ARGS=""
  if [ -n "${FLAGS_force_track}" ]; then
    EXTRA_PING_ARGS="${EXTRA_PING_ARGS} --track=${FLAGS_force_track}"
  fi
  if [ ${FLAGS_force_update} -eq ${FLAGS_TRUE} ]; then
    EXTRA_PING_ARGS="${EXTRA_PING_ARGS} --app_version=ForcedUpdate"
  fi
  if [ -n "${FLAGS_omaha_url}" ]; then
    EXTRA_PING_ARGS="${EXTRA_PING_ARGS} --omaha_url=${FLAGS_omaha_url}"
  fi
  if [ -n "${FLAGS_board}" ]; then
    EXTRA_PING_ARGS="${EXTRA_PING_ARGS} --board=${FLAGS_board}"
  fi

  OMAHA_CHECK_OUTPUT=$(`dirname "$0"`/ping_omaha.sh ${EXTRA_PING_ARGS})
  OMAHA_RC=$?
  if [ "$OMAHA_RC" != "0" ]; then
    log "Omaha connect failed."
    exit 1
  fi
  IMG_URL=$(echo "$OMAHA_CHECK_OUTPUT" | grep '^URL=' | cut -d = -f 2-)
  CHECKSUM=$(echo "$OMAHA_CHECK_OUTPUT" | grep '^HASH=' | cut -d = -f 2-)
else
  if [ -z "$FLAGS_install_url_checksum" ]; then
    log Specified --install_url, but not --install_url_checksum. Aborting.
    exit 1
  fi
  log User forced an update from: "$FLAGS_install_url" checksum: \
    "$FLAGS_install_url_checksum"
  IMG_URL="$FLAGS_install_url"
  CHECKSUM="$FLAGS_install_url_checksum"
fi

APP_VERSION=$(echo "$OMAHA_CHECK_OUTPUT" | grep '^APP_VERSION=' | \
  cut -d = -f 2-)

if [[ -z "$IMG_URL" || -z "$CHECKSUM" ]]
then
  log no update
  exit 0
fi
# TODO(adlr): make sure we have enough space for the download. This script is
# already correct if we don't have space, but it would be nice to fail
# fast.
log Update Found: $IMG_URL checksum: $CHECKSUM

# Figure out which partition I'm on, and which to download to.  If rootdev
# fails, we must be on ramdisk.
LOCAL_DEV=$(rootdev) || LOCAL_DEV=initramfs

# We install onto the other partition so if we end in 3, other ends in 5, and
# vice versa
if [ -n "${FLAGS_dst_partition}" ]; then
  INSTALL_DEV="${FLAGS_dst_partition}"
else
  if [ "$LOCAL_DEV" = "initramfs" ]; then
    log "Booted from initramfs, and no dst_partition specified!"
    exit 1
  fi
  INSTALL_DEV=$(echo $LOCAL_DEV | tr '35' '53')
fi
NEW_PART_NUM=${INSTALL_DEV##*/*[a-z]}
# The kernel needs to be installed to its own partition.
# partitions 2&3 are image A, partitions 4&5 are image B.
if [ -z "${FLAGS_kernel_partition}" ]; then
  KINSTALL_DEV=$(echo $INSTALL_DEV | tr '35' '24')
else
  KINSTALL_DEV="${FLAGS_kernel_partition}"
fi

if [ "$KINSTALL_DEV" = "$INSTALL_DEV" ]; then
  log "kernel install partition the same as rootfs install partition!"
  log "  (${KINSTALL_DEV})"
  exit 1
fi

# Do some device sanity checks.
if [ "$LOCAL_DEV" != "initramfs" -a ! -b "$LOCAL_DEV" ]
then
  log "didnt find good local device. local: $LOCAL_DEV install: $INSTALL_DEV"
  exit 1
fi
if [ "${FLAG_check_block_device}" = "${FLAGS_TRUE}" -a ! -b "$INSTALL_DEV" ]
then
  log "didnt find good install device. local: $LOCAL_DEV install: $INSTALL_DEV"
  exit 1
fi
if [ "$LOCAL_DEV" == "$INSTALL_DEV" ]
then
  log local and installation device are the same: "$LOCAL_DEV"
  exit 1
fi

log Booted from "$LOCAL_DEV" and installing onto "$INSTALL_DEV"

# Make sure installation device is unmounted.
if [ "$INSTALL_DEV" == ""$(grep "^$INSTALL_DEV " /proc/mounts | \
                           cut -d ' ' -f 1 | uniq) ]
then
  # Drive is mounted, must unmount.
  log unmounting "$INSTALL_DEV"
  umount "$INSTALL_DEV"
  # Check if it's still mounted for some strange reason.
  if [ "$INSTALL_DEV" == ""$(grep "^$INSTALL_DEV " /proc/mounts | \
                             cut -d ' ' -f 1 | uniq) ]
  then
    log unable to unmount "$INSTALL_DEV", which is where i need to write to
    exit 1
  fi
fi

# Download file to the device.
log downloading image. this may take a while

# wget - fetch file, send to stdout
# tee - save a copy off to device, also send to stdout
# openssl - calculate the sha1 hash of stdin, send checksum to stdout
# tr - convert trailing newline to a space
# pipestatus - append return codes for all prior commands. should all be 0

CHECKSUM_FILE="/tmp/memento_autoupdate_checksum"

# Generally we pipe to split_write to write to two devices, but if
# KINSTALL_DEV is 'none' we write directly to a specific output device.
WRITE_COMMAND='cat > "$INSTALL_DEV"'
if [ "$KINSTALL_DEV" != "none" ]; then
  WRITE_COMMAND='"$(dirname "$0")"/split_write "$KINSTALL_DEV" "$INSTALL_DEV"'
fi

COMMAND='wget --progress=dot:mega -O - --load-cookies <(echo "$COOKIES") \
  "$IMG_URL" 2>> "$MEMENTO_AU_LOG" | \
  tee >(openssl sha1 -binary | openssl base64 > "$CHECKSUM_FILE") | \
  gzip -d | '${WRITE_COMMAND}' ; echo ${PIPESTATUS[*]}'

RETURNED_CODES=$(eval "$COMMAND")

EXPECTED_CODES="0 0 0 0"
CALCULATED_CS=$(cat "$CHECKSUM_FILE")
rm -f "$CHECKSUM_FILE"

if [[ ("$CALCULATED_CS" == "$CHECKSUM")  && \
      ("$RETURNED_CODES" == "$EXPECTED_CODES") ]]
then
  # wonderful
  log download success
else
  # either checksum mismatch or ran out of space.
  log checksum mismatch or other error \
      calculated checksum: "$CALCULATED_CS" reference checksum: "$CHECKSUM" \
      return codes: "$RETURNED_CODES" expected codes: "$EXPECTED_CODES"
  # zero-out installation partition
  dd if=/dev/zero of=$INSTALL_DEV bs=4096 count=1
  exit 1
fi

# Return 0 if $1 > $2.
# $1 and $2 are in "a.b.c.d" format where a, b, c, and d are base 10.
function version_number_greater_than {
  # Replace periods with spaces and strip off leading 0s (lest numbers be
  # interpreted as octal). Strip underscores.
  REPLACED_A=$(echo "$1" | sed -r -e 's/(^|\.)0*/ /g' -e 's/_//g')
  REPLACED_B=$(echo "$2" | sed -r -e 's/(^|\.)0*/ /g' -e 's/_//g')
  EXPANDED_A=$(printf '%020d%020d%020d%020d' $REPLACED_A)
  EXPANDED_B=$(printf '%020d%020d%020d%020d' $REPLACED_B)
  # This is a string compare:
  [[ "$EXPANDED_A" > "$EXPANDED_B" ]]
}

# it's best not to interrupt the script from this point on out, since it
# should really be doing these things atomically. hopefully this part will
# run rather quickly.

# $1 is return code, $2 is command
function abort_update_if_cmd_failed_long {
  if [ "$1" -ne "0" ]
  then
    log "$2 failed with error code  $1 . aborting update"
    exit 1
  fi
}

function abort_update_if_cmd_failed {
  abort_update_if_cmd_failed_long "$?" "!!"
}

if [ $FLAGS_skip_postinst -eq $FLAGS_FALSE ]; then
  # tell the new image to make itself "ready"
  log running postinst on the downloaded image
  MOUNTPOINT=/tmp/newpart
  mkdir -p "$MOUNTPOINT"
  mount -o ro "$INSTALL_DEV" "$MOUNTPOINT"

  # Check version of new software if not forcing a dst partition
  if [ -z "${FLAGS_dst_partition}" ]; then
    NEW_VERSION=$(grep ^GOOGLE_RELEASE "$MOUNTPOINT"/etc/lsb-release | \
                  cut -d = -f 2-)
    if [ "x$NEW_VERSION" = "x" ]
    then
      log "Can't find new version number. aborting update"
      umount "$MOUNTPOINT"
      rmdir "$MOUNTPOINT"
      exit 1
    else
      # See if it's newer than us
      if [ "${FLAGS_force_update}" != "${FLAGS_TRUE}" ] &&
        version_number_greater_than "$APP_VERSION" "$NEW_VERSION"
      then
        log "Can't upgrade to older version: " "$NEW_VERSION"
        umount "$MOUNTPOINT"
        rmdir "$MOUNTPOINT"
        exit 1
      fi
    fi
  fi

  "$MOUNTPOINT"/postinst "$INSTALL_DEV" 2>&1 | cat \
      >> "$MEMENTO_AU_LOG"
  [ "${PIPESTATUS[*]}" = "0 0" ]
  POSTINST_RETURN_CODE=$?

  umount "$MOUNTPOINT"
  rmdir "$MOUNTPOINT"

  # If it failed, don't update MBR but just to be safe, zero out a page of
  # install device.
  abort_update_if_cmd_failed_long "$POSTINST_RETURN_CODE" "$MOUNTPOINT"/postinst
  # postinstall on new partition succeeded.
fi

if [ -z "${FLAGS_dst_partition}" ]; then
  # mark update as complete so we don't try to update again
  touch "$UPDATED_COMPLETED_FILE"
fi

# Flush linux caches; seems to be necessary
sync
echo 3 > /proc/sys/vm/drop_caches

# tell user to reboot
log Autoupdate applied. You should now reboot
echo UPDATED
