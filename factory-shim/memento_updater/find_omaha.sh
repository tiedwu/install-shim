# Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Parent file must include memento_updater_logging.sh
# This file cannot be run by itself, it must be included.

# Return the value for a given key in the override lsb-release file.
# If no value is found, checks in the standard lsb-release file.
findLSBValue()
{
  # Check factory lsb file.
  value=$(grep ^$1 $FACTORY_LSB_FILE | cut -d = -f 2-)

  if [ -z "$value" ]
  then
    value=$(grep ^$1 /etc/lsb-release | cut -d = -f 2-)
  fi

  # Don't remove this echo, this is not for test purpose
  echo $value
}

FACTORY_LSB_FILE=/mnt/stateful_partition/dev_image/etc/lsb-factory
