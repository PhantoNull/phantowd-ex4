#!/bin/sh

PACKAGE_PATH="$1"

[ -n "$PACKAGE_PATH" ] || PACKAGE_PATH="/mnt/HD/HD_a2/Nas_Prog/NfsMediaStack"
[ -x "$PACKAGE_PATH/start.sh" ] || exit 1

"$PACKAGE_PATH/start.sh"
