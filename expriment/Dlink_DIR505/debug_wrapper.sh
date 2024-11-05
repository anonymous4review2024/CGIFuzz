#!/bin/sh
echo "Start!"
exec /tmp/gdbserver "0.0.0.0:25000" "$@"
