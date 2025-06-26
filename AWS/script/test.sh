#!/usr/bin/env bash

if type readarray >/dev/null 2>&1; then
    echo "readarray is available"
else
    echo "readarray is not available"
fi
