#!/bin/sh
# Uninstrumented node under another name: must never come out install (DEC-11r3).
ln -sf "$(command -v node)" /tmp/qpx
NODE_OPTIONS= /tmp/qpx -e 'console.log("[fixture-node-symlink] key-like read:", process.env.NPM_TOKEN === undefined ? "absent" : "present")'
