# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

This is a modification of the existing adb_shell project, forked from https://github.com/JeffLIrion/adb_shell.

The goal of this modification is to add support for modern ADB, which includes WiFi pairing with a code as described in https://android.googlesource.com/platform/packages/modules/adb/+/15ffcacbfa1fed4bb59af1a96b9edc9604ba38a4/docs/dev/adb_wifi.md.

Once this modification is done to adb_shell, the goal is to use the modified adb_shell in Home Asisstant; the same that adb_shell is today.

## Sibling reference checkouts

These are **read-only references** living next to this repo, not dependencies to modify:

../adb - This is the reference implemnetation of adb that contains support for adb_wifi. Use this as the source of modifications to make to adb_shell for purposes of adding wifi support.