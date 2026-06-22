#!/usr/bin/env bash
set -euo pipefail

LIB_DIR="$(cd "$(dirname "$0")/MySQL Client Libraries/lib" && pwd)"
ARM_LIB="${LIB_DIR}/libmysqlclient_arm64.a"
X86_LIB="${LIB_DIR}/libmysqlclient_x86.a"
OUTPUT_LIB="${LIB_DIR}/libmysqlclient.a"

if [[ ! -f "$ARM_LIB" ]]; then
	ARM_LIB="${LIB_DIR}/libmysqlclient.a"
	if ! lipo -info "$ARM_LIB" 2>/dev/null | grep -q 'arm64'; then
		echo "Missing arm64 MySQL client library at ${LIB_DIR}/libmysqlclient_arm64.a" >&2
		exit 1
	fi
	if lipo -info "$ARM_LIB" 2>/dev/null | grep -q 'x86_64'; then
		echo "libmysqlclient.a is already a universal binary."
		lipo -info "$ARM_LIB"
		exit 0
	fi
	cp "$ARM_LIB" "${LIB_DIR}/libmysqlclient_arm64.a"
	ARM_LIB="${LIB_DIR}/libmysqlclient_arm64.a"
fi

if [[ ! -f "$X86_LIB" ]]; then
	echo "Missing x86_64 MySQL client library at ${X86_LIB}" >&2
	exit 1
fi

lipo -create "$ARM_LIB" "$X86_LIB" -output "$OUTPUT_LIB"
echo "Created universal libmysqlclient.a:"
lipo -info "$OUTPUT_LIB"
