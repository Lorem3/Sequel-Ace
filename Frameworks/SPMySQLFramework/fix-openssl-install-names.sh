#!/usr/bin/env bash
set -euo pipefail

FRAMEWORK_VERSION_DIR="${CONFIGURATION_BUILD_DIR}/${WRAPPER_NAME}/Versions/Current"
FRAMEWORK_VERSION_A_DIR="${CONFIGURATION_BUILD_DIR}/${WRAPPER_NAME}/Versions/A"

fix_openssl_paths() {
	local target_dir="$1"
	cd "$target_dir"

	# Use explicit library names. Parsing otool output breaks for fat binaries.
	install_name_tool -change libcrypto.1.1.dylib @loader_path/libcrypto.1.1.dylib SPMySQL
	install_name_tool -change libssl.1.1.dylib @loader_path/libssl.1.1.dylib SPMySQL

	install_name_tool -id @loader_path/libcrypto.1.1.dylib libcrypto.1.1.dylib
	install_name_tool -id @loader_path/libssl.1.1.dylib libssl.1.1.dylib
	install_name_tool -change libcrypto.1.1.dylib @loader_path/libcrypto.1.1.dylib libssl.1.1.dylib
}

echo "Fixing OpenSSL install names in ${FRAMEWORK_VERSION_DIR}"
fix_openssl_paths "$FRAMEWORK_VERSION_DIR"

if [[ -d "$FRAMEWORK_VERSION_A_DIR" && "$FRAMEWORK_VERSION_A_DIR" != "$FRAMEWORK_VERSION_DIR" ]]; then
	echo "Fixing OpenSSL install names in ${FRAMEWORK_VERSION_A_DIR}"
	fix_openssl_paths "$FRAMEWORK_VERSION_A_DIR"
fi

if [[ -n "${EXPANDED_CODE_SIGN_IDENTITY:-}" && "${EXPANDED_CODE_SIGN_IDENTITY}" != "-" ]]; then
	cd "$FRAMEWORK_VERSION_DIR"
	echo "Codesigning OpenSSL dylibs"
	/usr/bin/codesign --force --sign "${EXPANDED_CODE_SIGN_IDENTITY}" -o runtime --timestamp=none --preserve-metadata=identifier,entitlements,flags libcrypto.1.1.dylib libssl.1.1.dylib
	/usr/bin/codesign --force --sign "${EXPANDED_CODE_SIGN_IDENTITY}" SPMySQL
fi
