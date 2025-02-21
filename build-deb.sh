#!/bin/bash

# Version
VERSION="1.0.0"
PACKAGE_NAME="mask-cli_${VERSION}"

# Clean previous builds
rm -rf "${PACKAGE_NAME}"

# Create directory structure
mkdir -p "${PACKAGE_NAME}/DEBIAN"
mkdir -p "${PACKAGE_NAME}/usr/local/bin"
mkdir -p "${PACKAGE_NAME}/usr/lib/mask-cli"
mkdir -p "${PACKAGE_NAME}/usr/share/doc/mask-cli"

# Copy files
cp -r index.js "${PACKAGE_NAME}/usr/lib/mask-cli/"
cp -r utils "${PACKAGE_NAME}/usr/lib/mask-cli/"
cp -r package.json "${PACKAGE_NAME}/usr/lib/mask-cli/"
cp -r README.md "${PACKAGE_NAME}/usr/share/doc/mask-cli/"
cp -r LICENSE "${PACKAGE_NAME}/usr/share/doc/mask-cli/"

# Copy DEBIAN control files
cp DEBIAN/control "${PACKAGE_NAME}/DEBIAN/"
cp DEBIAN/postinst "${PACKAGE_NAME}/DEBIAN/"
cp DEBIAN/prerm "${PACKAGE_NAME}/DEBIAN/"

# Set permissions
chmod 755 "${PACKAGE_NAME}/DEBIAN/postinst"
chmod 755 "${PACKAGE_NAME}/DEBIAN/prerm"
chmod -R 755 "${PACKAGE_NAME}/usr/lib/mask-cli"

# Build the package
dpkg-deb --build "${PACKAGE_NAME}"

# Clean up
rm -rf "${PACKAGE_NAME}"

echo "Package created: ${PACKAGE_NAME}.deb"