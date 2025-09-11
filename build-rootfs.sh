#!/bin/bash

# Create FAT32 filesystem image from rootfs directory
IMAGE="rootfs.img"
SIZE_MB=16
ROOTFS_DIR="rootfs"

echo "Building FAT32 filesystem image..."

# Create a blank image file
dd if=/dev/zero of=$IMAGE bs=1M count=$SIZE_MB 2>/dev/null

# Format as FAT32
mkfs.vfat -F 32 $IMAGE >/dev/null

# Copy files from rootfs to the image
echo "Copying files to image..."

# Create directories in the image
for dir in $(find $ROOTFS_DIR -type d | sed "s|^$ROOTFS_DIR||" | grep -v "^$"); do
    mmd -i $IMAGE ::$dir 2>/dev/null || true
done

# Copy files to the image
for file in $(find $ROOTFS_DIR -type f); do
    dest=$(echo $file | sed "s|^$ROOTFS_DIR|::|")
    mcopy -i $IMAGE $file $dest
done

echo "Filesystem image created: $IMAGE (${SIZE_MB}MB)"
echo "Contents:"
mdir -i $IMAGE -/ ::

echo "Done!"