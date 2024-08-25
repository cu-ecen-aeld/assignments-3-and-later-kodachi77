#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u

OUTDIR=/tmp/aeld
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.1.10
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-
FORCE_CLEAN=1
COMPILE_MODULES=

if [ $# -lt 1 ]
then
    echo "Using default directory ${OUTDIR} for output"
else
    OUTDIR=$1
    echo "Using passed directory ${OUTDIR} for output"
fi

mkdir -p ${OUTDIR}
if [ ! -d "${OUTDIR}" ]; then
    echo "Output directory ${OUTDIR} cannot be created"
    exit 1
fi

# Make OUTDIR path absolute
OUTDIR=$(realpath ${OUTDIR})

cd $OUTDIR
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    # Clone only if the repository does not exist.
    echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
    git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
    cd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}
else
    cd linux-stable
fi

if [ "$FORCE_CLEAN" ] && [ -e "${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image" ]
then
    make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE mrproper
fi

if [ ! -e "${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image" ]; then
    echo "Compiling linux"

    # Don't forget to install bison, flex and openssl. Use:
    # sudo apt install flex bison libssl-dev

    if [ ! -e .config ]; then
	make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE defconfig
    fi

    make -j4 ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE all

    if [ "$COMPILE_MODULES" ]; then
        make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE modules
    fi

    make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE dtbs
fi

echo "Adding the Image in outdir"
cp "${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image" "$OUTDIR/"

echo "Creating the staging directory for the root filesystem"
if [ -d "${OUTDIR}/rootfs" ]; then
    echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm  -rf "${OUTDIR}/rootfs"
fi

mkdir -p "${OUTDIR}/rootfs" && cd "${OUTDIR}/rootfs"
mkdir -p bin dev etc home lib lib64 proc sbin sys tmp usr var
mkdir -p usr/bin usr/lib usr/sbin
mkdir -p var/log

echo "Compiling busybox"
cd $OUTDIR
if [ ! -d "${OUTDIR}/busybox" ]
then
    git clone git://busybox.net/busybox.git
    cd busybox
    git checkout ${BUSYBOX_VERSION}
else
    cd busybox
fi

if [ "$FORCE_CLEAN" ]; then
    make distclean

fi

if [ ! -e .config ]; then
    make defconfig
fi

make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE
make ARCH=$ARCH CROSS_COMPILE=$CROSS_COMPILE CONFIG_PREFIX="${OUTDIR}/rootfs" install

echo "Library dependencies"
${CROSS_COMPILE}readelf -a ${OUTDIR}/rootfs/bin/busybox | grep "program interpreter"
${CROSS_COMPILE}readelf -a ${OUTDIR}/rootfs/bin/busybox | grep "Shared library"

# Add library dependencies to rootfs
SYSROOT_DIR=$(${CROSS_COMPILE}gcc -print-sysroot)
SYSROOT_DIR=$(realpath $SYSROOT_DIR)

for file in $(${CROSS_COMPILE}readelf -a ${OUTDIR}/rootfs/bin/busybox | sed -n "s#.*program interpreter: \(.*\)]#${SYSROOT_DIR}\1#p"); do
    # Copy each file to the destination directory
    relative_path="${file#$SYSROOT_DIR}"
    echo "Copying ${file} to ${OUTDIR}/rootfs/${relative_path}"
    cp -L "$file" "${OUTDIR}/rootfs/${relative_path}"
done

for file in $(${CROSS_COMPILE}readelf -a ${OUTDIR}/rootfs/bin/busybox | sed -n "s#.*Shared library: \[\(.*\)\]#${SYSROOT_DIR}/lib64/\1#p"); do
    # Copy each file to the destination directory
    relative_path="${file#$SYSROOT_DIR}"
    echo "Copying ${file} to ${OUTDIR}/rootfs/${relative_path}"
    cp -L "$file" "${OUTDIR}/rootfs/${relative_path}"
done

# Make device nodes
cd "${OUTDIR}/rootfs"
if  [ -e dev/null ]; then 
    sudo mknod dev/null c 1 3
    sudo chmod 666 dev/null
fi

if [ -e dev/console ]; then
    sudo mknod dev/console c 5 1
    sudo chmod 600 dev/console
fi

# Clean and build the writer utility
cd "$FINDER_APP_DIR"
if [ "$FORCE_CLEAN" ]; then
    make CROSS_COMPILE=$CROSS_COMPILE clean
fi
make CROSS_COMPILE=$CROSS_COMPILE

# Copy the finder related scripts and executables to the /home directory on the target rootfs
cp writer finder.sh finder-test.sh autorun-qemu.sh "${OUTDIR}/rootfs/home/"

conf_relative_path=$(realpath --relative-to=$(realpath .) $(readlink -f conf))
cp -r $conf_relative_path "${OUTDIR}/rootfs/home/${conf_relative_path}"
cp -a conf "${OUTDIR}/rootfs/home/"

# Chown the root directory
sudo chown -R root:root "${OUTDIR}/rootfs"

# Create initramfs.cpio.gz
cd "${OUTDIR}/rootfs"
if [ -e "${OUTDIR}/initramfs.cpio.gz" ]; then
    rm -f "${OUTDIR}/initramfs.cpio.gz"
fi
find . | cpio -H newc -ov --owner root:root > ${OUTDIR}/initramfs.cpio
gzip ${OUTDIR}/initramfs.cpio

echo "Build complete!!!"