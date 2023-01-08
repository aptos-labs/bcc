#!/bin/bash

DEBUGFS="/sys/kernel/debug"
KERNEL_VERSION="${KERNEL_VERSION:-$(uname -r)}"
HEADERS="${HEADERS:-/bcc/headers/$KERNEL_VERSION}"

function die {
	echo "$@"
	exit -1
}

[ ! -d ${HEADERS} ] && die "No such file $HEADERS"

if [[ ! -e /lib/modules/.installed ]]; then
	echo "Linking /lib/modules/${KERNEL_VERSION}"
	mkdir -p "/lib/modules/${KERNEL_VERSION}"
	ln -sf "${HEADERS}" "/lib/modules/${KERNEL_VERSION}/source"
	ln -sf "${HEADERS}" "/lib/modules/${KERNEL_VERSION}/build"
	touch /lib/modules/.installed
fi

if [ ! -d ${DEBUGFS}/tracing ]; then
	echo "mounting $DEBUGFS"
	mount -t debugfs none $DEBUGFS
fi
echo "BCC setup done"

echo "alias bcc='sudo python3'" >> ~/.bashrc
