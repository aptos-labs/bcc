# Linux Headers HowTo
---
BCC tools need Linux headers installed. When running directly on a VM/Physical machine
`apt install linux-headers-$(uname -r)` will work, creating this directory `/usr/src/linux-headers-$(uname -r)`.

When running on docker, this approach will now work as the build machine will be different from where the docker will run.

# Preinstalling Headers
Given a kernel version, i.e., `uname -r`, kernel headers can be installed with apt-get for a fixed version.

## Kernel Header Unavailable
When kernel headers are unavailable, e.g., Amazon Linux, kernel headers can be manually imported from a machine running the needed kernel.

### IKHEADERS=m
When the kernel is compiled with IKHEADERS `grep -i ikheaders /boot/config-$(uname -r)

1. `modprobe kheaders`
2. `/sys/kernel/kheaders.tar.xz`

### Preparing from src
When the exact version is missing, headers can be prepared from the source code.

#### Preparing
1. git clone repo (e.g., `git@github.com:amazonlinux/linux.git`)
2. cd linux
3. git checkout \<release tag\> (e.g., `kernel-5.4.196-108.356.amzn2.x86_64`)
4. cp config-\<nearset possible kernel version\>  .config (`e.g., 5.4.219-126.411.amzn2.x86_64`)
5. make ARCH=x86 olddefconfig > /dev/null
6. make ARCH=x86 prepare > /dev/null

#### Packaging
1. mkdir -p headers/arch
2. mv arch/x86 headers/arch/
3. mv include headers
4. cd headers
5. delete non .h files
```
#!/bin/bash

i=0

function rec {
	for f in `ls`; do

		if [ -d $f ]; then
			cd $f
			rec
			cd ..
		else
			base=`basename $f .h`
			if [ ${base}.h != $f ]; then
				#let "i=i+1"
				#echo "$i) $f"
				rm $f
			fi
		fi
	done
}

rec
```

### [Additional resource](https://github.com/mclenhard/ebpf-summit/blob/master/init/fetch-linux-headers.sh)
