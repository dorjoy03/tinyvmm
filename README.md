## tinyvmm
tinyvmm is a very tiny vmm for x86 linux to run a x86 linux kernel bzImage in a
VM and print the kernel logs to the vmm process's stdout. It only emulates a
minimal ttyS0 serial console to be able to redirect the kernel logs to stdout.

## Usage
`tinyvmm --kernel=kernel_path [--intird=initrd_path, --cmdline=kernel_cmdline]`

You can optionally provide an initramfs. You need to provide `--cmdline console=ttyS0`
to be able to see the kernel logs in your terminal.

## How to build
You will need to be on a x86 linux system with gcc and make.
1. clone this repo
2. cd tinyvmm
3. make

## Trying it out
For testing I built a linux kernel bzImage (linux-6.6.66) with the .config file
provided in this repo (copy the .config to the kernel's source directory and run
`make bzImage`). The config only has the necessary config options like printk,
tty, serial drivers, initramfs support etc. You should be able to boot the
/boot/vmlinuz-* in your own linux system with tinyvmm or any bzImage built from
source with .config similar to the one provided.

To be able to verify initrd is properly loaded, I included a simple kernel module
that just does a printk (see demo), bundled it and insmod it from the init script
of the initramfs (the kernel doesn't seem to make ttyS0 available at /dev so I
couldn't verify using echo in the init script, something I need to look into).

## Demo
Here's a demo of tinyvmm running a bzImage with an initramfs:

![tinyvmm_demo](https://github.com/user-attachments/assets/88a6ff04-0199-47ab-80c8-2522d9f4ae12)

## References
Some references I used:
* https://bellard.org/tinyemu/
* https://lwn.net/Articles/658511/
* https://gist.github.com/zserge/ae9098a75b2b83a1299d19b79b5fe488
* https://cylab.be/blog/320/build-a-kernel-initramfs-and-busybox-to-create-your-own-micro-linux
* https://www.kernel.org/
* https://docs.kernel.org/virt/kvm/api.html
* https://www.kernel.org/doc/html/latest/arch/x86/boot.html