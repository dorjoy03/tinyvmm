## tinyvmm
tinyvmm is a very tiny vmm for x86 linux to run a x86 linux kernel bzImage in a
VM and print the kernel logs to the vmm process's stdout. It only emulates a
ttyS0 serial console (NS16450 UART) to be able to redirect the kernel logs to
stdout.

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

To be able to verify initrd is properly loaded, I included some 'echo' and 'ls'
in the init script (see demo).

## Demo
Here's a demo of tinyvmm running a bzImage with an initramfs:

![tinyvmm_demo](https://github.com/user-attachments/assets/da8d9e61-23c1-4c17-ae93-ef24cc04f7fb)

## References
Some references I used:
* https://bellard.org/tinyemu/
* https://lwn.net/Articles/658511/
* https://gist.github.com/zserge/ae9098a75b2b83a1299d19b79b5fe488
* https://cylab.be/blog/320/build-a-kernel-initramfs-and-busybox-to-create-your-own-micro-linux
* https://www.kernel.org/
* https://docs.kernel.org/virt/kvm/api.html
* https://www.kernel.org/doc/html/latest/arch/x86/boot.html