# Sandbox Extension Generator
A method of generating arbitary sandbox extensions using kernel read/write primitives on iOS 7 - 15.3.1 (patched via PAC in iOS 15.4). Mainly useful for iOS 15.0 - 15.3.1 because many other ways of escaping sandboxes using kernel r/w have been mitigated in iOS 15 on arm64e devices via PAC or PPL.

## Sandbox Extensions explained
Sandbox extensions are strings that consists of two parts, here's an example:

2e62aa619da8934a8c6ed37c413fa8e602cb00581f35f0bde3ccf0e910b5cc41;00;00000000;00000000;00000000;0000000000000020;com.apple.app-sandbox.read-write;01;01000007;0000000000000002;01;/

The very first segment (until the first ;) of it is a hash that the kernel generates when the extension is issued and verifies when the extension is attempted to be consumed, this hash is calculated based on the following data:
* The rest of the string (including the leading ; and the trailing null byte)
* A 128 bit secret that's generated when the device boots

The rest of the string describes what permissions the sandbox extensions allows when being consumed, in this example it is read/write access to /.

It is also important to note that the second part of the string never changes across reboots, so you can simply generate it once on a jailbroken device and then you have it, the secret is random however and therefore the hash at the beginning of the string changes every reboot.

Note that in iOS 11 and higher it is possible to generate a sandbox extension for a specific pid / audit token instead of generating one that can be consumed by the entire system, in this case the important process information is appended to the second part of the string and is included when the hash at the beginning is generated, this is largely irrelavant here however because this technique allows us to generate what we want, so we can just generate a generic extension instead of a process specific one (which would be more work).

## The Problem
As an educated reader may have already realized, this approach is not secure at all. When we have kernel read/write, we can simply read the 128 bit secret and then replicate the kernel hashing code to generate the sandbox extensions without calling the kernel. That's whats demonstrated in this project.

The hmac_sha256 kernel function is responsible for generating the hash and is called by syscall_extension_issue and syscall_extension_consume. It uses some arm64 neon instructions which were very hard to replicate but I did end up finding the right header to do it. Other than that, reimplementing the hmac_sha256 function is straight forward. I have called it hmac_sha256_secret in this project because it uses the secret passed to it instead of the global variable.

## Offsetless Approach
Because finding the offset of the "secret" kernel variable for every single device / iOS version combination is tedious, it is possible to dump the entire kernel __DATA:__bss section and try every single global variable until we find the secret and sandbox_extension_consume returns 1. This allows this technique to work without any hardcoded offsets. It only took about 0.1 seconds to find the offset on my iPhone 13 Pro.

## The Patch
On arm64e devices running 15.4 and above, the kernel now adds a generic PAC key to the extension hash which we cannot replicate in our userspace process, meaning that this technique no longer works.

## Is this useful for jailbreaking?
Unfortunately, not really. All you can technically do with this is:
* Give yourself permission to read/write to / (See sandbox_extension_issue_file)
* Give yourself permission to open an IOKit user client or registry entry otherwise not permitted by sandbox (See sandbox_extension_issue_iokit_registry_entry_class, sandbox_extension_issue_iokit_user_client_class)
* Give yourself permission to contact a mach service otherwise not permitted by sandbox (See sandbox_extension_issue_mach)
* Give yourself permission to contact a posix ipc service otherwise not permitted by sandbox (See sandbox_extension_issue_posix_ipc)
* Give yourself a generic sandbox extension permission, not really sure what that means, wasn't able to find much on it (See sandbox_extension_issue_generic)

This technique therefore only allows you to expand your attack vector to userspace processes and to access the file-system.

## Compilation
In order for this file to compile, you will need to replace the -[KernelManager readBufferAtAddress:intoBuffer:withLength:] calls with your own kread_buf function.