## Introducing integrity within Gentoo Linux

![Penguin Integrity](https://fujifilmxgfx.com/wp-content/uploads/2018/01/Antarctica_2017_06042.jpg)

In this guide we will install [Gentoo Linux](https://gentoo.org/) in a [HP EliteBook 8560p](https://support.hp.com/us-en/product/hp-elitebook-8560p-notebook-pc/5056949/model/5056950/document/c02782594), the one equiped with the [Intel® Core i7 2620M CPU](https://ark.intel.com/products/52231/Intel-Core-i7-2620M-Processor-4M-Cache-up-to-3_40-GHz) that include [Intel® HD Graphics 3000](https://ark.intel.com/products/52231/Intel-Core-i7-2620M-Processor-4M-Cache-up-to-3_40-GHz#tab-blade-1-0-4). 

We will start using the steps illustrated in the almost perfect [Sahaki's EFI Install Guide](https://wiki.gentoo.org/wiki/Sakaki%27s_EFI_Install_Guide), but we are going to expand it applying the rules of the [Gentoo Project Integrity](https://wiki.gentoo.org/wiki/Project:Integrity) that aims to integrate and maintain technologies related to system integrity within [Gentoo Hardened](https://wiki.gentoo.org/wiki/Hardened_Gentoo). 

## Download, verify and write last boot ISO Gentoo image

From an helper Linux PC (in this case `cyberdream` is also a Gentoo workstation) execute the following commands:

```sh
If Machiavelli were a programmer, he'd have worked for AT&T.
taglio@cyberdream ~ $ uname -a
Linux cyberdream 4.17.2-gentoo #4 SMP Fri Jun 22 23:57:11 CEST 2018 x86_64 Intel(R) Core(TM) i7-6700K CPU @ 4.00GHz GenuineIntel GNU/Linux
taglio@cyberdream ~ $ cd Work/npna/Gentoo/
taglio@cyberdream ~/Work/npna/Gentoo $ mkdir Integrity
taglio@cyberdream ~/Work/npna/Gentoo $ cd Integrity/
taglio@cyberdream ~/Work/npna/Gentoo/Integrity $ wget http://distfiles.gentoo.org/releases/amd64/autobuilds/latest-iso.txt
--2018-06-23 11:44:03--  http://distfiles.gentoo.org/releases/amd64/autobuilds/latest-iso.txt
Resolving distfiles.gentoo.org... 64.50.233.100, 64.50.236.52, 137.226.34.46, ...
Connecting to distfiles.gentoo.org|64.50.233.100|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 204 [text/plain]
Saving to: ‘latest-iso.txt’

latest-iso.txt      100%[===================>]     204  --.-KB/s    in 0s      

2018-06-23 11:44:03 (75.0 MB/s) - ‘latest-iso.txt’ saved [204/204]

taglio@cyberdream ~/Work/npna/Gentoo/Integrity $ cat latest-iso.txt 
# Latest as of Sat, 23 Jun 2018 09:00:02 +0000
# ts=1529744402
20180412T214502Z/hardened/admincd-amd64-20180412T214502Z.iso 497025024
20180415T214502Z/install-amd64-minimal-20180415T214502Z.iso 319815680
taglio@cyberdream ~/Work/npna/Gentoo/Integrity $ wget http://distfiles.gentoo.org/releases/amd64/autobuilds/20180415T214502Z/install-amd64-minimal-20180415T214502Z.iso{,.CONTENTS,.DIGESTS.asc}
--2018-06-23 11:48:30--  http://distfiles.gentoo.org/releases/amd64/autobuilds/20180415T214502Z/install-amd64-minimal-20180415T214502Z.iso
Resolving distfiles.gentoo.org... 64.50.233.100, 64.50.236.52, 137.226.34.46, ...
Connecting to distfiles.gentoo.org|64.50.233.100|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 319815680 (305M) [application/octet-stream]
Saving to: ‘install-amd64-minimal-20180415T214502Z.iso’

install-amd64-minim 100%[===================>] 305.00M  8.18MB/s    in 61s     

2018-06-23 11:49:31 (5.03 MB/s) - ‘install-amd64-minimal-20180415T214502Z.iso’ saved [319815680/319815680]

--2018-06-23 11:49:31--  http://distfiles.gentoo.org/releases/amd64/autobuilds/20180415T214502Z/install-amd64-minimal-20180415T214502Z.iso.CONTENTS
Reusing existing connection to distfiles.gentoo.org:80.
HTTP request sent, awaiting response... 200 OK
Length: 1916 (1.9K) [application/octet-stream]
Saving to: ‘install-amd64-minimal-20180415T214502Z.iso.CONTENTS’

install-amd64-minim 100%[===================>]   1.87K  --.-KB/s    in 0s      

2018-06-23 11:49:31 (352 MB/s) - ‘install-amd64-minimal-20180415T214502Z.iso.CONTENTS’ saved [1916/1916]

--2018-06-23 11:49:31--  http://distfiles.gentoo.org/releases/amd64/autobuilds/20180415T214502Z/install-amd64-minimal-20180415T214502Z.iso.DIGESTS.asc
Reusing existing connection to distfiles.gentoo.org:80.
HTTP request sent, awaiting response... 200 OK
Length: 1654 (1.6K) [text/plain]
Saving to: ‘install-amd64-minimal-20180415T214502Z.iso.DIGESTS.asc’

install-amd64-minim 100%[===================>]   1.62K  --.-KB/s    in 0s      

2018-06-23 11:49:31 (370 MB/s) - ‘install-amd64-minimal-20180415T214502Z.iso.DIGESTS.asc’ saved [1654/1654]

FINISHED --2018-06-23 11:49:31--
Total wall clock time: 1m 1s
Downloaded: 3 files, 305M in 1m 1s (5.03 MB/s)
taglio@cyberdream ~/Work/npna/Gentoo/Integrity $
```

After creating a directory for the project in our `cyberdream` machine we download a `.txt` from the Gentoo website that contain the latest minimal install ISO for the `amd64` architecture. Just append the **install** one to the URI `http://distfiles.gentoo.org/releases/amd64/autobuilds/` and download it togheter with the `.CONTENTS` and `.DIGESTS.asc` files. 

The `.DIGESTS.asc` file contains cryptographically signed digests (using various hash algorithms) for two other files we have downloaded. It is needed to check the [data integrity](https://en.wikipedia.org/wiki/Data_integrity) of them. The instructions to check it are in [this area](https://wiki.gentoo.org/wiki/Project:RelEng) of the Gentoo wiki.

```sh
taglio@cyberdream ~/Work/npna/Gentoo/Integrity $ gpg --recv-key 0xBB572E0E2D182910
gpg: key 0xBB572E0E2D182910: "Gentoo Linux Release Engineering (Automated Weekly Release Key) <releng@gentoo.org>" 1 new signature
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: depth: 0  valid:   7  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 7u
gpg: next trustdb check due at 2019-01-01
gpg: Total number processed: 1
gpg:         new signatures: 1
taglio@cyberdream ~/Work/npna/Gentoo/Integrity $ gpg --edit-key 0xBB572E0E2D182910
gpg (GnuPG) 2.2.8; Copyright (C) 2018 Free Software Foundation, Inc.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
pub  rsa4096/0xBB572E0E2D182910
     created: 2009-08-25  expires: 2019-08-22  usage: SC  
     trust: ultimate      validity: ultimate
[ultimate] (1). Gentoo Linux Release Engineering (Automated Weekly Release Key) <releng@gentoo.org>
gpg> fpr
pub   rsa4096/0xBB572E0E2D182910 2009-08-25 Gentoo Linux Release Engineering (Automated Weekly Release Key) <releng@gentoo.org>
 Primary key fingerprint: 13EB BDBE DE7A 1277 5DFD  B1BA BB57 2E0E 2D18 2910

gpg> trust
pub  rsa4096/0xBB572E0E2D182910
     created: 2009-08-25  expires: 2019-08-22  usage: SC  
     trust: ultimate      validity: ultimate
[ultimate] (1). Gentoo Linux Release Engineering (Automated Weekly Release Key) <releng@gentoo.org>

Please decide how far you trust this user to correctly verify other users' keys
(by looking at passports, checking fingerprints from different sources, etc.)

  1 = I don't know or won't say
  2 = I do NOT trust
  3 = I trust marginally
  4 = I trust fully
  5 = I trust ultimately
  m = back to the main menu

Your decision? 5
Do you really want to set this key to ultimate trust? (y/N) y

pub  rsa4096/0xBB572E0E2D182910
     created: 2009-08-25  expires: 2019-08-22  usage: SC  
     trust: ultimate      validity: ultimate
[ultimate] (1). Gentoo Linux Release Engineering (Automated Weekly Release Key) <releng@gentoo.org>

gpg> save
Key not changed so no update needed.
taglio@cyberdream ~/Work/npna/Gentoo/Integrity $ gpg --verify install-amd64-minimal-20180415T214502Z.iso.DIGESTS.asc 
gpg: Signature made Mon 16 Apr 2018 04:06:08 CEST
gpg:                using RSA key 13EBBDBEDE7A12775DFDB1BABB572E0E2D182910
gpg: Good signature from "Gentoo Linux Release Engineering (Automated Weekly Release Key) <releng@gentoo.org>" [ultimate]
Primary key fingerprint: 13EB BDBE DE7A 1277 5DFD  B1BA BB57 2E0E 2D18 2910
taglio@cyberdream ~/Work/npna/Gentoo/Integrity $ awk '/SHA512 HASH/{getline;print}' install-amd64-minimal-20180415T214502Z.iso.DIGESTS.asc | sha512sum --check
install-amd64-minimal-20180415T214502Z.iso: OK
install-amd64-minimal-20180415T214502Z.iso.CONTENTS: OK
taglio@cyberdream ~/Work/npna/Gentoo/Integrity $ 

```

What have we just done? 

First of all we have find the correct hexadecimal `gpg key id` in the [Gentoo Project Release Engineering](https://wiki.gentoo.org/wiki/Project:RelEng); we have to search for the line about *Automated weekly release key*. At the time of writing, *June 2018*, the correct id is `0xBB572E0E2D182910`.  Next:

- `gpg --receive-keys`: import keys from a keyserver.

- `gpg --edit-key`: sign or edit a key.

After doing this two operations we're going to execute commands under the `gpg shell`:

- `fpr`: show key fingerprint.

- `trust`: change the ownertrust.

- `5`: trust ultimately the *Automated weekly release key*.

- `save`: save and quit.

Next we return to the `bash shell` and we **verify** the `.DIGESTS.asc` with `gpg`:

- `gpg --verify`: verify a signature.

And at least we verify the checksum using the `sha512` hash. We use `awk`  that is an interpreter for a programming language used for pattern scanning and processing. It is a real programming language, look at the [*huge manual*](https://www.gnu.org/software/gawk/manual/html_node/Index.html#Index) of its version by *GNU*!

We use the functions:

- `getline`: [Getline-Summary](https://www.gnu.org/software/gawk/manual/html_node/Getline-Summary.html#Getline-Summary).
- `print`: [Print](https://www.gnu.org/software/gawk/manual/html_node/Print.html#Print). 

The result is *piped* to `sha512sum` that compute and check SHA512 message digest:

- `sha512sum --check`: read SHA512 sums from the FILEs and check them.


```sh
taglio@cyberdream ~ $ lsblk | grep sdf
sdf                                                      8:80   1  14.9G  0 disk  
taglio@cyberdream ~ $ 
taglio@cyberdream ~/Work/npna/Gentoo/Integrity $ dd if=install-amd64-minimal-20180415T214502Z.iso of=/dev/sdf status=progress bs=8192k
234881024 bytes (235 MB, 224 MiB) copied, 1 s, 228 MB/s
38+1 records in
38+1 records out
319815680 bytes (320 MB, 305 MiB) copied, 64.7066 s, 4.9 MB/s
taglio@cyberdream ~/Work/npna/Gentoo/Integrity $ sync && sync
taglio@cyberdream ~/Work/npna/Gentoo/Integrity $ sudo fdisk -l /dev/sdf
Disk /dev/sdf: 14.9 GiB, 16005464064 bytes, 31260672 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x04252123

Device     Boot Start    End Sectors  Size Id Type
/dev/sdf1  *        0 624639  624640  305M 17 Hidden HPFS/NTFS
taglio@cyberdream ~/Work/npna/Gentoo/Integrity $
```

Going ahead we have to write to downloaded and verified `.iso` image to a pendrive. We insert it in a `USB` port and with `lsblk` (*list block devices*)  we lists  information about all available or the specified block devices to find the letter assigned to it, it this case `f` (`sdf`). We write the image with the `dd` command (*convert and copy a file*) using this instructions:

- `if=FILE`: read from FILE instead of stdin.
- `of=FILE`: write to FILE instead of stdout.
- `status=progress`: shows periodic transfer statistics.
- `bs=BYTES`: read and write up to BYTES bytes at a time.

Next we *double* `sync` (*Synchronize cached writes to persistent storage*) the host storages and we verified what we've writed on the pendrive with `fdisk -l`. 

## Configuring the BIOS and booting the ISO image.

![1-HPBIOS-UTCtime](/home/taglio/Work/npna/Gentoo/Integrity/Resources/1-HPBIOS-UTCtime.jpg)

  

The first pass that we've to do in the **Hewlett-Packard BIOS** (*68SCF v. F.42*) is to set the hardware clock to the current UTC time, just [find it in google](https://www.google.com/search?num=40&source=hp&ei=mqkwW6LQOKWO5wL6h6TACA&q=UTC+Time&oq=UTC+Time&gs_l=psy-ab.3..0l10.1855.3297.0.3421.9.8.0.0.0.0.174.652.0j4.4.0....0...1.1.64.psy-ab..5.4.652.0..0i131k1.0.8ErstRMWEpI). Do it in the first screen.

  ![3-HPBIOS-Password](/home/taglio/Work/npna/Gentoo/Integrity/Resources/3-HPBIOS-Password.jpg)



Next on the second screen use the correct option to **set an administrator password**.  

![4-HPBIOS-TPM](/home/taglio/Work/npna/Gentoo/Integrity/Resources/4-HPBIOS-TPM.jpg)

Next always on the second screen enter in the **TPM Embedded Security** part and configure the options as above. But *what is the TPM or the [Trusted Platform Module](https://en.wikipedia.org/wiki/Trusted_Platform_Module)*? 

> **Trusted Platform Module** (**TPM**, also known as **ISO/IEC 11889**) is an [international standard](https://en.wikipedia.org/wiki/International_standard) for a [secure cryptoprocessor](https://en.wikipedia.org/wiki/Secure_cryptoprocessor), a dedicated [microcontroller](https://en.wikipedia.org/wiki/Microcontroller) designed to secure hardware through integrated [cryptographic keys](https://en.wikipedia.org/wiki/Cryptographic_keys).
>
> Trusted Platform Module provides
>
> - A [random number generator](https://en.wikipedia.org/wiki/Random_number_generation)[[5\]](https://en.wikipedia.org/wiki/Trusted_Platform_Module#cite_note-5)[[6\]](https://en.wikipedia.org/wiki/Trusted_Platform_Module#cite_note-6)
> - Facilities for the secure generation of [cryptographic keys](https://en.wikipedia.org/wiki/Cryptographic_keys) for limited uses.
> - [Remote attestation](https://en.wikipedia.org/wiki/Remote_attestation): Creates a nearly unforgeable [hash key](https://en.wikipedia.org/wiki/Cryptographic_hash_function) summary of the hardware and software configuration. The software in charge of hashing the configuration data determines the extent of the summary. This allows a third party to verify that the software has not been changed.
> - Binding: Encrypts data using the TPM bind key, a unique [RSA](https://en.wikipedia.org/wiki/RSA_(algorithm)) key descended from a storage key[*clarification needed*].[[7\]](https://en.wikipedia.org/wiki/Trusted_Platform_Module#cite_note-7)
> - [Sealing](https://en.wikipedia.org/wiki/Sealed_storage): Similar to binding, but in addition, specifies the TPM state[*clarification needed*] for the data to be decrypted (unsealed).[[8\]](https://en.wikipedia.org/wiki/Trusted_Platform_Module#cite_note-8)
>
> Computer programs can use a TPM to [authenticate](https://en.wikipedia.org/wiki/Authentication) hardware devices, since each TPM chip has a unique and secret [RSA](https://en.wikipedia.org/wiki/RSA_(algorithm)) key burned in as it is produced. Pushing the security down to the hardware level provides more protection than a software-only solution



![5-HPBIOS-System](/home/taglio/Work/npna/Gentoo/Integrity/Resources/5-HPBIOS-System.jpg)

![6-HPBIOS-System](/home/taglio/Work/npna/Gentoo/Integrity/Resources/6-HPBIOS-System.jpg)

At last we configure the *System Configuration* part like above. Important is not to enable the *Uefi Boot Mode* because, like we've see in the `fisk -l` that we've done before, the pendrive image doesn't support it.

[![HP Elitebook 8560p Gentoo latest minimal install ISO boot](https://i.ytimg.com/vi/2t5IrqMsygA/hqdefault.jpg)](https://www.youtube.com/watch?v=VID2t5IrqMsygA)

In the above video Kernel and OpenRC output of a standard installation ISO from Gentoo official distfile.

## First livecd configuration steps

Assuming that we've connected the ethernet interface of our HP laptop to the same switch of the helper machine, `cyberdream` in this case, let's start the `sshd` daemon and set the `root` password to connect by `ssh` to it.

```ssh
livecd # /etc/init.d/sshd start
ssh-keygen: generating new host keys: RSA DSA ED25519
* Starting sshd ...
livecd # passwd
New password:
Retype new password:
passwd: password updated successfully
livecd #
```

Then:

```sh
taglio@cyberdream ~/Work/npna/Gentoo/Integrity $ ssh root@192.168.1.35
The authenticity of host '192.168.1.35 (192.168.1.35)' can't be established.
ED25519 key fingerprint is SHA256:1C+3U/ratDH2X23JoXkoZBPrGT8IkQo5wDkJk9L4ZSg.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.1.35' (ED25519) to the list of known hosts.
Password: 
Welcome to the Gentoo Linux Minimal Installation CD!

The root password on this system has been auto-scrambled for security.

If any ethernet adapters were detected at boot, they should be auto-configured
if DHCP is available on your network.  Type "net-setup eth0" to specify eth0 IP
address settings by hand.

Check /etc/kernels/kernel-config-* for kernel configuration(s).
The latest version of the Handbook is always available from the Gentoo web
site by typing "links https://wiki.gentoo.org/wiki/Handbook".

To start an ssh server on this system, type "/etc/init.d/sshd start".  If you
need to log in remotely as root, type "passwd root" to reset root's password
to a known value.

Please report any bugs you find to https://bugs.gentoo.org. Be sure to include
detailed information about how to reproduce the bug you are reporting.
Thank you for using Gentoo Linux!

livecd ~ #
```

## GPT laptop hardrive schema and hard encryption

We're going to use partitionate the `SSD` hard drive recently adquired on amazon to start this guide. I strongly reccomend to use an [`SSD` capable drive like this one](https://www.amazon.com/dp/B0764WCXCV?aaxitk=HYYt.LOgWjJgESCw-xce6A&pd_rd_i=B0764WCXCV&pf_rd_m=ATVPDKIKX0DER&pf_rd_p=3930100107420870094&pf_rd_s=desktop-sx-top-slot&pf_rd_t=301&pf_rd_i=2.5+ssd+250&hsa_cr_id=9954094940201).

```sh
livecd ~ # lsblk
NAME   MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT
loop0    7:0    0 283.2M  1 loop /mnt/livecd
sda      8:0    0 232.9G  0 disk 
sdb      8:16   1  14.9G  0 disk 
`-sdb1   8:17   1   305M  0 part /mnt/cdrom
sr0     11:0    1  1024M  0 rom  
livecd ~ # fdisk /dev/sda

Welcome to fdisk (util-linux 2.30.2).
Changes will remain in memory only, until you decide to write them.
Be careful before using the write command.


Command (m for help): g
Created a new GPT disklabel (GUID: 01A190B8-F126-4E6E-AF87-B1BE6978F80C).

Command (m for help): n
Partition number (1-128, default 1): 
First sector (2048-488397134, default 2048): 
Last sector, +sectors or +size{K,M,G,T,P} (2048-488397134, default 488397134): +256M

Created a new partition 1 of type 'Linux filesystem' and of size 256 MiB.

Command (m for help): t
Selected partition 1
Partition type (type L to list all types): 1
Changed type of partition 'Linux filesystem' to 'EFI System'.

Command (m for help): n
Partition number (2-128, default 2): 
First sector (526336-488397134, default 526336): 
Last sector, +sectors or +size{K,M,G,T,P} (526336-488397134, default 488397134): 

Created a new partition 2 of type 'Linux filesystem' and of size 232.7 GiB.

Command (m for help): p
Disk /dev/sda: 232.9 GiB, 250059350016 bytes, 488397168 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 4096 bytes
I/O size (minimum/optimal): 4096 bytes / 4096 bytes
Disklabel type: gpt
Disk identifier: 01A190B8-F126-4E6E-AF87-B1BE6978F80C

Device      Start       End   Sectors   Size Type
/dev/sda1    2048    526335    524288   256M EFI System
/dev/sda2  526336 488397134 487870799 232.7G Linux filesystem

Command (m for help): w
The partition table has been altered.
Calling ioctl() to re-read partition table.
Syncing disks.
livecd ~ # mkfs.vfat -F32 /dev/sda1
mkfs.fat 4.0 (2016-05-06)
livecd ~ #
```

So after an `lsblk` to see block devices in our laptop we start to configure the partition table of our disk as above. To do this we use the `fdisk /dev/sda` to access the *subshell* of the program:

- `g`: create a new empty **GPT** partition table.
- `n`: add a new primary partition; a `256MB` one.
- `t`: change a partition type; we choose an **EFI System** one.
- `n`: add a new primary partion; this time with the total remaining space and of **Linux filesystem** type.
- `w`: write table to disk and exit.

Next we format the `sda1` partition as `fat32` filesystem.

```sh
livecd ~ # cat >> .bashrc <<EOF
> alias mount="mount -v"
> alias mkdir="mkdir -v"
> alias rm="rm -v"
> alias swapon="swapon -v"
> alias umount="umount -v"
> alias wget="wget -c"
> alias tar="tar -v"
> alias nano="nano -w"
> alias cp="cp -v"
> alias reloadgpg="echo RELOADAGENT | gpg-connect-agent"
> 
> export GPG_TTY=$(tty)
> EOF
livecd ~ # source .bashrc
livecd ~ # alias
alias cp='cp -i'
alias egrep='egrep --colour=auto'
alias fgrep='fgrep --colour=auto'
alias grep='grep --color=auto'
alias ll='ls -l'
alias ls='ls --color=auto'
alias mkdir='mkdir -v'
alias mount='mount -v'
alias mv='mv -i'
alias reloadgpg='echo RELOADAGENT | gpg-connect-agent'
alias rm='rm -v'
livecd ~ # env
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=01;05;37;41:mi=01;05;37;41:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.cfg=00;32:*.conf=00;32:*.diff=00;32:*.doc=00;32:*.ini=00;32:*.log=00;32:*.patch=00;32:*.pdf=00;32:*.ps=00;32:*.tex=00;32:*.txt=00;32:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
SSH_CONNECTION=192.168.1.33 33788 192.168.1.35 22
LANG=en_GB.utf8
LESS=-R -M --shift 5
CONFIG_PROTECT_MASK=/etc/sandbox.d /etc/gentoo-release /etc/terminfo /etc/ca-certificates.conf
EDITOR=/bin/nano
GPG_TTY=/dev/pts/0
GCC_SPECS=
USER=root
PAGER=/usr/bin/less
LC_COLLATE=C
PWD=/root
MANPAGER=manpager
HOME=/root
SSH_CLIENT=192.168.1.33 33788 22
SSH_TTY=/dev/pts/0
MAIL=/var/mail/root
CONFIG_PROTECT=/usr/share/gnupg/qualified.txt
TERM=xterm-256color
SHELL=/bin/bash
SHLVL=1
MANPATH=/usr/share/gcc-data/x86_64-pc-linux-gnu/6.4.0/man:/usr/share/binutils-data/x86_64-pc-linux-gnu/2.29.1/man:/usr/local/share/man:/usr/share/man
LOGNAME=root
PATH=/usr/x86_64-pc-linux-gnu/gcc-bin/6.4.0:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin
INFOPATH=/usr/share/gcc-data/x86_64-pc-linux-gnu/6.4.0/info:/usr/share/binutils-data/x86_64-pc-linux-gnu/2.29.1/info:/usr/share/info
LESSOPEN=|lesspipe %s
_=/usr/bin/env
livecd ~ #
```

Now we add some tricks to our `bash` shell and verify them. We add to the `.bashrc` file in the root directory some aliases to add more verbosity to some commands, create a `reloadgpg` alias to correctly reload the `gpg-agent` (*Secret key management for GnuPG*) and we add a variable to the environment always `gpg` related. Next we verify what we've done with this two `bash` embedded commands:

- `alias`: visualise all the aliases in the system.
- `env`: visualise all the system and local session variables.

```sh
livecd ~ # mkdir /tmp/efi
mkdir: created directory '/tmp/efi'
livecd ~ # mount /dev/sda1 /tmp/efi/
mount: /dev/sda1 mounted on /tmp/efi.
livecd ~ # dd if=/dev/urandom bs=8388607 count=1 | gpg --symmetric --cipher-algo AES256 --output /tmp/efi/luks-key.gpg
gpg: directory '/root/.gnupg' created
gpg: keybox '/root/.gnupg/pubring.kbx' created
1+0 records in
1+0 records out
8388607 bytes (8.4 MB, 8.0 MiB) copied, 19.9947 s, 420 kB/s
livecd ~ #
```

From the [Sahaki EFI Install Guide](https://wiki.gentoo.org/wiki/Sakaki%27s_EFI_Install_Guide):

> We will next create a (pseudo) random keyfile (for use with LUKS). This keyfile will be encrypted with [GPG](http://en.wikipedia.org/wiki/Gnu_Privacy_Guard) (using a typed-in passphrase) and then stored on the USB key.
>
> The point of this is to establish dual-factor security - both the (encrypted) keyfile, *and* your passphrase (to decrypt it) will be required to access the LUKS data stored on the target machine's hard drive. This means that even if a keylogger is present, should the machine be stolen - powered down but without the USB key - the LUKS data will still be safe (as the thief will not have your encrypted keyfile). Similarly, (assuming no keylogger!) if your machine were to be stolen powered down but with the USB key still in it, it will also not be possible to access your LUKS data (as in this case the thief will not know your passphrase).
>
> Note that we are going to create a (one byte short of) 8192[KiB](http://en.wikipedia.org/wiki/Kibibyte) underlying (i.e., binary plaintext) keyfile, even though, for the symmetric LUKS cipher we'll be using ([Serpent](http://en.wikipedia.org/wiki/Serpent_(cipher))), the maximum supported key size is 256 bits (32 bytes) (or two 256 bit keys = 512 bits = 64 bytes in XTS mode, as explained later). This works because LUKS / cryptsetup uses the [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2) key derivation function to map the keyfile into the actual (user) key material internally (which in turn is used to unlock the master key actually used for sector encryption / decryption), so we are free, within limits, to choose whatever size keyfile we want. As such, we elect to use the largest legal size, so as to make it (very slightly) harder for any data capture malware (in low-level drivers, for example) to intercept the file and squirrel it away, or transmit it over the network surreptitiously. In theory, the cryptsetup system can support keyfiles up to and including 8192KiB (execute cryptsetup --help to verify this); in practice, due to a off-by-one bug, it supports only keyfiles strictly less than 8[MiB](http://en.wikipedia.org/wiki/Mebibyte). We therefore create a keyfile of length (1024 * 8192) - 1 = 8388607 bytes.
>
> Note that we'll use the [/dev/urandom](http://en.wikipedia.org/wiki//dev/random) source to create the underlying (binary plaintext) pseudo-random keyfile, and then pipe it to gpg to encrypt (using a passphrase of your choosing). The resulting binary ciphertext is saved to the USB key. This avoids ever having the binary plaintext keyfile stored on disk anywhere (and indeed not even you need ever see the unencrypted contents)

The only difference is that **we don't use an external USB EFI System drive**.

``` sh
livecd ~ # modprobe wp512
livecd ~ # modinfo wp512
filename:       /lib/modules/4.9.76-gentoo-r1/kernel/crypto/wp512.ko
description:    Whirlpool Message Digest Algorithm
license:        GPL
alias:          crypto-wp256
alias:          wp256
alias:          crypto-wp384
alias:          wp384
alias:          crypto-wp512
alias:          wp512
depends:        
intree:         Y
vermagic:       4.9.76-gentoo-r1 SMP mod_unload modversions 
livecd ~ # gpg --decrypt /tmp/efi/luks-key.gpg | cryptsetup --cipher serpent-xts-plain64 --key-size 512 --hash whirlpool --key-file - luksFormat /dev/sda2
gpg: AES256 encrypted data
gpg: encrypted with 1 passphrase
System is out of entropy while generating volume key.
Please move mouse or type some text in another window to gather some random events.
Generating key (90% done).
Generating key (90% done).
Generating key (90% done).
Generating key (100% done).
livecd ~ #  cryptsetup luksDump /dev/sda2
LUKS header information for /dev/sda2

Version:       	1
Cipher name:   	serpent
Cipher mode:   	xts-plain64
Hash spec:     	whirlpool
Payload offset:	4096
MK bits:       	512
MK digest:     	f9 f5 0f c4 78 02 22 28 bc 14 aa 83 3d e8 3b c8 e7 d4 7a ca 
MK salt:       	4c 0f 29 eb ea 05 1d a7 e8 e9 f8 32 c7 d3 eb c3 
               	22 91 8b f2 89 96 7f e0 d4 ec ce fe 07 9c e6 4c 
MK iterations: 	98250
UUID:          	816fd5f6-581b-4b39-ad44-6958c64816a3

Key Slot 0: ENABLED
	Iterations:         	775755
	Salt:               	c9 d0 81 2d ee 81 20 ae 3e 25 66 6e fe 16 ee 13 
	                      	7f 1a a1 88 0b b4 7d 15 59 91 e0 1f 9e 09 25 79 
	Key material offset:	8
	AF stripes:            	4000
Key Slot 1: DISABLED
Key Slot 2: DISABLED
Key Slot 3: DISABLED
Key Slot 4: DISABLED
Key Slot 5: DISABLED
Key Slot 6: DISABLED
Key Slot 7: DISABLED
livecd ~ # cryptsetup luksHeaderBackup /dev/sda2 --header-backup-file /tmp/efi/luks-header.img
livecd ~ # 
taglio@cyberdream ~/Backups $ scp root@192.168.1.35:/tmp/efi/luks-header.img castor-header.img
Password: 
luks-header.img                                                                                          100% 2020KB  11.1MB/s   2.0MB/s   00:00    
taglio@cyberdream ~/Backups $ 
```

To permit the **Whirlpool Message Digest Algorithm** we need to include the `wp512` kernel module and we do it with the classic `modprobe` command; with `modinfo` we visualize some extra information about the module. 

Next we use the keyfile `luks-key.gpg`, decripted with the `gpg --decript` command, *piped* to an articulated `cryptsetup`(*manage plain dm-crypt and LUKS encrypted volumes*) command:

- `--cipher serpent-xts-plain64`: use [Serpent](https://en.wikipedia.org/wiki/Serpent_(cipher)) has block cipher, [XTS](https://en.wikipedia.org/wiki/Disk_encryption_theory#XEX-based_tweaked-codebook_mode_with_ciphertext_stealing_.28XTS.29) mode to both extend the cipher over multiple blocks within a sector, and perform the by-sector-index 'tweaking' and a [Plain64](https://www.saout.de/pipermail/dm-crypt/2010-July/001039.html) initialisation vector.
- `--key-size 512`: use a key lenght of `512bits` that really are two keys of `256bits`. 
- `--hash whirlpool`: use [Whirlpool](https://en.wikipedia.org/wiki/Whirlpool_(cryptography)) as cryptographic hash function.
- `--key-file -`: read the key from a file, in this case `-` mean the *piped* output from the previous `gpg` command.
- `luksFormat /dev/sda2`: format `sda2` as  a [LUKS](https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup) device.

With `luksDump` we dump LUKS partition information to verify the correctness of the previous commands and with `luksHeaderBackup` we backup LUKS device header and keyslots. Next we securely transfer it to the helper machine `cyberdream`.

```sh
livecd ~ # gpg --decrypt /tmp/efi/luks-key.gpg | cryptsetup --key-file - luksOpen /dev/sda2 castor
gpg: AES256 encrypted data
gpg: encrypted with 1 passphrase
livecd ~ # ls /dev/mapper/
castor  control
livecd ~ # pvcreate /dev/mapper/castor 
  Physical volume "/dev/mapper/castor" successfully created.
livecd ~ # vgcreate vg1 /dev/mapper/castor 
  Volume group "vg1" successfully created
livecd ~ # lvcreate --size 10G --name swap vg1
  Logical volume "swap" created.
livecd ~ # lvcreate --size 80G --name root vg1
  Logical volume "root" created.
livecd ~ # lvcreate --extents 95%FREE --name home vg1
  Logical volume "home" created.
livecd ~ # ls /dev/mapper
castor  control  vg1-home  vg1-root  vg1-swap
livecd ~ # pvdisplay
  --- Physical volume ---
  PV Name               /dev/disk/by-id/dm-name-castor
  VG Name               vg1
  PV Size               232.63 GiB / not usable 4.16 MiB
  Allocatable           yes 
  PE Size               4.00 MiB
  Total PE              59553
  Free PE               1826
  Allocated PE          57727
  PV UUID               IGB8r0-hwSj-yRZV-2Czt-vxGf-RHOk-Y1H68P
   
livecd ~ # vgdisplay 
  --- Volume group ---
  VG Name               vg1
  System ID             
  Format                lvm2
  Metadata Areas        1
  Metadata Sequence No  4
  VG Access             read/write
  VG Status             resizable
  MAX LV                0
  Cur LV                3
  Open LV               0
  Max PV                0
  Cur PV                1
  Act PV                1
  VG Size               232.63 GiB
  PE Size               4.00 MiB
  Total PE              59553
  Alloc PE / Size       57727 / 225.50 GiB
  Free  PE / Size       1826 / 7.13 GiB
  VG UUID               QrGDki-iDYT-flFm-74oH-SNNQ-gdHU-we6Yfo
   
livecd ~ # lvdisplay 
  --- Logical volume ---
  LV Path                /dev/vg1/swap
  LV Name                swap
  VG Name                vg1
  LV UUID                ummL8J-1zfH-m2K5-67mW-VlCj-WSbe-UwCIUV
  LV Write Access        read/write
  LV Creation host, time livecd, 2018-06-25 13:21:38 +0000
  LV Status              available
  # open                 0
  LV Size                10.00 GiB
  Current LE             2560
  Segments               1
  Allocation             inherit
  Read ahead sectors     auto
  - currently set to     256
  Block device           253:1
   
  --- Logical volume ---
  LV Path                /dev/vg1/root
  LV Name                root
  VG Name                vg1
  LV UUID                ExS1Nx-TPiA-wVrg-Ibv2-QkKr-uwDf-wFeogw
  LV Write Access        read/write
  LV Creation host, time livecd, 2018-06-25 13:22:16 +0000
  LV Status              available
  # open                 0
  LV Size                80.00 GiB
  Current LE             20480
  Segments               1
  Allocation             inherit
  Read ahead sectors     auto
  - currently set to     256
  Block device           253:2
   
  --- Logical volume ---
  LV Path                /dev/vg1/home
  LV Name                home
  VG Name                vg1
  LV UUID                svUTcH-DvIb-cJzQ-Wmyp-tAbX-nVdF-UzX0Xx
  LV Write Access        read/write
  LV Creation host, time livecd, 2018-06-25 13:22:24 +0000
  LV Status              available
  # open                 0
  LV Size                135.50 GiB
  Current LE             34687
  Segments               1
  Allocation             inherit
  Read ahead sectors     auto
  - currently set to     256
  Block device           253:3
   
livecd ~ # vgchange --available y
  3 logical volume(s) in volume group "vg1" now active
livecd ~ #
```

Another time we use the keyfile `luks-key.gpg`, decripted with the `gpg --decript` command, this time *piped* to `cryptsetup` but with the option `luksOpen` that indicate to open device as mapping as name `castor`, available under `/dev/mapper`.

Now is time to setup [LVM](https://en.wikipedia.org/wiki/Logical_Volume_Manager_(Linux)), another *device mapper*, but with differents purposes:

> - Creating single [logical volumes](https://en.wikipedia.org/wiki/Logical_volume) of multiple physical volumes or entire hard disks (somewhat similar to [RAID 0](https://en.wikipedia.org/wiki/RAID_0), but more similar to [JBOD](https://en.wikipedia.org/wiki/JBOD)), allowing for dynamic volume resizing.
> - Managing large hard disk farms by allowing disks to be added and replaced without downtime or service disruption, in combination with [hot swapping](https://en.wikipedia.org/wiki/Hot_swapping).
> - On small systems (like a desktop), instead of having to estimate at installation time how big a partition might need to be, LVM allows filesystems to be easily resized as needed.
> - Performing consistent backups by taking snapshots of the logical volumes.
> - Encrypting multiple physical partitions with one password.

Let's analize the meaning of every command:

- `pvcreate /dev/mapper/castor`: initializes `castor` for later use by the **Logical Volume Manager (LVM)**.
- `vgcreate vg1 /dev/mapper/castor`: creates a new volume group called `vg1` using the block special device `castor`.

With `lvcreate` a new logical volume in a volume group, `vg1` in this case. Here is the options used:

- `--size`: gives  the size to allocate for the new logical volume.
- `--name`: sets the name for the new logical volume.
- `--extents`: gives the number of logical extents to allocate for the new logical volume. In this case we allocate `95%` of the remaining free space in the `vg1` volume group.

Next we use a `ls` in the `/dev/mapper` directory to visualize the new created LVM devices. 

The others three commands are always from the LVM suite and are control commands:

- `pvdisplay`: display attributes of a physical volume.
- `vgdisplay`: display attributes of volume groups.
- `lvdisplay`: display attributes of a logical volume.

With `vgchange` we change attributes of a volume group, with the option `--available y` we controls the availability of the logical volumes in the volume group for input/output.  In other words, makes the  logical  volumes known/unknown to the kernel. Normally they are activate by default but is important to know this command to archieve some administration capacity of LVM volumenes.

```sh
livecd /dev/mapper # mkswap -L "swap" /dev/mapper/vg1-swap
Setting up swapspace version 1, size = 10 GiB (10737414144 bytes)
LABEL=swap, UUID=80d8faeb-35e3-4e0e-b98e-77c716fa492b
livecd /dev/mapper # mkfs.ext4 -L "root" /dev/mapper/vg1-root
mke2fs 1.43.6 (29-Aug-2017)
Creating filesystem with 20971520 4k blocks and 5242880 inodes
Filesystem UUID: ef18b96d-75db-4724-9fcb-717b914cdd70
Superblock backups stored on blocks: 
	32768, 98304, 163840, 229376, 294912, 819200, 884736, 1605632, 2654208, 
	4096000, 7962624, 11239424, 20480000

Allocating group tables: done                            
Writing inode tables: done                            
Creating journal (131072 blocks): done
Writing superblocks and filesystem accounting information: done   

livecd /dev/mapper # mkfs.ext4 -m 0 -L "home" /dev/mapper/vg1-home
mke2fs 1.43.6 (29-Aug-2017)
Creating filesystem with 35519488 4k blocks and 8880128 inodes
Filesystem UUID: 1708e6e9-06f9-499d-83df-16ce517a1127
Superblock backups stored on blocks: 
	32768, 98304, 163840, 229376, 294912, 819200, 884736, 1605632, 2654208, 
	4096000, 7962624, 11239424, 20480000, 23887872

Allocating group tables: done                            
Writing inode tables: done                            
Creating journal (262144 blocks): done
Writing superblocks and filesystem accounting information: done     

livecd /dev/mapper # mount -t ext4 /dev/mapper/vg1-root /mnt/gentoo/
mount: /dev/mapper/vg1-root mounted on /mnt/gentoo.
livecd ~ # mkfs.ext4 -m 0 -L "home" /dev/mapper/vg1-home
livecd ~ # mkdir /mnt/gentoo/{home,boot,boot/efi}
mkdir: created directory '/mnt/gentoo/home'
mkdir: created directory '/mnt/gentoo/boot'
mkdir: created directory '/mnt/gentoo/boot/efi'
        livecd ~ # mount -t ext4 /dev/mapper/vg1-home /mnt/gentoo/home/
mount: /dev/mapper/vg1-home mounted on /mnt/gentoo/home.
livecd ~ # umount /tmp/efi/
umount: /tmp/efi/ unmounted
livecd ~ # blkid
/dev/loop0: TYPE="squashfs"
/dev/sda1: UUID="3A27-317C" TYPE="vfat" PARTUUID="c7138523-0eca-403b-b40d-2fd5572b64f2"
/dev/sda2: UUID="816fd5f6-581b-4b39-ad44-6958c64816a3" TYPE="crypto_LUKS" PARTUUID="f287e0c6-cf3b-4809-8de4-f1bcacd48a18"
/dev/sdb1: UUID="2018-04-16-01-43-43-23" LABEL="Gentoo amd64 20180415T214502Z" TYPE="iso9660" PTUUID="04252123" PTTYPE="dos" PARTUUID="04252123-01"
/dev/mapper/castor: UUID="IGB8r0-hwSj-yRZV-2Czt-vxGf-RHOk-Y1H68P" TYPE="LVM2_member"
/dev/mapper/vg1-swap: LABEL="swap" UUID="80d8faeb-35e3-4e0e-b98e-77c716fa492b" TYPE="swap"
/dev/mapper/vg1-root: LABEL="root" UUID="ef18b96d-75db-4724-9fcb-717b914cdd70" TYPE="ext4"
/dev/mapper/vg1-home: LABEL="home" UUID="1708e6e9-06f9-499d-83df-16ce517a1127" TYPE="ext4"
livecd ~ #
```

Time to activate and format our logical volumenes. 

With `mkswap` we set up a Linux swap area, `-L` specify a [label](https://www.tldp.org/HOWTO/Partition/labels.html) for the device.

With `mkfs.ext4` we create an [ext4 filesystem](https://en.wikipedia.org/wiki/Ext4), with `-L` we set the *label* as we do above. Has we have reserved the `5%` of free space with **LVM**, we use `-m 0` to deny the default `5%` of reserved ext4 filesystem blocks.

`mount` obviously *mount* a filesystem, `umount` do the opposite action.

We create some subdirectory in the filesystem tree with `mkdir`(remember that `-v` is aliased). 

With `blkid` we print some unique device identificator that we're going to use in our `fstab` instead of the conventional nomenclature (`sda1` for example).

## Gentoo stage 3

![3 gentoo penguins](https://www.aboutanimals.com/images/gentoo-penguins-beach-walking-820x463.jpg)

The [Gentoo Linux stage3](https://wiki.gentoo.org/wiki/Handbook:AMD64/Installation/Stage) contains programs and libraries useful for a correct system [bootstrap](https://en.wikipedia.org/wiki/Bootstrapping#Computing).

```sh
taglio@cyberdream ~/Work/npna/Gentoo/Integrity $ wget http://distfiles.gentoo.org/releases/amd64/autobuilds/latest-stage3-amd64.txt
--2018-06-25 22:59:30--  http://distfiles.gentoo.org/releases/amd64/autobuilds/latest-stage3-amd64.txt
Resolving distfiles.gentoo.org... 64.50.233.100, 64.50.236.52, 137.226.34.46, ...
Connecting to distfiles.gentoo.org|64.50.233.100|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 127 [text/plain]
Saving to: ‘latest-stage3-amd64.txt’

latest-stage3-amd64.txt               100%[======================================================================>]     127  --.-KB/s    in 0s      

2018-06-25 22:59:32 (22.4 MB/s) - ‘latest-stage3-amd64.txt’ saved [127/127]

taglio@cyberdream ~/Work/npna/Gentoo/Integrity $ cat latest-stage3-amd64.txt 
# Latest as of Mon, 25 Jun 2018 20:00:01 +0000
# ts=1529956801
20180624T214502Z/stage3-amd64-20180624T214502Z.tar.xz 191153900
taglio@cyberdream ~/Work/npna/Gentoo/Integrity $ wget http://distfiles.gentoo.org/releases/amd64/autobuilds/20180624T214502Z/stage3-amd64-20180624T214502Z.tar.xz{,.CONTENTS,.DIGESTS.asc}
--2018-06-25 23:02:08--  http://distfiles.gentoo.org/releases/amd64/autobuilds/20180624T214502Z/stage3-amd64-20180624T214502Z.tar.xz
Resolving distfiles.gentoo.org... 64.50.233.100, 64.50.236.52, 137.226.34.46, ...
Connecting to distfiles.gentoo.org|64.50.233.100|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 191153900 (182M) [application/x-xz]
Saving to: ‘stage3-amd64-20180624T214502Z.tar.xz’

stage3-amd64-20180624T214502Z.tar.xz  100%[======================================================================>] 182.30M  2.55MB/s    in 97s     

2018-06-25 23:03:46 (1.87 MB/s) - ‘stage3-amd64-20180624T214502Z.tar.xz’ saved [191153900/191153900]

--2018-06-25 23:03:46--  http://distfiles.gentoo.org/releases/amd64/autobuilds/20180624T214502Z/stage3-amd64-20180624T214502Z.tar.xz.CONTENTS
Reusing existing connection to distfiles.gentoo.org:80.
HTTP request sent, awaiting response... 200 OK
Length: 5312721 (5.1M) [application/x-xz]
Saving to: ‘stage3-amd64-20180624T214502Z.tar.xz.CONTENTS’

stage3-amd64-20180624T214502Z.tar.xz. 100%[======================================================================>]   5.07M  2.40MB/s    in 2.1s    

2018-06-25 23:03:48 (2.40 MB/s) - ‘stage3-amd64-20180624T214502Z.tar.xz.CONTENTS’ saved [5312721/5312721]

--2018-06-25 23:03:48--  http://distfiles.gentoo.org/releases/amd64/autobuilds/20180624T214502Z/stage3-amd64-20180624T214502Z.tar.xz.DIGESTS.asc
Reusing existing connection to distfiles.gentoo.org:80.
HTTP request sent, awaiting response... 200 OK
Length: 1630 (1.6K) [text/plain]
Saving to: ‘stage3-amd64-20180624T214502Z.tar.xz.DIGESTS.asc’

stage3-amd64-20180624T214502Z.tar.xz. 100%[======================================================================>]   1.59K  --.-KB/s    in 0s      

2018-06-25 23:03:48 (545 MB/s) - ‘stage3-amd64-20180624T214502Z.tar.xz.DIGESTS.asc’ saved [1630/1630]

FINISHED --2018-06-25 23:03:48--
Total wall clock time: 1m 40s
Downloaded: 3 files, 187M in 1m 39s (1.88 MB/s)
taglio@cyberdream ~/Work/npna/Gentoo/Integrity $ gpg --verify 
Resources/                                              latest-stage3-amd64.txt
install-amd64-minimal-20180415T214502Z.iso              stage3-amd64-20180624T214502Z.tar.xz
install-amd64-minimal-20180415T214502Z.iso.CONTENTS     stage3-amd64-20180624T214502Z.tar.xz.CONTENTS
install-amd64-minimal-20180415T214502Z.iso.DIGESTS.asc  stage3-amd64-20180624T214502Z.tar.xz.DIGESTS.asc
latest-iso.txt                                          
taglio@cyberdream ~/Work/npna/Gentoo/Integrity $ gpg --verify stage3-amd64-20180624T214502Z.tar.xz.DIGESTS.asc
gpg: Signature made Mon 25 Jun 2018 05:04:21 CEST
gpg:                using RSA key 13EBBDBEDE7A12775DFDB1BABB572E0E2D182910
gpg: Good signature from "Gentoo Linux Release Engineering (Automated Weekly Release Key) <releng@gentoo.org>" [ultimate]
Primary key fingerprint: 13EB BDBE DE7A 1277 5DFD  B1BA BB57 2E0E 2D18 2910
taglio@cyberdream ~/Work/npna/Gentoo/Integrity $ awk '/SHA512 HASH/{getline;print}' stage3-amd64-20180624T214502Z.tar.xz.DIGESTS.asc | sha512sum --check
stage3-amd64-20180624T214502Z.tar.xz: OK
stage3-amd64-20180624T214502Z.tar.xz.CONTENTS: OK
taglio@cyberdream ~/Work/npna/Gentoo/Integrity $ scp stage3-amd64-20180624T214502Z.tar.xz root@192.168.1.35:/mnt/gentoo
Password: 
stage3-amd64-20180624T214502Z.tar.xz                                                                     100%  182MB  11.2MB/s  12.5MB/s   00:16    
taglio@cyberdream ~/Work/npna/Gentoo/Integrity $
```

This process is exactly the same of the boot ISO image download. The only difference is in the URL that we use to check the last version available, in this case is [this](http://distfiles.gentoo.org/releases/amd64/autobuilds/latest-stage3-amd64.txt). 

Then we secure transfer from the helper machine to the laptop using `scp`.

```sh
livecd /mnt/gentoo # tar -xJpf stage3-amd64-20180624T214502Z.tar.xz --xattrs-include='*.*' --numeric-owner
.
.
.
livecd /mnt/gentoo # rm stage3-amd64-20180624T214502Z.tar.xz 
removed 'stage3-amd64-20180624T214502Z.tar.xz'
livecd /mnt/gentoo #
```

Then we've to extract the **stage3** tarball with an articulated command (*output is supressed for space reasons*), here is the explanation:

- `-x`: extract files from an archive.
- `-J`: filter the archive through `xz` (*Compress or decompress .xz and .lzma files*).
- `-p`: extract information about file permissions.
- `-f`: use archive file `stage3-amd64-20180624T214502Z.tar.xz`.
- `--xattrs-include`: specify the include [POSIX](https://en.wikipedia.org/wiki/POSIX) regular expression for [xattr](https://en.wikipedia.org/wiki/Extended_file_attributes) keys.
- `--numeric-owner`: always use numbers for user/group names.

Next we remove the downloaded tarball with `rm`.

## The Gentoo make.conf file

We start to prepare the correct environment to adquire the perfect optimization for the *emerging*,  download / unpack / prepare / configure / compile / install / merge gentoo cycle, process under our distribution.

```fsharp
livecd ~ # cat >> .bashrc <<EOF
    > export NUMCPUS=$(nproc)
    > export NUMCPUSPLUSONE=$(( NUMCPUS + 1 ))
    > export MAKEOPTS="-j${NUMCPUSPLUSONE} -l${NUMCPUS}"
    > export EMERGE_DEFAULT_OPTS="--ask --verbose --jobs=${NUMCPUSPLUSONE} --load-average=${NUMCPUS}"
> EOF
livecd ~ # source .bashrc
livecd ~ # cat > /mnt/gentoo/etc/portage/make.conf <<EOF
> CHOST="x86_64-pc-linux-gnu"
> CFLAGS="-march=sandybridge -O2 -pipe"
> CXXFLAGS="${CFLAGS}"
> 
> # Note: MAKEOPTS and EMERGE_DEFAULT_OPTS are set in .bashrc
> 
> # Only free software, please.
> ACCEPT_LICENSE="-* @FREE CC-Sampling-Plus-1.0"
> 
> # testing branch
> ACCEPT_KEYWORDS="~amd64"
> 
> # Additional USE flags supplementary to those specified by the current profile.
> USE=""
> CPU_FLAGS_X86="mmx mmxext sse sse2"
> 
> # NOTE: This stage was built with the bindist Use flag enabled
> PORTDIR="/usr/portage"
> DISTDIR="/usr/portage/distfiles"
> PKGDIR="/usr/portage/packages"
> 
> # This sets the language of build output to English.
> # Please keep this setting intact when reporting bugs.
> LC_MESSAGES=C
> 
> # Turn on logging - see http://gentoo-en.vfose.ru/wiki/Gentoo_maintenance.
> PORTAGE_ELOG_CLASSES="info warn error log qa"
> # Echo messages after emerge, also save to /var/log/portage/elog
> PORTAGE_ELOG_SYSTEM="echo save"
> 
> # Ensure elogs saved in category subdirectories.
> # Build binary packages as a byproduct of each emerge, a useful backup.
> FEATURES="split-elog buildpkg"
> 
> # Settings for X11
> VIDEO_CARDS="intel i915"
> INPUT_DEVICES="libinput"
> EOF
livecd ~ #

```

First of all we declare four variables under `.bashrc` of the root directory.  `NUMCPUS` that indicates the numbers of cores of our processor and `NUMCPUSPLUSONE` that is this number plus one.  `MAKEOPTS` indicates the default options that we pass to the command `make` every time we invoque it:

- `-j`: specifies  the  number of jobs (commands) to run simultaneously.
- `-l`: specifies  that  no  new  jobs (commands) should be started if there are others jobs running and the load average is at least load (a floating-point number).

We do the same with `EMERGE_DEFAULT_OPTS` but those are the options that we pass every time we invoque the program `emerge`:

- `--ask`:  Before performing the action, display what will take place, then ask whether to proceed with the action or abort.
- `--verbose`: tell  emerge  to  run in verbose mode.
- `--jobs`: specifies the number of packages to build simultaneously.
- `--load-avarage`: specifies that no new builds should be started if there are other builds running and the load average is at least load (a floating-point  number).

Then we reload `.bashrc` with `source` as usual. 

In the file `make.conf` located under `/etc/portage` in our distribution Gentoo we can specify more options related to the fact of compiling the source tree.

- `CHOST`: this variable is passed by the ebuild scripts to the configure step as `--host=${CHOST}`.  This way you can force the build-host. More information [here](https://gcc.gnu.org/onlinedocs/gcc-6.1.0/gcc/x86-Options.html#x86-Options).
- `CFLAGS` and `CXXFLAGS`: use  these  variables  to set the desired optimization/CPU instruction settings for applications that you compile.  These two variables are passed to the C and C++ compilers, respectively. More information [here](https://wiki.gentoo.org/wiki/Safe_CFLAGS#Intel).
- `ACCEPT_LICENSE`: this variable is used to mask packages based on licensing restrictions. It may contain both license and group  names,  where  group names  are  prefixed  with  the  '@' symbol.
- `ACCEPT_KEYWORDS`: enable  testing  of ebuilds that have not yet been deemed 'stable' with the `~` suffix.
- `USE`: this  variable  contains options that control the build behavior of several packages.
- `CPU_FLAGS_X86`: is an `USE_EXPAND` variable containing instruction set and other CPU-specific features.
- `PORTDIR`: defines the location of main repository.
- `DISTDIR`: defines the location of your local source file repository.
- `PKGDIR`: defines the location where created `.tbz2` binary packages will be stored when  the  `emerge --buildpkg`  option  is  enabled.
- `LC_MESSAGES`: programs localizations stored in `/usr/share/locale` for applications that use a message-based localization scheme (the majority of GNU programs).
- `PORTAGE_ELOG_CLASSES`: selects messages to be logged.
- `PORTAGE_ELOG_SYSTEM`: selects the module(s) to process the log messages.
- `FEAUTURES`: defines actions portage takes by default.
- `VIDEO_CARDS`: used to set the video drivers that you intend to use and is usually based on the kind of video card you have.  More informations [here](https://wiki.gentoo.org/wiki/Intel#Drivers).
- `INPUT_DEVICES`: is used to determine which drivers are to be built for input devices.

## Build the Gentoo base system under chroot

![Gentoo penguin nido in the Antartida](https://previews.123rf.com/images/vladsilver/vladsilver1603/vladsilver160300026/56089631-ping%C3%BCino-de-gentoo-en-el-nido-con-huevos-en-la-ant%C3%A1rtida.jpg)

Like this beatiful Gentoo penguin have build his nido in the Antartida, we've got to compile all the *base system* of our new **Gentoo Linux system** installation above our HP laptop.

Start with those customizations in our `/mnt/gentoo/etc/portage` directory:

```sh
livecd /mnt/gentoo/etc/portage # mirrorselect -i -o >> make.conf
* Using url: https://api.gentoo.org/mirrors/distfiles.xml
* Downloading a list of mirrors...
 Got 133 mirrors.
livecd /mnt/gentoo/etc/portage # tail -n1 make.conf 
GENTOO_MIRRORS="ftp://ftp.free.fr/mirrors/ftp.gentoo.org/ http://gentoo.modulix.net/gentoo/ http://gentoo.mirrors.ovh.net/gentoo-distfiles/ ftp://gentoo.mirrors.ovh.net/gentoo-distfiles/ ftp://mirrors.soeasyto.com/distfiles.gentoo.org/ http://mirrors.soeasyto.com/distfiles.gentoo.org/"
livecd /mnt/gentoo/etc/portage # 
```

 ![](/home/taglio/Work/npna/Gentoo/Integrity/Resources/mirrorselect.png)

With `mirroselect` we assign to the variable `GENTOO_MIRRORS` a list of servers choosing the closer ones. This are the options used:

- `-i`: Interactive Mode, this will present a list to make it possible to select mirrors you wish to use.
- `-o`: Output Only Mode, this is especially useful when being used during installation, to redirect output to a file other than `/etc/portage/make.conf`.

```sh
livecd /mnt/gentoo/etc/portage # mkdir repos.conf
mkdir: created directory 'repos.conf'
livecd /mnt/gentoo/etc/portage # cd repos.conf/
livecd /mnt/gentoo/etc/portage/repos.conf # cat > gentoo.conf <<EOF
> [DEFAULT]
> main-repo = gentoo
> 
> [gentoo]
> location = /usr/portage
> sync-type = rsync
> auto-sync = no
> EOF
livecd /mnt/gentoo/etc/portage/repos.conf # mirrorselect -i -r -o | sed 's/^SYNC=/sync-uri = /;s/"//g' >> gentoo.conf 
* Using url: https://api.gentoo.org/mirrors/rsync.xml
* Downloading a list of mirrors...
 Got 68 mirrors.
livecd /mnt/gentoo/etc/portage/repos.conf # tail -n 1 gentoo.conf 
sync-uri = rsync://rsync.fr.gentoo.org/gentoo-portage
livecd /mnt/gentoo/etc/portage/repos.conf # 
```

![rsync Gentoo mirrorselect](/home/taglio/Work/npna/Gentoo/Integrity/Resources/rsyncgentoo.png)

We create the directory `repos.conf` and then we create the file  `gentoo.conf` that use the [`ini`](https://en.wikipedia.org/wiki/INI_file) syntax. From [Sahaki EFI guide](https://wiki.gentoo.org/wiki/Sakaki%27s_EFI_Install_Guide/Building_the_Gentoo_Base_System_Minus_Kernel) the explanation:

> - The main repository is set to be gentoo, for all other repositories (such as overlays) that do not specify masters;
> - The repository location is set to be /usr/portage (within the chroot, that is);
> - The repository will **not** be synced during emerge --sync and emaint sync --auto runs;
> - The repository is set to synchronize using the rsync protocol (this is unauthenticated, but don't worry, in this tutorial, we won't actually call for any syncs to be performed in this manner, and have specified changing the auto-sync value to no in the above, to prevent it happening inadvertently).
> - **sync-uri** variable, which tells Portage where to look for the rsync server, when bringing your Portage tree of ebuilds up to date.

```sh
livecd ~ # cp .bashrc /mnt/gentoo/root/
'.bashrc' -> '/mnt/gentoo/root/.bashrc'
livecd ~ # cp /etc/resolv.conf /mnt/gentoo/etc/
'/etc/resolv.conf' -> '/mnt/gentoo/etc/resolv.conf'
livecd ~ # mount -t proc none /mnt/gentoo/proc
mount: none mounted on /mnt/gentoo/proc.
livecd ~ # mount --rbind /sys /mnt/gentoo/sys
mount: /sys bound on /mnt/gentoo/sys.
livecd ~ # mount --rbind /dev /mnt/gentoo/dev
mount: /dev bound on /mnt/gentoo/dev.
livecd ~ # mount --make-rslave /mnt/gentoo/sys
mount: /mnt/gentoo/sys propagation flags changed.
livecd ~ # mount --make-rslave /mnt/gentoo/dev
mount: /mnt/gentoo/dev propagation flags changed.
livecd ~ # chroot /mnt/gentoo /bin/bash 
livecd / # source /etc/profile
livecd / #
```

The last passes to obtain a good [**chroot jail**](https://en.wikipedia.org/wiki/Chroot) compail envioronment. We copy the `.bashrc` file that we're using to the new `/root` directory. We do the same with the `resolv.conf` file (*resolver configuration file*).

Next we mount `procfs`, `sysfs` and `devfs` for the **chroot** system. But what are them?

- `procfs`: The  proc filesystem is a pseudo-filesystem which provides an interfac to kernel data structures.
- `sysfs`: Like `procfs` but the files under sysfs  provide  information  about devices, kernel modules, filesystems, and other kernel components.
- `devfs`: Devfs is an alternative to "real" character and block special devices on your root filesystem. Kernel device drivers can register devices by name rather than major and minor numbers. These devices will appear in devfs automatically, with whatever default ownership and protection the driver specified.

We utilize two new options to the `mount` command:

- `--rbind`: Remount  a subtree and all possible submounts somewhere else (so that its contents are available in both places).
- `--make-rslave`: Hence forth any mounts within the /directory done by the process will not show up in any other namespace. However mounts done in the parent namespace under /directory still shows up in the process's namespace.

Next we **chroot** in `/mnt/gentoo` executing the *shell* `/bin/bash`.

```sh
livecd / # PORTAGE_GPG_DIR="/tmp" FEATURES="webrsync-gpg" emerge-webrsync --keep
!!! Section 'x-portage' in repos.conf has location attribute set to nonexistent directory: '/usr/portage'
!!! Section 'gentoo' in repos.conf has location attribute set to nonexistent directory: '/usr/portage'

!!! Invalid Repository Location (not a dir): '/usr/portage'
Fetching most recent snapshot ...
Trying to retrieve 20180705 snapshot from ftp://ftp.free.fr/mirrors/ftp.gentoo.org ...
Fetching file portage-20180705.tar.xz.md5sum ...
Fetching file portage-20180705.tar.xz.gpgsig ...
Fetching file portage-20180705.tar.xz ...
Checking digest ...
Checking signature ...
emerge-webrsync: error: cannot check signature: gpg binary not found
livecd / # ls /usr/portage/distfiles/
portage-20180705.tar.xz         portage-20180705.tar.xz.md5sum
portage-20180705.tar.xz.gpgsig
livecd / #
```

Because there's no `gpg` binary under our **Stage 3** snapshot that we've *untar* in the last chapter, we've just downloaded the last **Portage** with his digest and digital signature from one of our `GENTOO_MIRRORS` server list. 

Next we verified it out the **chroot** environment:

```sh
livecd ~ # gpg --recv-key 0xDB6B8C1F96D8BF6D
gpg: key DB6B8C1F96D8BF6D: 15 signatures not checked due to missing keys
gpg: /root/.gnupg/trustdb.gpg: trustdb created
gpg: key DB6B8C1F96D8BF6D: public key "Gentoo ebuild repository signing key (Automated Signing Key) <infrastructure@gentoo.org>" imported
gpg: no ultimately trusted keys found
gpg: Total number processed: 1
gpg:               imported: 1
livecd ~ # gpg --edit-key 0xDB6B8C1F96D8BF6D
gpg (GnuPG) 2.2.4; Copyright (C) 2017 Free Software Foundation, Inc.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.


pub  rsa4096/DB6B8C1F96D8BF6D
     created: 2011-11-25  expires: 2019-01-01  usage: C   
     trust: unknown       validity: unknown
sub  rsa4096/EC590EEAC9189250
     created: 2011-11-25  expires: 2019-01-01  usage: S   
[ unknown] (1). Gentoo ebuild repository signing key (Automated Signing Key) <infrastructure@gentoo.org>
[ unknown] (2)  Gentoo Portage Snapshot Signing Key (Automated Signing Key)

gpg> fpr
pub   rsa4096/DB6B8C1F96D8BF6D 2011-11-25 Gentoo ebuild repository signing key (Automated Signing Key) <infrastructure@gentoo.org>
 Primary key fingerprint: DCD0 5B71 EAB9 4199 527F  44AC DB6B 8C1F 96D8 BF6D

gpg> trust
pub  rsa4096/DB6B8C1F96D8BF6D
     created: 2011-11-25  expires: 2019-01-01  usage: C   
     trust: unknown       validity: unknown
sub  rsa4096/EC590EEAC9189250
     created: 2011-11-25  expires: 2019-01-01  usage: S   
[ unknown] (1). Gentoo ebuild repository signing key (Automated Signing Key) <infrastructure@gentoo.org>
[ unknown] (2)  Gentoo Portage Snapshot Signing Key (Automated Signing Key)

Please decide how far you trust this user to correctly verify other users' keys
(by looking at passports, checking fingerprints from different sources, etc.)

  1 = I don't know or won't say
  2 = I do NOT trust
  3 = I trust marginally
  4 = I trust fully
  5 = I trust ultimately
  m = back to the main menu

Your decision? 5
Do you really want to set this key to ultimate trust? (y/N) y

pub  rsa4096/DB6B8C1F96D8BF6D
     created: 2011-11-25  expires: 2019-01-01  usage: C   
     trust: ultimate      validity: unknown
sub  rsa4096/EC590EEAC9189250
     created: 2011-11-25  expires: 2019-01-01  usage: S   
[ unknown] (1). Gentoo ebuild repository signing key (Automated Signing Key) <infrastructure@gentoo.org>
[ unknown] (2)  Gentoo Portage Snapshot Signing Key (Automated Signing Key)
Please note that the shown key validity is not necessarily correct
unless you restart the program.

gpg> save
Key not changed so no update needed.
livecd ~ # cd /mnt/gentoo/usr/portage/distfiles/
livecd /mnt/gentoo/usr/portage/distfiles # gpg --verify portage-20180705.tar.xz{.gpgsig,}
gpg: Signature made Fri Jul  6 00:51:25 2018 UTC
gpg:                using RSA key E1D6ABB63BFCFB4BA02FDF1CEC590EEAC9189250
gpg: checking the trustdb
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
gpg: next trustdb check due at 2019-01-01
gpg: Good signature from "Gentoo ebuild repository signing key (Automated Signing Key) <infrastructure@gentoo.org>" [ultimate]
gpg:                 aka "Gentoo Portage Snapshot Signing Key (Automated Signing Key)" [ultimate]
livecd /mnt/gentoo/usr/portage/distfiles #
```

The procedure is the same as before, remember that we're searching for the hexadecimal id `0xDB6B8C1F96D8BF6D` in the [official Gentoo page](https://wiki.gentoo.org/wiki/Project:RelEng#Keys), the name of the key is *Gentoo Portage Snapshot signing Key*.

```sh
livecd /mnt/gentoo/usr/portage/distfiles # !chroot
chroot /mnt/gentoo /bin/bash 
livecd / # emerge-webrsync --keep --revert=20180705
!!! Repository 'x-portage' is missing masters attribute in '/usr/portage/metadata/layout.conf'
!!! Set 'masters = gentoo' in this file for future compatibility
Trying to retrieve 20180705 snapshot from ftp://ftp.free.fr/mirrors/ftp.gentoo.org ...
Checking digest ...
Getting snapshot timestamp ...
Syncing local tree ...

Number of files: 161,945 (reg: 134,499, dir: 27,446)
Number of created files: 161,944 (reg: 134,499, dir: 27,445)
Number of deleted files: 0
Number of regular files transferred: 134,499
Total file size: 218.71M bytes
Total transferred file size: 218.71M bytes
Literal data: 218.71M bytes
Matched data: 0 bytes
File list size: 4.46M
File list generation time: 0.001 seconds
File list transfer time: 0.000 seconds
Total bytes sent: 115.92M
Total bytes received: 2.68M

sent 115.92M bytes  received 2.68M bytes  6.08M bytes/sec
total size is 218.71M  speedup is 1.84
Cleaning up ...

Performing Global Updates
(Could take a couple of minutes if you have a lot of binary packages.)



 * IMPORTANT: 13 news items need reading for repository 'gentoo'.
 * Use eselect news read to view new items.

livecd / # emerge --oneshot portage

 * IMPORTANT: 13 news items need reading for repository 'gentoo'.
 * Use eselect news read to view new items.


These are the packages that would be merged, in order:

Calculating dependencies... done!
[ebuild  N     ] app-crypt/openpgp-keys-gentoo-release-20180703::gentoo  46 KiB
[ebuild  N     ] dev-libs/libunistring-0.9.10:0/2::gentoo  USE="-doc -static-libs" ABI_X86="(64) -32 (-x32)" 3,658 KiB
[ebuild  N     ] dev-libs/npth-1.5::gentoo  USE="-static-libs" 293 KiB
[ebuild  N     ] app-eselect/eselect-lib-bin-symlink-0.1.1::gentoo  45 KiB
[ebuild  N     ] app-eselect/eselect-pinentry-0.7::gentoo  0 KiB
[ebuild  N     ] dev-libs/libassuan-2.5.1::gentoo  USE="-static-libs" 552 KiB
[ebuild  N     ] dev-libs/libksba-1.3.5-r1::gentoo  USE="-static-libs" 607 KiB
[ebuild  N     ] dev-python/bz2file-0.98::gentoo  PYTHON_TARGETS="python2_7 -pypy" 12 KiB
[ebuild  N     ] net-dns/libidn2-2.0.5::gentoo  USE="-static-libs" ABI_X86="(64) -32 (-x32)" 2,043 KiB
[ebuild  N     ] dev-libs/libtasn1-4.13:0/6::gentoo  USE="-doc -static-libs -valgrind" ABI_X86="(64) -32 (-x32)" 1,848 KiB
[ebuild  N     ] dev-libs/nettle-3.4:0/6.2::gentoo  USE="gmp -doc (-neon) -static-libs {-test}" ABI_X86="(64) -32 (-x32)" CPU_FLAGS_X86="-aes" 1,890 KiB
[ebuild  N     ] net-libs/gnutls-3.5.18:0/30::gentoo  USE="cxx idn nls openssl seccomp tls-heartbeat zlib -dane -doc -examples -guile -openpgp -pkcs11 -sslv2 -sslv3 -static-libs {-test} -test-full -tools -valgrind" ABI_X86="(64) -32 (-x32)" 7,092 KiB
[ebuild  N     ] app-crypt/pinentry-1.1.0-r2::gentoo  USE="ncurses -caps -emacs -fltk -gnome-keyring -gtk -qt5 -static" 457 KiB
[ebuild  N     ] net-misc/curl-7.60.0-r1::gentoo  USE="ipv6 ssl -adns -brotli -http2 -idn -kerberos -ldap -metalink -rtmp -samba -ssh -static-libs {-test} -threads" ABI_X86="(64) -32 (-x32)" CURL_SSL="openssl -axtls -gnutls -libressl -mbedtls -nss (-winssl)" 2,870 KiB
[ebuild  N     ] app-admin/metalog-3-r2::gentoo  USE="unicode" 353 KiB
[ebuild  N     ] virtual/logger-0::gentoo  0 KiB
[ebuild  N     ] mail-mta/nullmailer-2.0-r2::gentoo  USE="ssl {-test}" 244 KiB
[ebuild  N     ] virtual/mta-1::gentoo  0 KiB
[ebuild  N     ] app-crypt/gnupg-2.2.8::gentoo  USE="bzip2 nls readline smartcard ssl -doc -ldap (-selinux) -tofu -tools -usb -wks-server" 6,478 KiB
[ebuild  N     ] app-portage/gemato-13.1::gentoo  USE="blake2 bzip2 gpg -lzma -sha3 {-test} -tools" PYTHON_TARGETS="python2_7 python3_5 -pypy -python3_4 -python3_6" 66 KiB
[ebuild     U  ] sys-apps/portage-2.3.41::gentoo [2.3.40-r1::gentoo] USE="(ipc) native-extensions rsync-verify* xattr -build -doc -epydoc -gentoo-dev (-selinux)" PYTHON_TARGETS="python2_7 python3_5 -pypy -python3_4 -python3_6" 973 KiB

Total: 21 packages (1 upgrade, 20 new), Size of downloads: 29,518 KiB

Would you like to merge these packages? [Yes/No] Yes
>>> Verifying ebuild manifests
>>> Emerging (1 of 21) app-crypt/openpgp-keys-gentoo-release-20180703::gentoo
>>> Emerging (2 of 21) dev-libs/libunistring-0.9.10::gentoo
>>> Emerging (3 of 21) dev-libs/npth-1.5::gentoo
>>> Installing (1 of 21) app-crypt/openpgp-keys-gentoo-release-20180703::gentoo
>>> Installing (3 of 21) dev-libs/npth-1.5::gentoo
>>> Installing (2 of 21) dev-libs/libunistring-0.9.10::gentoo
>>> Emerging (4 of 21) app-eselect/eselect-lib-bin-symlink-0.1.1::gentoo
>>> Installing (4 of 21) app-eselect/eselect-lib-bin-symlink-0.1.1::gentoo
>>> Emerging (5 of 21) app-eselect/eselect-pinentry-0.7::gentoo
>>> Installing (5 of 21) app-eselect/eselect-pinentry-0.7::gentoo
>>> Emerging (6 of 21) dev-libs/libassuan-2.5.1::gentoo
>>> Installing (6 of 21) dev-libs/libassuan-2.5.1::gentoo
>>> Emerging (7 of 21) dev-libs/libksba-1.3.5-r1::gentoo
>>> Installing (7 of 21) dev-libs/libksba-1.3.5-r1::gentoo
>>> Emerging (8 of 21) dev-python/bz2file-0.98::gentoo
>>> Installing (8 of 21) dev-python/bz2file-0.98::gentoo
>>> Emerging (9 of 21) net-dns/libidn2-2.0.5::gentoo
>>> Installing (9 of 21) net-dns/libidn2-2.0.5::gentoo
>>> Emerging (10 of 21) dev-libs/libtasn1-4.13::gentoo
>>> Installing (10 of 21) dev-libs/libtasn1-4.13::gentoo
>>> Emerging (11 of 21) dev-libs/nettle-3.4::gentoo
>>> Installing (11 of 21) dev-libs/nettle-3.4::gentoo
>>> Emerging (12 of 21) net-libs/gnutls-3.5.18::gentoo
>>> Installing (12 of 21) net-libs/gnutls-3.5.18::gentoo
>>> Emerging (13 of 21) app-crypt/pinentry-1.1.0-r2::gentoo
>>> Installing (13 of 21) app-crypt/pinentry-1.1.0-r2::gentoo
>>> Emerging (14 of 21) net-misc/curl-7.60.0-r1::gentoo
>>> Installing (14 of 21) net-misc/curl-7.60.0-r1::gentoo
>>> Emerging (15 of 21) app-admin/metalog-3-r2::gentoo
>>> Installing (15 of 21) app-admin/metalog-3-r2::gentoo
>>> Emerging (16 of 21) virtual/logger-0::gentoo
>>> Installing (16 of 21) virtual/logger-0::gentoo
>>> Emerging (17 of 21) mail-mta/nullmailer-2.0-r2::gentoo
>>> Installing (17 of 21) mail-mta/nullmailer-2.0-r2::gentoo
>>> Emerging (18 of 21) virtual/mta-1::gentoo
>>> Installing (18 of 21) virtual/mta-1::gentoo
>>> Emerging (19 of 21) app-crypt/gnupg-2.2.8::gentoo
>>> Installing (19 of 21) app-crypt/gnupg-2.2.8::gentoo
>>> Emerging (20 of 21) app-portage/gemato-13.1::gentoo
>>> Installing (20 of 21) app-portage/gemato-13.1::gentoo
>>> Emerging (21 of 21) sys-apps/portage-2.3.41::gentoo
>>> Installing (21 of 21) sys-apps/portage-2.3.41::gentoo
>>> Jobs: 21 of 21 complete                         Load avg: 2.66, 2.17, 1.24

 * Messages for package app-crypt/openpgp-keys-gentoo-release-20180703:

 * Package:    app-crypt/openpgp-keys-gentoo-release-20180703
 * Repository: gentoo
 * Maintainer: mgorny@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux userland_GNU
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * Final size of build directory: 68 KiB
 * Final size of installed tree:  80 KiB

 * Messages for package dev-libs/npth-1.5:

 * Package:    dev-libs/npth-1.5
 * Repository: gentoo
 * Maintainer: crypto@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux userland_GNU
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * Removing unnecessary /usr/lib64/libnpth.la (no static archive)
 * Final size of build directory: 2396 KiB (2.3 MiB)
 * Final size of installed tree:   124 KiB

 * Messages for package dev-libs/libunistring-0.9.10:

 * Package:    dev-libs/libunistring-0.9.10
 * Repository: gentoo
 * Maintainer: scheme@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux userland_GNU
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * Applying libunistring-nodocs.patch ...
 * abi_x86_64.amd64: running multilib-minimal_abi_src_configure
 * abi_x86_64.amd64: running multilib-minimal_abi_src_compile
 * abi_x86_64.amd64: running multilib-minimal_abi_src_install
 * Removing unnecessary /usr/lib64/libunistring.la (no static archive)
 * Final size of build directory: 38804 KiB (37.8 MiB)
 * Final size of installed tree:   1904 KiB ( 1.8 MiB)

 * Messages for package app-eselect/eselect-lib-bin-symlink-0.1.1:

 * Package:    app-eselect/eselect-lib-bin-symlink-0.1.1
 * Repository: gentoo
 * Maintainer: mgorny@gentoo.org
 * Upstream:   mgorny@gentoo.org https://bitbucket.org/mgorny/eselect-lib-bin-symlink/issues/
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux userland_GNU
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * Final size of build directory: 284 KiB
 * Final size of installed tree:   40 KiB

 * Messages for package app-eselect/eselect-pinentry-0.7:

 * Package:    app-eselect/eselect-pinentry-0.7
 * Repository: gentoo
 * Maintainer: crypto@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux userland_GNU
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * Final size of build directory:  4 KiB
 * Final size of installed tree:  24 KiB

 * Messages for package dev-libs/libassuan-2.5.1:

 * Package:    dev-libs/libassuan-2.5.1
 * Repository: gentoo
 * Maintainer: crypto@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux userland_GNU
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * Removing unnecessary /usr/lib64/libassuan.la (no static archive)
 * Final size of build directory: 4332 KiB (4.2 MiB)
 * Final size of installed tree:   400 KiB

 * Messages for package dev-libs/libksba-1.3.5-r1:

 * Package:    dev-libs/libksba-1.3.5-r1
 * Repository: gentoo
 * Maintainer: crypto@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux userland_GNU
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * Removing unnecessary /usr/lib64/libksba.la (no static archive)
 * Final size of build directory: 5472 KiB (5.3 MiB)
 * Final size of installed tree:   460 KiB

 * Messages for package dev-python/bz2file-0.98:

 * Package:    dev-python/bz2file-0.98
 * Repository: gentoo
 * Maintainer: python@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux python_targets_python2_7 userland_GNU
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * python2_7: running distutils-r1_run_phase distutils-r1_python_compile
 * python2_7: running distutils-r1_run_phase distutils-r1_python_install
 * python2_7: running distutils-r1_run_phase distutils-r1_python_install_all
 * Final size of build directory: 96 KiB
 * Final size of installed tree:  88 KiB

 * Messages for package net-dns/libidn2-2.0.5:

 * Package:    net-dns/libidn2-2.0.5
 * Repository: gentoo
 * Maintainer: jer@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux userland_GNU
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * Will copy sources from /var/tmp/portage/net-dns/libidn2-2.0.5/work/libidn2-2.0.5
 * abi_x86_64.amd64: copying to /var/tmp/portage/net-dns/libidn2-2.0.5/work/libidn2-2.0.5-abi_x86_64.amd64
 * abi_x86_64.amd64: running multilib-minimal_abi_src_configure
 * abi_x86_64.amd64: running multilib-minimal_abi_src_compile
 * abi_x86_64.amd64: running multilib-minimal_abi_src_install
 * Removing unnecessary /usr/lib64/libidn2.la (no static archive)
 * Final size of build directory: 28712 KiB (28.0 MiB)
 * Final size of installed tree:    632 KiB

 * Messages for package dev-libs/libtasn1-4.13:

 * Package:    dev-libs/libtasn1-4.13
 * Repository: gentoo
 * Maintainer: crypto@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux userland_GNU
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * abi_x86_64.amd64: running multilib-minimal_abi_src_configure
 * abi_x86_64.amd64: running multilib-minimal_abi_src_compile
 * abi_x86_64.amd64: running multilib-minimal_abi_src_install
 * Removing unnecessary /usr/lib64/libtasn1.la (no static archive)
 * Final size of build directory: 9888 KiB (9.6 MiB)
 * Final size of installed tree:   516 KiB

 * Messages for package dev-libs/nettle-3.4:

 * Package:    dev-libs/nettle-3.4
 * Repository: gentoo
 * Maintainer: crypto@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc gmp kernel_linux userland_GNU
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * Running eautoreconf in '/var/tmp/portage/dev-libs/nettle-3.4/work/nettle-3.4' ...
 * Running autoconf --force ...
 * Running autoheader ...
 * abi_x86_64.amd64: running multilib-minimal_abi_src_configure
 * abi_x86_64.amd64: running multilib-minimal_abi_src_compile
 * abi_x86_64.amd64: running multilib-minimal_abi_src_install
 * Final size of build directory: 11068 KiB (10.8 MiB)
 * Final size of installed tree:   1012 KiB

 * Messages for package net-libs/gnutls-3.5.18:

 * Package:    net-libs/gnutls-3.5.18
 * Repository: gentoo
 * Maintainer: crypto@gentoo.org
 * USE:        abi_x86_64 amd64 cxx elibc_glibc idn kernel_linux nls openssl seccomp tls-heartbeat userland_GNU zlib
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * abi_x86_64.amd64: running multilib-minimal_abi_src_configure
 * abi_x86_64.amd64: running multilib-minimal_abi_src_compile
 * abi_x86_64.amd64: running multilib-minimal_abi_src_install
 * Removing unnecessary /usr/lib64/libgnutlsxx.la (requested)
 * Removing unnecessary /usr/lib64/libgnutls.la (requested)
 * Removing unnecessary /usr/lib64/libgnutls-openssl.la (requested)
 * Final size of build directory: 74128 KiB (72.3 MiB)
 * Final size of installed tree:   2496 KiB ( 2.4 MiB)

 * Messages for package app-crypt/pinentry-1.1.0-r2:

 * Package:    app-crypt/pinentry-1.1.0-r2
 * Repository: gentoo
 * Maintainer: k_f@gentoo.org crypto@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux ncurses userland_GNU
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * Applying pinentry-1.0.0-make-icon-work-under-Plasma-Wayland.patch ...
 * Applying pinentry-0.8.2-ncurses.patch ...
 * Running eautoreconf in '/var/tmp/portage/app-crypt/pinentry-1.1.0-r2/work/pinentry-1.1.0' ...
 * Running aclocal -I m4 ...
 * Running autoconf --force ...
 * Running autoheader ...
 * Running automake --add-missing --copy --force-missing ...
 * Final size of build directory: 4688 KiB (4.5 MiB)
 * Final size of installed tree:   332 KiB

 * Messages for package net-misc/curl-7.60.0-r1:

 * Package:    net-misc/curl-7.60.0-r1
 * Repository: gentoo
 * Maintainer: blueness@gentoo.org
 * USE:        abi_x86_64 amd64 curl_ssl_openssl elibc_glibc ipv6 kernel_linux ssl userland_GNU
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * Applying curl-7.30.0-prefix.patch ...
 * Applying curl-respect-cflags-3.patch ...
 * Applying curl-fix-gnutls-nettle.patch ...
 * Adjusting to prefix /
 *   curl-config.in ...
 * Running eautoreconf in '/var/tmp/portage/net-misc/curl-7.60.0-r1/work/curl-7.60.0' ...
 * Running libtoolize --install --copy --force --automake ...
 * Running aclocal -I m4 ...
 * Running autoconf --force ...
 * Running autoheader ...
 * Running automake --add-missing --copy --foreign --force-missing ...
 * abi_x86_64.amd64: running multilib-minimal_abi_src_configure
 * SSL provided by openssl
 * abi_x86_64.amd64: running multilib-minimal_abi_src_compile
 * Skipping make test/check due to ebuild restriction.
 * abi_x86_64.amd64: running multilib-minimal_abi_src_install
 * Removing unnecessary /usr/lib64/libcurl.la (requested)
 * Final size of build directory: 39960 KiB (39.0 MiB)
 * Final size of installed tree:   3500 KiB ( 3.4 MiB)

 * Messages for package app-admin/metalog-3-r2:

 * Package:    app-admin/metalog-3-r2
 * Repository: gentoo
 * Maintainer: base-system@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux unicode userland_GNU
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * Applying metalog-0.9-metalog-conf.patch ...
 * Final size of build directory: 5084 KiB (4.9 MiB)
 * Final size of installed tree:   180 KiB

 * Messages for package virtual/logger-0:

 * Package:    virtual/logger-0
 * Repository: gentoo
 * Maintainer: ultrabug@gentoo.org base-system@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux userland_GNU
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * Final size of build directory: 4 KiB
 * Final size of installed tree:  4 KiB

 * Messages for package mail-mta/nullmailer-2.0-r2:

 * Package:    mail-mta/nullmailer-2.0-r2
 * Repository: gentoo
 * Maintainer: robbat2@gentoo.org net-mail@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux ssl userland_GNU
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * Adding group 'nullmail' to your system ...
 *  - Groupid: 88
 * Adding user 'nullmail' to your system ...
 *  - Userid: 88
 *  - Shell: /sbin/nologin
 *  - Home: /var/spool/nullmailer
 *  - Groups: nullmail
 *  - GECOS: added by portage for nullmailer
 *  - Creating /var/spool/nullmailer in /
 * Running eautoreconf in '/var/tmp/portage/mail-mta/nullmailer-2.0-r2/work/nullmailer-2.0' ...
 * Running aclocal ...
 * Running autoconf --force ...
 * Running autoheader ...
 * Running automake --add-missing --copy --force-missing ...
 * Final size of build directory: 4236 KiB (4.1 MiB)
 * Final size of installed tree:   868 KiB
 * To create an initial setup, please do:
 * emerge --config =mail-mta/nullmailer-2.0-r2
 * One or more empty directories installed to /var:
 * 
 *   /var/spool/nullmailer/failed
 * 
 * If those directories need to be preserved, please make sure to create
 * or mark them for keeping using 'keepdir'. Future versions of Portage
 * will strip empty directories from installation image.
 * >>> SetUID: [chmod go-r] /usr/bin/mailq ...
 * >>> SetUID: [chmod go-r] /usr/sbin/nullmailer-queue ...

 * Messages for package virtual/mta-1:

 * Package:    virtual/mta-1
 * Repository: gentoo
 * Maintainer: net-mail@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux userland_GNU
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * Final size of build directory: 4 KiB
 * Final size of installed tree:  4 KiB

 * Messages for package app-crypt/gnupg-2.2.8:

 * Package:    app-crypt/gnupg-2.2.8
 * Repository: gentoo
 * Maintainer: k_f@gentoo.org crypto@gentoo.org
 * USE:        abi_x86_64 amd64 bzip2 elibc_glibc kernel_linux nls readline smartcard ssl userland_GNU
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * Applying gnupg-2.1.20-gpgscm-Use-shorter-socket-path-lengts-to-improve-tes.patch ...
 * Final size of build directory: 52244 KiB (51.0 MiB)
 * Final size of installed tree:  12276 KiB (11.9 MiB)

 * Messages for package app-portage/gemato-13.1:

 * Package:    app-portage/gemato-13.1
 * Repository: gentoo
 * Maintainer: mgorny@gentoo.org
 * Upstream:   https://github.com/mgorny/gemato/issues/
 * USE:        abi_x86_64 amd64 blake2 bzip2 elibc_glibc gpg kernel_linux python_targets_python2_7 python_targets_python3_5 userland_GNU
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * python2_7: running distutils-r1_run_phase distutils-r1_python_compile
 * python3_5: running distutils-r1_run_phase distutils-r1_python_compile
 * python2_7: running distutils-r1_run_phase distutils-r1_python_install
 * python3_5: running distutils-r1_run_phase distutils-r1_python_install
 * python3_5: running distutils-r1_run_phase python_install_all
 * Final size of build directory:  948 KiB
 * Final size of installed tree:  1100 KiB (1.0 MiB)

 * Messages for package sys-apps/portage-2.3.41:

 * Package:    sys-apps/portage-2.3.41
 * Repository: gentoo
 * Maintainer: dev-portage@gentoo.org
 * Upstream:   dev-portage@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc ipc kernel_linux native-extensions python_targets_python2_7 python_targets_python3_5 rsync-verify userland_GNU xattr
 * FEATURES:   preserve-libs sandbox userpriv usersandbox
 * Adding FEATURES=xattr to make.globals ...
 * python2_7: running distutils-r1_run_phase distutils-r1_python_compile
 * python3_5: running distutils-r1_run_phase distutils-r1_python_compile
 * python3_5: running distutils-r1_run_phase python_compile_all
 * python2_7: running distutils-r1_run_phase python_install
 * python3_5: running distutils-r1_run_phase python_install
 * python3_5: running distutils-r1_run_phase python_install_all
 * Moving admin scripts to the correct directory
 * Moving /usr/bin/archive-conf to /usr/sbin/archive-conf
 * Moving /usr/bin/dispatch-conf to /usr/sbin/dispatch-conf
 * Moving /usr/bin/emaint to /usr/sbin/emaint
 * Moving /usr/bin/env-update to /usr/sbin/env-update
 * Moving /usr/bin/etc-update to /usr/sbin/etc-update
 * Moving /usr/bin/fixpackages to /usr/sbin/fixpackages
 * Moving /usr/bin/regenworld to /usr/sbin/regenworld
 * Final size of build directory: 19820 KiB (19.3 MiB)
 * Final size of installed tree:  35896 KiB (35.0 MiB)
 * 
 * This release of portage NO LONGER contains the repoman code base.
 * Repoman has its own ebuild and release package.
 * For repoman functionality please emerge app-portage/repoman
 * Please report any bugs you may encounter.
 * 
>>> Auto-cleaning packages...

>>> No outdated packages were found on your system.

 * Regenerating GNU info directory index...
 * Processed 78 info files.

 * IMPORTANT: 13 news items need reading for repository 'gentoo'.
 * Use eselect news read to view new items.

livecd / #
```

Next we relaunch the `chroot` program with the special `bash` feature `!` that execute the last command executed after the exclamation sign.

We use `emerge-webrsync` with those options:

- `--keep`: Keep snapshots in `/usr/portage/distfile`.
- `--revert`: come back to `yyyymmdd`.

Next we update the just installed `portage` with `emerge`. We've used in our `~/.bashrc` file the variable `EMERGE_DEFAULT_OPTS` where we already indicate to use `--ask` and `--verbose`. This time we add `-oneshot` that indicate *emerge as normal, but do not add the packages to the world file for later updating*.

```sh
livecd ~ # eselect profile list
Available profile symlink targets:
  [1]   default/linux/amd64/13.0 (stable)
  [2]   default/linux/amd64/13.0/selinux (dev)
  [3]   default/linux/amd64/13.0/desktop (stable)
  [4]   default/linux/amd64/13.0/desktop/gnome (stable)
  [5]   default/linux/amd64/13.0/desktop/gnome/systemd (stable)
  [6]   default/linux/amd64/13.0/desktop/plasma (stable)
  [7]   default/linux/amd64/13.0/desktop/plasma/systemd (stable)
  [8]   default/linux/amd64/13.0/developer (stable)
  [9]   default/linux/amd64/13.0/no-multilib (stable)
  [10]  default/linux/amd64/13.0/systemd (stable)
  [11]  default/linux/amd64/13.0/x32 (dev)
  [12]  default/linux/amd64/17.0 (stable) *
  [13]  default/linux/amd64/17.0/selinux (stable)
  [14]  default/linux/amd64/17.0/hardened (stable)
  [15]  default/linux/amd64/17.0/hardened/selinux (stable)
  [16]  default/linux/amd64/17.0/desktop (stable)
  [17]  default/linux/amd64/17.0/desktop/gnome (stable)
  [18]  default/linux/amd64/17.0/desktop/gnome/systemd (stable)
  [19]  default/linux/amd64/17.0/desktop/plasma (stable)
  [20]  default/linux/amd64/17.0/desktop/plasma/systemd (stable)
  [21]  default/linux/amd64/17.0/developer (stable)
  [22]  default/linux/amd64/17.0/no-multilib (stable)
  [23]  default/linux/amd64/17.0/no-multilib/hardened (stable)
  [24]  default/linux/amd64/17.0/no-multilib/hardened/selinux (stable)
  [25]  default/linux/amd64/17.0/systemd (stable)
  [26]  default/linux/amd64/17.0/x32 (dev)
  [27]  default/linux/amd64/17.1 (exp)
  [28]  default/linux/amd64/17.1/selinux (exp)
  [29]  default/linux/amd64/17.1/hardened (exp)
  [30]  default/linux/amd64/17.1/hardened/selinux (exp)
  [31]  default/linux/amd64/17.1/desktop (exp)
  [32]  default/linux/amd64/17.1/desktop/gnome (exp)
  [33]  default/linux/amd64/17.1/desktop/gnome/systemd (exp)
  [34]  default/linux/amd64/17.1/desktop/plasma (exp)
  [35]  default/linux/amd64/17.1/desktop/plasma/systemd (exp)
  [36]  default/linux/amd64/17.1/developer (exp)
  [37]  default/linux/amd64/17.1/no-multilib (exp)
  [38]  default/linux/amd64/17.1/no-multilib/hardened (exp)
  [39]  default/linux/amd64/17.1/no-multilib/hardened/selinux (exp)
  [40]  default/linux/amd64/17.1/systemd (exp)
  [41]  hardened/linux/amd64 (stable)
  [42]  hardened/linux/amd64/selinux (stable)
  [43]  hardened/linux/amd64/no-multilib (stable)
  [44]  hardened/linux/amd64/no-multilib/selinux (stable)
  [45]  hardened/linux/amd64/x32 (dev)
  [46]  default/linux/musl/amd64 (exp)
  [47]  hardened/linux/musl/amd64 (exp)
  [48]  default/linux/musl/amd64/x32 (exp)
  [49]  hardened/linux/musl/amd64/x32 (exp)
  [50]  default/linux/amd64/17.0/musl (exp)
  [51]  default/linux/amd64/17.0/musl/hardened (exp)
  [52]  default/linux/amd64/17.0/musl/hardened/selinux (exp)
  [53]  default/linux/uclibc/amd64 (exp)
  [54]  hardened/linux/uclibc/amd64 (exp)
livecd ~ # eselect profile set 15
livecd ~ # eselect profile list | grep 15
  [15]  default/linux/amd64/17.0/hardened/selinux (stable) *
livecd ~ # cd /etc/portage/
livecd /etc/portage # ls -al
total 40
drwxr-xr-x  8 root root 4096 Jul  6 20:42 .
drwxr-xr-x 32 root root 4096 Jul  6 20:06 ..
-rw-r--r--  1 root root 1468 Jul  6 19:24 make.conf
lrwxrwxrwx  1 root root   68 Jul  6 20:42 make.profile -> ../../usr/portage/profiles/default/linux/amd64/17.0/hardened/selinux
drwxr-xr-x  2 root root 4096 Jun 25 02:34 package.accept_keywords
drwxr-xr-x  2 root root 4096 Jun 25 02:34 package.mask
drwxr-xr-x  2 root root 4096 Jun 25 02:34 package.use
drwxr-xr-x  2 root root 4096 Jul  6 19:57 repo.postsync.d
drwxr-xr-x  2 root root 4096 Jul  6 10:23 repos.conf
drwxr-xr-x  3 root root 4096 Jun 25 00:57 savedconfig
livecd /etc/portage #
```

With `eselect` we can *select* various options to configure our Gentoo system.

With `eselect profile` we change the symbolic link `/etc/portage/make.profile` to indicate what kind of system we're going to install. There's a lot of.  In this case we're selecting an [hardened + selinux](https://wiki.gentoo.org/wiki/Project:Hardened) installation (*take care is different from the Sakaki EFI install guide*). We can visualize all the variables of this kind of `profile`:

```sh
livecd /etc/portage # emerge --info
Portage 2.3.41 (python 3.6.6-final-0, default/linux/amd64/17.0/hardened/selinux, gcc-7.3.0, glibc-2.27-r5, 4.9.76-gentoo-r1 x86_64)
=================================================================
System uname: Linux-4.9.76-gentoo-r1-x86_64-Intel-R-_Core-TM-_i7-2620M_CPU_@_2.70GHz-with-gentoo-2.6
KiB Mem:     3963424 total,   1381068 free
KiB Swap:          0 total,         0 free
Timestamp of repository gentoo: Fri, 06 Jul 2018 00:45:01 +0000
Head commit of repository gentoo: f8f48a7991916da84d772315003d334f6c5a9699
sh bash 4.4_p12
ld GNU ld (Gentoo 2.30 p2) 2.30.0
app-shells/bash:          4.4_p12::gentoo
dev-lang/perl:            5.24.3-r1::gentoo
dev-lang/python:          2.7.14-r1::gentoo, 3.6.6::gentoo
dev-util/pkgconfig:       0.29.2::gentoo
sys-apps/baselayout:      2.6::gentoo
sys-apps/openrc:          0.34.11::gentoo
sys-apps/sandbox:         2.13::gentoo
sys-devel/autoconf:       2.69-r4::gentoo
sys-devel/automake:       1.15.1-r2::gentoo
sys-devel/binutils:       2.30-r2::gentoo
sys-devel/gcc:            7.3.0-r3::gentoo
sys-devel/gcc-config:     1.8-r1::gentoo
sys-devel/libtool:        2.4.6-r3::gentoo
sys-devel/make:           4.2.1::gentoo
sys-kernel/linux-headers: 4.13::gentoo (virtual/os-headers)
sys-libs/glibc:           2.27-r5::gentoo
Repositories:

gentoo
    location: /usr/portage
    sync-type: rsync
    sync-uri: rsync://rsync.fr.gentoo.org/gentoo-portage
    priority: -1000
    sync-rsync-extra-opts: 
    sync-rsync-verify-metamanifest: yes
    sync-rsync-verify-jobs: 1
    sync-rsync-verify-max-age: 24

ABI="amd64"
ABI_X86="64"
ACCEPT_KEYWORDS="amd64 ~amd64"
ACCEPT_LICENSE="@FREE CC-Sampling-Plus-1.0"
ACCEPT_PROPERTIES="*"
ACCEPT_RESTRICT="*"
ALSA_CARDS="ali5451 als4000 atiixp atiixp-modem bt87x ca0106 cmipci emu10k1x ens1370 ens1371 es1938 es1968 fm801 hda-intel intel8x0 intel8x0m maestro3 trident usb-audio via82xx via82xx-modem ymfpci"
APACHE2_MODULES="authn_core authz_core socache_shmcb unixd actions alias auth_basic authn_alias authn_anon authn_dbm authn_default authn_file authz_dbm authz_default authz_groupfile authz_host authz_owner authz_user autoindex cache cgi cgid dav dav_fs dav_lock deflate dir disk_cache env expires ext_filter file_cache filter headers include info log_config logio mem_cache mime mime_magic negotiation rewrite setenvif speling status unique_id userdir usertrack vhost_alias"
ARCH="amd64"
AUTOCLEAN="yes"
BOOTSTRAP_USE="cxx unicode internal-glib split-usr python_targets_python3_5 python_targets_python2_7 multilib hardened pic xtpax -jit -orc"
BROOT=""
CALLIGRA_FEATURES="karbon plan sheets stage words"
CBUILD="x86_64-pc-linux-gnu"
CFLAGS="-march=sandybridge -O2 -pipe"
CFLAGS_amd64="-m64"
CFLAGS_x32="-mx32"
CFLAGS_x86="-m32"
CHOST="x86_64-pc-linux-gnu"
CHOST_amd64="x86_64-pc-linux-gnu"
CHOST_x32="x86_64-pc-linux-gnux32"
CHOST_x86="i686-pc-linux-gnu"
CLEAN_DELAY="5"
COLLECTD_PLUGINS="df interface irq load memory rrdtool swap syslog"
COLLISION_IGNORE="/lib/modules/* *.py[co] *$py.class */dropin.cache"
CONFIG_PROTECT="/etc /usr/share/gnupg/qualified.txt"
CONFIG_PROTECT_MASK="/etc/ca-certificates.conf /etc/env.d /etc/gconf /etc/gentoo-release /etc/sandbox.d /etc/terminfo"
CPU_FLAGS_X86="mmx mmxext sse sse2"
CXXFLAGS=""
DEFAULT_ABI="amd64"
DISTDIR="/usr/portage/distfiles"
EDITOR="/bin/nano"
ELIBC="glibc"
EMERGE_DEFAULT_OPTS="--ask --verbose --jobs=5 --load-average=4"
EMERGE_WARNING_DELAY="10"
ENV_UNSET="DBUS_SESSION_BUS_ADDRESS DISPLAY PERL5LIB PERL5OPT PERLPREFIX PERL_CORE PERL_MB_OPT PERL_MM_OPT XAUTHORITY XDG_CACHE_HOME XDG_CONFIG_HOME XDG_DATA_HOME XDG_RUNTIME_DIR"
EPREFIX=""
EROOT="/"
ESYSROOT="/"
FCFLAGS="-O2 -pipe"
FEATURES="assume-digests binpkg-logs buildpkg config-protect-if-modified distlocks ebuild-locks fixlafiles merge-sync multilib-strict news parallel-fetch preserve-libs protect-owned sandbox selinux sesandbox sfperms split-elog strict unknown-features-warn unmerge-logs unmerge-orphans userfetch userpriv usersandbox usersync xattr"
FETCHCOMMAND="wget -t 3 -T 60 --passive-ftp -O "${DISTDIR}/${FILE}" "${URI}""
FETCHCOMMAND_RSYNC="rsync -avP "${URI}" "${DISTDIR}/${FILE}""
FETCHCOMMAND_SFTP="bash -c "x=\${2#sftp://} ; host=\${x%%/*} ; port=\${host##*:} ; host=\${host%:*} ; [[ \${host} = \${port} ]] && port= ; eval \"declare -a ssh_opts=(\${3})\" ; exec sftp \${port:+-P \${port}} \"\${ssh_opts[@]}\" \"\${host}:/\${x#*/}\" \"\$1\"" sftp "${DISTDIR}/${FILE}" "${URI}" "${PORTAGE_SSH_OPTS}""
FETCHCOMMAND_SSH="bash -c "x=\${2#ssh://} ; host=\${x%%/*} ; port=\${host##*:} ; host=\${host%:*} ; [[ \${host} = \${port} ]] && port= ; exec rsync --rsh=\"ssh \${port:+-p\${port}} \${3}\" -avP \"\${host}:/\${x#*/}\" \"\$1\"" rsync "${DISTDIR}/${FILE}" "${URI}" "${PORTAGE_SSH_OPTS}""
FFLAGS="-O2 -pipe"
GCC_SPECS=""
GENTOO_MIRRORS="ftp://ftp.free.fr/mirrors/ftp.gentoo.org/ http://gentoo.modulix.net/gentoo/ http://gentoo.mirrors.ovh.net/gentoo-distfiles/ ftp://gentoo.mirrors.ovh.net/gentoo-distfiles/ ftp://mirrors.soeasyto.com/distfiles.gentoo.org/ http://mirrors.soeasyto.com/distfiles.gentoo.org/"
GPG_TTY="/dev/pts/0"
GPSD_PROTOCOLS="ashtech aivdm earthmate evermore fv18 garmin garmintxt gpsclock isync itrax mtk3301 nmea ntrip navcom oceanserver oldstyle oncore rtcm104v2 rtcm104v3 sirf skytraq superstar2 timing tsip tripmate tnt ublox ubx"
GRUB_PLATFORMS=""
HOME="/root"
INFOPATH="/usr/share/gcc-data/x86_64-pc-linux-gnu/6.4.0/info:/usr/share/binutils-data/x86_64-pc-linux-gnu/2.29.1/info:/usr/share/info"
INPUT_DEVICES="libinput"
IUSE_IMPLICIT="abi_x86_64 prefix prefix-chain prefix-guest"
KERNEL="linux"
LANG="en_GB.utf8"
LCD_DEVICES="bayrad cfontz cfontz633 glk hd44780 lb216 lcdm001 mtxorb ncurses text"
LC_COLLATE="C"
LC_MESSAGES="C"
LDFLAGS="-Wl,-O1 -Wl,--as-needed"
LDFLAGS_amd64="-m elf_x86_64"
LDFLAGS_x32="-m elf32_x86_64"
LDFLAGS_x86="-m elf_i386"
LESS="-R -M --shift 5"
LESSOPEN="|lesspipe %s"
LIBDIR_amd64="lib64"
LIBDIR_x32="libx32"
LIBDIR_x86="lib32"
LIBREOFFICE_EXTENSIONS="presenter-console presenter-minimizer"
LOGNAME="root"
LS_COLORS="rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=01;05;37;41:mi=01;05;37;41:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.Z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.cfg=00;32:*.conf=00;32:*.diff=00;32:*.doc=00;32:*.ini=00;32:*.log=00;32:*.patch=00;32:*.pdf=00;32:*.ps=00;32:*.tex=00;32:*.txt=00;32:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:"
MAIL="/var/mail/root"
MAKEOPTS="-j5 -l4"
MANPAGER="manpager"
MANPATH="/usr/share/gcc-data/x86_64-pc-linux-gnu/6.4.0/man:/usr/share/binutils-data/x86_64-pc-linux-gnu/2.29.1/man:/usr/local/share/man:/usr/share/man"
MULTILIB_ABIS="amd64 x86"
MULTILIB_STRICT_DENY="64-bit.*shared object"
MULTILIB_STRICT_DIRS="/lib32 /lib /usr/lib32 /usr/lib /usr/kde/*/lib32 /usr/kde/*/lib /usr/qt/*/lib32 /usr/qt/*/lib /usr/X11R6/lib32 /usr/X11R6/lib"
MULTILIB_STRICT_EXEMPT="(perl5|gcc|gcc-lib|binutils|eclipse-3|debug|portage|udev|systemd|clang|python-exec|llvm)"
NETBEANS="apisupport cnd groovy gsf harness ide identity j2ee java mobility nb php profiler soa visualweb webcommon websvccommon xml"
NUMCPUS="4"
NUMCPUSPLUSONE="5"
OFFICE_IMPLEMENTATION="libreoffice"
OLDPWD="/etc/portage"
PAGER="/usr/bin/less"
PATH="/usr/x86_64-pc-linux-gnu/gcc-bin/6.4.0:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin"
PAX_MARKINGS="XT"
PHP_TARGETS="php5-6 php7-0"
PKGDIR="/usr/portage/packages"
POLICY_TYPES="strict targeted"
PORTAGE_ARCHLIST="alpha amd64 amd64-fbsd amd64-linux arm arm-linux arm64 arm64-linux hppa ia64 m68k m68k-mint mips ppc ppc-aix ppc-macos ppc64 ppc64-linux s390 sh sparc sparc-solaris sparc64-solaris x64-cygwin x64-macos x64-solaris x86 x86-cygwin x86-fbsd x86-linux x86-macos x86-solaris x86-winnt"
PORTAGE_BIN_PATH="/usr/lib/portage/python3.6"
PORTAGE_COMPRESS_EXCLUDE_SUFFIXES="css gif htm[l]? jp[e]?g js pdf png"
PORTAGE_CONFIGROOT="/"
PORTAGE_DEBUG="0"
PORTAGE_DEPCACHEDIR="/var/cache/edb/dep"
PORTAGE_ELOG_CLASSES="info warn error log qa"
PORTAGE_ELOG_MAILFROM="portage@localhost"
PORTAGE_ELOG_MAILSUBJECT="[portage] ebuild log for ${PACKAGE} on ${HOST}"
PORTAGE_ELOG_MAILURI="root"
PORTAGE_ELOG_SYSTEM="echo save"
PORTAGE_FETCH_CHECKSUM_TRY_MIRRORS="5"
PORTAGE_FETCH_RESUME_MIN_SIZE="350K"
PORTAGE_FETCH_T="portage_fetch_t"
PORTAGE_GID="250"
PORTAGE_GPG_SIGNING_COMMAND="gpg --sign --digest-algo SHA256 --clearsign --yes --default-key "${PORTAGE_GPG_KEY}" --homedir "${PORTAGE_GPG_DIR}" "${FILE}""
PORTAGE_INST_GID="0"
PORTAGE_INST_UID="0"
PORTAGE_INTERNAL_CALLER="1"
PORTAGE_OVERRIDE_EPREFIX=""
PORTAGE_PYM_PATH="/usr/lib64/python3.6/site-packages"
PORTAGE_PYTHONPATH="/usr/lib64/python3.6/site-packages"
PORTAGE_RSYNC_OPTS="--recursive --links --safe-links --perms --times --omit-dir-times --compress --force --whole-file --delete --stats --human-readable --timeout=180 --exclude=/distfiles --exclude=/local --exclude=/packages --exclude=/.git"
PORTAGE_RSYNC_RETRIES="-1"
PORTAGE_SANDBOX_T="portage_sandbox_t"
PORTAGE_SYNC_STALE="30"
PORTAGE_T="portage_t"
PORTAGE_TMPDIR="/var/tmp"
PORTAGE_VERBOSE="1"
PORTAGE_WORKDIR_MODE="0700"
PORTAGE_XATTR_EXCLUDE="btrfs.* security.evm security.ima 	security.selinux system.nfs4_acl user.apache_handler 	user.Beagle.* user.dublincore.* user.mime_encoding user.xdg.*"
PORT_LOGDIR_CLEAN="find "${PORT_LOGDIR}" -type f ! -name "summary.log*" -mtime +7 -delete"
POSTGRES_TARGETS="postgres9_5 postgres10"
PROFILE_IS_HARDENED="1"
PROFILE_ONLY_VARIABLES="ARCH ELIBC IUSE_IMPLICIT KERNEL USERLAND USE_EXPAND_IMPLICIT USE_EXPAND_UNPREFIXED USE_EXPAND_VALUES_ARCH USE_EXPAND_VALUES_ELIBC USE_EXPAND_VALUES_KERNEL USE_EXPAND_VALUES_USERLAND"
PWD="/etc/portage"
PYTHONDONTWRITEBYTECODE="1"
PYTHON_SINGLE_TARGET="python3_6"
PYTHON_TARGETS="python2_7 python3_6"
RESUMECOMMAND="wget -c -t 3 -T 60 --passive-ftp -O "${DISTDIR}/${FILE}" "${URI}""
RESUMECOMMAND_RSYNC="rsync -avP "${URI}" "${DISTDIR}/${FILE}""
RESUMECOMMAND_SSH="bash -c "x=\${2#ssh://} ; host=\${x%%/*} ; port=\${host##*:} ; host=\${host%:*} ; [[ \${host} = \${port} ]] && port= ; exec rsync --rsh=\"ssh \${port:+-p\${port}} \${3}\" -avP \"\${host}:/\${x#*/}\" \"\$1\"" rsync "${DISTDIR}/${FILE}" "${URI}" "${PORTAGE_SSH_OPTS}""
ROOT="/"
ROOTPATH="/usr/x86_64-pc-linux-gnu/gcc-bin/7.3.0:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin"
RPMDIR="/usr/portage/rpm"
RUBY_TARGETS="ruby23"
SHELL="/bin/bash"
SHLVL="2"
SSH_CLIENT="10.3.30.1 35898 22"
SSH_CONNECTION="10.3.30.1 35898 10.3.30.2 22"
SSH_TTY="/dev/pts/0"
SYMLINK_LIB="yes"
SYSROOT="/"
TERM="xterm-256color"
TWISTED_DISABLE_WRITING_OF_PLUGIN_CACHE="1"
UNINSTALL_IGNORE="/lib/modules/* /var/run /var/lock"
USE="acl amd64 bzip2 crypt cxx hardened iconv ipv6 libtirpc multilib ncurses nls nptl openmp pam pcre pie readline seccomp selinux ssl ssp unicode xattr xtpax zlib" ABI_X86="64" ALSA_CARDS="ali5451 als4000 atiixp atiixp-modem bt87x ca0106 cmipci emu10k1x ens1370 ens1371 es1938 es1968 fm801 hda-intel intel8x0 intel8x0m maestro3 trident usb-audio via82xx via82xx-modem ymfpci" APACHE2_MODULES="authn_core authz_core socache_shmcb unixd actions alias auth_basic authn_alias authn_anon authn_dbm authn_default authn_file authz_dbm authz_default authz_groupfile authz_host authz_owner authz_user autoindex cache cgi cgid dav dav_fs dav_lock deflate dir disk_cache env expires ext_filter file_cache filter headers include info log_config logio mem_cache mime mime_magic negotiation rewrite setenvif speling status unique_id userdir usertrack vhost_alias" CALLIGRA_FEATURES="karbon plan sheets stage words" COLLECTD_PLUGINS="df interface irq load memory rrdtool swap syslog" CPU_FLAGS_X86="mmx mmxext sse sse2" ELIBC="glibc" GPSD_PROTOCOLS="ashtech aivdm earthmate evermore fv18 garmin garmintxt gpsclock isync itrax mtk3301 nmea ntrip navcom oceanserver oldstyle oncore rtcm104v2 rtcm104v3 sirf skytraq superstar2 timing tsip tripmate tnt ublox ubx" INPUT_DEVICES="libinput" KERNEL="linux" LCD_DEVICES="bayrad cfontz cfontz633 glk hd44780 lb216 lcdm001 mtxorb ncurses text" LIBREOFFICE_EXTENSIONS="presenter-console presenter-minimizer" OFFICE_IMPLEMENTATION="libreoffice" PHP_TARGETS="php5-6 php7-0" POSTGRES_TARGETS="postgres9_5 postgres10" PYTHON_SINGLE_TARGET="python3_6" PYTHON_TARGETS="python2_7 python3_6" RUBY_TARGETS="ruby23" USERLAND="GNU" VIDEO_CARDS="intel i915" XTABLES_ADDONS="quota2 psd pknock lscan length2 ipv4options ipset ipp2p iface geoip fuzzy condition tee tarpit sysrq steal rawnat logmark ipmark dhcpmac delude chaos account"
USER="root"
USERLAND="GNU"
USE_EXPAND="ABI_MIPS ABI_PPC ABI_S390 ABI_X86 ALSA_CARDS APACHE2_MODULES APACHE2_MPMS CALLIGRA_EXPERIMENTAL_FEATURES CALLIGRA_FEATURES CAMERAS COLLECTD_PLUGINS CPU_FLAGS_ARM CPU_FLAGS_X86 CURL_SSL ELIBC ENLIGHTENMENT_MODULES FFTOOLS GPSD_PROTOCOLS GRUB_PLATFORMS INPUT_DEVICES KERNEL L10N LCD_DEVICES LIBREOFFICE_EXTENSIONS LIRC_DEVICES LLVM_TARGETS MONKEYD_PLUGINS NETBEANS_MODULES NGINX_MODULES_HTTP NGINX_MODULES_MAIL NGINX_MODULES_STREAM OFED_DRIVERS OFFICE_IMPLEMENTATION OPENMPI_FABRICS OPENMPI_OFED_FEATURES OPENMPI_RM PHP_TARGETS POSTGRES_TARGETS PYTHON_SINGLE_TARGET PYTHON_TARGETS QEMU_SOFTMMU_TARGETS QEMU_USER_TARGETS ROS_MESSAGES RUBY_TARGETS SANE_BACKENDS USERLAND UWSGI_PLUGINS VIDEO_CARDS VOICEMAIL_STORAGE XFCE_PLUGINS XTABLES_ADDONS"
USE_EXPAND_HIDDEN="ABI_MIPS ABI_PPC ABI_S390 CPU_FLAGS_ARM ELIBC KERNEL USERLAND"
USE_EXPAND_IMPLICIT="ARCH ELIBC KERNEL USERLAND"
USE_EXPAND_UNPREFIXED="ARCH"
USE_EXPAND_VALUES_ARCH="alpha amd64 amd64-fbsd amd64-linux arm arm-linux arm64 hppa ia64 m68k m68k-mint mips ppc ppc64 ppc64-linux ppc-aix ppc-macos s390 sh sparc sparc64-solaris sparc-solaris x64-cygwin x64-macos x64-solaris x86 x86-cygwin x86-fbsd x86-linux x86-macos x86-solaris x86-winnt"
USE_EXPAND_VALUES_ELIBC="AIX bionic Cygwin Darwin DragonFly FreeBSD glibc HPUX Interix mingw mintlib musl NetBSD OpenBSD SunOS uclibc Winnt"
USE_EXPAND_VALUES_KERNEL="AIX Darwin FreeBSD freemint HPUX linux NetBSD OpenBSD SunOS Winnt"
USE_EXPAND_VALUES_USERLAND="BSD GNU"
USE_ORDER="env:pkg:conf:defaults:pkginternal:repo:env.d"
VIDEO_CARDS="intel i915"
XTABLES_ADDONS="quota2 psd pknock lscan length2 ipv4options ipset ipp2p iface geoip fuzzy condition tee tarpit sysrq steal rawnat logmark ipmark dhcpmac delude chaos account"

livecd /etc/portage #
```

Go ahead with the customization:

```sh
livecd /etc/portage # echo "Europe/Madrid" > /etc/timezone
livecd /etc/portage # emerge --config timezone-data


Ready to configure sys-libs/timezone-data-2018d? [Yes/No] Yes

!!! SELinux module not found. Please verify that it was installed.
 * Updating /etc/localtime with /usr/share/zoneinfo/Europe/Madrid

livecd /etc/portage # 
```

We've configured local time to our current  zone. Then another type of `emerge` option:

- `--config`: run package specific actions needed to be executed after the emerge process has completed.

```sh
livecd /etc # cat >> locale.gen <<EOF
> en_GB ISO-8859-1
> en_GB.UTF-8 UTF-8
> EOF
livecd /etc # cd conf.d
livecd /etc/conf.d # sed -i 's/keymap="us"/keymap="es"/g' keymaps 
livecd /etc/conf.d # emerge --verbose --oneshot app-portage/cpuid2cpuflags

 * IMPORTANT: 13 news items need reading for repository 'gentoo'.
 * Use eselect news read to view new items.


These are the packages that would be merged, in order:

Calculating dependencies... done!
[ebuild  N     ] app-portage/cpuid2cpuflags-5::gentoo  71 KiB

Total: 1 package (1 new), Size of downloads: 71 KiB

Would you like to merge these packages? [Yes/No] Yes
>>> Verifying ebuild manifests
>>> Emerging (1 of 1) app-portage/cpuid2cpuflags-5::gentoo
>>> Jobs: 0 of 1 complete, 1 running                Load avg: 0.00, 0.00, 0.00!!! SELinux module not found. Please verify that it was installed.
>>> Jobs: 0 of 1 complete, 1 running                Load avg: 0.08, 0.02, 0.01!!! SELinux module not found. Please verify that it was installed.
>>> Installing (1 of 1) app-portage/cpuid2cpuflags-5::gentoo
>>> Jobs: 1 of 1 complete                           Load avg: 0.15, 0.03, 0.01

 * Messages for package app-portage/cpuid2cpuflags-5:

 * Package:    app-portage/cpuid2cpuflags-5
 * Repository: gentoo
 * Maintainer: mgorny@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux userland_GNU
 * FEATURES:   preserve-libs sandbox selinux sesandbox userpriv usersandbox
 * Final size of build directory: 488 KiB
 * Final size of installed tree:   44 KiB
>>> Auto-cleaning packages...

>>> No outdated packages were found on your system.

 * GNU info directory index is up-to-date.

 * IMPORTANT: 13 news items need reading for repository 'gentoo'.
 * Use eselect news read to view new items.

livecd /etc/conf.d # cpuid2cpuflags
CPU_FLAGS_X86: aes avx mmx mmxext pclmul popcnt sse sse2 sse3 sse4_1 sse4_2 ssse3
livecd /etc/conf.d # cd ../portage/
livecd /etc/portage # sed -i 's/CPU_FLAGS_X86=.*/CPU_FLAGS_X86="aes avx mmx mmxext pclmul popcnt sse sse2 sse3 sse4_1 sse4_2 ssse3"/g' make.conf
livecd /etc/portage #
```

Next we add [english locale](https://en.wikipedia.org/wiki/Locale_(computer_software)) to our chroot subsystem and configure the keymap under `/etc/conf.d` with a `sed` (*stream editor for filtering and transforming text*) command:

- `-i`: in-place (i.e. save back to the original file).
- `s`: the substitute command.
- `g`: global (i.e. replace all and not just the first occurrence).

We also install `cpuid2cpuflags` to better identify `CPU_FLAGS_X86` variable depending on what processor are we using. The `sed` command is the same of the one before but the `.*` that is used to substitute all the line beggin with.

Now we're going to bootstrap the Gentoo Linux [toolchain](https://elinux.org/Toolchains):

```sh
livecd /usr/portage/scripts # ./bootstrap.sh --pretend

Gentoo Linux; http://www.gentoo.org/
Copyright 1999-$ Gentoo Foundation; Distributed under the GPLv2
-------------------------------------------------------------------------------
  [[ (0/3) Locating packages ]]
!!! SELinux module not found. Please verify that it was installed.
!!! SELinux module not found. Please verify that it was installed.
!!! SELinux module not found. Please verify that it was installed.
!!! SELinux module not found. Please verify that it was installed.
!!! SELinux module not found. Please verify that it was installed.
 * Using baselayout : >=sys-apps/baselayout-2
 * Using portage    : portage
 * Using os-headers : >=sys-kernel/linux-headers-4.17
 * Using binutils   : sys-devel/binutils
 * Using gcc        : sys-devel/gcc
 * Using gettext    : gettext
 * Using libc       : virtual/libc
 * Using texinfo    : sys-apps/texinfo
 * Using zlib       : zlib
 * Using ncurses    : ncurses
-------------------------------------------------------------------------------
  [[ (1/3) Configuring environment ]]
-------------------------------------------------------------------------------
!!! SELinux module not found. Please verify that it was installed.
  [[ (2/3) Updating portage ]]
!!! CONFIG_PROTECT is empty

These are the packages that would be merged, in order:

Calculating dependencies... done!
[ebuild  N     ] sys-libs/libsepol-2.8::gentoo  ABI_X86="(64) -32 (-x32)" 463 KiB
[ebuild  N     ] dev-lang/swig-3.0.12::gentoo  USE="-ccache -doc -pcre" 7,959 KiB
[ebuild  N     ] sys-libs/libselinux-2.8::gentoo  USE="(python) (static-libs) -pcre2 -ruby" ABI_X86="(64) -32 (-x32)" PYTHON_TARGETS="python2_7 python3_5 -python3_4 -python3_6" RUBY_TARGETS="-ruby23" 184 KiB
[ebuild   R    ] sys-apps/portage-2.3.41::gentoo  USE="build* (ipc) (selinux*) (xattr) -doc -epydoc -gentoo-dev -native-extensions* -rsync-verify*" PYTHON_TARGETS="python2_7 python3_5 (-pypy) -python3_4 -python3_6" 0 KiB

Total: 4 packages (3 new, 1 reinstall), Size of downloads: 8,605 KiB

 * IMPORTANT: 13 news items need reading for repository 'gentoo'.
 * Use eselect news read to view new items.

-------------------------------------------------------------------------------
  [[ (3/3) Emerging packages ]]
!!! CONFIG_PROTECT is empty

These are the packages that would be merged, in order:

Calculating dependencies... done!
[ebuild     U  ] sys-apps/baselayout-2.6::gentoo [2.4.1-r2::gentoo] USE="split-usr%* -build" 32 KiB
[ebuild     U  ] sys-libs/zlib-1.2.11-r2:0/1::gentoo [1.2.11-r1:0/1::gentoo] USE="-minizip -static-libs" ABI_X86="(64) -32 (-x32)" 594 KiB
[ebuild   R    ] virtual/libc-1::gentoo  0 KiB
[ebuild   R    ] sys-devel/gettext-0.19.8.1::gentoo  USE="cxx nls -acl* -cvs -doc -emacs -git -java -ncurses* -openmp* -static-libs" ABI_X86="(64) -32 (-x32)" 19,243 KiB
[ebuild     U  ] sys-devel/binutils-2.30-r3:2.30::gentoo [2.30-r2:2.30::gentoo] USE="cxx nls -doc -multitarget -static-libs {-test}" 20,348 KiB
[ebuild   R    ] sys-devel/gcc-7.3.0-r3:7.3.0::gentoo  USE="cxx hardened* (multilib) nls nptl (pie) (ssp) (-altivec) -cilk -debug -doc (-fixed-point) -fortran* -go -graphite (-jit) (-libssp) -mpx -objc -objc++ -objc-gc -openmp* (-pch*) -pgo -regression-test (-sanitize*) -vanilla -vtv*" 61,007 KiB
[ebuild     U  ] sys-kernel/linux-headers-4.17::gentoo [4.13::gentoo] USE="-headers-only" 7,728 KiB
[ebuild     U  ] sys-apps/texinfo-6.5::gentoo [6.3::gentoo] USE="nls -static" 4,398 KiB

Total: 8 packages (5 upgrades, 3 reinstalls), Size of downloads: 113,345 KiB

 * IMPORTANT: 13 news items need reading for repository 'gentoo'.
 * Use eselect news read to view new items.

-------------------------------------------------------------------------------
livecd /usr/portage/scripts #
```

With `--pretend` we only visualize the upgoing work.

 From the Sakaki Guide:

> In Gentoo parlance, people speak of three ['stages'](http://en.wikipedia.org/wiki/Gentoo_Linux#Stages) of bootstrapping (and their corresponding file system tarballs):
>
> 1. **Stage 1**: When starting from a stage 1 tarball, the base toolchain (GCC, standard C libary etc.) must be built using the existing (binary) host system toolchain, under direction of the /usr/portage/scripts/bootstrap.sh script. This yields a:
> 2. **Stage 2** system. Here, we still need to emerge (build) the core [@world](https://wiki.gentoo.org/wiki/World_set_(Portage)) package set, using our new toolchain. This yields a:
> 3. **Stage 3** system, in which the toolchain has been bootstrapped, and the important system binaries and libraries have been compiled using it. A tarball of such a stage 3 system's directories is now provided as a default part of the Gentoo distribution (stage 1 and stage 2 tarballs are not available to end-users anymore).
>
> Although we have [already](https://wiki.gentoo.org/wiki/Sakaki%27s_EFI_Install_Guide/Installing_the_Gentoo_Stage_3_Files#download_stage_3_tarball) downloaded a stage 3 tarball, we're going to pretend we haven't, and instead build up from stage 1.

[![asciicast](https://asciinema.org/a/190924.png)](https://asciinema.org/a/190924)

In this rapid *asciicast* we edit `bootstrap.sh` file changing a line of text, explanation by Sakaki:

> The Gentoo [FAQ](https://wiki.gentoo.org/wiki/FAQ#How_do_I_Install_Gentoo_Using_a_Stage1_or_Stage2_Tarball.3F) suggests you may wish to edit the /usr/portage/scripts/bootstrap.sh script after reviewing it - and indeed, we will do so, because there are two 'gotchas' lurking in the above proposed emerge list. The first problem is that the [C standard library](http://en.wikipedia.org/wiki/C_standard_library) that the bootstrap intends to rebuild is a [*virtual*](https://devmanual.gentoo.org/general-concepts/virtuals/) ([virtual/libc](https://packages.gentoo.org/packages/virtual/libc)); however, in Portage, emerging a virtual package does *not*, by default, cause any already-installed package that satisfies that virtual (in our case, [sys-libs/glibc](https://packages.gentoo.org/packages/sys-libs/glibc)) to be rebuilt - which we want.

```sh
livecd /usr/portage/scripts # ./bootstrap.sh 

Gentoo Linux; http://www.gentoo.org/
Copyright 1999-$ Gentoo Foundation; Distributed under the GPLv2
Starting Bootstrap of base system ...
-------------------------------------------------------------------------------
  [[ (0/3) Locating packages ]]
!!! SELinux module not found. Please verify that it was installed.
!!! SELinux module not found. Please verify that it was installed.
!!! SELinux module not found. Please verify that it was installed.
!!! SELinux module not found. Please verify that it was installed.
!!! SELinux module not found. Please verify that it was installed.
!!! SELinux module not found. Please verify that it was installed.
 * Using baselayout : >=sys-apps/baselayout-2
 * Using portage    : portage
 * Using os-headers : >=sys-kernel/linux-headers-4.17
 * Using binutils   : sys-devel/binutils
 * Using gcc        : sys-devel/gcc
 * Using gettext    : gettext
 * Using libc       : sys-libs/glibc:2.2
 * Using texinfo    : sys-apps/texinfo
 * Using zlib       : zlib
 * Using ncurses    : ncurses
-------------------------------------------------------------------------------
  [[ (1/3) Configuring environment ]]
-------------------------------------------------------------------------------
!!! SELinux module not found. Please verify that it was installed.
  [[ (2/3) Updating portage ]]
!!! CONFIG_PROTECT is empty

 * IMPORTANT: 13 news items need reading for repository 'gentoo'.
 * Use eselect news read to view new items.


These are the packages that would be merged, in order:

Calculating dependencies... done!
[ebuild  N     ] sys-libs/libsepol-2.8::gentoo  ABI_X86="(64) -32 (-x32)" 463 KiB
[ebuild  N     ] dev-lang/swig-3.0.12::gentoo  USE="-ccache -doc -pcre" 7,959 KiB
[ebuild  N     ] sys-libs/libselinux-2.8::gentoo  USE="(python) (static-libs) -pcre2 -ruby" ABI_X86="(64) -32 (-x32)" PYTHON_TARGETS="python2_7 python3_5 -python3_4 -python3_6" RUBY_TARGETS="-ruby23" 184 KiB
[ebuild   R    ] sys-apps/portage-2.3.41::gentoo  USE="build* (ipc) (selinux*) (xattr) -doc -epydoc -gentoo-dev -native-extensions* -rsync-verify*" PYTHON_TARGETS="python2_7 python3_5 (-pypy) -python3_4 -python3_6" 0 KiB

Total: 4 packages (3 new, 1 reinstall), Size of downloads: 8,605 KiB

Would you like to merge these packages? [Yes/No] Yes
>>> Verifying ebuild manifests
>>> Emerging (1 of 4) sys-libs/libsepol-2.8::gentoo
>>> Emerging (2 of 4) dev-lang/swig-3.0.12::gentoo
>>> Jobs: 0 of 4 complete, 2 running                Load avg: 0.08, 0.04, 0.00!!! SELinux module not found. Please verify that it was installed.
>>> Jobs: 0 of 4 complete, 2 running                Load avg: 0.07, 0.04, 0.00!!! SELinux module not found. Please verify that it was installed.
>>> Jobs: 0 of 4 complete, 2 running                Load avg: 1.92, 0.46, 0.14!!! SELinux module not found. Please verify that it was installed.
>>> Installing (2 of 4) dev-lang/swig-3.0.12::gentoo
>>> Installing (1 of 4) sys-libs/libsepol-2.8::gentoo
>>> Emerging (3 of 4) sys-libs/libselinux-2.8::gentoo
>>> Installing (3 of 4) sys-libs/libselinux-2.8::gentoo
>>> Emerging (4 of 4) sys-apps/portage-2.3.41::gentoo
>>> Installing (4 of 4) sys-apps/portage-2.3.41::gentoo
>>> Jobs: 4 of 4 complete                           Load avg: 2.20, 0.99, 0.37

 * Messages for package dev-lang/swig-3.0.12:

 * Package:    dev-lang/swig-3.0.12
 * Repository: gentoo
 * Maintainer: radhermit@gentoo.org scheme@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux userland_GNU
 * FEATURES:   preserve-libs sandbox selinux sesandbox userpriv usersandbox
 * Skipping make test/check due to ebuild restriction.
 * Final size of build directory: 52588 KiB (51.3 MiB)
 * Final size of installed tree:   8212 KiB ( 8.0 MiB)

 * Messages for package sys-libs/libsepol-2.8:

 * Package:    sys-libs/libsepol-2.8
 * Repository: gentoo
 * Maintainer: selinux@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux userland_GNU
 * FEATURES:   preserve-libs sandbox selinux sesandbox userpriv usersandbox
 * Will copy sources from /var/tmp/portage/sys-libs/libsepol-2.8/work/libsepol-2.8
 * abi_x86_64.amd64: copying to /var/tmp/portage/sys-libs/libsepol-2.8/work/libsepol-2.8-abi_x86_64.amd64
 * abi_x86_64.amd64: running multilib-minimal_abi_src_configure
 * abi_x86_64.amd64: running multilib-minimal_abi_src_compile
 * Skipping make test/check due to ebuild restriction.
 * abi_x86_64.amd64: running multilib-minimal_abi_src_install
 * Final size of build directory: 14300 KiB (13.9 MiB)
 * Final size of installed tree:   2720 KiB ( 2.6 MiB)

 * Messages for package sys-libs/libselinux-2.8:

 * Package:    sys-libs/libselinux-2.8
 * Repository: gentoo
 * Maintainer: selinux@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux python python_targets_python2_7 python_targets_python3_5 static-libs userland_GNU
 * FEATURES:   preserve-libs sandbox selinux sesandbox userpriv usersandbox
 * Will copy sources from /var/tmp/portage/sys-libs/libselinux-2.8/work/libselinux-2.8
 * abi_x86_64.amd64: copying to /var/tmp/portage/sys-libs/libselinux-2.8/work/libselinux-2.8-abi_x86_64.amd64
 * abi_x86_64.amd64: running multilib-minimal_abi_src_configure
 * abi_x86_64.amd64: running multilib-minimal_abi_src_compile
 * python2_7: running building
 * python3_5: running building
 * abi_x86_64.amd64: running multilib-minimal_abi_src_install
 * python2_7: running installation
 * python3_5: running installation
 * Final size of build directory: 8208 KiB (8.0 MiB)
 * Final size of installed tree:  3740 KiB (3.6 MiB)

 * Messages for package sys-apps/portage-2.3.41:

 * Package:    sys-apps/portage-2.3.41
 * Repository: gentoo
 * Maintainer: dev-portage@gentoo.org
 * Upstream:   dev-portage@gentoo.org
 * USE:        abi_x86_64 amd64 build elibc_glibc ipc kernel_linux python_targets_python2_7 python_targets_python3_5 selinux userland_GNU xattr
 * FEATURES:   preserve-libs sandbox selinux sesandbox userpriv usersandbox
 * Adding FEATURES=xattr to make.globals ...
 * python2_7: running distutils-r1_run_phase distutils-r1_python_compile
 * python3_5: running distutils-r1_run_phase distutils-r1_python_compile
 * python3_5: running distutils-r1_run_phase python_compile_all
 * python2_7: running distutils-r1_run_phase python_install
 * python3_5: running distutils-r1_run_phase python_install
 * python3_5: running distutils-r1_run_phase python_install_all
 * Moving admin scripts to the correct directory
 * Moving /usr/bin/archive-conf to /usr/sbin/archive-conf
 * Moving /usr/bin/dispatch-conf to /usr/sbin/dispatch-conf
 * Moving /usr/bin/emaint to /usr/sbin/emaint
 * Moving /usr/bin/env-update to /usr/sbin/env-update
 * Moving /usr/bin/etc-update to /usr/sbin/etc-update
 * Moving /usr/bin/fixpackages to /usr/sbin/fixpackages
 * Moving /usr/bin/regenworld to /usr/sbin/regenworld
 * Final size of build directory: 19728 KiB (19.2 MiB)
 * Final size of installed tree:  35852 KiB (35.0 MiB)
 * 
 * This release of portage NO LONGER contains the repoman code base.
 * Repoman has its own ebuild and release package.
 * For repoman functionality please emerge app-portage/repoman
 * Please report any bugs you may encounter.
 * 
>>> Auto-cleaning packages...

>>> No outdated packages were found on your system.

 * GNU info directory index is up-to-date.

 * IMPORTANT: 13 news items need reading for repository 'gentoo'.
 * Use eselect news read to view new items.

-------------------------------------------------------------------------------
  [[ (3/3) Emerging packages ]]
!!! CONFIG_PROTECT is empty

 * IMPORTANT: 13 news items need reading for repository 'gentoo'.
 * Use eselect news read to view new items.


These are the packages that would be merged, in order:

Calculating dependencies... done!
[ebuild     U  ] sys-kernel/linux-headers-4.17::gentoo [4.13::gentoo] USE="-headers-only" 7,728 KiB
[ebuild     U  ] sys-libs/glibc-2.27-r5:2.2::gentoo [2.26-r7:2.2::gentoo] USE="hardened* (multilib) (selinux*) -audit -caps (-compile-locales) -doc -gd -headers-only -multiarch% -nscd (-profile) -suid -systemtap (-vanilla) (-debug%)" 17,499 KiB
[ebuild     U  ] sys-apps/baselayout-2.6::gentoo [2.4.1-r2::gentoo] USE="split-usr%* -build" 32 KiB
[ebuild     U  ] sys-libs/zlib-1.2.11-r2:0/1::gentoo [1.2.11-r1:0/1::gentoo] USE="-minizip -static-libs" ABI_X86="(64) -32 (-x32)" 594 KiB
[ebuild   R    ] sys-devel/gettext-0.19.8.1::gentoo  USE="cxx nls -acl* -cvs -doc -emacs -git -java -ncurses* -openmp* -static-libs" ABI_X86="(64) -32 (-x32)" 19,243 KiB
[ebuild     U  ] sys-devel/binutils-2.30-r3:2.30::gentoo [2.30-r2:2.30::gentoo] USE="cxx nls -doc -multitarget -static-libs {-test}" 20,348 KiB
[ebuild   R    ] sys-devel/gcc-7.3.0-r3:7.3.0::gentoo  USE="cxx hardened* (multilib) nls nptl (pie) (ssp) (-altivec) -cilk -debug -doc (-fixed-point) -fortran* -go -graphite (-jit) (-libssp) -mpx -objc -objc++ -objc-gc -openmp* (-pch*) -pgo -regression-test (-sanitize*) -vanilla -vtv*" 61,007 KiB
[ebuild     U  ] sys-apps/texinfo-6.5::gentoo [6.3::gentoo] USE="nls -static" 4,398 KiB

Total: 8 packages (6 upgrades, 2 reinstalls), Size of downloads: 130,844 KiB

Would you like to merge these packages? [Yes/No] Yes
>>> Verifying ebuild manifests
>>> Running pre-merge checks for sys-libs/glibc-2.27-r5
 * Checking general environment sanity.
make -j5 -l4 -s glibc-test 
 * Checking that IA32 emulation is enabled in the running kernel ...                             [ ok ]
 * Checking gcc for __thread support ...                                                         [ ok ]
 * Checking running kernel version (4.9.76-gentoo-r1 >= 3.2.0) ...                               [ ok ]
 * Checking linux-headers version (4.13.0 >= 3.2.0) ...                                          [ ok ]
>>> Running pre-merge checks for sys-devel/gcc-7.3.0-r3
>>> Emerging (1 of 8) sys-kernel/linux-headers-4.17::gentoo
>>> Installing (1 of 8) sys-kernel/linux-headers-4.17::gentoo
>>> Emerging (2 of 8) sys-libs/glibc-2.27-r5::gentoo
>>> Installing (2 of 8) sys-libs/glibc-2.27-r5::gentoo
>>> Emerging (3 of 8) sys-apps/baselayout-2.6::gentoo
>>> Installing (3 of 8) sys-apps/baselayout-2.6::gentoo
>>> Emerging (4 of 8) sys-libs/zlib-1.2.11-r2::gentoo
>>> Installing (4 of 8) sys-libs/zlib-1.2.11-r2::gentoo
>>> Emerging (5 of 8) sys-devel/gettext-0.19.8.1::gentoo
>>> Installing (5 of 8) sys-devel/gettext-0.19.8.1::gentoo
>>> Emerging (6 of 8) sys-devel/binutils-2.30-r3::gentoo
>>> Installing (6 of 8) sys-devel/binutils-2.30-r3::gentoo
>>> Emerging (7 of 8) sys-devel/gcc-7.3.0-r3::gentoo
>>> Jobs: 6 of 8 complete, 1 running                Load avg: 2.41, 3.27, 3.58
>>> Installing (7 of 8) sys-devel/gcc-7.3.0-r3::gentoo
>>> Emerging (8 of 8) sys-apps/texinfo-6.5::gentoo
>>> Installing (8 of 8) sys-apps/texinfo-6.5::gentoo
>>> Jobs: 8 of 8 complete                           Load avg: 1.60, 2.71, 3.27

 * Messages for package sys-libs/glibc-2.27-r5:

 * Package:    sys-libs/glibc-2.27-r5
 * Repository: gentoo
 * Maintainer: toolchain@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc hardened kernel_linux multilib selinux userland_GNU
 * FEATURES:   preserve-libs sandbox selinux sesandbox userpriv usersandbox
 * Checking general environment sanity.
 * Checking that IA32 emulation is enabled in the running kernel ...
 * Checking gcc for __thread support ...
 * Checking running kernel version (4.9.76-gentoo-r1 >= 3.2.0) ...
 * Checking linux-headers version (4.13.0 >= 3.2.0) ...

 * Messages for package sys-devel/gcc-7.3.0-r3:

 * Package:    sys-devel/gcc-7.3.0-r3
 * Repository: gentoo
 * Maintainer: toolchain@gentoo.org
 * USE:        abi_x86_64 amd64 cxx elibc_glibc hardened kernel_linux multilib nls nptl pie ssp userland_GNU
 * FEATURES:   preserve-libs sandbox selinux sesandbox userpriv usersandbox

 * Messages for package sys-kernel/linux-headers-4.17:

 * Package:    sys-kernel/linux-headers-4.17
 * Repository: gentoo
 * Maintainer: toolchain@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux userland_GNU
 * FEATURES:   preserve-libs sandbox selinux sesandbox userpriv usersandbox
 * Applying 00_all_0001-linux-stat.h-remove-__GLIBC__-checks.patch ...
 * Applying 00_all_0002-netfilter-pull-in-limits.h.patch ...
 * Applying 00_all_0003-convert-PAGE_SIZE-usage.patch ...
 * Applying 00_all_0004-asm-generic-fcntl.h-namespace-kernel-file-structs.patch ...
 * Applying 00_all_0005-unifdef-drop-unused-errno.h-include.patch ...
 * Applying 00_all_0006-x86-do-not-build-relocs-tool-when-installing-headers.patch ...
 * Applying 00_all_0007-netlink-drop-int-cast-on-length-arg-in-NLMSG_OK.patch ...
 * Applying 00_all_0008-uapi-fix-System-V-buf-header-includes.patch ...
 * Final size of build directory: 70664 KiB (69.0 MiB)
 * Final size of installed tree:   6764 KiB ( 6.6 MiB)

 * Messages for package sys-libs/glibc-2.27-r5:

 * Package:    sys-libs/glibc-2.27-r5
 * Repository: gentoo
 * Maintainer: toolchain@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc hardened kernel_linux multilib selinux userland_GNU
 * FEATURES:   preserve-libs sandbox selinux sesandbox userpriv usersandbox
 * Checking that IA32 emulation is enabled in the running kernel ...
 * Checking gcc for __thread support ...
 * Checking running kernel version (4.9.76-gentoo-r1 >= 3.2.0) ...
 * Checking linux-headers version (4.17.0 >= 3.2.0) ...
 *       Manual CC:   x86_64-pc-linux-gnu-gcc -m64
 * Applying Gentoo Glibc Patchset 2.27-2
 * Applying patches from /var/tmp/portage/sys-libs/glibc-2.27-r5/work/patches ...
 *   0001-Gentoo-disable-ldconfig-during-install.patch ...
 *   0002-Gentoo-support-running-tests-under-sandbox.patch ...
 *   0004-Revert-sysdeps-posix-getaddrinfo.c-gaih_inet-Only-us.patch ...
 *   0005-Gentoo-disable-tests-that-fail-only-in-sandbox.patch ...
 *   0006-libidn-libidn-punycode.c-decode_digit-Fix-integer-ov.patch ...
 *   0007-libidn-Fix-out-of-bounds-stack-read.-Report-and-patc.patch ...
 *   0009-Gentoo-disable-tests-that-fail-only-in-sandbox.patch ...
 *   0010-Gentoo-Disable-test-that-fails-because-of-the-gethos.patch ...
 *   0011-sparc-Check-PIC-instead-of-SHARED-in-start.S.patch ...
 *   0012-sys-types.h-drop-sys-sysmacros.h-include.patch ...
 *   0014-Record-CVE-2018-6551-in-NEWS-and-ChangeLog-BZ-22774.patch ...
 *   0015-sparc-Check-PIC-instead-of-SHARED-in-start.S-BZ-2263.patch ...
 *   0016-NEWS-add-an-entry-for-bug-22638.patch ...
 *   0017-Add-a-missing-ChangeLog-item-in-commit-371b220f620.patch ...
 *   0018-Linux-use-reserved-name-__key-in-pkey_get-BZ-22797.patch ...
 *   0019-RISC-V-Fix-parsing-flags-in-ELF64-files.patch ...
 *   0020-Update-SH-libm-tests-ulps.patch ...
 *   0021-et_EE-Add-missing-reorder-end-keyword-bug-22861.patch ...
 *   0022-NEWS-add-an-entry-for-bug-22827.patch ...
 *   0023-linux-aarch64-sync-sys-ptrace.h-with-Linux-4.15-BZ-2.patch ...
 *   0024-time-Reference-CLOCKS_PER_SEC-in-clock-comment-BZ-22.patch ...
 *   0025-Fix-posix-tst-glob_lstat_compat-on-alpha-BZ-22818.patch ...
 *   0026-manual-Fix-Texinfo-warnings-about-improper-node-name.patch ...
 *   0027-manual-Fix-a-syntax-error.patch ...
 *   0028-manual-Improve-documentation-of-get_current_dir_name.patch ...
 *   0029-powerpc-Fix-TLE-build-for-SPE-BZ-22926.patch ...
 *   0030-sparc32-Add-nop-before-__startcontext-to-stop-unwind.patch ...
 *   0031-NEWS-add-entries-for-bugs-22919-and-22926.patch ...
 *   0032-manual-Document-missing-feature-test-macros.patch ...
 *   0033-manual-Update-the-_ISOC99_SOURCE-description.patch ...
 *   0034-Fix-a-typo-in-a-comment.patch ...
 *   0035-Add-missing-reorder-end-in-LC_COLLATE-of-et_EE-BZ-22.patch ...
 *   0036-powerpc-Undefine-Linux-ptrace-macros-that-conflict-w.patch ...
 *   0037-linux-powerpc-sync-sys-ptrace.h-with-Linux-4.15-BZ-2.patch ...
 *   0038-BZ-22342-Fix-netgroup-cache-keys.patch ...
 *   0039-Fix-multiple-definitions-of-__nss_-_database-bug-229.patch ...
 *   0040-i386-Fix-i386-sigaction-sa_restorer-initialization-B.patch ...
 *   0041-Update-translations-from-the-Translation-Project.patch ...
 *   0042-ca_ES-locale-Update-LC_TIME-bug-22848.patch ...
 *   0043-lt_LT-locale-Update-abbreviated-month-names-bug-2293.patch ...
 *   0044-Greek-el_CY-el_GR-locales-Introduce-ab_alt_mon-bug-2.patch ...
 *   0045-cs_CZ-locale-Add-alternative-month-names-bug-22963.patch ...
 *   0046-NEWS-Add-entries-for-bugs-22848-22932-22937-22963.patch ...
 *   0047-RISC-V-Do-not-initialize-gp-in-TLS-macros.patch ...
 *   0048-RISC-V-fmax-fmin-Handle-signalling-NaNs-correctly.patch ...
 *   0049-Update-ChangeLog-for-BZ-22884-riscv-fmax-fmin.patch ...
 *   0050-Fix-i386-memmove-issue-bug-22644.patch ...
 *   0051-Linux-i386-tst-bz21269-triggers-SIGBUS-on-some-kerne.patch ...
 *   0052-RISC-V-fix-struct-kernel_sigaction-to-match-the-kern.patch ...
 *   0053-Add-tst-sigaction.c-to-test-BZ-23069.patch ...
 *   0054-Fix-signed-integer-overflow-in-random_r-bug-17343.patch ...
 *   0055-Fix-crash-in-resolver-on-memory-allocation-failure-b.patch ...
 *   0056-getlogin_r-return-early-when-linux-sentinel-value-is.patch ...
 *   0057-Update-RWF_SUPPORTED-for-Linux-kernel-4.16-BZ-22947.patch ...
 *   0058-manual-Move-mbstouwcs-to-an-example-C-file.patch ...
 *   0059-manual-Various-fixes-to-the-mbstouwcs-example-and-mb.patch ...
 *   0060-resolv-Fully-initialize-struct-mmsghdr-in-send_dg-BZ.patch ...
 *   0061-Add-PTRACE_SECCOMP_GET_METADATA-from-Linux-4.16-to-s.patch ...
 *   0062-Fix-blocking-pthread_join.-BZ-23137.patch ...
 *   0063-Fix-stack-overflow-with-huge-PT_NOTE-segment-BZ-2041.patch ...
 *   0064-Fix-path-length-overflow-in-realpath-BZ-22786.patch ...
 *   0065-NEWS-add-entries-for-bugs-17343-20419-22644-22786-22.patch ...
 *   0066-gd_GB-Fix-typo-in-abbreviated-May-bug-23152.patch ...
 *   0067-sunrpc-Remove-stray-exports-without-enable-obsolete-.patch ...
 * Done.
 * Using GNU config files from /usr/share/gnuconfig
 *   Updating scripts/config.sub
 *   Updating scripts/config.guess
 * Adjusting to prefix /
 *   locale-gen ...
 *       Manual CC:   x86_64-pc-linux-gnu-gcc -m64
 *       Manual CC:   x86_64-pc-linux-gnu-gcc -m32
 * Running do_src_configure for ABI x86
 * Configuring glibc for nptl
 *             ABI:   x86
 *          CBUILD:   x86_64-pc-linux-gnu
 *           CHOST:   x86_64-pc-linux-gnu
 *         CTARGET:   x86_64-pc-linux-gnu
 *      CBUILD_OPT:   i686-pc-linux-gnu
 *     CTARGET_OPT:   i686-pc-linux-gnu
 *              CC:   x86_64-pc-linux-gnu-gcc -m32
 *             CXX:   
 *              LD:   
 *         ASFLAGS:   
 *          CFLAGS:   -march=sandybridge -pipe -O2 -fno-strict-aliasing
 *        CPPFLAGS:   
 *        CXXFLAGS:   -O2 -fno-strict-aliasing
 *         LDFLAGS:   -Wl,-O1 -Wl,--as-needed
 *        MAKEINFO:   /dev/null
 *       Manual CC:   x86_64-pc-linux-gnu-gcc -m32 -march=sandybridge -pipe -O2 -fno-strict-aliasing -Wl,-O1 -Wl,--as-needed
 *      Manual CXX:   x86_64-pc-linux-gnu-g++ -m32 -march=sandybridge -pipe -O2 -fno-strict-aliasing
 *       Manual CC:   x86_64-pc-linux-gnu-gcc -m64
 * Running do_src_configure for ABI amd64
 * Configuring glibc for nptl
 *             ABI:   amd64
 *          CBUILD:   x86_64-pc-linux-gnu
 *           CHOST:   x86_64-pc-linux-gnu
 *         CTARGET:   x86_64-pc-linux-gnu
 *      CBUILD_OPT:   x86_64-pc-linux-gnu
 *     CTARGET_OPT:   x86_64-pc-linux-gnu
 *              CC:   x86_64-pc-linux-gnu-gcc -m64
 *             CXX:   
 *              LD:   
 *         ASFLAGS:   
 *          CFLAGS:   -march=sandybridge -pipe -O2 -fno-strict-aliasing
 *        CPPFLAGS:   
 *        CXXFLAGS:   -O2 -fno-strict-aliasing
 *         LDFLAGS:   -Wl,-O1 -Wl,--as-needed
 *        MAKEINFO:   /dev/null
 *       Manual CC:   x86_64-pc-linux-gnu-gcc -m64 -march=sandybridge -pipe -O2 -fno-strict-aliasing -Wl,-O1 -Wl,--as-needed
 *      Manual CXX:   x86_64-pc-linux-gnu-g++ -m64 -march=sandybridge -pipe -O2 -fno-strict-aliasing
 *       Manual CC:   x86_64-pc-linux-gnu-gcc -m64
 *       Manual CC:   x86_64-pc-linux-gnu-gcc -m32
 * Running do_src_compile for ABI x86
 *       Manual CC:   x86_64-pc-linux-gnu-gcc -m64
 * Running do_src_compile for ABI amd64
 *       Manual CC:   x86_64-pc-linux-gnu-gcc -m64
 *       Manual CC:   x86_64-pc-linux-gnu-gcc -m32
 * Running glibc_do_src_install for ABI x86
 *       Manual CC:   x86_64-pc-linux-gnu-gcc -m64
 * Running glibc_do_src_install for ABI amd64
 * Final size of build directory: 552612 KiB (539.6 MiB)
 * Final size of installed tree:   69248 KiB ( 67.6 MiB)
 * Defaulting /etc/host.conf:multi to on
 * Generating all locales; edit /etc/locale.gen to save time/space

 * Messages for package sys-apps/baselayout-2.6:

 * Package:    sys-apps/baselayout-2.6
 * Repository: gentoo
 * Maintainer: williamh@gentoo.org base-system@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux split-usr userland_GNU
 * FEATURES:   preserve-libs sandbox selinux sesandbox userpriv usersandbox
 * Final size of build directory: 220 KiB
 * Final size of installed tree:  168 KiB
 * You should reboot now to get /run mounted with tmpfs!
 * Please run env-update then log out and back in to
 * update your path.

 * Messages for package sys-libs/zlib-1.2.11-r2:

 * Package:    sys-libs/zlib-1.2.11-r2
 * Repository: gentoo
 * Maintainer: base-system@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux userland_GNU
 * FEATURES:   preserve-libs sandbox selinux sesandbox userpriv usersandbox
 * Applying zlib-1.2.11-fix-deflateParams-usage.patch ...
 * Applying zlib-1.2.11-minizip-drop-crypt-header.patch ...
 * abi_x86_64.amd64: running multilib-minimal_abi_src_configure
 * abi_x86_64.amd64: running multilib-minimal_abi_src_compile
 * abi_x86_64.amd64: running multilib-minimal_abi_src_install
 * Final size of build directory: 4676 KiB (4.5 MiB)
 * Final size of installed tree:   492 KiB

 * Messages for package sys-devel/gettext-0.19.8.1:

 * Package:    sys-devel/gettext-0.19.8.1
 * Repository: gentoo
 * Maintainer: base-system@gentoo.org
 * USE:        abi_x86_64 amd64 cxx elibc_glibc kernel_linux nls userland_GNU
 * FEATURES:   preserve-libs sandbox selinux sesandbox userpriv usersandbox
 * Applying gettext-0.19.7-disable-libintl.patch ...
 * Applying gettext-0.19.8.1-format-security.patch ...
 * Removing useless C++ checks ...
 * abi_x86_64.amd64: running multilib-minimal_abi_src_configure
 * abi_x86_64.amd64: running multilib-minimal_abi_src_compile
 * abi_x86_64.amd64: running multilib-minimal_abi_src_install
 * Removing unnecessary /usr/lib64/libgettextpo.la (requested)
 * Removing unnecessary /usr/lib64/libasprintf.la (requested)
 * Removing unnecessary /usr/lib64/libgettextsrc.la (requested)
 * Removing unnecessary /usr/lib64/libgettextlib.la (requested)
 * Final size of build directory: 128212 KiB (125.2 MiB)
 * Final size of installed tree:   10364 KiB ( 10.1 MiB)
 * QA Notice: Missing soname symlink(s):
 * 
 * 	usr/lib64/libgnuintl.so.8 -> preloadable_libintl.so
 * 

 * Messages for package sys-devel/binutils-2.30-r3:

 * Package:    sys-devel/binutils-2.30-r3
 * Repository: gentoo
 * Maintainer: toolchain@gentoo.org
 * USE:        abi_x86_64 amd64 cxx elibc_glibc kernel_linux nls userland_GNU
 * FEATURES:   preserve-libs sandbox selinux sesandbox userpriv usersandbox
 * Applying binutils-2.30 patchset 3
 * Applying 0001-Gentoo-ld-always-warn-about-textrels-in-files.patch ...
 * Applying 0002-Gentoo-gold-ld-add-support-for-poisoned-system-direc.patch ...
 * Applying 0003-Gentoo-ld-enable-new-dtags-by-default-for-linux-gnu-.patch ...
 * Applying 0004-Gentoo-libiberty-install-PIC-version-of-libiberty.a.patch ...
 * Applying 0005-Gentoo-opcodes-link-against-libbfd.la-for-rpath-deps.patch ...
 * Applying 0007-Gentoo-Adapt-the-testsuite-to-our-enhanced-textrel-w.patch ...
 * Applying 0008-Gentoo-Adapt-the-test-suite-to-our-changed-hash-styl.patch ...
 * Applying 0009-Gentoo-We-can-t-test-for-textrel-warnings-if-we-regs.patch ...
 * Applying 0010-Gentoo-Disable-failing-test-ld-x86-64-x86-64.exp-pie.patch ...
 * Applying 0011-Revert-to-development-on-the-2.30-branch.-Set-the-ve.patch ...
 * Applying 0013-Gentoo-Disable-another-test-that-checks-for-textrel-.patch ...
 * Applying 0014-Gentoo-Disable-gold-test-suite-since-it-still-always.patch ...
 * Applying 0015-Automatic-date-update-in-version.in.patch ...
 * Applying 0016-Update-Russian-translation-for-the-gas-sub-directory.patch ...
 * Applying 0017-Automatic-date-update-in-version.in.patch ...
 * Applying 0018-Add-support-for-DWARF-4-line-number-tables.patch ...
 * Applying 0019-Automatic-date-update-in-version.in.patch ...
 * Applying 0020-Import-patch-from-mainline-to-remove-PROVODE-qualifi.patch ...
 * Applying 0021-Updated-Brazillian-portuguese-and-Russian-translatio.patch ...
 * Applying 0022-PR22764-LD-AARCH64-Allow-R_AARCH64_ABS16-and-R_AARCH.patch ...
 * Applying 0023-Automatic-date-update-in-version.in.patch ...
 * Applying 0024-Revert-PowerPC-PLT-speculative-execution-barriers.patch ...
 * Applying 0025-Automatic-date-update-in-version.in.patch ...
 * Applying 0026-Import-patch-from-mainline-to-fix-possible-seg-fault.patch ...
 * Applying 0027-Fix-GOT-relocation-overflow-on-SPARC.patch ...
 * Applying 0028-Fix-PR-gas-22738-.dc.a-directive-has-wrong-size-on-S.patch ...
 * Applying 0029-Updated-Russian-translation-for-the-gas-sub-director.patch ...
 * Applying 0030-gas-xtensa-fix-trampoline-placement.patch ...
 * Applying 0031-PR-ld-22832-on-SPARC.patch ...
 * Applying 0032-Import-patch-from-mainline-to-fix-a-bug-that-would-p.patch ...
 * Applying 0033-Fix-AArch32-build-attributes-for-Armv8.4-A.patch ...
 * Applying 0034-Import-patch-from-mainline-to-fix-memory-corruption-.patch ...
 * Applying 0035-Automatic-date-update-in-version.in.patch ...
 * Applying 0036-Gentoo-Restore-TEXTREL-warnings-for-non-shared-objec.patch ...
 * Applying 0037-Gentoo-Properly-ignore-new-textrel-warnings-in-tests.patch ...
 * Applying 0038-Gentoo-We-can-t-test-for-textrel-warnings-if-we-igno.patch ...
 * Applying 0039-Updated-Russian-translation-for-the-gas-sub-director.patch ...
 * Applying 0040-Enable-link-time-garbage-collection-for-the-IA64-tar.patch ...
 * Applying 0041-IA-64-Fix-linker-error-with-no-keep-memory.patch ...
 * Applying 0042-GC-Also-check-the-local-debug-definition-section.patch ...
 * Applying 0043-ARM-Fix-bxns-mask.patch ...
 * Applying 0044-PR22836-r-s-doesn-t-work-with-g3-using-GCC-7.patch ...
 * Applying 0045-PR22836-testcases.patch ...
 * Applying 0046-Set-non_ir_ref_dynamic-if-a-symbol-is-made-dynamic.patch ...
 * Applying 0047-ld-testsuite-XFAIL-pr20995-2-on-aarch64-elf.patch ...
 * Applying 0048-Remove-unnecessary-power9-group-terminating-nop.patch ...
 * Applying 0049-Really-remove-unnecessary-power9-group-terminating-n.patch ...
 * Applying 0050-PowerPC64-debian-bug-886264-out-of-line-save-restore.patch ...
 * Applying 0051-x86-64-Add-ENDBR64-to-the-TLSDESC-PLT-entry.patch ...
 * Applying 0052-gold-testsuite-Fix-bad-regexp-in-split_x86_64.sh.patch ...
 * Applying 0053-PR-ld-22972-on-SPARC.patch ...
 * Applying 0054-Fix-case-where-IR-file-provides-symbol-visibility-bu.patch ...
 * Applying 0055-Automatic-date-update-in-version.in.patch ...
 * Applying 0056-Import-patch-from-the-mainline-that-fixes-the-ARM-as.patch ...
 * Applying 0057-i386-Clear-vex-instead-of-vex.evex.patch ...
 * Applying 0058-Import-patch-from-mainline-sources-to-stop-the-linke.patch ...
 * Applying 0059-Updated-Spanish-and-Russian-translations-for-the-gas.patch ...
 * Applying 0060-Updated-Spanish-translations-for-the-gold-and-gprof-.patch ...
 * Applying 0061-Updated-Spanish-translation-for-gas-sub-directory.patch ...
 * Applying 0062-x86-Remove-the-unused-_GLOBAL_OFFSET_TABLE_.patch ...
 * Applying 0063-x86-Keep-the-unused-_GLOBAL_OFFSET_TABLE_-for-Solari.patch ...
 * Applying 0064-x86-Add-is_solaris-to-elf_x86_target_os.patch ...
 * Applying 0065-Fix-the-mask-for-the-sqrdml-a-s-h-instructions.patch ...
 * Applying 0066-PR23123-PowerPC32-ifunc-regression.patch ...
 * Applying 0067-Automatic-date-update-in-version.in.patch ...
 * Applying 0068-Prevent-attempts-to-call-strncpy-with-a-zero-length-.patch ...
 * Applying 0069-PR22769-crash-when-running-32-bit-objdump-on-corrupt.patch ...
 * Applying 0070-PR22887-null-pointer-dereference-in-aout_32_swap_std.patch ...
 * Applying 0071-Prevent-illegal-memory-accesses-triggerd-by-intger-o.patch ...
 * Applying 0072-Catch-integer-overflows-underflows-when-parsing-corr.patch ...
 * Applying 0073-Fix-potential-integer-overflow-when-reading-corrupt-.patch ...
 * Applying 0074-PR22741-objcopy-segfault-on-fuzzed-COFF-object.patch ...
 * Applying 0075-Add-new-Portuguese-translation-for-the-bfd-sub-direc.patch ...
 * Applying 0076-Fix-uninitialised-memory-acccess-in-COFF-bfd-backend.patch ...
 * Applying 0077-Fix-disassembly-mask-for-vector-sdot-on-AArch64.patch ...
 * Applying 0078-PR23199-Invalid-SHT_GROUP-entry-leads-to-group-confu.patch ...
 * Applying 0079-x86-Don-t-set-eh-local_ref-to-1-for-linker-defined-s.patch ...
 * Applying 0080-x86-Don-t-set-eh-local_ref-to-1-for-versioned-symbol.patch ...
 * Applying 0081-Mark-section-in-a-section-group-with-SHF_GROUP.patch ...
 * Applying 0082-Automatic-date-update-in-version.in.patch ...
 * Applying 0083-Add-an-option-no-warn-shared-textrel-self-explanator.patch ...
 * Applying 0084-Revert-Gentoo-Adapt-the-testsuite-to-our-enhanced-te.patch ...
 * Applying 0085-Revert-Gentoo-We-can-t-test-for-textrel-warnings-if-.patch ...
 * Applying 0086-Revert-Gentoo-Disable-failing-test-ld-x86-64-x86-64..patch ...
 * Applying 0087-Revert-Gentoo-Disable-another-test-that-checks-for-t.patch ...
 * Applying 0088-Revert-Gentoo-We-can-t-test-for-textrel-warnings-if-.patch ...
 * Applying 0089-Pass-no-warn-shared-textrel-to-ld-in-its-testsuite.patch ...
 * Applying 0090-Fix-test-for-precise-textrel-warning-message.patch ...
 * Applying 0091-Fix-the-PR22983-test-so-that-it-will-work-regardless.patch ...
 * Applying 0092-x86-64-Add-TLSDESC-fields-to-elf_x86_lazy_plt_layout.patch ...
 * Applying 0093-Automatic-date-update-in-version.in.patch ...
 * Applying 9999-Gentoo-We-make-a-release.patch ...
 * Fixing misc issues in configure files
 * Using GNU config files from /usr/share/gnuconfig
 *   Updating config.sub
 *   Updating config.guess
 *  CATEGORY: sys-devel
 *    CBUILD: x86_64-pc-linux-gnu
 *     CHOST: x86_64-pc-linux-gnu
 *   CTARGET: x86_64-pc-linux-gnu
 *    CFLAGS: -march=sandybridge -O2 -pipe
 *   LDFLAGS: -Wl,-O1 -Wl,--as-needed
 * Final size of build directory: 461180 KiB (450.3 MiB)
 * Final size of installed tree:   59528 KiB ( 58.1 MiB)

 * Messages for package sys-devel/gcc-7.3.0-r3:

 * Package:    sys-devel/gcc-7.3.0-r3
 * Repository: gentoo
 * Maintainer: toolchain@gentoo.org
 * USE:        abi_x86_64 amd64 cxx elibc_glibc hardened kernel_linux multilib nls nptl pie ssp userland_GNU
 * FEATURES:   preserve-libs sandbox selinux sesandbox userpriv usersandbox
 * Applying Gentoo patches ...
 *   10_all_default-fortify-source.patch ...
 *   11_all_default-warn-format-security.patch ...
 *   12_all_default-warn-trampolines.patch ...
 *   13_all_default-ssp-fix.patch ...
 *   25_all_alpha-mieee-default.patch ...
 *   34_all_ia64_note.GNU-stack.patch ...
 *   50_all_libiberty-asprintf.patch ...
 *   51_all_libiberty-pic.patch ...
 *   54_all_nopie-all-flags.patch ...
 *   55_all_extra-options.patch ...
 *   90_all_pr55930-dependency-tracking.patch ...
 *   91_all_bmi-i386-PR-target-81763.patch ...
 *   92_all_sh-drop-sysroot-suffix.patch ...
 *   93_all_copy-constructible-fix.patch ...
 * Done with patching
 * Updating gcc to use automatic PIE building ...
 * Updating gcc to use automatic SSP building ...
 * updating multilib directories to be: ../lib64 ../lib32
 * Using GNU config files from /usr/share/gnuconfig
 *   Updating config.sub
 *   Updating config.guess
 * Fixing misc issues in configure files
 * Applying gcc-configure-texinfo.patch ...
 * Touching generated files
 * CFLAGS="-march=sandybridge -O2 -pipe"
 * CXXFLAGS=""
 * LDFLAGS="-Wl,-O1 -Wl,--as-needed"
 * PREFIX:          /usr
 * BINPATH:         /usr/x86_64-pc-linux-gnu/gcc-bin/7.3.0
 * LIBPATH:         /usr/lib/gcc/x86_64-pc-linux-gnu/7.3.0
 * DATAPATH:        /usr/share/gcc-data/x86_64-pc-linux-gnu/7.3.0
 * STDCXX_INCDIR:   /usr/lib/gcc/x86_64-pc-linux-gnu/7.3.0/include/g++-v7
 * Languages:       c,c++
 * Configuring GCC with: 
 * 	--host=x86_64-pc-linux-gnu 
 * 	--build=x86_64-pc-linux-gnu 
 * 	--prefix=/usr 
 * 	--bindir=/usr/x86_64-pc-linux-gnu/gcc-bin/7.3.0 
 * 	--includedir=/usr/lib/gcc/x86_64-pc-linux-gnu/7.3.0/include 
 * 	--datadir=/usr/share/gcc-data/x86_64-pc-linux-gnu/7.3.0 
 * 	--mandir=/usr/share/gcc-data/x86_64-pc-linux-gnu/7.3.0/man 
 * 	--infodir=/usr/share/gcc-data/x86_64-pc-linux-gnu/7.3.0/info 
 * 	--with-gxx-include-dir=/usr/lib/gcc/x86_64-pc-linux-gnu/7.3.0/include/g++-v7 
 * 	--with-python-dir=/share/gcc-data/x86_64-pc-linux-gnu/7.3.0/python 
 * 	--enable-languages=c,c++ 
 * 	--enable-obsolete 
 * 	--enable-secureplt 
 * 	--disable-werror 
 * 	--with-system-zlib 
 * 	--enable-nls 
 * 	--without-included-gettext 
 * 	--enable-checking=release 
 * 	--with-bugurl=https://bugs.gentoo.org/ 
 * 	--with-pkgversion=Gentoo Hardened 7.3.0-r3 p1.4 
 * 	--enable-esp 
 * 	--enable-libstdcxx-time 
 * 	--disable-libstdcxx-pch 
 * 	--enable-shared 
 * 	--enable-threads=posix 
 * 	--enable-__cxa_atexit 
 * 	--enable-clocale=gnu 
 * 	--enable-multilib 
 * 	--with-multilib-list=m32,m64 
 * 	--disable-altivec 
 * 	--disable-fixed-point 
 * 	--enable-targets=all 
 * 	--disable-libgomp 
 * 	--disable-libmudflap 
 * 	--disable-libssp 
 * 	--disable-libcilkrts 
 * 	--disable-libmpx 
 * 	--disable-vtable-verify 
 * 	--disable-libvtv 
 * 	--disable-libquadmath 
 * 	--enable-lto 
 * 	--without-isl 
 * 	--disable-libsanitizer 
 * 	--enable-default-pie 
 * 	--enable-default-ssp
 * Compiling gcc (bootstrap-lean)...
 * XATTR_PAX marking -re /var/tmp/portage/sys-devel/gcc-7.3.0-r3/image//usr/libexec/gcc/x86_64-pc-linux-gnu/7.3.0/cc1 with setfattr
 * XATTR_PAX marking -re /var/tmp/portage/sys-devel/gcc-7.3.0-r3/image//usr/libexec/gcc/x86_64-pc-linux-gnu/7.3.0/cc1plus with setfattr
 * Final size of build directory: 1209936 KiB (  1.1 GiB)
 * Final size of installed tree:   137816 KiB (134.5 MiB)
 * If you have issues with packages unable to locate libstdc++.la,
 * then try running 'fix_libtool_files.sh' on the old gcc versions.
 * You might want to review the GCC upgrade guide when moving between
 * major versions (like 4.2 to 4.3):
 * https://wiki.gentoo.org/wiki/Upgrading_GCC

 * Messages for package sys-apps/texinfo-6.5:

 * Package:    sys-apps/texinfo-6.5
 * Repository: gentoo
 * Maintainer: base-system@gentoo.org
 * USE:        abi_x86_64 amd64 elibc_glibc kernel_linux nls userland_GNU
 * FEATURES:   preserve-libs sandbox selinux sesandbox userpriv usersandbox
 * Final size of build directory: 93668 KiB (91.4 MiB)
 * Final size of installed tree:   6980 KiB ( 6.8 MiB)
>>> Auto-cleaning packages...

>>> No outdated packages were found on your system.

 * Regenerating GNU info directory index...
 * Processed 89 info files.

 * IMPORTANT: 13 news items need reading for repository 'gentoo'.
 * Use eselect news read to view new items.

-------------------------------------------------------------------------------
!!! CONFIG_PROTECT is empty
!!! You have no world file.

Calculating dependencies... done!
  sys-devel/gcc-7.3.0-r3 pulled in by:
    @system requires sys-devel/gcc
    sys-libs/glibc-2.27-r5 requires >=sys-devel/gcc-4.9

>>> No packages selected for removal by prune
>>> To ignore dependencies, use --nodeps
-------------------------------------------------------------------------------
 * Please note that you should now add the '-e' option for emerge system:

 *   # emerge -e system

livecd /usr/portage/scripts #

```

So with the `bootstrap.sh` script we've recompiled [Gentoo stage 2 toolchain](https://en.wikipedia.org/wiki/Gentoo_Linux#Stages). 

Now with the *new toolchain* we're going recompile all the stage 3:

*full output [here](https://raw.githubusercontent.com/noplacenoaddress/gentoo-integrity/master/emerge-stage3.txt)*

```fsharp
livecd /usr/portage/scripts # emerge --emptytree --with-bdeps=y @world

 * IMPORTANT: 13 news items need reading for repository 'gentoo'.
 * Use eselect news read to view new items.


These are the packages that would be merged, in order:

Calculating dependencies... done!
[ebuild   R    ] virtual/libintl-0-r2::gentoo  ABI_X86="(64) -32 (-x32)" 0 KiB
[ebuild     U  ] dev-lang/python-exec-2.4.6:2::gentoo [2.4.5:2::gentoo] PYTHON_TARGETS="(jython2_7) (pypy) (pypy3) (python2_7) (python3_4) (python3_5) (python3_6) (python3_7%*)" 86 KiB
[ebuild     U  ] sys-libs/ncurses-6.1-r3:0/6::gentoo [6.1-r2:0/6::gentoo] USE="cxx unicode -ada -debug -doc -gpm -minimal (-profile) -static-libs {-test} -threads -tinfo -trace" ABI_X86="(64) -32 (-x32)" 3287 KiB
[ebuild   R    ] sys-libs/libsepol-2.8::gentoo  ABI_X86="(64) -32 (-x32)" 0 KiB
[ebuild   R    ] app-arch/bzip2-1.0.6-r9:0/1::gentoo  USE="-static -static-libs" ABI_X86="(64) -32 (-x32)" 764 KiB
[ebuild     U  ] sys-devel/gnuconfig-20180101::gentoo [20170101::gentoo] 51 KiB
[ebuild   R    ] sys-apps/gentoo-functions-0.12::gentoo  12 KiB
[ebuild   R    ] virtual/libiconv-0-r2::gentoo  ABI_X86="(64) -32 (-x32)" 0 KiB
[ebuild   R    ] app-misc/c_rehash-1.7-r1::gentoo  5 KiB
[ebuild   R    ] app-misc/mime-types-9::gentoo  16 KiB
[ebuild     U  ] app-arch/gzip-1.9::gentoo [1.8::gentoo] USE="-pic -static" 745 KiB
[ebuild     U  ] sys-apps/debianutils-4.8.6::gentoo [4.8.3::gentoo] USE="installkernel%* -static" 153 KiB
[ebuild   R    ] app-misc/editor-wrapper-4::gentoo  0 KiB
[ebuild  N     ] dev-libs/ustr-1.0.4-r8::gentoo  USE="-static-libs -ustr-import" ABI_X86="(64) -32 (-x32)" 229 KiB
[ebuild   R    ] net-libs/libmnl-1.0.4:0/0.2.0::gentoo  USE="-examples -static-libs" 295 KiB
[ebuild   R    ] app-text/manpager-1::gentoo  0 KiB
[ebuild   R    ] app-crypt/openpgp-keys-gentoo-release-20180706::gentoo  USE="{-test}" 0 KiB
[ebuild     U  ] sys-apps/install-xattr-0.5-r1::gentoo [0.5::gentoo] 16 KiB
[ebuild   R    ] sys-apps/baselayout-2.6::gentoo  USE="split-usr -build" 0 KiB
[ebuild   R    ] sys-apps/which-2.21::gentoo  146 KiB
[ebuild   R    ] app-text/sgml-common-0.6.3-r6::gentoo  126 KiB
[ebuild   R    ] sys-devel/autoconf-wrapper-13-r1::gentoo  0 KiB
[ebuild     U  ] sys-devel/automake-wrapper-11::gentoo [10::gentoo] 0 KiB
[ebuild     U  ] dev-util/gperf-3.1::gentoo [3.0.4::gentoo] 1188 KiB
[ebuild     U  ] sys-devel/gcc-config-1.9.1::gentoo [1.8-r1::gentoo] 18 KiB
[ebuild     U  ] sys-libs/timezone-data-2018e::gentoo [2018d::gentoo] USE="nls -leaps_timezone" 572 KiB
[ebuild     U  ] sys-devel/binutils-config-5.1-r1::gentoo [5-r4::gentoo] 0 KiB
[ebuild  N     ] sys-apps/semodule-utils-2.8::gentoo  13 KiB
[ebuild   R    ] app-arch/unzip-6.0_p21-r2::gentoo  USE="bzip2 unicode -natspec" 1362 KiB
[ebuild     U  ] virtual/os-headers-0-r1::gentoo [0::gentoo] 0 KiB
[ebuild   R    ] virtual/pam-0-r1::gentoo  ABI_X86="(64) -32 (-x32)" 0 KiB
[ebuild   R    ] virtual/udev-217::gentoo  USE="(-systemd)" 0 KiB
[ebuild   R    ] sys-fs/udev-init-scripts-32::gentoo  4 KiB
[ebuild   R    ] virtual/dev-manager-0-r1::gentoo  0 KiB
[ebuild   R    ] virtual/acl-0-r2::gentoo  USE="-static-libs" ABI_X86="(64) -32 (-x32)" 0 KiB
[ebuild   R    ] virtual/libffi-3.0.13-r1::gentoo  ABI_X86="(64) -32 (-x32)" 0 KiB
[ebuild   R    ] virtual/man-0-r1::gentoo  0 KiB
[ebuild   R    ] sys-apps/man-pages-posix-2013a::gentoo  909 KiB
[ebuild     U  ] sys-apps/man-pages-4.16::gentoo [4.14::gentoo] USE="nls" L10N="-da -de -fr -it -ja -nl -pl -ru -zh-CN" 1597 KiB
[ebuild   R    ] virtual/shadow-0::gentoo  0 KiB
[ebuild   R    ] app-eselect/eselect-python-20171204::gentoo  46 KiB
[ebuild   R    ] virtual/tmpfiles-0::gentoo  0 KiB
[ebuild   R    ] app-eselect/eselect-pinentry-0.7::gentoo  0 KiB
[ebuild   R    ] virtual/mta-1::gentoo  0 KiB
[ebuild   R    ] virtual/logger-0::gentoo  0 KiB
[ebuild   R    ] virtual/pkgconfig-0-r1::gentoo  ABI_X86="(64) -32 (-x32)" 0 KiB
[ebuild     U  ] sys-libs/readline-7.0_p5:0/7::gentoo [7.0_p3:0/7::gentoo] USE="-static-libs -utils" ABI_X86="(64) -32 (-x32)" 2851 KiB
[ebuild     U  ] sys-apps/hwids-20180518::gentoo [20171003::gentoo] USE="net pci udev usb" 3077 KiB
[ebuild     U  ] dev-libs/libpipeline-1.5.0::gentoo [1.4.2::gentoo] USE="-static-libs {-test}" 810 KiB
[ebuild   R    ] sys-apps/kbd-2.0.4::gentoo  USE="nls pam {-test}" 1008 KiB
[ebuild     U  ] app-shells/bash-4.4_p23::gentoo [4.4_p12::gentoo] USE="net nls (readline) -afs -bashlogger -examples -mem-scramble -plugins" 9209 KiB
[ebuild     U  ] net-misc/netifrc-0.6.0::gentoo [0.5.1::gentoo] 82 KiB
[ebuild   R    ] app-text/docbook-xml-dtd-4.1.2-r6:4.1.2::gentoo  74 KiB
[ebuild   R    ] app-text/docbook-xsl-stylesheets-1.79.1-r2::gentoo  USE="-ruby" 21454 KiB
[ebuild   R    ] virtual/yacc-0::gentoo  0 KiB
[ebuild   R    ] virtual/perl-File-Temp-0.230.400-r5::gentoo  0 KiB
[ebuild     U  ] app-admin/perl-cleaner-2.26-r1::gentoo [2.25::gentoo] 8 KiB
[ebuild     U  ] app-arch/xz-utils-5.2.4-r2::gentoo [5.2.3::gentoo] USE="extra-filters nls threads -static-libs" ABI_X86="(64) -32 (-x32)" 1536 KiB
[ebuild     U  ] app-portage/elt-patches-20170826.1::gentoo [20170815::gentoo] 28 KiB
[ebuild     U  ] sys-devel/m4-1.4.18::gentoo [1.4.17::gentoo] USE="-examples" 1180 KiB
[ebuild   R    ] dev-libs/libltdl-2.4.6::gentoo  USE="-static-libs" ABI_X86="(64) -32 (-x32)" 951 KiB
[ebuild   R    ] sys-libs/zlib-1.2.11-r2:0/1::gentoo  USE="-minizip -static-libs" ABI_X86="(64) -32 (-x32)" 0 KiB
[ebuild     U  ] dev-libs/gmp-6.1.2-r1:0/10.4::gentoo [6.1.2:0/10.4::gentoo] USE="asm cxx -doc -static-libs (-pgo%)" ABI_X86="(64) -32 (-x32)" 1901 KiB
[ebuild   R    ] dev-libs/libunistring-0.9.10:0/2::gentoo  USE="-doc -static-libs" ABI_X86="(64) -32 (-x32)" 0 KiB
[ebuild     U  ] dev-libs/libffi-3.2.1-r2::gentoo [3.2.1::gentoo] USE="-debug -pax_kernel -static-libs {-test}" ABI_X86="(64) -32 (-x32)" 919 KiB
[ebuild   R    ] dev-libs/npth-1.5::gentoo  USE="-static-libs" 0 KiB
[ebuild     U  ] dev-libs/libpcre-8.42:3::gentoo [8.41-r1:3::gentoo] USE="bzip2 cxx readline recursion-limit (static-libs) (unicode) zlib -jit* -libedit -pcre16 -pcre32" ABI_X86="(64) -32 (-x32)" 1534 KiB
[ebuild   R    ] sys-apps/file-5.33-r2::gentoo  USE="zlib -python -static-libs" ABI_X86="(64) -32 (-x32)" PYTHON_TARGETS="python2_7 python3_5 -pypy -python3_4 -python3_6" 798 KiB
[ebuild   R    ] sys-libs/cracklib-2.9.6-r1::gentoo  USE="nls zlib -python -static-libs" ABI_X86="(64) -32 (-x32)" PYTHON_TARGETS="python2_7 python3_5 -python3_4 -python3_6" 628 KiB
[ebuild     U  ] dev-libs/mpfr-4.0.1:0/6::gentoo [3.1.6:0/4::gentoo] USE="-static-libs" ABI_X86="(64) -32 (-x32)" 1380 KiB
[ebuild     U  ] sys-apps/kmod-25::gentoo [24::gentoo] USE="tools zlib -debug -doc -lzma -python -static-libs" PYTHON_TARGETS="python2_7 python3_5 -python3_4 -python3_6" 533 KiB
[ebuild     U  ] sys-apps/less-531::gentoo [529::gentoo] USE="pcre unicode" 333 KiB
[ebuild     U  ] dev-libs/mpc-1.1.0-r1:0/3::gentoo [1.0.3:0/0::gentoo] USE="-static-libs" ABI_X86="(64) -32 (-x32)" 685 KiB
[ebuild   R    ] app-admin/metalog-3-r2::gentoo  USE="unicode" 0 KiB
[ebuild   R    ] virtual/modutils-0::gentoo  0 KiB
[ebuild   R    ] dev-lang/swig-3.0.12::gentoo  USE="pcre* -ccache -doc" 0 KiB
[ebuild   R    ] virtual/pager-0::gentoo  0 KiB
[ebuild     U  ] dev-lang/perl-5.26.2:0/5.26::gentoo [5.24.3-r1:0/5.24::gentoo] USE="-berkdb* -debug -doc -gdbm* -ithreads" 11770 KiB
[ebuild   R    ] sys-kernel/linux-headers-4.17::gentoo  USE="-headers-only" 0 KiB
[ebuild     U  ] sys-apps/groff-1.22.3::gentoo [1.22.2::gentoo] USE="-X -examples" L10N="(-ja%)" 4091 KiB
[ebuild   R    ] sys-devel/autoconf-2.69-r4:2.69::gentoo  USE="-emacs" 1187 KiB
[ebuild     U  ] virtual/perl-ExtUtils-MakeMaker-7.240.0::gentoo [7.100.200_rc-r4::gentoo] 0 KiB
[ebuild   R    ] dev-util/gtk-doc-am-1.25-r1::gentoo  658 KiB
[ebuild     U  ] virtual/perl-Parse-CPAN-Meta-2.150.10::gentoo [1.441.700.100_rc-r4::gentoo] 0 KiB
[ebuild   R    ] virtual/perl-CPAN-Meta-YAML-0.18.0-r2::gentoo  0 KiB
[ebuild     U  ] virtual/perl-Test-Harness-3.380.0::gentoo [3.360.100_rc-r3::gentoo] 0 KiB
[ebuild     U  ] virtual/perl-File-Spec-3.670.0::gentoo [3.630.100_rc-r4::gentoo] 0 KiB
[ebuild     U  ] virtual/perl-Data-Dumper-2.167.0::gentoo [2.160.0-r1::gentoo] 0 KiB
[ebuild   R    ] dev-perl/Text-CharWidth-0.40.0-r1::gentoo  9 KiB
[ebuild   R    ] perl-core/File-Temp-0.230.400-r1::gentoo  59 KiB
[ebuild     U  ] virtual/perl-version-0.991.700::gentoo [0.991.600-r1::gentoo] 0 KiB
[ebuild  N     ] virtual/perl-podlators-4.90.0::gentoo  0 KiB
[ebuild   R    ] virtual/perl-Text-ParseWords-3.300.0-r3::gentoo  0 KiB
[ebuild     U  ] virtual/perl-Perl-OSType-1.10.0::gentoo [1.9.0-r1::gentoo] 0 KiB
[ebuild     U  ] virtual/perl-Module-Metadata-1.0.33::gentoo [1.0.31-r1::gentoo] 0 KiB
[ebuild     U  ] virtual/perl-Getopt-Long-2.490.0::gentoo [2.480.0-r1::gentoo] 0 KiB
[ebuild     U  ] virtual/perl-ExtUtils-ParseXS-3.340.0::gentoo [3.310.0-r1::gentoo] 0 KiB
[ebuild   R    ] virtual/perl-ExtUtils-Manifest-1.700.0-r4::gentoo  0 KiB
[ebuild   R    ] virtual/perl-ExtUtils-Install-2.40.0-r3::gentoo  0 KiB
[ebuild   R    ] virtual/perl-ExtUtils-CBuilder-0.280.225-r2::gentoo  0 KiB
[ebuild     U  ] virtual/perl-JSON-PP-2.274.0.200_rc::gentoo [2.273.0.100_rc-r6::gentoo] 0 KiB
[ebuild   R    ] sys-libs/libseccomp-2.3.3::gentoo  USE="-static-libs" ABI_X86="(64) -32 (-x32)" 552 KiB
[ebuild  N     ] sys-libs/libcap-ng-0.7.9::gentoo  USE="-python -static-libs" PYTHON_TARGETS="python2_7 python3_5 -python3_4 -python3_6" 439 KiB
[ebuild     U  ] net-firewall/iptables-1.6.2-r2:0/12::gentoo [1.6.1-r3:0/12::gentoo] USE="ipv6 -conntrack -netlink -nftables -pcap -static-libs" 625 KiB
[ebuild     U  ] dev-perl/Text-Unidecode-1.300.0::gentoo [1.270.0::gentoo] 135 KiB
[ebuild     U  ] dev-perl/libintl-perl-1.280.0::gentoo [1.240.0-r2::gentoo] 460 KiB
[ebuild   R    ] dev-perl/Unicode-EastAsianWidth-1.330.0-r1::gentoo  31 KiB
[ebuild     U  ] dev-perl/TermReadKey-2.370.0::gentoo [2.330.0::gentoo] USE="-examples%" 84 KiB
[ebuild   R    ] dev-perl/Text-WrapI18N-0.60.0-r1::gentoo  4 KiB
[ebuild     U  ] virtual/perl-CPAN-Meta-2.150.10::gentoo [2.150.5-r1::gentoo] 0 KiB
[ebuild     U  ] app-misc/pax-utils-1.2.3-r1::gentoo [1.2.3::gentoo] USE="seccomp -caps -debug -python" PYTHON_SINGLE_TARGET="python3_5%* -python2_7% -python3_4% -python3_6%" PYTHON_TARGETS="python2_7%* python3_5%* -python3_4% -python3_6%" 647 KiB
[ebuild     U  ] dev-perl/Module-Build-0.422.400::gentoo [0.421.600::gentoo] USE="{-test}" 298 KiB
[ebuild   R    ] sys-apps/sandbox-2.13::gentoo  ABI_X86="(32) (64) (-x32)" 416 KiB
[ebuild     U  ] dev-perl/SGMLSpm-1.1-r1::gentoo [1.03-r7::gentoo] 112 KiB
[ebuild     U  ] dev-libs/openssl-1.0.2o-r6::gentoo [1.0.2o-r3::gentoo] USE="asm sslv3 tls-heartbeat zlib -bindist* -gmp -kerberos -rfc3779 -sctp -sslv2 -static-libs {-test} -vanilla" ABI_X86="(64) -32 (-x32)" CPU_FLAGS_X86="(sse2)" 5218 KiB
[ebuild   R    ] sys-libs/libselinux-2.8::gentoo  USE="(python) (static-libs) -pcre2 -ruby" ABI_X86="(64) -32 (-x32)" PYTHON_TARGETS="python2_7 python3_5 -python3_4 -python3_6" RUBY_TARGETS="ruby23*" 0 KiB
[ebuild     U  ] sys-apps/net-tools-1.60_p20170221182432::gentoo [1.60_p20161110235919::gentoo] USE="arp hostname ipv6 nls (selinux*) -nis -plipconfig -slattach -static" 223 KiB
[ebuild   R    ] sys-process/procps-3.3.15-r1:0/6::gentoo  USE="kill ncurses nls (selinux*) unicode -elogind -modern-top -static-libs (-systemd) {-test}" 884 KiB
[ebuild     U  ] sys-apps/busybox-1.29.0::gentoo [1.28.0::gentoo] USE="ipv6 (selinux*) static -debug -livecd -make-symlinks -math -mdev -pam -savedconfig -sep-usr -syslog (-systemd)" 2250 KiB
[ebuild     U  ] sys-apps/attr-2.4.48-r2::gentoo [2.4.47-r2::gentoo] USE="nls -debug% -static-libs" ABI_X86="(64) -32 (-x32)" 457 KiB
[ebuild  N     ] sys-libs/libcap-2.25-r1::gentoo  USE="pam -static-libs" ABI_X86="(64) -32 (-x32)" 63 KiB
[ebuild   R    ] sys-devel/patch-2.7.6-r1::gentoo  USE="xattr -static {-test}" 766 KiB
[ebuild     U  ] net-misc/iputils-20171016_pre-r1::gentoo [20171016_pre::gentoo] USE="arping filecaps* ipv6 ssl -SECURITY_HAZARD -caps -clockdiff -doc -gcrypt -idn -libressl -nettle -rarpd -rdisc -static -tftpd -tracepath -traceroute (-openssl%*)" 220 KiB
[ebuild     U  ] dev-python/setuptools-38.6.1::gentoo [36.7.2::gentoo] USE="{-test}" PYTHON_TARGETS="python2_7 python3_5 -pypy -pypy3 -python3_4 -python3_6" 722 KiB
[ebuild   R    ] dev-libs/libgpg-error-1.29::gentoo  USE="nls -common-lisp -static-libs" ABI_X86="(64) -32 (-x32)" 874 KiB
[ebuild   R    ] dev-libs/libassuan-2.5.1::gentoo  USE="-static-libs" 0 KiB
[ebuild   R    ] dev-libs/libksba-1.3.5-r1::gentoo  USE="-static-libs" 0 KiB
[ebuild   R    ] sys-apps/sed-4.5::gentoo  USE="acl nls (selinux*) -forced-sandbox -static" 1245 KiB
[ebuild     U  ] sys-apps/util-linux-2.32-r3::gentoo [2.30.2-r1::gentoo] USE="cramfs ncurses nls pam readline (selinux*) suid unicode -build -caps -fdformat -kill -python -slang -static-libs (-systemd) {-test} -tty-helpers -udev" ABI_X86="(64) -32 (-x32)" PYTHON_SINGLE_TARGET="python3_5 -python2_7 -python3_4 -python3_6" PYTHON_TARGETS="python2_7 python3_5 -python3_4 -python3_6" 4444 KiB
[ebuild     U  ] sys-libs/pam-1.3.0-r2::gentoo [1.2.1-r2::gentoo] USE="cracklib filecaps* nls (pie) (selinux*) -audit -berkdb* -debug -nis {-test} -vim-syntax%" ABI_X86="(64) -32 (-x32)" 1754 KiB
[ebuild   R    ] sys-auth/pambase-20150213-r1::gentoo  USE="cracklib nullok (selinux*) sha512 -consolekit -debug -elogind -gnome-keyring -minimal -mktemp -pam_krb5 -pam_ssh -passwdqc -securetty (-systemd)" 4 KiB
[ebuild     U  ] sys-apps/acl-2.2.53::gentoo [2.2.52-r1::gentoo] USE="nls -static-libs" ABI_X86="(64) -32 (-x32)" 513 KiB
[ebuild     U  ] sys-apps/coreutils-8.30::gentoo [8.28-r1::gentoo] USE="acl nls (selinux*) split-usr%* (xattr) -caps -gmp -hostname -kill -multicall -static {-test} -vanilla" 5240 KiB
[ebuild     U  ] app-admin/eselect-1.4.13::gentoo [1.4.12::gentoo] USE="-doc -emacs -vim-syntax" 174 KiB
[ebuild   R    ] app-eselect/eselect-lib-bin-symlink-0.1.1::gentoo  0 KiB
[ebuild   R    ] sys-libs/glibc-2.27-r5:2.2::gentoo  USE="hardened multiarch* (multilib) (selinux) -audit -caps (-compile-locales) -doc -gd -headers-only -nscd (-profile) -suid -systemtap (-vanilla)" 0 KiB
[ebuild   R    ] virtual/libc-1::gentoo  0 KiB
[ebuild   R    ] sys-devel/binutils-2.30-r3:2.30::gentoo  USE="cxx nls -doc -multitarget -static-libs {-test}" 0 KiB
[ebuild     U  ] app-misc/ca-certificates-20180409.3.37::gentoo [20170717.3.36.1::gentoo] USE="-cacert (-insecure_certs%)" 22729 KiB
[ebuild  N     ] dev-python/ipy-0.83::gentoo  USE="-examples" PYTHON_TARGETS="python2_7 python3_5 -pypy -python3_4 -python3_6" 32 KiB
[ebuild   R    ] sys-apps/portage-2.3.41::gentoo  USE="(ipc) native-extensions* rsync-verify* (selinux) (xattr) -build* -doc -epydoc -gentoo-dev" PYTHON_TARGETS="python2_7 python3_5 (-pypy) -python3_4 -python3_6" 0 KiB
[ebuild   R    ] virtual/package-manager-1::gentoo  0 KiB
[ebuild   R    ] dev-python/pyblake2-1.1.2::gentoo  PYTHON_TARGETS="python2_7 python3_5 -pypy -pypy3 -python3_4 -python3_6" 124 KiB
[ebuild     U  ] sys-devel/make-4.2.1-r3::gentoo [4.2.1::gentoo] USE="nls -guile -static" 1375 KiB
[ebuild   R    ] sys-process/psmisc-23.1-r1::gentoo  USE="ipv6 nls (selinux*) -X" 290 KiB
[ebuild     U  ] sys-libs/e2fsprogs-libs-1.44.2::gentoo [1.43.9::gentoo] USE="nls -static-libs" ABI_X86="(64) -32 (-x32)" 699 KiB
[ebuild   R    ] dev-libs/popt-1.16-r2::gentoo  USE="nls -static-libs" ABI_X86="(64) -32 (-x32)" 687 KiB
[ebuild   R    ] net-misc/rsync-3.1.3::gentoo  USE="acl iconv ipv6 xattr -examples -static -stunnel" 885 KiB
[ebuild  N     ] dev-python/decorator-4.2.1::gentoo  USE="-doc" PYTHON_TARGETS="python2_7 python3_5 -pypy -pypy3 -python3_4 -python3_6" 33 KiB
[ebuild  N     ] dev-python/networkx-1.11-r1::gentoo  USE="-doc -examples -scipy {-test}" PYTHON_TARGETS="python2_7 python3_5 -python3_4 -python3_6" 1285 KiB
[ebuild  N     ] dev-python/pypax-0.9.2::gentoo  USE="xtpax -ptpax" PYTHON_TARGETS="python2_7 python3_5 -pypy -python3_4 -python3_6" 390 KiB
[ebuild  N     ] sys-apps/elfix-0.9.2::gentoo  USE="xtpax -ptpax" 0 KiB
[ebuild  N     ] dev-python/enum34-1.1.6::gentoo  USE="-doc" PYTHON_TARGETS="python2_7 -pypy -pypy3" 40 KiB
[ebuild  N     ] virtual/python-enum34-1::gentoo  PYTHON_TARGETS="python2_7 python3_5 -pypy -pypy3 -python3_4 -python3_6" 0 KiB
[ebuild  N     ] app-admin/setools-4.1.1::gentoo  USE="-X -debug {-test}" PYTHON_TARGETS="python2_7 python3_5 -python3_4 -python3_6" 451 KiB
[ebuild   R    ] dev-python/bz2file-0.98::gentoo  PYTHON_TARGETS="python2_7 -pypy" 0 KiB
[ebuild   R    ] dev-libs/libtasn1-4.13:0/6::gentoo  USE="-doc -static-libs -valgrind" ABI_X86="(64) -32 (-x32)" 0 KiB
[ebuild   R    ] net-dns/libidn2-2.0.5::gentoo  USE="-static-libs" ABI_X86="(64) -32 (-x32)" 0 KiB
[ebuild     U  ] app-editors/nano-2.9.8::gentoo [2.8.7::gentoo] USE="magic ncurses nls spell unicode -debug -justify -minimal -slang -static" 2838 KiB
[ebuild   R    ] virtual/editor-0-r1::gentoo  0 KiB
[ebuild  NS    ] sys-devel/automake-1.16.1-r1:1.16::gentoo [1.15.1-r2:1.15::gentoo] USE="{-test}" 1499 KiB
[ebuild     U  ] sys-devel/libtool-2.4.6-r5:2::gentoo [2.4.6-r3:2::gentoo] USE="-vanilla" 0 KiB
[ebuild   R    ] dev-libs/libxml2-2.9.8:2::gentoo  USE="ipv6 readline -debug -examples -icu -lzma -python -static-libs {-test}" ABI_X86="(64) -32 (-x32)" PYTHON_TARGETS="python2_7 python3_5 -python3_4 -python3_6" 5341 KiB
[ebuild   R    ] dev-libs/expat-2.2.5::gentoo  USE="unicode -examples -static-libs" ABI_X86="(64) -32 (-x32)" 499 KiB
[ebuild     U  ] sys-libs/gdbm-1.16:0/6::gentoo [1.13-r2:0/1.13::gentoo] USE="berkdb nls readline -static-libs (-exporter%)" ABI_X86="(64) -32 (-x32)" 915 KiB
[ebuild   R    ] dev-libs/libgcrypt-1.8.3:0/20::gentoo  USE="-doc -o-flag-munging -static-libs" ABI_X86="(64) -32 (-x32)" 2920 KiB
[ebuild  N     ] sys-process/audit-2.8.3::gentoo  USE="-gssapi -ldap -python -static-libs" ABI_X86="(64) -32 (-x32)" PYTHON_TARGETS="python2_7 python3_5 -python3_4 -python3_6" 1082 KiB
[ebuild     U  ] net-misc/openssh-7.7_p1-r6::gentoo [7.7_p1-r5::gentoo] USE="pam (pie) (selinux*) ssl -X -X509 -audit -bindist* -debug -hpn -kerberos -ldap -ldns -libedit -libressl -livecd -sctp -skey -static {-test}" 1517 KiB
[ebuild   R    ] net-misc/curl-7.60.0-r1::gentoo  USE="ipv6 ssl -adns -brotli -http2 -idn -kerberos -ldap -metalink -rtmp -samba -ssh -static-libs {-test} -threads" ABI_X86="(64) -32 (-x32)" CURL_SSL="openssl -axtls -gnutls -libressl -mbedtls -nss (-winssl)" 0 KiB
[ebuild   R    ] dev-libs/nettle-3.4:0/6.2::gentoo  USE="gmp -doc (-neon) -static-libs {-test}" ABI_X86="(64) -32 (-x32)" CPU_FLAGS_X86="aes*" 0 KiB
[ebuild   R    ] dev-libs/iniparser-3.1-r1::gentoo  USE="-doc -examples -static-libs" ABI_X86="(64) -32 (-x32)" 39 KiB
[ebuild     U  ] net-libs/libtirpc-1.0.3:0/3::gentoo [1.0.2-r1:0/3::gentoo] USE="ipv6 -kerberos -static-libs" ABI_X86="(64) -32 (-x32)" 507 KiB
[ebuild   R    ] sys-devel/gettext-0.19.8.1::gentoo  USE="acl* cxx ncurses* nls openmp* -cvs -doc -emacs -git -java -static-libs" ABI_X86="(64) -32 (-x32)" 0 KiB
[ebuild     U  ] dev-lang/python-2.7.15:2.7::gentoo [2.7.14-r1:2.7::gentoo] USE="gdbm hardened* ipv6 ncurses readline ssl (threads) (wide-unicode) (xml) (-berkdb) -bluetooth% -build -doc -examples -libressl -sqlite -tk -wininst" 12362 KiB
[ebuild     U  ] dev-lang/python-3.5.5-r1:3.5/3.5m::gentoo [3.5.5:3.5/3.5m::gentoo] USE="gdbm hardened* ipv6 ncurses readline ssl (threads) (xml) -bluetooth% -build -examples -libressl -sqlite {-test} -tk -wininst" 15004 KiB
[ebuild   R    ] virtual/ssh-0::gentoo  USE="-minimal" 0 KiB
[ebuild     U  ] app-portage/portage-utils-0.71::gentoo [0.64::gentoo] USE="nls -static" 543 KiB
[ebuild   R    ] dev-libs/libxslt-1.1.32::gentoo  USE="crypt -debug -examples -python -static-libs" ABI_X86="(64) -32 (-x32)" PYTHON_TARGETS="python2_7" 3361 KiB
[ebuild   R    ] app-text/build-docbook-catalog-1.21::gentoo  5 KiB
[ebuild   R    ] dev-perl/XML-Parser-2.440.0::gentoo  232 KiB
[ebuild   R    ] net-libs/libnsl-1.2.0:0/2::gentoo  ABI_X86="(64) -32 (-x32)" 205 KiB
[ebuild   R    ] net-libs/gnutls-3.5.18:0/30::gentoo  USE="cxx idn nls openssl seccomp tls-heartbeat zlib -dane -doc -examples -guile -openpgp -pkcs11 -sslv2 -sslv3 -static-libs {-test} -test-full -tools -valgrind" ABI_X86="(64) -32 (-x32)" 0 KiB
[ebuild   R    ] app-arch/tar-1.30::gentoo  USE="acl nls (selinux*) (xattr) -minimal -static" 2792 KiB
[ebuild   R    ] dev-python/certifi-2018.4.16::gentoo  PYTHON_TARGETS="python2_7 python3_5 -pypy -pypy3 -python3_4 -python3_6" 147 KiB
[ebuild     U  ] dev-python/pyxattr-0.6.0-r1::gentoo [0.5.5::gentoo] USE="-doc {-test}" PYTHON_TARGETS="python2_7 python3_5 -pypy -python3_4 -python3_6%" 31 KiB
[ebuild   R    ] app-crypt/pinentry-1.1.0-r2::gentoo  USE="ncurses -caps -emacs -fltk -gnome-keyring -gtk -qt5 -static" 0 KiB
[ebuild   R    ] sys-apps/findutils-4.6.0-r1::gentoo  USE="nls (selinux*) -static {-test}" 3692 KiB
[ebuild     U  ] sys-apps/grep-3.1::gentoo [3.0::gentoo] USE="nls pcre -static" 1339 KiB
[ebuild     U  ] sys-apps/gawk-4.2.1-r1::gentoo [4.1.4::gentoo] USE="nls readline -forced-sandbox% -mpfr" 2916 KiB
[ebuild     U  ] sys-apps/diffutils-3.6-r1::gentoo [3.5::gentoo] USE="nls -static" 1366 KiB
[ebuild   R    ] net-misc/wget-1.19.5::gentoo  USE="ipv6 nls pcre ssl zlib -debug -gnutls -idn -libressl -ntlm -static {-test} -uuid" 4352 KiB
[ebuild   R    ] sys-devel/flex-2.6.4-r1::gentoo  USE="nls -static {-test}" ABI_X86="(64) -32 (-x32)" 1386 KiB
[ebuild   R    ] dev-perl/Locale-gettext-1.70.0::gentoo  9 KiB
[ebuild   R    ] dev-util/intltool-0.51.0-r2::gentoo  159 KiB
[ebuild   R    ] sys-apps/texinfo-6.5::gentoo  USE="nls -static" 0 KiB
[ebuild     U  ] app-text/opensp-1.5.2-r6::gentoo [1.5.2-r3::gentoo] USE="nls -doc -static-libs {-test}" 1486 KiB
[ebuild   R    ] sys-fs/eudev-3.2.5::gentoo  USE="hwdb kmod (selinux*) -introspection -rule-generator -static-libs {-test}" ABI_X86="(64) -32 (-x32)" 1814 KiB
[ebuild   R    ] mail-mta/nullmailer-2.0-r2::gentoo  USE="ssl {-test}" 0 KiB
[ebuild     U  ] sys-fs/e2fsprogs-1.44.2::gentoo [1.43.9::gentoo] USE="nls -fuse -static-libs" 7386 KiB
[ebuild     U  ] sys-devel/bison-3.0.5::gentoo [3.0.4-r1::gentoo] USE="nls -examples -static {-test}" 1915 KiB
[ebuild     U  ] sys-apps/help2man-1.47.6::gentoo [1.47.4::gentoo] USE="nls" 189 KiB
[ebuild   R    ] app-text/openjade-1.3.2-r7::gentoo  USE="-static-libs" 874 KiB
[ebuild  N     ] sys-libs/libsemanage-2.8::gentoo  USE="(python)" ABI_X86="(64) -32 (-x32)" PYTHON_TARGETS="python2_7 python3_5 -python3_4 -python3_6" 151 KiB
[ebuild   R    ] sys-devel/gcc-7.3.0-r3:7.3.0::gentoo  USE="cxx hardened (multilib) nls nptl openmp* (pie) (ssp) vtv* (-altivec) -cilk -debug -doc (-fixed-point) -fortran -go -graphite (-jit) (-libssp) -mpx -objc -objc++ -objc-gc (-pch) -pgo -regression-test (-sanitize) -vanilla" 0 KiB
[ebuild     U  ] sys-apps/iproute2-4.17.0::gentoo [4.14.1-r2::gentoo] USE="iptables ipv6 (selinux*) -atm -berkdb* -elf% -minimal" 660 KiB
[ebuild   R    ] app-text/po4a-0.47-r1::gentoo  USE="{-test}" 2334 KiB
[ebuild  N     ] sys-apps/checkpolicy-2.8::gentoo  USE="-debug" 65 KiB
[ebuild  N     ] sys-apps/selinux-python-2.8::gentoo  PYTHON_TARGETS="python2_7 python3_5 -python3_4 -python3_6" 2020 KiB
[ebuild   R    ] sys-apps/shadow-4.6::gentoo  USE="acl cracklib nls pam (selinux*) xattr -audit -skey" 3716 KiB
[ebuild  N     ] sys-apps/policycoreutils-2.8::gentoo  USE="pam -audit -dbus" PYTHON_TARGETS="python2_7 python3_5 -python3_4 -python3_6" 2740 KiB
[ebuild  N     ] sec-policy/selinux-base-2.20180114-r3::gentoo  USE="open_perms peer_perms ubac unconfined -doc (-systemd)" 1022 KiB
[ebuild  N     ] sec-policy/selinux-base-policy-2.20180114-r3::gentoo  USE="unconfined (-systemd)" 0 KiB
[ebuild  N     ] sec-policy/selinux-unconfined-2.20180114-r3::gentoo  0 KiB
[ebuild  N     ] sec-policy/selinux-openrc-2.20180114-r3::gentoo  0 KiB
[ebuild  N     ] sec-policy/selinux-shutdown-2.20180114-r3::gentoo  0 KiB
[ebuild     U  ] sys-apps/opentmpfiles-0.1.3-r1::gentoo [0.1.3::gentoo] USE="(selinux*)" 6 KiB
[ebuild  N     ] sec-policy/selinux-mandb-2.20180114-r3::gentoo  0 KiB
[ebuild  N     ] sec-policy/selinux-dirmngr-2.20180114-r3::gentoo  0 KiB
[ebuild     U  ] sys-apps/sysvinit-2.90::gentoo [2.88-r9::gentoo] USE="(selinux*) (-ibm) -static" 111 KiB
[ebuild     U  ] sys-apps/man-db-2.8.3::gentoo [2.7.6.1-r2::gentoo] USE="manpager nls seccomp%* (selinux*) zlib -berkdb* -gdbm* -static-libs" 1587 KiB
[ebuild  N     ] sec-policy/selinux-gpg-2.20180114-r3::gentoo  0 KiB
[ebuild     U  ] sys-apps/openrc-0.38.1::gentoo [0.34.11::gentoo] USE="ncurses netifrc pam (selinux*) unicode -audit -debug -newnet (-prefix) -static-libs" 236 KiB
[ebuild   R    ] app-crypt/gnupg-2.2.8::gentoo  USE="bzip2 nls readline (selinux*) smartcard ssl -doc -ldap -tofu -tools -usb -wks-server" 0 KiB
[ebuild   R    ] app-portage/gemato-13.1::gentoo  USE="blake2 bzip2 gpg -lzma -sha3 {-test} -tools" PYTHON_TARGETS="python2_7 python3_5 -pypy -python3_4 -python3_6" 0 KiB
[ebuild   R    ] virtual/service-manager-0::gentoo  USE="(-prefix)" 0 KiB
[ebuild     U  ] dev-libs/glib-2.54.3-r6:2::gentoo [2.52.3:2::gentoo] USE="mime (selinux*) xattr -dbus -debug (-fam) -static-libs -systemtap {-test} -utils" ABI_X86="(64) -32 (-x32)" PYTHON_SINGLE_TARGET="python3_5%* -python2_7% -python3_6%" PYTHON_TARGETS="python2_7 python3_5%* -python3_6%" 9578 KiB
[ebuild   R    ] dev-util/pkgconfig-0.29.2::gentoo  USE="hardened* -internal-glib" ABI_X86="(64) -32 (-x32)" 1970 KiB
[ebuild     U  ] x11-misc/shared-mime-info-1.10::gentoo [1.9::gentoo] USE="{-test}" 603 KiB

Total: 228 packages (87 upgrades, 26 new, 1 in new slot, 114 reinstalls), Size of downloads: 245719 KiB
.
. 
.
livecd /usr/portage/scripts #
```

This is the `emerge` options:

- `--emptytree`: Reinstalls target atoms and their entire deep dependency tree, as  though  no  packages are  currently  installed.
-  `--with-bdeps=y`: In  dependency  calculations,  pull  in  build  time dependencies that are not strictly required.
- `@world`: is one of the six *sets* available in Gentoo Linux; all the packages listed on `/var/lib/portage/world`

After recompile the *stage 3* we've got to *clean the system by removing packages that are not associated with  explicitly  merged packages*.

*full output [here](https://raw.githubusercontent.com/noplacenoaddress/gentoo-integrity/master/emerge-stage3-depclean.txt)*

```sh
livecd /usr/portage/scripts # emerge --depclean

 * Always study the list of packages to be cleaned for any obvious
 * mistakes. Packages that are part of the world set will always
 * be kept.  They can be manually added to this set with
 * `emerge --noreplace <atom>`.  Packages that are listed in
 * package.provided (see portage(5)) will be removed by
 * depclean, even if they are part of the world set.
 * 
 * As a safety measure, depclean will not remove any packages
 * unless *all* required dependencies have been resolved.  As a
 * consequence of this, it often becomes necessary to run 
 * `emerge --update --newuse --deep @world` prior to depclean.
!!! You have no world file.

Calculating dependencies... done!
.
.
.
livecd /usr/portage/scripts #
```

Because we've read *IMPORTANT: 13 news items need reading for repository 'gentoo'*, we can read them:

```sh
livecd ~ # eselect news list
News items:
  [1]   N  2013-09-27  Separate /usr on Linux requires initramfs
  [2]   N  2014-06-15  GCC 4.8.3 defaults to -fstack-protector
  [3]   N  2014-10-26  GCC 4.7 Introduced the New C++11 ABI 
  [4]   N  2015-02-02  New portage plug-in sync system
  [5]   N  2015-07-25  Python 3.4 enabled by default
  [6]   N  2015-08-13  OpenSSH 7.0 disables ssh-dss keys by default
  [7]   N  2015-10-22  GCC 5 Defaults to the New C++11 ABI
  [8]   N  2016-06-19  L10N USE_EXPAND variable replacing LINGUAS
  [9]   N  2017-12-26  Experimental amd64 17.1 profiles up for testing
  [10]  N  2018-01-30  Portage rsync tree verification
  [11]  N  2018-03-13  Portage rsync tree verification unstable
  [12]  N  2018-05-22  Python 3.6 to become the default target
  [13]  N  2018-06-23  (2018-06-23-mpfr-4-update - removed?)
livecd ~ # eselect news read 12
2018-05-22-python3-6
  Title                     Python 3.6 to become the default target
  Author                    Michał Górny <mgorny@gentoo.org>
  Posted                    2018-05-22
  Revision                  1

On 2018-06-22, Python 3.6 will replace Python 3.5 in the default Python
targets for Gentoo systems.  The new default targets will be:

    PYTHON_TARGETS="python2_7 python3_6"
    PYTHON_SINGLE_TARGET="python3_6"

If you have not overriden the value of those variables on your system,
then your package manager will want to use the new targets immediately.
In order to prevent dependency conflicts, please clean stray packages
and rebuild/upgrade all packages with USE flag changes after the change,
e.g.:

    emerge --depclean
    emerge -1vUD @world
    emerge --depclean

Please note that upgrading dependencies in place may cause some
of the package dependencies to be temporarily missing.  While this
should not affect scripts that are already fully loaded, it may cause
ImportErrors while starting Python scripts or loading additional
modules (only scripts running Python 3.5 are affected).

In order to improve stability of the upgrade, you may choose to
temporarily enable both targets, i.e. set in /etc/portage/make.conf
or its equivalent:

    PYTHON_TARGETS="python2_7 python3_5 python3_6"
    PYTHON_SINGLE_TARGET="python3_5"

This will cause the dependencies to include both Python 3.5 and 3.6
support on the next system upgrade.  Once all packages are updated,
you can restart your scripts, remove the custom setting and run another
upgrade to remove support for Python 3.5.

If you would like to postpone the switch to Python 3.6, you can copy
the current value of PYTHON_TARGETS and/or PYTHON_SINGLE_TARGET
to /etc/portage/make.conf or its equivalent:

    PYTHON_TARGETS="python2_7 python3_5"
    PYTHON_SINGLE_TARGET="python3_5"

If you would like to migrate your systems earlier, you can do the same
with the new value.

If you are still using Python 3.4, please consider switching to a newer
version as it is reaching its end-of-life.  The end-of-life dates
for the currently used versions are:

  Python 3.4        2019-03-16
  Python 2.7        2020-01-01
  Python 3.5        2020-09-13 [1]

[1]:https://devguide.python.org/#status-of-python-branches

livecd ~ #
```

I've read the news number `12` because it is very important we've to do some change:

```sh
livecd ~ # cat >> /etc/portage/make.conf <<EOF
> PYTHON_TARGETS="python2_7 python3_6"
> PYTHON_SINGLE_TARGET="python3_6"
> EOF
livecd ~ # emerge --depclean

 * Always study the list of packages to be cleaned for any obvious
 * mistakes. Packages that are part of the world set will always
 * be kept.  They can be manually added to this set with
 * `emerge --noreplace <atom>`.  Packages that are listed in
 * package.provided (see portage(5)) will be removed by
 * depclean, even if they are part of the world set.
 * 
 * As a safety measure, depclean will not remove any packages
 * unless *all* required dependencies have been resolved.  As a
 * consequence of this, it often becomes necessary to run 
 * `emerge --update --newuse --deep @world` prior to depclean.
!!! You have no world file.

Calculating dependencies... done!
  app-admin/eselect-1.4.12 pulled in by:
    app-eselect/eselect-lib-bin-symlink-0.1.1 requires app-admin/eselect
    app-eselect/eselect-python-20171204 requires >=app-admin/eselect-1.2.3
    sys-apps/portage-2.3.41 requires >=app-admin/eselect-1.2

  app-admin/metalog-3-r2 pulled in by:
    virtual/logger-0 requires app-admin/metalog

  app-admin/perl-cleaner-2.25 pulled in by:
    dev-lang/perl-5.24.3-r1 requires >=app-admin/perl-cleaner-2.5

  app-arch/bzip2-1.0.6-r9 pulled in by:
    @system requires app-arch/bzip2
    app-arch/unzip-6.0_p21-r2 requires app-arch/bzip2
    app-crypt/gnupg-2.2.8 requires app-arch/bzip2
    dev-lang/perl-5.24.3-r1 requires app-arch/bzip2
    dev-lang/python-2.7.14-r1 requires app-arch/bzip2:0=, app-arch/bzip2:0/1=
    dev-lang/python-3.6.6 requires app-arch/bzip2:0/1=, app-arch/bzip2:0=
    dev-libs/elfutils-0.170-r1 requires >=app-arch/bzip2-1.0.6-r4[abi_x86_64(-)]
    dev-libs/libpcre-8.42 requires app-arch/bzip2

  app-arch/gzip-1.8 pulled in by:
    @system requires app-arch/gzip
    sys-apps/kbd-2.0.4 requires app-arch/gzip

  app-arch/tar-1.30 pulled in by:
    @system requires app-arch/tar
    sys-apps/portage-2.3.41 requires >=app-arch/tar-1.27

  app-arch/unzip-6.0_p21-r2 pulled in by:
    app-text/docbook-xml-dtd-4.1.2-r6 requires >=app-arch/unzip-5.41
    dev-python/setuptools-38.6.1 requires app-arch/unzip

  app-arch/xz-utils-5.2.3 pulled in by:
    @system requires app-arch/xz-utils
    app-admin/metalog-3-r2 requires app-arch/xz-utils
    app-misc/pax-utils-1.2.3-r1 requires app-arch/xz-utils
    app-portage/elt-patches-20170815 requires app-arch/xz-utils
    app-portage/portage-utils-0.64 requires app-arch/xz-utils
    dev-lang/python-3.6.6 requires app-arch/xz-utils:0/0=, app-arch/xz-utils:0=
    dev-libs/glib-2.54.3-r6 requires app-arch/xz-utils
    dev-libs/gmp-6.1.2 requires app-arch/xz-utils
    dev-libs/libltdl-2.4.6 requires app-arch/xz-utils
    dev-util/gtk-doc-am-1.25-r1 requires app-arch/xz-utils
    net-libs/libtirpc-1.0.2-r1 requires app-arch/xz-utils
    net-misc/wget-1.19.5 requires app-arch/xz-utils
    sys-apps/coreutils-8.30 requires app-arch/xz-utils
    sys-apps/diffutils-3.5 requires app-arch/xz-utils
    sys-apps/iproute2-4.14.1-r2 requires app-arch/xz-utils
    sys-apps/man-db-2.8.3 requires app-arch/xz-utils
    sys-apps/net-tools-1.60_p20161110235919 requires app-arch/xz-utils
    sys-apps/sandbox-2.13 requires app-arch/xz-utils
    sys-apps/shadow-4.6 requires app-arch/xz-utils
    sys-apps/texinfo-6.3 requires app-arch/xz-utils
    sys-auth/pambase-20150213-r1 requires app-arch/xz-utils
    sys-devel/flex-2.6.4-r1 requires app-arch/xz-utils
    sys-devel/libtool-2.4.6-r3 requires app-arch/xz-utils
    sys-devel/m4-1.4.17 requires app-arch/xz-utils
    sys-kernel/linux-headers-4.13 requires app-arch/xz-utils

  app-crypt/gnupg-2.2.8 pulled in by:
    app-portage/gemato-13.1 requires app-crypt/gnupg
    sys-apps/portage-2.3.41 requires >=app-crypt/gnupg-2.2.4-r2[ssl(-)]

  app-crypt/openpgp-keys-gentoo-release-20180703 pulled in by:
    sys-apps/portage-2.3.41 requires app-crypt/openpgp-keys-gentoo-release

  app-crypt/pinentry-1.1.0-r2 pulled in by:
    app-crypt/gnupg-2.2.8 requires app-crypt/pinentry

  app-editors/nano-2.8.7 pulled in by:
    virtual/editor-0-r1 requires app-editors/nano

  app-eselect/eselect-lib-bin-symlink-0.1.1 pulled in by:
    app-eselect/eselect-pinentry-0.7 requires >=app-eselect/eselect-lib-bin-symlink-0.1.1

  app-eselect/eselect-pinentry-0.7 pulled in by:
    app-crypt/pinentry-1.1.0-r2 requires app-eselect/eselect-pinentry

  app-eselect/eselect-python-20171204 pulled in by:
    dev-lang/python-2.7.14-r1 requires >=app-eselect/eselect-python-20140125-r1
    dev-lang/python-3.6.6 requires >=app-eselect/eselect-python-20140125-r1

  app-misc/c_rehash-1.7-r1 pulled in by:
    app-misc/ca-certificates-20170717.3.36.1 requires app-misc/c_rehash
    dev-libs/openssl-1.0.2o-r6 requires >=app-misc/c_rehash-1.7-r1

  app-misc/ca-certificates-20170717.3.36.1 pulled in by:
    dev-libs/openssl-1.0.2o-r6 requires app-misc/ca-certificates
    dev-python/certifi-2018.4.16 requires app-misc/ca-certificates

  app-misc/editor-wrapper-4 pulled in by:
    sys-apps/less-529 requires >=app-misc/editor-wrapper-3

  app-misc/mime-types-9 pulled in by:
    dev-lang/python-2.7.14-r1 requires app-misc/mime-types
    dev-lang/python-3.6.6 requires app-misc/mime-types

  app-misc/pax-utils-1.2.3-r1 pulled in by:
    sys-apps/portage-2.3.41 requires >=app-misc/pax-utils-0.1.17
    sys-apps/sandbox-2.13 requires >=app-misc/pax-utils-0.1.19
    sys-libs/glibc-2.27-r5 requires >=app-misc/pax-utils-0.1.10

  app-portage/elt-patches-20170815 pulled in by:
    app-arch/xz-utils-5.2.3 requires >=app-portage/elt-patches-20170422
    app-crypt/pinentry-1.1.0-r2 requires >=app-portage/elt-patches-20170422
    app-eselect/eselect-lib-bin-symlink-0.1.1 requires >=app-portage/elt-patches-20170422
    app-text/openjade-1.3.2-r7 requires >=app-portage/elt-patches-20170422
    app-text/opensp-1.5.2-r6 requires >=app-portage/elt-patches-20170422
    dev-lang/python-2.7.14-r1 requires >=app-portage/elt-patches-20170422
    dev-lang/python-3.6.6 requires >=app-portage/elt-patches-20170422
    dev-libs/expat-2.2.5 requires >=app-portage/elt-patches-20170422
    dev-libs/glib-2.54.3-r6 requires >=app-portage/elt-patches-20170317, >=app-portage/elt-patches-20170422
    dev-libs/gmp-6.1.2 requires >=app-portage/elt-patches-20170422
    dev-libs/iniparser-3.1-r1 requires >=app-portage/elt-patches-20170422
    dev-libs/libassuan-2.5.1 requires >=app-portage/elt-patches-20170422
    dev-libs/libffi-3.2.1 requires >=app-portage/elt-patches-20170422
    dev-libs/libgcrypt-1.8.3 requires >=app-portage/elt-patches-20170422
    dev-libs/libgpg-error-1.29 requires >=app-portage/elt-patches-20170422
    dev-libs/libpcre-8.42 requires >=app-portage/elt-patches-20170422
    dev-libs/libtasn1-4.13 requires >=app-portage/elt-patches-20170422
    dev-libs/libunistring-0.9.10 requires >=app-portage/elt-patches-20170422
    dev-libs/libxml2-2.9.8 requires >=app-portage/elt-patches-20170422
    dev-libs/libxslt-1.1.32 requires >=app-portage/elt-patches-20170422
    dev-libs/mpc-1.0.3 requires >=app-portage/elt-patches-20170422
    dev-libs/mpfr-3.1.6 requires >=app-portage/elt-patches-20170422
    dev-libs/nettle-3.4 requires >=app-portage/elt-patches-20170422
    dev-libs/npth-1.5 requires >=app-portage/elt-patches-20170422
    dev-libs/popt-1.16-r2 requires >=app-portage/elt-patches-20170422
    dev-util/pkgconfig-0.29.2 requires >=app-portage/elt-patches-20170422
    mail-mta/nullmailer-2.0-r2 requires >=app-portage/elt-patches-20170422
    net-firewall/iptables-1.6.1-r3 requires >=app-portage/elt-patches-20170422
    net-libs/gnutls-3.5.18 requires >=app-portage/elt-patches-20170422
    net-libs/libnsl-1.2.0 requires >=app-portage/elt-patches-20170422
    net-libs/libtirpc-1.0.2-r1 requires >=app-portage/elt-patches-20170422
    net-misc/curl-7.60.0-r1 requires >=app-portage/elt-patches-20170422
    net-misc/openssh-7.7_p1-r6 requires >=app-portage/elt-patches-20170422
    sys-apps/acl-2.2.52-r1 requires >=app-portage/elt-patches-20170422
    sys-apps/attr-2.4.47-r2 requires >=app-portage/elt-patches-20170422
    sys-apps/file-5.33-r2 requires >=app-portage/elt-patches-20170422
    sys-apps/groff-1.22.2 requires >=app-portage/elt-patches-20170422
    sys-apps/kmod-25 requires >=app-portage/elt-patches-20170422
    sys-apps/shadow-4.6 requires >=app-portage/elt-patches-20170422
    sys-apps/util-linux-2.32-r3 requires >=app-portage/elt-patches-20170422
    sys-devel/binutils-2.30-r2 requires >=app-portage/elt-patches-20170422
    sys-devel/flex-2.6.4-r1 requires >=app-portage/elt-patches-20170422
    sys-devel/gcc-7.3.0-r3 requires >=app-portage/elt-patches-20170422
    sys-devel/gettext-0.19.8.1 requires >=app-portage/elt-patches-20170422, >=app-portage/elt-patches-20170317
    sys-devel/libtool-2.4.6-r3 requires >=app-portage/elt-patches-20170317, >=app-portage/elt-patches-20170422
    sys-fs/eudev-3.2.5 requires >=app-portage/elt-patches-20170422
    sys-libs/cracklib-2.9.6-r1 requires >=app-portage/elt-patches-20170422
    sys-libs/db-5.3.28-r2 requires >=app-portage/elt-patches-20170422
    sys-libs/gdbm-1.13-r2 requires >=app-portage/elt-patches-20170422
    sys-libs/pam-1.3.0-r2 requires >=app-portage/elt-patches-20170422
    sys-libs/zlib-1.2.11-r1 requires >=app-portage/elt-patches-20170422

  app-portage/gemato-13.1 pulled in by:
    sys-apps/portage-2.3.41 requires >=app-portage/gemato-12.1[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_pypy(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-),-python_single_target_python3_6(-)]

  app-portage/portage-utils-0.64 pulled in by:
    app-admin/perl-cleaner-2.25 requires app-portage/portage-utils
    sys-auth/pambase-20150213-r1 requires app-portage/portage-utils

  app-shells/bash-4.4_p12 pulled in by:
    @system requires app-shells/bash:0
    app-admin/perl-cleaner-2.25 requires app-shells/bash
    sys-apps/portage-2.3.41 requires app-shells/bash:0[readline]

  app-text/build-docbook-catalog-1.21 pulled in by:
    app-text/docbook-xml-dtd-4.1.2-r6 requires >=app-text/build-docbook-catalog-1.2
    app-text/docbook-xsl-stylesheets-1.79.1-r2 requires >=app-text/build-docbook-catalog-1.1

  app-text/docbook-xml-dtd-4.1.2-r6 pulled in by:
    app-text/po4a-0.47-r1 requires app-text/docbook-xml-dtd:4.1.2
    dev-libs/glib-2.54.3-r6 requires app-text/docbook-xml-dtd:4.1.2

  app-text/docbook-xsl-stylesheets-1.79.1-r2 pulled in by:
    app-text/docbook-xml-dtd-4.1.2-r6 requires >=app-text/docbook-xsl-stylesheets-1.65
    app-text/po4a-0.47-r1 requires app-text/docbook-xsl-stylesheets

  app-text/manpager-1 pulled in by:
    sys-apps/man-db-2.8.3 requires app-text/manpager

  app-text/openjade-1.3.2-r7 pulled in by:
    app-text/po4a-0.47-r1 requires app-text/openjade

  app-text/opensp-1.5.2-r6 pulled in by:
    app-text/openjade-1.3.2-r7 requires >=app-text/opensp-1.5.1

  app-text/po4a-0.47-r1 pulled in by:
    sys-apps/man-db-2.8.3 requires >=app-text/po4a-0.45

  app-text/sgml-common-0.6.3-r6 pulled in by:
    app-text/docbook-xml-dtd-4.1.2-r6 requires >=app-text/sgml-common-0.6.3-r2
    app-text/openjade-1.3.2-r7 requires app-text/sgml-common, >=app-text/sgml-common-0.6.3-r2

  dev-lang/perl-5.24.3-r1 pulled in by:
    app-admin/perl-cleaner-2.25 requires dev-lang/perl
    app-text/openjade-1.3.2-r7 requires dev-lang/perl
    app-text/po4a-0.47-r1 requires dev-lang/perl:0/5.24=, dev-lang/perl:=
    dev-libs/libtasn1-4.13 requires >=dev-lang/perl-5.6
    dev-libs/openssl-1.0.2o-r6 requires >=dev-lang/perl-5
    dev-perl/Locale-gettext-1.70.0 requires dev-lang/perl:=, dev-lang/perl:0/5.24=
    dev-perl/Module-Build-0.421.600 requires dev-lang/perl:0/5.24=, dev-lang/perl:=
    dev-perl/SGMLSpm-1.03-r7 requires dev-lang/perl:=[-build(-)], dev-lang/perl:0/5.24=[-build(-)]
    dev-perl/TermReadKey-2.330.0 requires dev-lang/perl:=[-build(-)], dev-lang/perl:0/5.24=[-build(-)]
    dev-perl/Text-CharWidth-0.40.0-r1 requires dev-lang/perl:=[-build(-)], dev-lang/perl:0/5.24=[-build(-)]
    dev-perl/Text-Unidecode-1.270.0 requires dev-lang/perl:0/5.24=[-build(-)], dev-lang/perl:=[-build(-)]
    dev-perl/Text-WrapI18N-0.60.0-r1 requires dev-lang/perl:=[-build(-)], dev-lang/perl:0/5.24=[-build(-)]
    dev-perl/Unicode-EastAsianWidth-1.330.0-r1 requires dev-lang/perl:=[-build(-)], dev-lang/perl:0/5.24=[-build(-)]
    dev-perl/XML-Parser-2.440.0 requires dev-lang/perl:0/5.24=[-build(-)], dev-lang/perl:=[-build(-)]
    dev-perl/libintl-perl-1.240.0-r2 requires dev-lang/perl:0/5.24=, dev-lang/perl:=
    dev-util/gtk-doc-am-1.25-r1 requires >=dev-lang/perl-5.18
    dev-util/intltool-0.51.0-r2 requires dev-lang/perl
    net-dns/libidn2-2.0.5 requires dev-lang/perl
    perl-core/File-Path-2.130.0 requires dev-lang/perl:0/5.24=, dev-lang/perl:=
    perl-core/File-Temp-0.230.400-r1 requires dev-lang/perl:=[-build(-)], dev-lang/perl:0/5.24=[-build(-)]
    sys-apps/groff-1.22.2 requires dev-lang/perl
    sys-apps/help2man-1.47.4 requires dev-lang/perl
    sys-apps/texinfo-6.3 requires dev-lang/perl:=, dev-lang/perl:0/5.24=
    sys-devel/autoconf-2.69-r4 requires >=dev-lang/perl-5.6
    sys-devel/automake-1.15.1-r2 requires dev-lang/perl
    sys-kernel/linux-headers-4.13 requires dev-lang/perl
    virtual/perl-CPAN-Meta-2.150.5-r1 requires dev-lang/perl:0/5.24=, =dev-lang/perl-5.24*, dev-lang/perl:=
    virtual/perl-CPAN-Meta-YAML-0.18.0-r2 requires dev-lang/perl:=, =dev-lang/perl-5.24*, dev-lang/perl:0/5.24=
    virtual/perl-Data-Dumper-2.160.0-r1 requires dev-lang/perl:=, dev-lang/perl:0/5.24=, =dev-lang/perl-5.24*
    virtual/perl-ExtUtils-CBuilder-0.280.225-r2 requires =dev-lang/perl-5.24*, dev-lang/perl:0/5.24=, dev-lang/perl:=
    virtual/perl-ExtUtils-Install-2.40.0-r3 requires =dev-lang/perl-5.24*, dev-lang/perl:=, dev-lang/perl:0/5.24=
    virtual/perl-ExtUtils-MakeMaker-7.100.200_rc-r4 requires dev-lang/perl:0/5.24=, dev-lang/perl:=, =dev-lang/perl-5.24.3*
    virtual/perl-ExtUtils-Manifest-1.700.0-r4 requires dev-lang/perl:=, dev-lang/perl:0/5.24=, =dev-lang/perl-5.24*
    virtual/perl-ExtUtils-ParseXS-3.310.0-r1 requires dev-lang/perl:0/5.24=, =dev-lang/perl-5.24*, dev-lang/perl:=
    virtual/perl-File-Path-2.130.0 requires dev-lang/perl:=, dev-lang/perl:0/5.24=
    virtual/perl-File-Spec-3.630.100_rc-r4 requires dev-lang/perl:=, dev-lang/perl:0/5.24=, =dev-lang/perl-5.24.3*
    virtual/perl-File-Temp-0.230.400-r5 requires dev-lang/perl:0/5.24=, dev-lang/perl:=
    virtual/perl-Getopt-Long-2.480.0-r1 requires dev-lang/perl:0/5.24=, =dev-lang/perl-5.24*, dev-lang/perl:=
    virtual/perl-JSON-PP-2.273.0.100_rc-r6 requires =dev-lang/perl-5.24.3*, dev-lang/perl:0/5.24=, dev-lang/perl:=
    virtual/perl-Module-Metadata-1.0.31-r1 requires =dev-lang/perl-5.24*, dev-lang/perl:=, dev-lang/perl:0/5.24=
    virtual/perl-Parse-CPAN-Meta-1.441.700.100_rc-r4 requires =dev-lang/perl-5.24.3*, dev-lang/perl:=, dev-lang/perl:0/5.24=
    virtual/perl-Perl-OSType-1.9.0-r1 requires =dev-lang/perl-5.24*, dev-lang/perl:0/5.24=, dev-lang/perl:=
    virtual/perl-Test-Harness-3.360.100_rc-r3 requires dev-lang/perl:0/5.24=, dev-lang/perl:=, =dev-lang/perl-5.24.3*
    virtual/perl-Text-ParseWords-3.300.0-r3 requires dev-lang/perl:=, =dev-lang/perl-5.24*, dev-lang/perl:0/5.24=
    virtual/perl-version-0.991.600-r1 requires =dev-lang/perl-5.24*, dev-lang/perl:=, dev-lang/perl:0/5.24=

  dev-lang/python-2.7.14-r1 pulled in by:
    app-portage/gemato-13.1 requires >=dev-lang/python-2.7.5-r2:2.7[threads(+)]
    dev-python/bz2file-0.98 requires >=dev-lang/python-2.7.5-r2:2.7
    dev-python/certifi-2018.4.16 requires >=dev-lang/python-2.7.5-r2:2.7
    dev-python/pyblake2-1.1.2 requires >=dev-lang/python-2.7.5-r2:2.7
    dev-python/pyxattr-0.6.0-r1 requires >=dev-lang/python-2.7.5-r2:2.7
    dev-python/setuptools-38.6.1 requires >=dev-lang/python-2.7.5-r2:2.7[xml(+)]
    sys-apps/portage-2.3.41 requires >=dev-lang/python-2.7.5-r2:2.7[bzip2(+),threads(+)], >=dev-lang/python-2.7.5-r2:2.7[ssl(+)]

  dev-lang/python-3.6.6 pulled in by:
    app-misc/ca-certificates-20170717.3.36.1 requires dev-lang/python:3.6
    app-portage/gemato-13.1 requires dev-lang/python:3.6[threads(+)]
    dev-libs/glib-2.54.3-r6 requires dev-lang/python:3.6
    dev-python/certifi-2018.4.16 requires dev-lang/python:3.6
    dev-python/pyblake2-1.1.2 requires dev-lang/python:3.6
    dev-python/pyxattr-0.6.0-r1 requires dev-lang/python:3.6
    dev-python/setuptools-38.6.1 requires dev-lang/python:3.6[xml(+)]
    sys-apps/portage-2.3.41 requires dev-lang/python:3.6[bzip2(+),threads(+)], dev-lang/python:3.6[ssl(+)]

  dev-lang/python-exec-2.4.5 pulled in by:
    app-eselect/eselect-python-20171204 requires >=dev-lang/python-exec-2.4.2
    app-portage/gemato-13.1 requires >=dev-lang/python-exec-2:2/2=[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_pypy(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-),-python_single_target_python3_6(-)], >=dev-lang/python-exec-2:=[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_pypy(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-),-python_single_target_python3_6(-)]
    dev-libs/glib-2.54.3-r6 requires >=dev-lang/python-exec-2:2/2=[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_jython2_7(-),-python_single_target_pypy(-),-python_single_target_pypy3(-),-python_single_target_python3_4(-),python_single_target_python3_6(+)], >=dev-lang/python-exec-2:=[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_jython2_7(-),-python_single_target_pypy(-),-python_single_target_pypy3(-),-python_single_target_python3_4(-),python_single_target_python3_6(+)]
    dev-python/bz2file-0.98 requires >=dev-lang/python-exec-2:2/2=[python_targets_python2_7(-),-python_single_target_pypy(-),-python_single_target_python2_7(-)], >=dev-lang/python-exec-2:=[python_targets_python2_7(-),-python_single_target_pypy(-),-python_single_target_python2_7(-)]
    dev-python/certifi-2018.4.16 requires >=dev-lang/python-exec-2:2/2=[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_pypy(-),-python_single_target_pypy3(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-),-python_single_target_python3_6(-)], >=dev-lang/python-exec-2:=[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_pypy(-),-python_single_target_pypy3(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-),-python_single_target_python3_6(-)]
    dev-python/pyblake2-1.1.2 requires >=dev-lang/python-exec-2:=[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_pypy(-),-python_single_target_pypy3(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-),-python_single_target_python3_6(-)], >=dev-lang/python-exec-2:2/2=[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_pypy(-),-python_single_target_pypy3(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-),-python_single_target_python3_6(-)]
    dev-python/pyxattr-0.6.0-r1 requires >=dev-lang/python-exec-2:=[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_pypy(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-),-python_single_target_python3_6(-)], >=dev-lang/python-exec-2:2/2=[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_pypy(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-),-python_single_target_python3_6(-)]
    dev-python/setuptools-38.6.1 requires >=dev-lang/python-exec-2:=[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_pypy(-),-python_single_target_pypy3(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-),-python_single_target_python3_6(-)], >=dev-lang/python-exec-2:2/2=[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_pypy(-),-python_single_target_pypy3(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-),-python_single_target_python3_6(-)]
    sys-apps/portage-2.3.41 requires >=dev-lang/python-exec-2:=[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_pypy(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-),-python_single_target_python3_6(-)], >=dev-lang/python-exec-2:2/2=[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_pypy(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-),-python_single_target_python3_6(-)], dev-lang/python-exec:2

  dev-libs/elfutils-0.170-r1 pulled in by:
    virtual/libelf-3 requires >=dev-libs/elfutils-0.155-r1:0/0[abi_x86_64(-)]

  dev-libs/expat-2.2.5 pulled in by:
    dev-lang/python-2.7.14-r1 requires >=dev-libs/expat-2.1
    dev-lang/python-3.6.6 requires >=dev-libs/expat-2.1:0=, >=dev-libs/expat-2.1:0/0=
    dev-perl/XML-Parser-2.440.0 requires >=dev-libs/expat-1.95.1-r1
    sys-devel/gettext-0.19.8.1 requires dev-libs/expat

  dev-libs/glib-2.54.3-r6 pulled in by:
    dev-util/pkgconfig-0.29.2 requires >=dev-libs/glib-2.34.3[abi_x86_64(-)]
    x11-misc/shared-mime-info-1.9 requires >=dev-libs/glib-2

  dev-libs/gmp-6.1.2 pulled in by:
    dev-libs/mpc-1.0.3 requires >=dev-libs/gmp-4.3.2[abi_x86_64(-)]
    dev-libs/mpfr-3.1.6 requires >=dev-libs/gmp-4.1.4-r2[abi_x86_64(-)]
    dev-libs/nettle-3.4 requires >=dev-libs/gmp-5.0:0=[abi_x86_64(-)], >=dev-libs/gmp-5.0:0/10.4=[abi_x86_64(-)]
    net-libs/gnutls-3.5.18 requires >=dev-libs/gmp-5.1.3-r1:=[abi_x86_64(-)], >=dev-libs/gmp-5.1.3-r1:0/10.4=[abi_x86_64(-)]
    sys-devel/gcc-7.3.0-r3 requires >=dev-libs/gmp-4.3.2:0=, >=dev-libs/gmp-4.3.2:0/10.4=

  dev-libs/iniparser-3.1-r1 pulled in by:
    app-portage/portage-utils-0.64 requires dev-libs/iniparser:0

  dev-libs/libassuan-2.5.1 pulled in by:
    app-crypt/gnupg-2.2.8 requires >=dev-libs/libassuan-2.5.0
    app-crypt/pinentry-1.1.0-r2 requires >=dev-libs/libassuan-2.1

  dev-libs/libffi-3.2.1 pulled in by:
    virtual/libffi-3.0.13-r1 requires >=dev-libs/libffi-3.0.13-r1[abi_x86_64(-)]

  dev-libs/libgcrypt-1.8.3 pulled in by:
    app-crypt/gnupg-2.2.8 requires >=dev-libs/libgcrypt-1.7.3
    app-crypt/pinentry-1.1.0-r2 requires >=dev-libs/libgcrypt-1.6.3
    dev-libs/libxslt-1.1.32 requires >=dev-libs/libgcrypt-1.5.3:0/20=[abi_x86_64(-)], >=dev-libs/libgcrypt-1.5.3:0=[abi_x86_64(-)]

  dev-libs/libgpg-error-1.29 pulled in by:
    app-crypt/gnupg-2.2.8 requires >=dev-libs/libgpg-error-1.28
    app-crypt/pinentry-1.1.0-r2 requires >=dev-libs/libgpg-error-1.17
    dev-libs/libassuan-2.5.1 requires >=dev-libs/libgpg-error-1.8
    dev-libs/libgcrypt-1.8.3 requires >=dev-libs/libgpg-error-1.25[abi_x86_64(-)]
    dev-libs/libksba-1.3.5-r1 requires >=dev-libs/libgpg-error-1.8

  dev-libs/libksba-1.3.5-r1 pulled in by:
    app-crypt/gnupg-2.2.8 requires >=dev-libs/libksba-1.3.4

  dev-libs/libltdl-2.4.6 pulled in by:
    sys-devel/libtool-2.4.6-r3 requires dev-libs/libltdl:0

  dev-libs/libpcre-8.42 pulled in by:
    app-admin/metalog-3-r2 requires >=dev-libs/libpcre-3.4
    dev-libs/glib-2.54.3-r6 requires >=dev-libs/libpcre-8.13:3[abi_x86_64(-)]
    net-misc/wget-1.19.5 requires dev-libs/libpcre
    sys-apps/grep-3.0 requires >=dev-libs/libpcre-7.8-r1
    sys-apps/less-529 requires dev-libs/libpcre

  dev-libs/libpipeline-1.5.0 pulled in by:
    sys-apps/man-db-2.8.3 requires >=dev-libs/libpipeline-1.5.0

  dev-libs/libtasn1-4.13 pulled in by:
    net-libs/gnutls-3.5.18 requires >=dev-libs/libtasn1-4.9:0/6=[abi_x86_64(-)], >=dev-libs/libtasn1-4.9:=[abi_x86_64(-)]

  dev-libs/libunistring-0.9.10 pulled in by:
    net-dns/libidn2-2.0.5 requires dev-libs/libunistring[abi_x86_64(-)]
    net-libs/gnutls-3.5.18 requires dev-libs/libunistring:=[abi_x86_64(-)], dev-libs/libunistring:0/2=[abi_x86_64(-)]

  dev-libs/libxml2-2.9.8 pulled in by:
    app-text/build-docbook-catalog-1.21 requires dev-libs/libxml2
    dev-libs/libxslt-1.1.32 requires >=dev-libs/libxml2-2.9.1-r5:2[abi_x86_64(-)]
    sys-devel/gettext-0.19.8.1 requires >=dev-libs/libxml2-2.9.3:2/2=, >=dev-libs/libxml2-2.9.3:=
    x11-misc/shared-mime-info-1.9 requires dev-libs/libxml2

  dev-libs/libxslt-1.1.32 pulled in by:
    app-text/po4a-0.47-r1 requires dev-libs/libxslt
    dev-libs/glib-2.54.3-r6 requires >=dev-libs/libxslt-1.0

  dev-libs/mpc-1.0.3 pulled in by:
    sys-devel/gcc-7.3.0-r3 requires >=dev-libs/mpc-0.8.1:0=, >=dev-libs/mpc-0.8.1:0/0=

  dev-libs/mpfr-3.1.6 pulled in by:
    dev-libs/mpc-1.0.3 requires >=dev-libs/mpfr-2.4.2[abi_x86_64(-)], <dev-libs/mpfr-4.0.0
    sys-devel/gcc-7.3.0-r3 requires >=dev-libs/mpfr-2.4.2:0=, >=dev-libs/mpfr-2.4.2:0/4=

  dev-libs/nettle-3.4 pulled in by:
    net-libs/gnutls-3.5.18 requires >=dev-libs/nettle-3.1:0/6.2=[gmp,abi_x86_64(-)], >=dev-libs/nettle-3.1:=[gmp,abi_x86_64(-)]

  dev-libs/npth-1.5 pulled in by:
    app-crypt/gnupg-2.2.8 requires >=dev-libs/npth-1.2

  dev-libs/openssl-1.0.2o-r6 pulled in by:
    dev-lang/python-2.7.14-r1 requires dev-libs/openssl:0/0=, dev-libs/openssl:0=
    dev-lang/python-3.6.6 requires dev-libs/openssl:0=, dev-libs/openssl:0/0=
    net-misc/curl-7.60.0-r1 requires dev-libs/openssl:0/0=[abi_x86_64(-)], dev-libs/openssl:0=[abi_x86_64(-)]
    net-misc/iputils-20171016_pre-r1 requires dev-libs/openssl:0=, dev-libs/openssl:0/0=
    net-misc/openssh-7.7_p1-r6 requires >=dev-libs/openssl-1.0.1:0/0=[-bindist], >=dev-libs/openssl-1.0.1:0=[-bindist], dev-libs/openssl:0/0=, dev-libs/openssl:0=
    net-misc/wget-1.19.5 requires dev-libs/openssl:0/0=, dev-libs/openssl:0=

  dev-libs/popt-1.16-r2 pulled in by:
    net-misc/rsync-3.1.3 requires >=dev-libs/popt-1.5

  dev-perl/Locale-gettext-1.70.0 pulled in by:
    app-text/po4a-0.47-r1 requires dev-perl/Locale-gettext
    sys-apps/help2man-1.47.4 requires dev-perl/Locale-gettext

  dev-perl/Module-Build-0.421.600 pulled in by:
    app-text/po4a-0.47-r1 requires >=dev-perl/Module-Build-0.380.0

  dev-perl/SGMLSpm-1.03-r7 pulled in by:
    app-text/po4a-0.47-r1 requires dev-perl/SGMLSpm

  dev-perl/TermReadKey-2.330.0 pulled in by:
    app-text/po4a-0.47-r1 requires dev-perl/TermReadKey

  dev-perl/Text-CharWidth-0.40.0-r1 pulled in by:
    dev-perl/Text-WrapI18N-0.60.0-r1 requires dev-perl/Text-CharWidth

  dev-perl/Text-Unidecode-1.270.0 pulled in by:
    sys-apps/texinfo-6.3 requires dev-perl/Text-Unidecode

  dev-perl/Text-WrapI18N-0.60.0-r1 pulled in by:
    app-text/po4a-0.47-r1 requires dev-perl/Text-WrapI18N

  dev-perl/Unicode-EastAsianWidth-1.330.0-r1 pulled in by:
    sys-apps/texinfo-6.3 requires dev-perl/Unicode-EastAsianWidth

  dev-perl/XML-Parser-2.440.0 pulled in by:
    dev-util/intltool-0.51.0-r2 requires dev-perl/XML-Parser

  dev-perl/libintl-perl-1.240.0-r2 pulled in by:
    sys-apps/texinfo-6.3 requires dev-perl/libintl-perl

  dev-python/bz2file-0.98 pulled in by:
    app-portage/gemato-13.1 requires dev-python/bz2file[-python_single_target_pypy(-),python_targets_python2_7(-),-python_single_target_python2_7(-)]

  dev-python/certifi-2018.4.16 pulled in by:
    dev-python/setuptools-38.6.1 requires >=dev-python/certifi-2016.9.26[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_pypy(-),-python_single_target_pypy3(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-),-python_single_target_python3_6(-)]

  dev-python/pyblake2-1.1.2 pulled in by:
    app-portage/gemato-13.1 requires dev-python/pyblake2[-python_single_target_pypy(-),python_targets_python2_7(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-)]
    sys-apps/portage-2.3.41 requires dev-python/pyblake2[-python_single_target_pypy(-),python_targets_python2_7(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-)]

  dev-python/pyxattr-0.6.0-r1 pulled in by:
    sys-apps/portage-2.3.41 requires dev-python/pyxattr[-python_single_target_pypy(-),python_targets_python2_7(-),-python_single_target_python2_7(-)]

  dev-python/setuptools-38.6.1 pulled in by:
    app-portage/gemato-13.1 requires dev-python/setuptools[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_pypy(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-),-python_single_target_python3_6(-)], >=dev-python/setuptools-34[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_pypy(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-),-python_single_target_python3_6(-)]
    dev-python/certifi-2018.4.16 requires dev-python/setuptools[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_pypy(-),-python_single_target_pypy3(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-),-python_single_target_python3_6(-)]
    dev-python/pyblake2-1.1.2 requires dev-python/setuptools[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_pypy(-),-python_single_target_pypy3(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-),-python_single_target_python3_6(-)]
    dev-python/pyxattr-0.6.0-r1 requires dev-python/setuptools[python_targets_python2_7(-),python_targets_python3_6(-),-python_single_target_pypy(-),-python_single_target_python2_7(-),-python_single_target_python3_4(-),-python_single_target_python3_5(-),-python_single_target_python3_6(-)]

  dev-util/gperf-3.0.4 pulled in by:
    sys-fs/eudev-3.2.5 requires dev-util/gperf

  dev-util/gtk-doc-am-1.25-r1 pulled in by:
    dev-libs/glib-2.54.3-r6 requires >=dev-util/gtk-doc-am-1.20
    dev-libs/libxml2-2.9.8 requires dev-util/gtk-doc-am

  dev-util/intltool-0.51.0-r2 pulled in by:
    sys-fs/eudev-3.2.5 requires >=dev-util/intltool-0.50
    x11-misc/shared-mime-info-1.9 requires dev-util/intltool

  dev-util/pkgconfig-0.29.2 pulled in by:
    virtual/pkgconfig-0-r1 requires >=dev-util/pkgconfig-0.28-r1[abi_x86_64(-)]

  mail-mta/nullmailer-2.0-r2 pulled in by:
    virtual/mta-1 requires mail-mta/nullmailer

  net-dns/libidn2-2.0.5 pulled in by:
    net-libs/gnutls-3.5.18 requires >=net-dns/libidn2-0.16-r1[abi_x86_64(-)]

  net-firewall/iptables-1.6.1-r3 pulled in by:
    sys-apps/iproute2-4.14.1-r2 requires >=net-firewall/iptables-1.4.20:0/12=, >=net-firewall/iptables-1.4.20:=

  net-libs/gnutls-3.5.18 pulled in by:
    app-crypt/gnupg-2.2.8 requires >=net-libs/gnutls-3.0:0/30=, >=net-libs/gnutls-3.0:0=
    mail-mta/nullmailer-2.0-r2 requires net-libs/gnutls:0=, net-libs/gnutls:0/30=

  net-libs/libmnl-1.0.4 pulled in by:
    sys-apps/iproute2-4.14.1-r2 requires net-libs/libmnl

  net-libs/libnsl-1.2.0 pulled in by:
    app-text/opensp-1.5.2-r6 requires net-libs/libnsl:0/2=, net-libs/libnsl:0=

  net-libs/libtirpc-1.0.2-r1 pulled in by:
    net-libs/libnsl-1.2.0 requires net-libs/libtirpc[abi_x86_64(-)]

  net-misc/curl-7.60.0-r1 pulled in by:
    app-crypt/gnupg-2.2.8 requires >=net-misc/curl-7.10

  net-misc/iputils-20171016_pre-r1 pulled in by:
    @system requires net-misc/iputils

  net-misc/netifrc-0.5.1 pulled in by:
    sys-apps/openrc-0.34.11 requires net-misc/netifrc

  net-misc/openssh-7.7_p1-r6 pulled in by:
    virtual/ssh-0 requires net-misc/openssh

  net-misc/rsync-3.1.3 pulled in by:
    @system requires net-misc/rsync
    sys-apps/portage-2.3.41 requires >=net-misc/rsync-2.6.4

  net-misc/wget-1.19.5 pulled in by:
    @system requires net-misc/wget

  perl-core/File-Path-2.130.0 pulled in by:
    virtual/perl-File-Path-2.130.0 requires ~perl-core/File-Path-2.130.0

  perl-core/File-Temp-0.230.400-r1 pulled in by:
    virtual/perl-File-Temp-0.230.400-r5 requires ~perl-core/File-Temp-0.230.400

  sys-apps/acl-2.2.52-r1 pulled in by:
    sys-apps/coreutils-8.30 requires sys-apps/acl
    sys-apps/shadow-4.6 requires sys-apps/acl:0/0=, sys-apps/acl:0=
    virtual/acl-0-r2 requires >=sys-apps/acl-2.2.52-r1[abi_x86_64(-)]

  sys-apps/attr-2.4.47-r2 pulled in by:
    app-arch/tar-1.30 requires sys-apps/attr
    dev-libs/glib-2.54.3-r6 requires >=sys-apps/attr-2.4.47-r1[abi_x86_64(-)]
    dev-python/pyxattr-0.6.0-r1 requires sys-apps/attr
    net-misc/rsync-3.1.3 requires sys-apps/attr
    sys-apps/acl-2.2.52-r1 requires >=sys-apps/attr-2.4.47-r1[abi_x86_64(-)]
    sys-apps/coreutils-8.30 requires sys-apps/attr
    sys-apps/shadow-4.6 requires sys-apps/attr:0=, sys-apps/attr:0/0=
    sys-devel/patch-2.7.6-r1 requires sys-apps/attr
    sys-libs/libcap-2.25-r1 requires >=sys-apps/attr-2.4.47-r1[abi_x86_64(-)]

  sys-apps/baselayout-2.6 pulled in by:
    @system requires >=sys-apps/baselayout-2

  sys-apps/busybox-1.28.0 pulled in by:
    @system requires sys-apps/busybox

  sys-apps/coreutils-8.30 pulled in by:
    @system requires sys-apps/coreutils
    app-admin/eselect-1.4.12 requires sys-apps/coreutils
    sys-apps/portage-2.3.41 requires >=sys-apps/coreutils-6.4

  sys-apps/debianutils-4.8.6 pulled in by:
    app-misc/ca-certificates-20170717.3.36.1 requires sys-apps/debianutils

  sys-apps/diffutils-3.5 pulled in by:
    @system requires sys-apps/diffutils

  sys-apps/file-5.33-r2 pulled in by:
    @system requires sys-apps/file
    app-admin/eselect-1.4.12 requires sys-apps/file
    app-editors/nano-2.8.7 requires sys-apps/file

  sys-apps/findutils-4.6.0-r1 pulled in by:
    @system requires >=sys-apps/findutils-4.4

  sys-apps/gawk-4.1.4 pulled in by:
    @system requires sys-apps/gawk

  sys-apps/gentoo-functions-0.12 pulled in by:
    app-portage/elt-patches-20170815 requires sys-apps/gentoo-functions
    net-misc/netifrc-0.5.1 requires sys-apps/gentoo-functions
    sys-devel/binutils-config-5-r4 requires sys-apps/gentoo-functions
    sys-devel/gcc-config-1.8-r1 requires >=sys-apps/gentoo-functions-0.10
    sys-libs/glibc-2.27-r5 requires sys-apps/gentoo-functions

  sys-apps/grep-3.0 pulled in by:
    @system requires sys-apps/grep

  sys-apps/groff-1.22.2 pulled in by:
    mail-mta/nullmailer-2.0-r2 requires sys-apps/groff
    sys-apps/man-db-2.8.3 requires sys-apps/groff

  sys-apps/help2man-1.47.4 pulled in by:
    dev-libs/libtasn1-4.13 requires sys-apps/help2man
    net-dns/libidn2-2.0.5 requires sys-apps/help2man
    sys-devel/automake-1.15.1-r2 requires sys-apps/help2man

  sys-apps/hwids-20171003 pulled in by:
    sys-fs/eudev-3.2.5 requires >=sys-apps/hwids-20140304[udev]

  sys-apps/install-xattr-0.5 pulled in by:
    sys-apps/portage-2.3.41 requires >=sys-apps/install-xattr-0.3

  sys-apps/iproute2-4.14.1-r2 pulled in by:
    @system requires sys-apps/iproute2

  sys-apps/kbd-2.0.4 pulled in by:
    @system requires sys-apps/kbd

  sys-apps/kmod-25 pulled in by:
    sys-fs/eudev-3.2.5 requires >=sys-apps/kmod-16
    virtual/modutils-0 requires sys-apps/kmod[tools]

  sys-apps/less-529 pulled in by:
    @system requires sys-apps/less
    virtual/pager-0 requires sys-apps/less

  sys-apps/man-db-2.8.3 pulled in by:
    virtual/man-0-r1 requires sys-apps/man-db

  sys-apps/man-pages-4.14 pulled in by:
    @system requires sys-apps/man-pages

  sys-apps/man-pages-posix-2013a pulled in by:
    sys-apps/man-pages-4.14 requires sys-apps/man-pages-posix

  sys-apps/net-tools-1.60_p20161110235919 pulled in by:
    @system requires sys-apps/net-tools

  sys-apps/openrc-0.34.11 pulled in by:
    net-misc/netifrc-0.5.1 requires >=sys-apps/openrc-0.15
    virtual/service-manager-0 requires sys-apps/openrc

  sys-apps/opentmpfiles-0.1.3 pulled in by:
    virtual/tmpfiles-0 requires sys-apps/opentmpfiles

  sys-apps/portage-2.3.41 pulled in by:
    app-admin/perl-cleaner-2.25 requires sys-apps/portage
    virtual/package-manager-1 requires sys-apps/portage

  sys-apps/sandbox-2.13 pulled in by:
    sys-apps/portage-2.3.41 requires >=sys-apps/sandbox-2.2

  sys-apps/sed-4.5 pulled in by:
    @system requires sys-apps/sed
    app-admin/eselect-1.4.12 requires sys-apps/sed
    dev-libs/glib-2.54.3-r6 requires >=sys-apps/sed-4
    sys-apps/portage-2.3.41 requires >=sys-apps/sed-4.0.5
    sys-devel/gcc-7.3.0-r3 requires >=sys-apps/sed-4

  sys-apps/shadow-4.6 pulled in by:
    virtual/shadow-0 requires >=sys-apps/shadow-4.1

  sys-apps/sysvinit-2.88-r9 pulled in by:
    sys-apps/openrc-0.34.11 requires >=sys-apps/sysvinit-2.86-r6

  sys-apps/texinfo-6.3 pulled in by:
    sys-fs/e2fsprogs-1.43.9 requires sys-apps/texinfo

  sys-apps/util-linux-2.32-r3 pulled in by:
    @system requires sys-apps/util-linux
    app-text/build-docbook-catalog-1.21 requires sys-apps/util-linux
    dev-libs/glib-2.54.3-r6 requires sys-apps/util-linux[abi_x86_64(-)]
    sys-fs/e2fsprogs-1.43.9 requires >=sys-apps/util-linux-2.16
    sys-fs/eudev-3.2.5 requires >=sys-apps/util-linux-2.20

  sys-apps/which-2.21 pulled in by:
    @system requires sys-apps/which

  sys-auth/pambase-20150213-r1 pulled in by:
    net-misc/openssh-7.7_p1-r6 requires >=sys-auth/pambase-20081028
    sys-apps/openrc-0.34.11 requires sys-auth/pambase
    sys-apps/shadow-4.6 requires >=sys-auth/pambase-20150213
    sys-libs/pam-1.3.0-r2 requires sys-auth/pambase

  sys-devel/autoconf-2.69-r4 pulled in by:
    app-crypt/pinentry-1.1.0-r2 requires >=sys-devel/autoconf-2.69
    app-text/openjade-1.3.2-r7 requires >=sys-devel/autoconf-2.69
    app-text/opensp-1.5.2-r6 requires >=sys-devel/autoconf-2.69
    dev-lang/python-2.7.14-r1 requires >=sys-devel/autoconf-2.65, >=sys-devel/autoconf-2.69
    dev-lang/python-3.6.6 requires >=sys-devel/autoconf-2.69
    dev-libs/expat-2.2.5 requires >=sys-devel/autoconf-2.69
    dev-libs/glib-2.54.3-r6 requires >=sys-devel/autoconf-2.69
    dev-libs/iniparser-3.1-r1 requires >=sys-devel/autoconf-2.69
    dev-libs/libgcrypt-1.8.3 requires >=sys-devel/autoconf-2.69
    dev-libs/libxml2-2.9.8 requires >=sys-devel/autoconf-2.69
    dev-libs/libxslt-1.1.32 requires >=sys-devel/autoconf-2.69
    dev-libs/nettle-3.4 requires >=sys-devel/autoconf-2.69
    mail-mta/nullmailer-2.0-r2 requires >=sys-devel/autoconf-2.69
    net-libs/libnsl-1.2.0 requires >=sys-devel/autoconf-2.69
    net-libs/libtirpc-1.0.2-r1 requires >=sys-devel/autoconf-2.69
    net-misc/curl-7.60.0-r1 requires >=sys-devel/autoconf-2.69
    net-misc/openssh-7.7_p1-r6 requires sys-devel/autoconf, >=sys-devel/autoconf-2.69
    sys-apps/attr-2.4.47-r2 requires sys-devel/autoconf
    sys-apps/groff-1.22.2 requires >=sys-devel/autoconf-2.69
    sys-devel/automake-1.15.1-r2 requires >=sys-devel/autoconf-2.69:*
    sys-devel/libtool-2.4.6-r3 requires >=sys-devel/autoconf-2.69
    sys-fs/eudev-3.2.5 requires >=sys-devel/autoconf-2.69
    sys-libs/db-5.3.28-r2 requires >=sys-devel/autoconf-2.69
    sys-libs/gdbm-1.13-r2 requires >=sys-devel/autoconf-2.69

  sys-devel/autoconf-wrapper-13-r1 pulled in by:
    sys-devel/autoconf-2.69-r4 requires >=sys-devel/autoconf-wrapper-13

  sys-devel/automake-1.15.1-r2 pulled in by:
    app-crypt/pinentry-1.1.0-r2 requires >=sys-devel/automake-1.15.1:1.15
    app-text/openjade-1.3.2-r7 requires >=sys-devel/automake-1.15.1:1.15
    app-text/opensp-1.5.2-r6 requires >=sys-devel/automake-1.15.1:1.15
    dev-lang/python-2.7.14-r1 requires >=sys-devel/automake-1.15.1:1.15
    dev-lang/python-3.6.6 requires >=sys-devel/automake-1.15.1:1.15
    dev-libs/expat-2.2.5 requires >=sys-devel/automake-1.15.1:1.15
    dev-libs/glib-2.54.3-r6 requires >=sys-devel/automake-1.15.1:1.15
    dev-libs/iniparser-3.1-r1 requires >=sys-devel/automake-1.15.1:1.15
    dev-libs/libgcrypt-1.8.3 requires >=sys-devel/automake-1.15.1:1.15
    dev-libs/libxml2-2.9.8 requires >=sys-devel/automake-1.15.1:1.15
    dev-libs/libxslt-1.1.32 requires >=sys-devel/automake-1.15.1:1.15
    dev-libs/nettle-3.4 requires >=sys-devel/automake-1.15.1:1.15
    mail-mta/nullmailer-2.0-r2 requires >=sys-devel/automake-1.15.1:1.15
    net-libs/libnsl-1.2.0 requires >=sys-devel/automake-1.15.1:1.15
    net-libs/libtirpc-1.0.2-r1 requires >=sys-devel/automake-1.15.1:1.15
    net-misc/curl-7.60.0-r1 requires >=sys-devel/automake-1.15.1:1.15
    net-misc/openssh-7.7_p1-r6 requires >=sys-devel/automake-1.15.1:1.15
    sys-apps/groff-1.22.2 requires >=sys-devel/automake-1.15.1:1.15
    sys-devel/libtool-2.4.6-r3 requires >=sys-devel/automake-1.13, >=sys-devel/automake-1.15.1:1.15
    sys-fs/eudev-3.2.5 requires >=sys-devel/automake-1.15.1:1.15
    sys-libs/db-5.3.28-r2 requires >=sys-devel/automake-1.15.1:1.15
    sys-libs/gdbm-1.13-r2 requires >=sys-devel/automake-1.15.1:1.15

  sys-devel/automake-wrapper-10 pulled in by:
    sys-devel/automake-1.15.1-r2 requires >=sys-devel/automake-wrapper-10

  sys-devel/binutils-2.30-r2 pulled in by:
    @system requires sys-devel/binutils
    sys-devel/gcc-7.3.0-r3 requires >=sys-devel/binutils-2.20
    sys-libs/db-5.3.28-r2 requires >=sys-devel/binutils-2.16.1
    sys-libs/glibc-2.27-r5 requires >=sys-devel/binutils-2.24

  sys-devel/binutils-config-5-r4 pulled in by:
    sys-devel/binutils-2.30-r2 requires >=sys-devel/binutils-config-3

  sys-devel/bison-3.0.4-r1 pulled in by:
    sys-apps/iproute2-4.14.1-r2 requires >=sys-devel/bison-2.4
    sys-devel/gcc-7.3.0-r3 requires >=sys-devel/bison-1.875
    sys-libs/glibc-2.27-r5 requires sys-devel/bison
    virtual/yacc-0 requires sys-devel/bison

  sys-devel/flex-2.6.4-r1 pulled in by:
    dev-libs/elfutils-0.170-r1 requires >=sys-devel/flex-2.5.4a
    sys-apps/iproute2-4.14.1-r2 requires sys-devel/flex
    sys-devel/binutils-2.30-r2 requires sys-devel/flex
    sys-devel/bison-3.0.4-r1 requires sys-devel/flex
    sys-devel/gcc-7.3.0-r3 requires >=sys-devel/flex-2.5.4
    sys-libs/pam-1.3.0-r2 requires >=sys-devel/flex-2.5.39-r1[abi_x86_64(-)]

  sys-devel/gcc-7.3.0-r3 pulled in by:
    @system requires sys-devel/gcc
    sys-libs/glibc-2.27-r5 requires >=sys-devel/gcc-4.9

  sys-devel/gcc-config-1.8-r1 pulled in by:
    sys-devel/gcc-7.3.0-r3 requires >=sys-devel/gcc-config-1.7

  sys-devel/gettext-0.19.8.1 pulled in by:
    app-arch/tar-1.30 requires >=sys-devel/gettext-0.10.35
    app-crypt/gnupg-2.2.8 requires sys-devel/gettext
    app-crypt/pinentry-1.1.0-r2 requires sys-devel/gettext
    app-editors/nano-2.8.7 requires sys-devel/gettext
    app-text/opensp-1.5.2-r6 requires sys-devel/gettext
    app-text/po4a-0.47-r1 requires >=sys-devel/gettext-0.13
    dev-libs/elfutils-0.170-r1 requires sys-devel/gettext
    dev-libs/glib-2.54.3-r6 requires >=sys-devel/gettext-0.11
    dev-libs/libgpg-error-1.29 requires sys-devel/gettext
    dev-libs/popt-1.16-r2 requires sys-devel/gettext
    dev-perl/Locale-gettext-1.70.0 requires sys-devel/gettext
    dev-util/intltool-0.51.0-r2 requires sys-devel/gettext
    net-libs/gnutls-3.5.18 requires sys-devel/gettext
    net-misc/wget-1.19.5 requires sys-devel/gettext
    sys-apps/acl-2.2.52-r1 requires sys-devel/gettext
    sys-apps/attr-2.4.47-r2 requires sys-devel/gettext
    sys-apps/diffutils-3.5 requires sys-devel/gettext
    sys-apps/findutils-4.6.0-r1 requires sys-devel/gettext
    sys-apps/gawk-4.1.4 requires sys-devel/gettext
    sys-apps/grep-3.0 requires sys-devel/gettext
    sys-apps/man-db-2.8.3 requires sys-devel/gettext
    sys-apps/sed-4.5 requires sys-devel/gettext
    sys-apps/shadow-4.6 requires sys-devel/gettext
    sys-apps/texinfo-6.3 requires >=sys-devel/gettext-0.19.6
    sys-apps/util-linux-2.32-r3 requires sys-devel/gettext
    sys-devel/binutils-2.30-r2 requires sys-devel/gettext
    sys-devel/bison-3.0.4-r1 requires sys-devel/gettext
    sys-devel/flex-2.6.4-r1 requires sys-devel/gettext
    sys-devel/gcc-7.3.0-r3 requires sys-devel/gettext
    sys-devel/make-4.2.1 requires sys-devel/gettext
    sys-fs/e2fsprogs-1.43.9 requires sys-devel/gettext
    sys-libs/e2fsprogs-libs-1.43.9 requires sys-devel/gettext
    sys-libs/pam-1.3.0-r2 requires sys-devel/gettext
    sys-process/psmisc-23.1-r1 requires sys-devel/gettext
    x11-misc/shared-mime-info-1.9 requires sys-devel/gettext

  sys-devel/gnuconfig-20170101 pulled in by:
    @system requires sys-devel/gnuconfig
    sys-devel/automake-1.15.1-r2 requires sys-devel/gnuconfig
    sys-devel/binutils-2.30-r2 requires sys-devel/gnuconfig
    sys-devel/gcc-7.3.0-r3 requires sys-devel/gnuconfig
    sys-devel/libtool-2.4.6-r3 requires sys-devel/gnuconfig
    sys-libs/glibc-2.27-r5 requires sys-devel/gnuconfig

  sys-devel/libtool-2.4.6-r3 pulled in by:
    app-crypt/pinentry-1.1.0-r2 requires >=sys-devel/libtool-2.4
    app-text/openjade-1.3.2-r7 requires >=sys-devel/libtool-2.4
    app-text/opensp-1.5.2-r6 requires >=sys-devel/libtool-2.4
    dev-libs/expat-2.2.5 requires >=sys-devel/libtool-2.4
    dev-libs/glib-2.54.3-r6 requires >=sys-devel/libtool-2.4
    dev-libs/iniparser-3.1-r1 requires sys-devel/libtool, >=sys-devel/libtool-2.4
    dev-libs/libgcrypt-1.8.3 requires >=sys-devel/libtool-2.4
    dev-libs/libxml2-2.9.8 requires >=sys-devel/libtool-2.4
    dev-libs/libxslt-1.1.32 requires >=sys-devel/libtool-2.4
    dev-libs/nettle-3.4 requires >=sys-devel/libtool-2.4
    mail-mta/nullmailer-2.0-r2 requires >=sys-devel/libtool-2.4
    net-libs/libnsl-1.2.0 requires >=sys-devel/libtool-2.4
    net-libs/libtirpc-1.0.2-r1 requires >=sys-devel/libtool-2.4
    net-misc/curl-7.60.0-r1 requires >=sys-devel/libtool-2.4
    net-misc/openssh-7.7_p1-r6 requires >=sys-devel/libtool-2.4
    sys-apps/groff-1.22.2 requires >=sys-devel/libtool-2.4
    sys-fs/eudev-3.2.5 requires >=sys-devel/libtool-2.4
    sys-libs/db-5.3.28-r2 requires >=sys-devel/libtool-2.4
    sys-libs/gdbm-1.13-r2 requires >=sys-devel/libtool-2.4
    sys-libs/pam-1.3.0-r2 requires >=sys-devel/libtool-2
    sys-process/psmisc-23.1-r1 requires >=sys-devel/libtool-2.2.6b

  sys-devel/m4-1.4.17 pulled in by:
    dev-libs/elfutils-0.170-r1 requires sys-devel/m4
    dev-libs/gmp-6.1.2 requires sys-devel/m4
    sys-devel/autoconf-2.69-r4 requires >=sys-devel/m4-1.4.16
    sys-devel/bison-3.0.4-r1 requires >=sys-devel/m4-1.4.16
    sys-devel/flex-2.6.4-r1 requires sys-devel/m4

  sys-devel/make-4.2.1 pulled in by:
    @system requires sys-devel/make
    sys-fs/eudev-3.2.5 requires >=sys-devel/make-3.82-r4

  sys-devel/patch-2.7.6-r1 pulled in by:
    @system requires >=sys-devel/patch-2.7
    sys-apps/portage-2.3.41 requires sys-devel/patch

  sys-fs/e2fsprogs-1.43.9 pulled in by:
    @system requires sys-fs/e2fsprogs

  sys-fs/eudev-3.2.5 pulled in by:
    virtual/udev-217 requires >=sys-fs/eudev-2.1.1

  sys-fs/udev-init-scripts-32 pulled in by:
    sys-fs/eudev-3.2.5 requires >=sys-fs/udev-init-scripts-26

  sys-kernel/linux-headers-4.13 pulled in by:
    net-firewall/iptables-1.6.1-r3 requires >=sys-kernel/linux-headers-4.4:0
    sys-apps/busybox-1.28.0 requires >=sys-kernel/linux-headers-2.6.39
    sys-apps/iproute2-4.14.1-r2 requires >=sys-kernel/linux-headers-3.16
    sys-fs/eudev-3.2.5 requires >=sys-kernel/linux-headers-2.6.39
    sys-libs/libcap-2.25-r1 requires sys-kernel/linux-headers
    sys-libs/libseccomp-2.3.3 requires >=sys-kernel/linux-headers-4.3
    virtual/os-headers-0 requires sys-kernel/linux-headers:0

  sys-libs/cracklib-2.9.6-r1 pulled in by:
    sys-apps/shadow-4.6 requires >=sys-libs/cracklib-2.7-r3:0/0=, >=sys-libs/cracklib-2.7-r3:0=
    sys-libs/pam-1.3.0-r2 requires >=sys-libs/cracklib-2.9.1-r1[abi_x86_64(-)]

  sys-libs/db-5.3.28-r2 pulled in by:
    dev-lang/perl-5.24.3-r1 requires sys-libs/db:=, sys-libs/db:5.3/5.3=
    sys-apps/iproute2-4.14.1-r2 requires sys-libs/db:=, sys-libs/db:5.3/5.3=
    sys-apps/man-db-2.8.3 requires sys-libs/db:5.3/5.3=, sys-libs/db:=
    sys-libs/pam-1.3.0-r2 requires >=sys-libs/db-4.8.30-r1:=[abi_x86_64(-)], >=sys-libs/db-4.8.30-r1:5.3/5.3=[abi_x86_64(-)]

  sys-libs/e2fsprogs-libs-1.43.9 pulled in by:
    sys-fs/e2fsprogs-1.43.9 requires ~sys-libs/e2fsprogs-libs-1.43.9

  sys-libs/gdbm-1.13-r2 pulled in by:
    dev-lang/perl-5.24.3-r1 requires >=sys-libs/gdbm-1.8.3:0/1.13=, >=sys-libs/gdbm-1.8.3:=
    dev-lang/python-2.7.14-r1 requires sys-libs/gdbm:0/1.13=[berkdb], sys-libs/gdbm:0=[berkdb]
    dev-lang/python-3.6.6 requires sys-libs/gdbm:0=[berkdb], sys-libs/gdbm:0/1.13=[berkdb]
    sys-apps/man-db-2.8.3 requires sys-libs/gdbm:=, sys-libs/gdbm:0/1.13=

  sys-libs/glibc-2.27-r5 pulled in by:
    sys-apps/iproute2-4.14.1-r2 requires >=sys-libs/glibc-2.7
    sys-devel/gcc-7.3.0-r3 requires >=sys-libs/glibc-2.13
    virtual/libc-1 requires sys-libs/glibc:2.2

  sys-libs/libcap-2.25-r1 pulled in by:
    net-misc/iputils-20171016_pre-r1 requires sys-libs/libcap
    sys-libs/pam-1.3.0-r2 requires sys-libs/libcap

  sys-libs/libseccomp-2.3.3 pulled in by:
    app-misc/pax-utils-1.2.3-r1 requires sys-libs/libseccomp
    sys-apps/man-db-2.8.3 requires sys-libs/libseccomp

  sys-libs/ncurses-6.1-r2 pulled in by:
    app-admin/eselect-1.4.12 requires sys-libs/ncurses:0
    app-crypt/pinentry-1.1.0-r2 requires sys-libs/ncurses:0=, sys-libs/ncurses:0/6=
    app-editors/nano-2.8.7 requires sys-libs/ncurses:0=, sys-libs/ncurses:0/6=, >=sys-libs/ncurses-5.9-r1:0/6=[unicode], >=sys-libs/ncurses-5.9-r1:0=[unicode]
    app-shells/bash-4.4_p12 requires >=sys-libs/ncurses-5.2-r2:0=, >=sys-libs/ncurses-5.2-r2:0/6=
    dev-lang/python-2.7.14-r1 requires >=sys-libs/ncurses-5.2:0=, >=sys-libs/ncurses-5.2:0/6=
    dev-lang/python-3.6.6 requires >=sys-libs/ncurses-5.2:0/6=, >=sys-libs/ncurses-5.2:0=
    sys-apps/less-529 requires >=sys-libs/ncurses-5.2:0=, >=sys-libs/ncurses-5.2:0/6=
    sys-apps/openrc-0.34.11 requires sys-libs/ncurses:0=, sys-libs/ncurses:0/6=
    sys-apps/texinfo-6.3 requires >=sys-libs/ncurses-5.2-r2:0/6=, >=sys-libs/ncurses-5.2-r2:0=
    sys-apps/util-linux-2.32-r3 requires >=sys-libs/ncurses-5.2-r2:0/6=[unicode], >=sys-libs/ncurses-5.2-r2:0=[unicode]
    sys-devel/gettext-0.19.8.1 requires sys-libs/ncurses:0=, sys-libs/ncurses:0/6=
    sys-libs/readline-7.0_p3 requires >=sys-libs/ncurses-5.9-r3:0=[abi_x86_64(-)], >=sys-libs/ncurses-5.9-r3:0/6=[abi_x86_64(-)]
    sys-process/procps-3.3.15-r1 requires >=sys-libs/ncurses-5.7-r7:=[unicode], >=sys-libs/ncurses-5.7-r7:0/6=[unicode]
    sys-process/psmisc-23.1-r1 requires >=sys-libs/ncurses-5.7-r7:0=, >=sys-libs/ncurses-5.7-r7:0/6=

  sys-libs/pam-1.3.0-r2 pulled in by:
    sys-apps/util-linux-2.32-r3 requires sys-libs/pam
    sys-auth/pambase-20150213-r1 requires >=sys-libs/pam-1.1.3, sys-libs/pam[cracklib]
    virtual/pam-0-r1 requires >=sys-libs/pam-1.1.6-r2[abi_x86_64(-)]

  sys-libs/readline-7.0_p3 pulled in by:
    app-crypt/gnupg-2.2.8 requires sys-libs/readline:0/7=, sys-libs/readline:0=
    app-shells/bash-4.4_p12 requires >=sys-libs/readline-7.0:0=, >=sys-libs/readline-7.0:0/7=
    dev-lang/python-2.7.14-r1 requires >=sys-libs/readline-4.1:0=, >=sys-libs/readline-4.1:0/7=
    dev-lang/python-3.6.6 requires >=sys-libs/readline-4.1:0=, >=sys-libs/readline-4.1:0/7=
    dev-libs/libpcre-8.42 requires sys-libs/readline:0/7=, sys-libs/readline:0=
    dev-libs/libxml2-2.9.8 requires sys-libs/readline:0/7=, sys-libs/readline:=
    sys-apps/gawk-4.1.4 requires sys-libs/readline:0/7=, sys-libs/readline:0=
    sys-apps/util-linux-2.32-r3 requires sys-libs/readline:0/7=, sys-libs/readline:0=
    sys-libs/gdbm-1.13-r2 requires sys-libs/readline:0/7=[abi_x86_64(-)], sys-libs/readline:0=[abi_x86_64(-)]

  sys-libs/timezone-data-2018d pulled in by:
    sys-libs/glibc-2.27-r5 requires sys-libs/timezone-data

  sys-libs/zlib-1.2.11-r1 pulled in by:
    app-crypt/gnupg-2.2.8 requires sys-libs/zlib
    dev-lang/perl-5.24.3-r1 requires sys-libs/zlib
    dev-lang/python-2.7.14-r1 requires >=sys-libs/zlib-1.1.3:0=, >=sys-libs/zlib-1.1.3:0/1=
    dev-lang/python-3.6.6 requires >=sys-libs/zlib-1.1.3:0/1=, >=sys-libs/zlib-1.1.3:0=
    dev-libs/elfutils-0.170-r1 requires >=sys-libs/zlib-1.2.8-r1[abi_x86_64(-)]
    dev-libs/glib-2.54.3-r6 requires >=sys-libs/zlib-1.2.8-r1[abi_x86_64(-)]
    dev-libs/libpcre-8.42 requires sys-libs/zlib
    dev-libs/libxml2-2.9.8 requires >=sys-libs/zlib-1.2.8-r1:=[abi_x86_64(-)], >=sys-libs/zlib-1.2.8-r1:0/1=[abi_x86_64(-)]
    dev-libs/openssl-1.0.2o-r6 requires >=sys-libs/zlib-1.2.8-r1[abi_x86_64(-)]
    net-libs/gnutls-3.5.18 requires >=sys-libs/zlib-1.2.8-r1[abi_x86_64(-)]
    net-misc/curl-7.60.0-r1 requires sys-libs/zlib[abi_x86_64(-)]
    net-misc/openssh-7.7_p1-r6 requires >=sys-libs/zlib-1.2.3:0/1=, >=sys-libs/zlib-1.2.3:=
    net-misc/wget-1.19.5 requires sys-libs/zlib
    sys-apps/file-5.33-r2 requires >=sys-libs/zlib-1.2.8-r1[abi_x86_64(-)]
    sys-apps/kmod-25 requires >=sys-libs/zlib-1.2.6
    sys-apps/man-db-2.8.3 requires sys-libs/zlib
    sys-apps/util-linux-2.32-r3 requires sys-libs/zlib:=, sys-libs/zlib:0/1=
    sys-devel/binutils-2.30-r2 requires sys-libs/zlib
    sys-devel/gcc-7.3.0-r3 requires sys-libs/zlib
    sys-libs/cracklib-2.9.6-r1 requires >=sys-libs/zlib-1.2.8-r1[abi_x86_64(-)]

  sys-process/procps-3.3.15-r1 pulled in by:
    @system requires sys-process/procps

  sys-process/psmisc-23.1-r1 pulled in by:
    @system requires sys-process/psmisc
    sys-apps/openrc-0.34.11 requires sys-process/psmisc

  virtual/acl-0-r2 pulled in by:
    app-arch/tar-1.30 requires virtual/acl, =virtual/acl-0-r2
    net-misc/rsync-3.1.3 requires virtual/acl, =virtual/acl-0-r2
    sys-apps/sed-4.5 requires virtual/acl, =virtual/acl-0-r2
    sys-devel/gettext-0.19.8.1 requires =virtual/acl-0-r2, virtual/acl

  virtual/dev-manager-0-r1 pulled in by:
    @system requires virtual/dev-manager

  virtual/editor-0-r1 pulled in by:
    @system requires virtual/editor

  virtual/libc-1 pulled in by:
    @system requires virtual/libc

  virtual/libelf-3 pulled in by:
    sys-apps/iproute2-4.14.1-r2 requires =virtual/libelf-3, virtual/libelf

  virtual/libffi-3.0.13-r1 pulled in by:
    dev-lang/python-2.7.14-r1 requires virtual/libffi, =virtual/libffi-3.0.13-r1
    dev-lang/python-3.6.6 requires virtual/libffi, =virtual/libffi-3.0.13-r1
    dev-libs/glib-2.54.3-r6 requires =virtual/libffi-3.0.13-r1[abi_x86_64(-)], >=virtual/libffi-3.0.13-r1[abi_x86_64(-)]

  virtual/libiconv-0-r2 pulled in by:
    dev-libs/glib-2.54.3-r6 requires >=virtual/libiconv-0-r1[abi_x86_64(-)], =virtual/libiconv-0-r2[abi_x86_64(-)]
    net-misc/rsync-3.1.3 requires virtual/libiconv, =virtual/libiconv-0-r2
    sys-apps/grep-3.0 requires virtual/libiconv, =virtual/libiconv-0-r2
    sys-devel/gcc-7.3.0-r3 requires virtual/libiconv, =virtual/libiconv-0-r2
    sys-devel/gettext-0.19.8.1 requires =virtual/libiconv-0-r2[abi_x86_64(-)], >=virtual/libiconv-0-r1[abi_x86_64(-)]

  virtual/libintl-0-r2 pulled in by:
    app-crypt/gnupg-2.2.8 requires virtual/libintl, =virtual/libintl-0-r2
    app-editors/nano-2.8.7 requires =virtual/libintl-0-r2, virtual/libintl
    app-shells/bash-4.4_p12 requires virtual/libintl, =virtual/libintl-0-r2
    dev-lang/python-2.7.14-r1 requires =virtual/libintl-0-r2, virtual/libintl
    dev-lang/python-3.6.6 requires virtual/libintl, =virtual/libintl-0-r2
    dev-libs/glib-2.54.3-r6 requires =virtual/libintl-0-r2[abi_x86_64(-)], >=virtual/libintl-0-r2[abi_x86_64(-)]
    dev-libs/libgpg-error-1.29 requires >=virtual/libintl-0-r1[abi_x86_64(-)], =virtual/libintl-0-r2[abi_x86_64(-)]
    dev-libs/popt-1.16-r2 requires =virtual/libintl-0-r2[abi_x86_64(-)], >=virtual/libintl-0-r1[abi_x86_64(-)]
    dev-perl/libintl-perl-1.240.0-r2 requires =virtual/libintl-0-r2, virtual/libintl
    dev-util/pkgconfig-0.29.2 requires virtual/libintl, =virtual/libintl-0-r2
    net-libs/gnutls-3.5.18 requires >=virtual/libintl-0-r1[abi_x86_64(-)], =virtual/libintl-0-r2[abi_x86_64(-)]
    sys-apps/coreutils-8.30 requires =virtual/libintl-0-r2, virtual/libintl
    sys-apps/findutils-4.6.0-r1 requires virtual/libintl, =virtual/libintl-0-r2
    sys-apps/grep-3.0 requires =virtual/libintl-0-r2, virtual/libintl
    sys-apps/sed-4.5 requires virtual/libintl, =virtual/libintl-0-r2
    sys-apps/shadow-4.6 requires virtual/libintl, =virtual/libintl-0-r2
    sys-apps/texinfo-6.3 requires =virtual/libintl-0-r2, virtual/libintl
    sys-apps/util-linux-2.32-r3 requires virtual/libintl[abi_x86_64(-)], =virtual/libintl-0-r2[abi_x86_64(-)]
    sys-devel/gcc-7.3.0-r3 requires virtual/libintl, =virtual/libintl-0-r2
    sys-devel/gettext-0.19.8.1 requires >=virtual/libintl-0-r2[abi_x86_64(-)], =virtual/libintl-0-r2[abi_x86_64(-)]
    sys-devel/make-4.2.1 requires =virtual/libintl-0-r2, virtual/libintl
    sys-fs/e2fsprogs-1.43.9 requires virtual/libintl, =virtual/libintl-0-r2
    sys-libs/pam-1.3.0-r2 requires >=virtual/libintl-0-r1[abi_x86_64(-)], =virtual/libintl-0-r2[abi_x86_64(-)]
    sys-libs/timezone-data-2018d requires =virtual/libintl-0-r2, virtual/libintl
    sys-process/psmisc-23.1-r1 requires =virtual/libintl-0-r2, virtual/libintl

  virtual/logger-0 pulled in by:
    mail-mta/nullmailer-2.0-r2 requires virtual/logger, =virtual/logger-0

  virtual/man-0-r1 pulled in by:
    @system requires virtual/man
    sys-apps/man-pages-4.14 requires =virtual/man-0-r1, virtual/man
    sys-apps/man-pages-posix-2013a requires virtual/man, =virtual/man-0-r1

  virtual/modutils-0 pulled in by:
    @system requires virtual/modutils

  virtual/mta-1 pulled in by:
    app-crypt/gnupg-2.2.8 requires =virtual/mta-1, virtual/mta

  virtual/os-headers-0 pulled in by:
    @system requires virtual/os-headers
    net-firewall/iptables-1.6.1-r3 requires virtual/os-headers, =virtual/os-headers-0
    net-misc/iputils-20171016_pre-r1 requires virtual/os-headers, =virtual/os-headers-0
    net-misc/openssh-7.7_p1-r6 requires =virtual/os-headers-0, virtual/os-headers
    sys-apps/openrc-0.34.11 requires =virtual/os-headers-0, virtual/os-headers
    sys-apps/sysvinit-2.88-r9 requires =virtual/os-headers-0, virtual/os-headers
    sys-apps/util-linux-2.32-r3 requires virtual/os-headers, =virtual/os-headers-0
    sys-fs/eudev-3.2.5 requires =virtual/os-headers-0, virtual/os-headers
    sys-libs/glibc-2.27-r5 requires virtual/os-headers, =virtual/os-headers-0

  virtual/package-manager-1 pulled in by:
    @system requires virtual/package-manager

  virtual/pager-0 pulled in by:
    @system requires virtual/pager

  virtual/pam-0-r1 pulled in by:
    net-misc/openssh-7.7_p1-r6 requires =virtual/pam-0-r1, virtual/pam
    sys-apps/kbd-2.0.4 requires =virtual/pam-0-r1, virtual/pam
    sys-apps/openrc-0.34.11 requires =virtual/pam-0-r1, virtual/pam
    sys-apps/shadow-4.6 requires virtual/pam:0=, =virtual/pam-0-r1, virtual/pam:0/0=
    sys-libs/libcap-2.25-r1 requires virtual/pam, =virtual/pam-0-r1

  virtual/perl-CPAN-Meta-2.150.5-r1 pulled in by:
    dev-perl/Module-Build-0.421.600 requires =virtual/perl-CPAN-Meta-2.150.5-r1, >=virtual/perl-CPAN-Meta-2.142.60

  virtual/perl-CPAN-Meta-YAML-0.18.0-r2 pulled in by:
    dev-perl/Module-Build-0.421.600 requires >=virtual/perl-CPAN-Meta-YAML-0.3.0
    virtual/perl-CPAN-Meta-2.150.5-r1 requires >=virtual/perl-CPAN-Meta-YAML-0.11.0

  virtual/perl-Data-Dumper-2.160.0-r1 pulled in by:
    dev-lang/perl-5.24.3-r1 requires >=virtual/perl-Data-Dumper-2.154.0
    dev-perl/Module-Build-0.421.600 requires virtual/perl-Data-Dumper

  virtual/perl-ExtUtils-CBuilder-0.280.225-r2 pulled in by:
    dev-perl/Module-Build-0.421.600 requires >=virtual/perl-ExtUtils-CBuilder-0.270.0

  virtual/perl-ExtUtils-Install-2.40.0-r3 pulled in by:
    dev-perl/Module-Build-0.421.600 requires virtual/perl-ExtUtils-Install

  virtual/perl-ExtUtils-MakeMaker-7.100.200_rc-r4 pulled in by:
    dev-perl/Locale-gettext-1.70.0 requires virtual/perl-ExtUtils-MakeMaker
    dev-perl/Module-Build-0.421.600 requires virtual/perl-ExtUtils-MakeMaker
    dev-perl/TermReadKey-2.330.0 requires virtual/perl-ExtUtils-MakeMaker
    dev-perl/Text-Unidecode-1.270.0 requires virtual/perl-ExtUtils-MakeMaker
    dev-perl/Unicode-EastAsianWidth-1.330.0-r1 requires virtual/perl-ExtUtils-MakeMaker
    dev-perl/libintl-perl-1.240.0-r2 requires virtual/perl-ExtUtils-MakeMaker

  virtual/perl-ExtUtils-Manifest-1.700.0-r4 pulled in by:
    dev-perl/Module-Build-0.421.600 requires virtual/perl-ExtUtils-Manifest

  virtual/perl-ExtUtils-ParseXS-3.310.0-r1 pulled in by:
    dev-perl/Module-Build-0.421.600 requires >=virtual/perl-ExtUtils-ParseXS-2.210.0

  virtual/perl-File-Path-2.130.0 pulled in by:
    dev-lang/perl-5.24.3-r1 requires >=virtual/perl-File-Path-2.130.0

  virtual/perl-File-Spec-3.630.100_rc-r4 pulled in by:
    dev-perl/Module-Build-0.421.600 requires >=virtual/perl-File-Spec-0.820.0
    dev-perl/Unicode-EastAsianWidth-1.330.0-r1 requires virtual/perl-File-Spec

  virtual/perl-File-Temp-0.230.400-r5 pulled in by:
    dev-lang/perl-5.24.3-r1 requires >=virtual/perl-File-Temp-0.230.400-r2
    dev-perl/Module-Build-0.421.600 requires >=virtual/perl-File-Temp-0.150.0

  virtual/perl-Getopt-Long-2.480.0-r1 pulled in by:
    dev-perl/Module-Build-0.421.600 requires virtual/perl-Getopt-Long

  virtual/perl-JSON-PP-2.273.0.100_rc-r6 pulled in by:
    virtual/perl-CPAN-Meta-2.150.5-r1 requires >=virtual/perl-JSON-PP-2.271.30

  virtual/perl-Module-Metadata-1.0.31-r1 pulled in by:
    dev-perl/Module-Build-0.421.600 requires >=virtual/perl-Module-Metadata-1.0.2

  virtual/perl-Parse-CPAN-Meta-1.441.700.100_rc-r4 pulled in by:
    dev-perl/Module-Build-0.421.600 requires >=virtual/perl-Parse-CPAN-Meta-1.440.100
    virtual/perl-CPAN-Meta-2.150.5-r1 requires >=virtual/perl-Parse-CPAN-Meta-1.441.400

  virtual/perl-Perl-OSType-1.9.0-r1 pulled in by:
    dev-perl/Module-Build-0.421.600 requires >=virtual/perl-Perl-OSType-1

  virtual/perl-Test-Harness-3.360.100_rc-r3 pulled in by:
    dev-lang/perl-5.24.3-r1 requires virtual/perl-Test-Harness
    dev-perl/Module-Build-0.421.600 requires virtual/perl-Test-Harness

  virtual/perl-Text-ParseWords-3.300.0-r3 pulled in by:
    dev-perl/Module-Build-0.421.600 requires virtual/perl-Text-ParseWords

  virtual/perl-version-0.991.600-r1 pulled in by:
    dev-perl/Module-Build-0.421.600 requires >=virtual/perl-version-0.870.0

  virtual/pkgconfig-0-r1 pulled in by:
    app-admin/metalog-3-r2 requires =virtual/pkgconfig-0-r1, virtual/pkgconfig
    app-crypt/gnupg-2.2.8 requires virtual/pkgconfig, =virtual/pkgconfig-0-r1
    app-crypt/pinentry-1.1.0-r2 requires =virtual/pkgconfig-0-r1, virtual/pkgconfig
    app-editors/nano-2.8.7 requires =virtual/pkgconfig-0-r1, virtual/pkgconfig
    app-misc/pax-utils-1.2.3-r1 requires =virtual/pkgconfig-0-r1, virtual/pkgconfig
    dev-lang/python-2.7.14-r1 requires =virtual/pkgconfig-0-r1, virtual/pkgconfig
    dev-lang/python-3.6.6 requires =virtual/pkgconfig-0-r1, virtual/pkgconfig
    dev-libs/libpcre-8.42 requires virtual/pkgconfig, =virtual/pkgconfig-0-r1
    dev-libs/libpipeline-1.5.0 requires virtual/pkgconfig, =virtual/pkgconfig-0-r1
    dev-libs/libxml2-2.9.8 requires virtual/pkgconfig, =virtual/pkgconfig-0-r1
    dev-util/gtk-doc-am-1.25-r1 requires virtual/pkgconfig, =virtual/pkgconfig-0-r1
    mail-mta/nullmailer-2.0-r2 requires =virtual/pkgconfig-0-r1, virtual/pkgconfig
    net-firewall/iptables-1.6.1-r3 requires virtual/pkgconfig, =virtual/pkgconfig-0-r1
    net-libs/gnutls-3.5.18 requires =virtual/pkgconfig-0-r1[abi_x86_64(-)], >=virtual/pkgconfig-0-r1[abi_x86_64(-)]
    net-libs/libtirpc-1.0.2-r1 requires >=virtual/pkgconfig-0-r1[abi_x86_64(-)], =virtual/pkgconfig-0-r1[abi_x86_64(-)]
    net-misc/curl-7.60.0-r1 requires >=virtual/pkgconfig-0-r1[abi_x86_64(-)], =virtual/pkgconfig-0-r1[abi_x86_64(-)]
    net-misc/netifrc-0.5.1 requires =virtual/pkgconfig-0-r1, virtual/pkgconfig
    net-misc/openssh-7.7_p1-r6 requires virtual/pkgconfig, =virtual/pkgconfig-0-r1
    net-misc/rsync-3.1.3 requires =virtual/pkgconfig-0-r1, virtual/pkgconfig
    net-misc/wget-1.19.5 requires =virtual/pkgconfig-0-r1, virtual/pkgconfig
    sys-apps/grep-3.0 requires =virtual/pkgconfig-0-r1, virtual/pkgconfig
    sys-apps/hwids-20171003 requires =virtual/pkgconfig-0-r1, virtual/pkgconfig
    sys-apps/iproute2-4.14.1-r2 requires =virtual/pkgconfig-0-r1, virtual/pkgconfig
    sys-apps/kbd-2.0.4 requires virtual/pkgconfig, =virtual/pkgconfig-0-r1
    sys-apps/kmod-25 requires virtual/pkgconfig, =virtual/pkgconfig-0-r1
    sys-apps/man-db-2.8.3 requires virtual/pkgconfig, =virtual/pkgconfig-0-r1
    sys-apps/openrc-0.34.11 requires =virtual/pkgconfig-0-r1, virtual/pkgconfig
    sys-apps/portage-2.3.41 requires virtual/pkgconfig, =virtual/pkgconfig-0-r1
    sys-apps/util-linux-2.32-r3 requires virtual/pkgconfig, =virtual/pkgconfig-0-r1
    sys-fs/e2fsprogs-1.43.9 requires virtual/pkgconfig, =virtual/pkgconfig-0-r1
    sys-fs/eudev-3.2.5 requires virtual/pkgconfig, =virtual/pkgconfig-0-r1
    sys-libs/e2fsprogs-libs-1.43.9 requires =virtual/pkgconfig-0-r1, virtual/pkgconfig
    sys-libs/glibc-2.27-r5 requires virtual/pkgconfig, =virtual/pkgconfig-0-r1
    sys-libs/readline-7.0_p3 requires =virtual/pkgconfig-0-r1, virtual/pkgconfig
    sys-process/procps-3.3.15-r1 requires =virtual/pkgconfig-0-r1, virtual/pkgconfig
    x11-misc/shared-mime-info-1.9 requires virtual/pkgconfig, =virtual/pkgconfig-0-r1

  virtual/service-manager-0 pulled in by:
    @system requires virtual/service-manager

  virtual/shadow-0 pulled in by:
    @system requires virtual/shadow
    mail-mta/nullmailer-2.0-r2 requires =virtual/shadow-0, virtual/shadow
    net-misc/openssh-7.7_p1-r6 requires =virtual/shadow-0, virtual/shadow

  virtual/ssh-0 pulled in by:
    @system requires virtual/ssh

  virtual/tmpfiles-0 pulled in by:
    sys-apps/openrc-0.34.11 requires virtual/tmpfiles, =virtual/tmpfiles-0

  virtual/udev-217 pulled in by:
    sys-apps/hwids-20171003 requires =virtual/udev-217, virtual/udev
    sys-fs/udev-init-scripts-32 requires =virtual/udev-217, >=virtual/udev-217
    virtual/dev-manager-0-r1 requires =virtual/udev-217, virtual/udev

  virtual/yacc-0 pulled in by:
    dev-libs/libtasn1-4.13 requires virtual/yacc, =virtual/yacc-0
    sys-devel/binutils-2.30-r2 requires =virtual/yacc-0, virtual/yacc

  x11-misc/shared-mime-info-1.9 pulled in by:
    dev-libs/glib-2.54.3-r6 requires x11-misc/shared-mime-info

>>> Calculating removal order...

>>> These are the packages that would be unmerged:

 dev-lang/python
    selected: 3.5.5 
   protected: none 
     omitted: 2.7.14-r1 3.6.6 

All selected packages: =dev-lang/python-3.5.5

>>> 'Selected' packages are slated for removal.
>>> 'Protected' and 'omitted' packages will not be removed.

Would you like to unmerge these packages? [Yes/No] Yes
>>> Waiting 5 seconds before starting...
>>> (Control-C to abort)...
>>> Unmerging in: 5 4 3 2 1
>>> Unmerging (1 of 1) dev-lang/python-3.5.5...
Packages installed:   205
Packages in world:    0
Packages in system:   43
Required packages:    205
Number removed:       1

 * GNU info directory index is up-to-date.
livecd ~ #
```

We add two variables to our `/etc/portage/make.conf` file, `PYTHON_TARGETS` and `PYTHON_SINGLE_TARGET`. 

To update our system we use `emerge` with differens options:

- `--depclean`: cleans the system by removing packages that are not associated with explicitly merged packages.
- `-1`: it's the same of `--oneshot`.
- `-U`: the same as `--changed-use`, tells emerge to include installed packages where `USE` flags have changed since installation.
- `-D`: the same as `--deep`, this  flag forces emerge to consider the entire dependency tree of packages, instead of checking only the immediate dependencies of the packages.

We use `--deepclean` two times.

