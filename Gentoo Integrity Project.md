## Introducing integrity within Gentoo Linux - part 1.

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
livecd ~ # mkfs.ext4 -m 0 -L "home" /dev/mapper/vg1-home^C
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
livecd /mnt/gentoo # tar xJpf stage3-amd64-20180624T214502Z.tar.xz --xattrs-include='*.*' --numeric-owner
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