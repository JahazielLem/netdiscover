# Building and running netdiscover on macOS

This document describes how to build netdiscover on macOS and the changes
that were made to the source to support it.

## Requirements

- Xcode Command Line Tools (`xcode-select --install`), which provide clang
  and libpcap (headers and library are part of the macOS SDK).
- Autotools, e.g. via Homebrew:

  ```
  brew install autoconf automake
  ```

No extra libraries are needed: libpcap ships with macOS.

## Build

```
./update-oui-database.sh   # optional, refreshes the MAC vendor table
./autogen.sh
./configure
make
```

The binary is `src/netdiscover`. `sudo make install` installs it to
`/usr/local/sbin`.

## Run

Root privileges are needed to open the BPF devices (`/dev/bpf*`):

```
ifconfig                                   # find your interface, e.g. en0
sudo ./src/netdiscover -i en0 -r 192.168.1.0/24
```

Notes:

- If `-i` is not given, the first interface that is up, is not loopback and
  has an IPv4 address is selected (on macOS the first pcap device is often a
  tunnel or bridge, which cannot be used for ARP).
- Only Ethernet-type interfaces (Ethernet and Wi-Fi, `en*`) are supported;
  `utun*`, `lo0`, etc. are rejected with "not an Ethernet interface".
- Without `-r`, a set of common private ranges is scanned, which is slow.
  Restricting the range with `-r` is recommended.
- Passive mode (`-p`) only sniffs and does not inject packets.

## Source changes for macOS support

| File | Change |
|------|--------|
| `src/ifaces.c` | The interface MAC address is read with `getifaddrs()` and `AF_LINK`/`sockaddr_dl` on macOS/BSD. Previously this was only implemented for Linux (`SIOCGIFHWADDR`) and the MAC stayed `00:00:00:00:00:00` elsewhere, producing invalid ARP requests. |
| `src/ifaces.c` | The sniffer opens the device with `pcap_create()` + `pcap_set_immediate_mode()`. On macOS, BPF otherwise holds packets until its buffer fills or the read timeout expires, delaying results. |
| `src/ifaces.h`, `src/misc.c` | Headers are included in a portable order (`sys/types.h`, `sys/socket.h`, `net/if.h`, `netinet/in.h` before `netinet/if_ether.h`), as required by the macOS SDK. |
| `src/main.c` | Smarter automatic interface selection (see above). |
| `src/screen.c` | The interactive screen clears the terminal on first draw, on window resize and on view change, and writes escape sequences through `stdout` instead of `stderr`. Previously, leftover terminal contents (e.g. `make` output) could appear between the header lines. |
| `.gitignore` | Ignores autotools-generated files and build outputs. |

Linux behaviour is unchanged.

## Troubleshooting

- **`pcap_activate(): ... Permission denied`**: run with `sudo`.
- **`en0: not an Ethernet interface`**: pick another interface with `-i`.
- **`0 Captured ARP Req/Rep packets`**: check that the interface is the one
  connected to the target network and that the range given with `-r`
  matches its subnet.
- **`configure: error: Cannot find pcap.h`**: install the Command Line Tools
  (`xcode-select --install`).
