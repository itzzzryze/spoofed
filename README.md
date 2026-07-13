# Spoofed?

check if your hardware serials are actually spoofed or not. pulls real IOCTL-level data instead of just trusting WMI like most tools do.

<img width="2024" height="2376" alt="spoofed" src="https://github.com/user-attachments/assets/0ad0f91e-1f59-44fa-9498-48e8c0c2a943" />

## latest update

- smarter comparison with separate **Important** and **All values** tabs
- clear Pass, Stable, Attention, Info, and Unavailable results
- comparison logic now understands generic serials, hidden identifiers, RAID storage, ARP entries, and TPM state
- dedicated TPM page with status, ownership, manufacturer details, endorsement-key serial, and thumbprint
- improved native disk queries for Storage Property, SMART, WWN, SCSI pass-through, and ATA pass-through
- values can be selected and copied directly
- redesigned interface with larger text, clearer grouping, smoother animations, and cleaner navigation

## what it does

- **disk serials (nvme + sata)**  talks directly to your drives via IOCTL, grabs the real serial/firmware/wwn. shows `00000000` for unsupported fields instead of making stuff up, this is good for eac games and it bypasses some spoofers that block getting drive information
- **tpm checks**  checks if your tpm is actually owned by the OS, pulls the endorsement key and sows sha256, checks if tpm is enabled or off and checks if its a dtpm or ftpm
- **usb / peripherals** - shows (only) real usb serials and has a option to clean ghost usb's devices
- **ram, volume serials, machine guid, monitor, arp, gpu, etc.**  all the usual tracking vectors from ac's
- **live compare**  take a snapshot, change something (swap a usb, spoof a mac, whatever), run it again and diff the results in comparison view
- **auto admin**  asks for UAC on launch since it needs it for WMI/registry access
 
## built with

- C# / .NET
- WPF
- WMI + Ps (barely)

## building

```
dotnet build
dotnet run
```

needs admin to run (to get tpm, network adapters, etc).


*claudius pluribus opium​*
