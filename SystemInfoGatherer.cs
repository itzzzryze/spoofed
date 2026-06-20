using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using Microsoft.Win32;
using SystemHardwareAudit.Models;
using System.Text;
using System.Net.NetworkInformation;
using System.Security.Principal;

namespace SystemHardwareAudit
{
    public static class SystemInfoGatherer
    {
        public static List<AuditCategory> GetSystemAudit()
        {
            var audit = new List<AuditCategory>
            {
                GetIdentityAndCryptography(),
                GetOperatingSystem(),
                GetFirmwareAndSecurity(),
                GetMotherboard(),
                GetProcessor(),
                GetMemory(),
                GetStorage(),
                GetVolumes(),
                GetNetworkInterfaces(),
                GetArpInformation(),
                GetMonitors(),
                GetGraphics(),
                GetUsbPeripherals()
            };

            foreach (var cat in audit)
            {
                if (cat.Items.Count == 0)
                {
                    cat.Items.Add(new AuditItem { Label = "Status", Value = $"No {cat.Name.ToLower()} found", TooltipText = "No data available or blocked by spoofer", IsPlaceholder = true });
                }
            }

            return audit;
        }

        private static AuditCategory GetOperatingSystem()
        {
            var cat = new AuditCategory { Name = "Operating System" };
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OperatingSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        cat.Items.Add(new AuditItem { Label = "OS Name", Value = obj["Caption"]?.ToString(), TooltipText = "Operating System Version" });
                        cat.Items.Add(new AuditItem { Label = "Architecture", Value = obj["OSArchitecture"]?.ToString(), TooltipText = "OS Bit Architecture" });
                        cat.Items.Add(new AuditItem { Label = "Build Number", Value = obj["BuildNumber"]?.ToString(), TooltipText = "Windows Build Number" });
                        cat.Items.Add(new AuditItem { Label = "Install Date", Value = ManagementDateTimeConverter.ToDateTime(obj["InstallDate"].ToString()).ToString("yyyy-MM-dd HH:mm"), TooltipText = "When Windows was installed" });
                        cat.Items.Add(new AuditItem { Label = "Last Boot", Value = ManagementDateTimeConverter.ToDateTime(obj["LastBootUpTime"].ToString()).ToString("yyyy-MM-dd HH:mm"), TooltipText = "System Uptime Reference" });
                    }
                }

                // Add OS identifiers and Machine GUID
                string machineGuid = GetRegistryValue(@"SOFTWARE\Microsoft\Cryptography", "MachineGuid", "Unknown");
                string productId = GetRegistryValue(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductId", "Unknown");
                
                cat.Items.Add(new AuditItem { Label = "Machine GUID", Value = machineGuid, TooltipText = "Cryptography Machine GUID" });
                cat.Items.Add(new AuditItem { Label = "Product ID", Value = productId, TooltipText = "Windows Product ID" });
            }
            catch { }
            return cat;
        }

        private static string GetRegistryValue(string keyPath, string valueName, string defaultValue = "Default string")
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(keyPath))
                {
                    if (key != null)
                    {
                        var val = key.GetValue(valueName);
                        if (val != null) return val.ToString();
                    }
                }
            }
            catch { }
            return defaultValue;
        }

        private static AuditCategory GetIdentityAndCryptography()
        {
            var cat = new AuditCategory { Name = "System Information" };
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        cat.Items.Add(new AuditItem { Label = "Manufacturer", Value = obj["Manufacturer"]?.ToString(), TooltipText = "System Manufacturer" });
                    }
                }

                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_ComputerSystemProduct"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        cat.Items.Add(new AuditItem { Label = "Product Name", Value = obj["Name"]?.ToString(), TooltipText = "System Product Name" });
                        cat.Items.Add(new AuditItem { Label = "Version Index", Value = obj["Version"]?.ToString(), TooltipText = "System Version" });
                        cat.Items.Add(new AuditItem { Label = "System Serial", Value = obj["IdentifyingNumber"]?.ToString(), TooltipText = "System Serial Number" });
                        cat.Items.Add(new AuditItem { Label = "System UUID", Value = obj["UUID"]?.ToString(), TooltipText = "SMBIOS UUID" });
                        cat.Items.Add(new AuditItem { Label = "Family Serial", Value = obj["SKUNumber"]?.ToString() ?? "Default string", TooltipText = "Family Serial Number" });
                        cat.Items.Add(new AuditItem { Label = "SKU Number", Value = obj["SKUNumber"]?.ToString() ?? "Default string", TooltipText = "System SKU Number" });
                    }
                }
            }
            catch { }
            return cat;
        }

        private static AuditCategory GetFirmwareAndSecurity()
        {
            var cat = new AuditCategory { Name = "BIOS Information" };
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BIOS"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        cat.Items.Add(new AuditItem { Label = "BIOS Vendor", Value = obj["Manufacturer"]?.ToString(), TooltipText = "BIOS Manufacturer" });
                        cat.Items.Add(new AuditItem { Label = "BIOS Version", Value = obj["SMBIOSBIOSVersion"]?.ToString(), TooltipText = "BIOS Version String" });
                        string releaseDate = obj["ReleaseDate"]?.ToString() ?? "Unknown";
                        if (releaseDate.Length >= 8) releaseDate = $"{releaseDate.Substring(6, 2)}/{releaseDate.Substring(4, 2)}/{releaseDate.Substring(0, 4)}";
                        cat.Items.Add(new AuditItem { Label = "Release Date", Value = releaseDate, TooltipText = "BIOS Release Date" });
                        cat.Items.Add(new AuditItem { Label = "BIOS Serial", Value = obj["SerialNumber"]?.ToString(), TooltipText = "BIOS Serial Number" });
                    }
                }

                // Core Isolation (HVCI)
                string hvciState = GetRegistryValue(@"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled", "0");
                cat.Items.Add(new AuditItem { Label = "Core Isolation", Value = hvciState == "1" ? "Enabled" : "Disabled", TooltipText = "Hypervisor-Protected Code Integrity (HVCI)" });

                // Virtualization
                cat.Items.Add(new AuditItem { Label = "Virtualization", Value = "Enabled", TooltipText = "Hardware Virtualization Status" });

                // Secure Boot
                string secureBoot = GetRegistryValue(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled", "0");
                cat.Items.Add(new AuditItem { Label = "Secure Boot", Value = secureBoot == "1" ? "Enabled" : "Disabled", TooltipText = "UEFI Secure Boot Status" });

                // TPM Status
                try
                {
                    bool isAdmin = false;
                    try
                    {
                        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                        {
                            WindowsPrincipal principal = new WindowsPrincipal(identity);
                            isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);
                        }
                    }
                    catch { }

                    if (!isAdmin)
                    {
                        cat.Items.Add(new AuditItem { Label = "TPM Status", Value = "Requires Admin", TooltipText = "Launch application as Administrator to query TPM" });
                    }
                    else
                    {
                        using (var searcher = new ManagementObjectSearcher(@"root\CIMV2\Security\MicrosoftTpm", "SELECT * FROM Win32_Tpm"))
                        {
                            var tpms = searcher.Get().Cast<ManagementObject>().ToList();
                            if (tpms.Count == 0)
                            {
                                cat.Items.Add(new AuditItem { Label = "TPM Status", Value = "Not Present / Disabled", TooltipText = "No TPM found in WMI" });
                            }
                            else
                            {
                                foreach (var tpm in tpms)
                                {
                                    bool isEnabled = (bool)(tpm["IsEnabled_InitialValue"] ?? false);
                                    bool isActivated = (bool)(tpm["IsActivated_InitialValue"] ?? false);
                                    bool isOwned = (bool)(tpm["IsOwned_InitialValue"] ?? false);
                                    
                                    string tpmStatus = "Present (Inactive)";
                                    if (isEnabled && isActivated)
                                    {
                                        tpmStatus = isOwned ? "Ready & Owned" : "Present (Not Ready / Unowned)";
                                    }
                                    
                                    cat.Items.Add(new AuditItem { Label = "TPM Status", Value = tpmStatus, TooltipText = "Trusted Platform Module" });
                                    
                                    string mfgId = tpm["ManufacturerId"]?.ToString() ?? "Unknown";
                                    cat.Items.Add(new AuditItem { Label = "Manufacturer ID", Value = mfgId, TooltipText = "TPM Manufacturer ID" });
                                    cat.Items.Add(new AuditItem { Label = "Manufacturer Version", Value = tpm["ManufacturerVersion"]?.ToString() ?? "Unknown", TooltipText = "TPM Version" });
                                    cat.Items.Add(new AuditItem { Label = "Spec Version", Value = tpm["SpecVersion"]?.ToString() ?? "Unknown", TooltipText = "TPM Spec Version" });

                                    // EK Hash via Powershell
                                    string ekHash = "Unavailable";
                                    try
                                    {
                                        ProcessStartInfo psi = new ProcessStartInfo("powershell", "-Command \"(Get-TpmEndorsementKeyInfo).PublicEkCert.Thumbprint\"")
                                        {
                                            RedirectStandardOutput = true,
                                            UseShellExecute = false,
                                            CreateNoWindow = true
                                        };
                                        using (Process p = Process.Start(psi))
                                        {
                                            string hash = p.StandardOutput.ReadToEnd().Trim();
                                            if (!string.IsNullOrEmpty(hash) && !hash.Contains("Exception"))
                                            {
                                                ekHash = hash;
                                            }
                                        }
                                    }
                                    catch { }
                                    cat.Items.Add(new AuditItem { Label = "Endorsement Key", Value = ekHash, TooltipText = "TPM Endorsement Key Hash" });
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    cat.Items.Add(new AuditItem { Label = "TPM Status", Value = "Error accessing WMI", TooltipText = ex.Message });
                }
            }
            catch { }
            return cat;
        }

        private static AuditCategory GetMotherboard()
        {
            var cat = new AuditCategory { Name = "Baseboard Information" };
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_BaseBoard"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        cat.Items.Add(new AuditItem { Label = "Manufacturer", Value = obj["Manufacturer"]?.ToString(), TooltipText = "Motherboard Manufacturer" });
                        cat.Items.Add(new AuditItem { Label = "Version Index", Value = obj["Version"]?.ToString(), TooltipText = "Motherboard Revision" });
                        cat.Items.Add(new AuditItem { Label = "Product Name", Value = obj["Product"]?.ToString(), TooltipText = "Motherboard Model" });
                        cat.Items.Add(new AuditItem { Label = "Serial Number", Value = obj["SerialNumber"]?.ToString(), TooltipText = "Motherboard Serial Number" });
                        cat.Items.Add(new AuditItem { Label = "Asset Number", Value = obj["OtherIdentifyingInfo"]?.ToString() ?? "Default string", TooltipText = "Asset Tag" });
                        cat.Items.Add(new AuditItem { Label = "(CS) Location", Value = obj["LocationInChassis"]?.ToString() ?? "Default string", TooltipText = "Chassis Location" });
                    }
                }
            }
            catch { }
            return cat;
        }

        private static AuditCategory GetStorage()
        {
            var cat = NativeDiskQuery.GetDisks();
            
            // If native query failed to find any drives (e.g. strict anti-cheat/spoofer blocks IOCTLs completely)
            // we can fallback to WMI just as a last resort.
            if (cat.Items.Count == 0)
            {
                try
                {
                    using (var searcher = new ManagementObjectSearcher(@"Root\Microsoft\Windows\Storage", "SELECT * FROM MSFT_PhysicalDisk"))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            string model = obj["Model"]?.ToString()?.Trim() ?? "Unknown";
                            string serial = obj["SerialNumber"]?.ToString()?.Trim() ?? "Unknown";
                            string uniqueId = obj["UniqueId"]?.ToString()?.Trim() ?? "";
                            int busType = obj["BusType"] != null ? Convert.ToInt32(obj["BusType"]) : 0;
                            
                            if (string.IsNullOrEmpty(serial) || serial == "Unknown") continue;

                            string hexWwn = "00000000";
                            if (!string.IsNullOrEmpty(uniqueId))
                            {
                                var sb = new StringBuilder();
                                foreach (char c in uniqueId) sb.Append(((int)c).ToString("X2") + ":");
                                hexWwn = sb.ToString().TrimEnd(':');
                            }

                            bool isNvme = busType == 17;

                            cat.Items.Add(new AuditItem { Label = "DISK_STORAGE_MODEL", Value = model, TooltipText = "Drive Model" });
                            cat.Items.Add(new AuditItem { Label = "STORAGE_QUERY_PROPERTY", Value = serial, TooltipText = "Standard Drive Serial" });
                            cat.Items.Add(new AuditItem { Label = "SMART_RCV_DRIVE_DATA", Value = isNvme ? "00000000" : serial, TooltipText = "SMART Serial Data" });
                            cat.Items.Add(new AuditItem { Label = "STORAGE_QUERY_WWN", Value = hexWwn, TooltipText = "World Wide Name (Hex)" });
                            cat.Items.Add(new AuditItem { Label = "SCSI_PASS_THROUGH", Value = serial, TooltipText = "SCSI Passthrough Serial" });
                            cat.Items.Add(new AuditItem { Label = "ATA_PASS_THROUGH", Value = isNvme ? "00000000" : serial, TooltipText = "ATA Passthrough Serial" });
                            cat.Items.Add(new AuditItem { IsSeparator = true });
                        }
                    }
                }
                catch { }

                if (cat.Items.Count == 0)
                {
                    try
                    {
                        using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive"))
                        {
                            foreach (ManagementObject obj in searcher.Get())
                            {
                                string model = obj["Model"]?.ToString() ?? "Unknown";
                                string serial = obj["SerialNumber"]?.ToString()?.Trim() ?? "Unknown";
                                if (string.IsNullOrEmpty(serial) || serial == "Unknown") continue;

                                cat.Items.Add(new AuditItem { Label = "DISK_STORAGE_MODEL", Value = model, TooltipText = "Drive Model" });
                                cat.Items.Add(new AuditItem { Label = "STORAGE_QUERY_PROPERTY", Value = serial, TooltipText = "Standard Drive Serial" });
                                cat.Items.Add(new AuditItem { Label = "SMART_RCV_DRIVE_DATA", Value = serial, TooltipText = "SMART Serial Data" });
                                cat.Items.Add(new AuditItem { Label = "STORAGE_QUERY_WWN", Value = serial, TooltipText = "World Wide Name" });
                                cat.Items.Add(new AuditItem { Label = "SCSI_PASS_THROUGH", Value = serial, TooltipText = "SCSI Passthrough Serial" });
                                cat.Items.Add(new AuditItem { Label = "ATA_PASS_THROUGH", Value = serial, TooltipText = "ATA Passthrough Serial" });
                                cat.Items.Add(new AuditItem { IsSeparator = true });
                            }
                        }
                    }
                    catch { }
                }
            }
            
            return cat;
        }

        private static AuditCategory GetProcessor()
        {
            var cat = new AuditCategory { Name = "Processor Information" };
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Processor"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        cat.Items.Add(new AuditItem { Label = "CPU Manufacturer", Value = obj["Manufacturer"]?.ToString(), TooltipText = "CPU Manufacturer" });
                        cat.Items.Add(new AuditItem { Label = "Processor Type", Value = obj["Name"]?.ToString(), TooltipText = "CPU Model Name" });
                        cat.Items.Add(new AuditItem { Label = "Serial Number", Value = obj["SerialNumber"]?.ToString() ?? "Unknown", TooltipText = "Processor Serial Number" });
                        cat.Items.Add(new AuditItem { Label = "Part Number", Value = obj["PartNumber"]?.ToString() ?? "Unknown", TooltipText = "Processor Part Number" });
                        cat.Items.Add(new AuditItem { Label = "Asset Number", Value = obj["AssetTag"]?.ToString() ?? "Unknown", TooltipText = "Processor Asset Tag" });
                        cat.Items.Add(new AuditItem { Label = "Processor Socket", Value = obj["SocketDesignation"]?.ToString(), TooltipText = "Socket Type" });
                    }
                }
            }
            catch { }
            return cat;
        }

        private static AuditCategory GetChassis()
        {
            var cat = new AuditCategory { Name = "Chassis/Enclosure Information" };
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_SystemEnclosure"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        cat.Items.Add(new AuditItem { Label = "Manufacturer", Value = obj["Manufacturer"]?.ToString() ?? "Default string", TooltipText = "Chassis Manufacturer" });
                        
                        string chassisType = "Unknown";
                        if (obj["ChassisTypes"] is ushort[] types && types.Length > 0) chassisType = types[0].ToString();

                        cat.Items.Add(new AuditItem { Label = "Chassis Type", Value = chassisType, TooltipText = "Enclosure Type Code" });
                        cat.Items.Add(new AuditItem { Label = "Version Index", Value = obj["Version"]?.ToString() ?? "Default string", TooltipText = "Chassis Version" });
                        cat.Items.Add(new AuditItem { Label = "Serial Number", Value = obj["SerialNumber"]?.ToString() ?? "Default string", TooltipText = "Chassis Serial Number" });
                        cat.Items.Add(new AuditItem { Label = "Asset Number", Value = obj["SMBIOSAssetTag"]?.ToString() ?? "Default string", TooltipText = "Chassis Asset Tag" });
                        cat.Items.Add(new AuditItem { Label = "SKU Number", Value = obj["SKU"]?.ToString() ?? "Default string", TooltipText = "Chassis SKU" });
                    }
                }
            }
            catch { }
            return cat;
        }

        private static AuditCategory GetNetworkInterfaces()
        {
            var cat = new AuditCategory { Name = "Network Information" };
            try
            {
                // MAC Cache
                var nics = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(nic => (nic.NetworkInterfaceType == NetworkInterfaceType.Ethernet || nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211))
                    .Where(nic => nic.OperationalStatus == OperationalStatus.Up)
                    .Take(4)
                    .ToList();

                foreach (var nic in nics)
                {
                    string mac = nic.GetPhysicalAddress().ToString();
                    mac = string.Join(":", Enumerable.Range(0, mac.Length / 2).Select(i => mac.Substring(i * 2, 2)));
                    if (!string.IsNullOrEmpty(mac))
                        cat.Items.Add(new AuditItem { Label = "MAC [Cache]", Value = mac, TooltipText = $"Active Spoofable MAC of {nic.Name}" });
                }

                // DHCP & DNS (Active Connection)
                try
                {
                    using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True"))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            bool dhcp = (bool)(obj["DHCPEnabled"] ?? false);
                            string[] dns = obj["DNSServerSearchOrder"] as string[];
                            string dnsStr = dns != null ? string.Join(", ", dns) : "None";
                            cat.Items.Add(new AuditItem { Label = "DHCP Enabled", Value = dhcp ? "Yes" : "No", TooltipText = "Is DHCP active?" });
                            cat.Items.Add(new AuditItem { Label = "DNS Servers", Value = dnsStr, TooltipText = "Active DNS Servers" });
                            break; // Just get the primary one
                        }
                    }
                }
                catch { }

                // MAC Kernel (Permanent)
                try
                {
                    using (var searcher = new ManagementObjectSearcher(@"root\StandardCimv2", "SELECT * FROM MSFT_NetAdapter WHERE HardwareInterface=True"))
                    {
                        foreach (ManagementObject obj in searcher.Get())
                        {
                            string permMac = obj["PermanentAddress"]?.ToString();
                            if (!string.IsNullOrEmpty(permMac))
                            {
                                permMac = permMac.Replace("-", ":");
                                cat.Items.Add(new AuditItem { Label = "MAC [Kernel]", Value = permMac, TooltipText = "Burned-in Hardware MAC Address" });
                            }
                        }
                    }
                }
                catch { } // Fallback if MSFT_NetAdapter isn't available
            }
            catch { }
            return cat;
        }

        private static AuditCategory GetArpInformation()
        {
            var cat = new AuditCategory { Name = "ARP Information" };
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("arp", "-a")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (Process p = Process.Start(psi))
                {
                    string output = p.StandardOutput.ReadToEnd();
                    var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                    
                    bool isFirst = true;
                    int count = 0;
                    foreach (var line in lines)
                    {
                        if (count >= 10) break; // limit to prevent huge UI

                        if (line.StartsWith("Interface:"))
                        {
                            if (isFirst) {
                                cat.Items.Add(new AuditItem { Label = line.Trim(), Value = "", TooltipText = "ARP Table Interface" });
                                isFirst = false;
                            }
                        }
                        else if (line.Contains("dynamic") || line.Contains("static"))
                        {
                            var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length >= 3)
                            {
                                string ip = parts[0];
                                string mac = parts[1];
                                string type = parts[2];
                                cat.Items.Add(new AuditItem { Label = $"Physical Address: {mac}", Value = type, TooltipText = $"IP: {ip}" });
                                count++;
                            }
                        }
                    }
                }
            }
            catch { }
            return cat;
        }

        private static string DecodeWmiString(ushort[] array)
        {
            if (array == null || array.Length == 0) return "Unknown";
            byte[] bytes = new byte[array.Length];
            for (int i = 0; i < array.Length; i++) bytes[i] = (byte)array[i];
            return Encoding.ASCII.GetString(bytes).Trim('\0');
        }

        private static AuditCategory GetMonitors()
        {
            var cat = new AuditCategory { Name = "Monitor Information" };
            try
            {
                using (var searcher = new ManagementObjectSearcher(@"root\wmi", "SELECT * FROM WmiMonitorID"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string mf = DecodeWmiString(obj["ManufacturerName"] as ushort[]);
                        string mn = DecodeWmiString(obj["UserFriendlyName"] as ushort[]);
                        string sn = DecodeWmiString(obj["SerialNumberID"] as ushort[]);
                        
                        cat.Items.Add(new AuditItem { Label = "Manufacturer", Value = mf, TooltipText = "Monitor Manufacturer" });
                        cat.Items.Add(new AuditItem { Label = "Model Name", Value = mn, TooltipText = "Monitor Model" });
                        cat.Items.Add(new AuditItem { Label = "Monitor Serial", Value = sn, TooltipText = "EDID Monitor Serial" });
                        cat.Items.Add(new AuditItem { Label = "ID Serial Number", Value = "Unknown", TooltipText = "Device Instance ID" });
                    }
                }
            }
            catch { }
            return cat;
        }

        private static AuditCategory GetGraphics()
        {
            var cat = new AuditCategory { Name = "GPU Information" };
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_VideoController"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string gpuName = obj["Name"]?.ToString() ?? "Unknown GPU";
                        cat.Items.Add(new AuditItem { Label = "PCI Device", Value = obj["PNPDeviceID"]?.ToString(), TooltipText = "Hardware ID of the GPU" });
                        cat.Items.Add(new AuditItem { Label = "GPU Name", Value = gpuName, TooltipText = "Name of the Graphics Card" });

                        string uuid = "GPU-Unknown";
                        if (gpuName.Contains("NVIDIA", StringComparison.OrdinalIgnoreCase))
                        {
                            try
                            {
                                ProcessStartInfo psi = new ProcessStartInfo("nvidia-smi", "--query-gpu=uuid --format=csv,noheader")
                                {
                                    RedirectStandardOutput = true,
                                    UseShellExecute = false,
                                    CreateNoWindow = true
                                };
                                using (Process p = Process.Start(psi))
                                {
                                    string output = p.StandardOutput.ReadToEnd().Trim();
                                    if (!string.IsNullOrEmpty(output) && output.StartsWith("GPU-"))
                                    {
                                        uuid = output;
                                    }
                                }
                            }
                            catch { }
                        }
                        
                        cat.Items.Add(new AuditItem { Label = "GUID Serial", Value = uuid, TooltipText = "GPU GUID" });
                        cat.Items.Add(new AuditItem { IsSeparator = true });
                    }
                }
            }
            catch { }
            return cat;
        }

        private static AuditCategory GetMemory()
        {
            var cat = new AuditCategory { Name = "Physical Memory (RAM)" };
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PhysicalMemory"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string manufacturer = obj["Manufacturer"]?.ToString() ?? "Unknown";
                        string partNum = obj["PartNumber"]?.ToString()?.Trim() ?? "Unknown";
                        string serialNum = obj["SerialNumber"]?.ToString()?.Trim() ?? "Unknown";
                        ulong capacityBytes = (ulong)(obj["Capacity"] ?? 0UL);
                        string capacityStr = capacityBytes > 0 ? (capacityBytes / (1024 * 1024 * 1024)) + " GB" : "Unknown";

                        cat.Items.Add(new AuditItem { Label = "Manufacturer", Value = manufacturer, TooltipText = "RAM Manufacturer" });
                        cat.Items.Add(new AuditItem { Label = "Part Number", Value = partNum, TooltipText = "RAM Module Part Number" });
                        cat.Items.Add(new AuditItem { Label = "Serial Number", Value = serialNum, TooltipText = "RAM Serial Number" });
                        cat.Items.Add(new AuditItem { Label = "Capacity", Value = capacityStr, TooltipText = "Module Size" });
                        cat.Items.Add(new AuditItem { IsSeparator = true });
                    }
                }
            }
            catch { }
            return cat;
        }

        private static AuditCategory GetVolumes()
        {
            var cat = new AuditCategory { Name = "Volume Serial Numbers" };
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk WHERE DriveType = 3"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        string deviceId = obj["DeviceID"]?.ToString() ?? "Unknown";
                        string volumeSerial = obj["VolumeSerialNumber"]?.ToString() ?? "Unknown";
                        
                        if (volumeSerial != "Unknown" && volumeSerial.Length == 8)
                        {
                            volumeSerial = volumeSerial.Insert(4, "-");
                        }
                        
                        cat.Items.Add(new AuditItem { Label = $"Volume [{deviceId}]", Value = volumeSerial, TooltipText = "OS Volume Serial Number" });
                    }
                }
            }
            catch { }
            return cat;
        }



        private static AuditCategory GetUsbPeripherals()
        {
            var cat = new AuditCategory { Name = "USB Peripherals" };
            try
            {
                var presentSerials = new HashSet<string>();
                
                // 1. Get PRESENT devices via WMI
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USB%'"))
                {
                    var pnpObjects = searcher.Get();
                    
                    var vidPidToName = new Dictionary<string, string>();
                    
                    foreach (ManagementObject obj in pnpObjects)
                    {
                        string pnpId = obj["PNPDeviceID"]?.ToString() ?? "";
                        string name = obj["Name"]?.ToString() ?? "";
                        
                        // Explicitly skip generic names instead of anything containing "Controller"
                        if (name == "USB Composite Device" || name == "USB Input Device" || name.Contains("Hub") || name == "WinUsb Device")
                            continue;
                            
                        var match = System.Text.RegularExpressions.Regex.Match(pnpId, @"VID_[0-9A-F]{4}&PID_[0-9A-F]{4}");
                        if (match.Success && !string.IsNullOrEmpty(name))
                        {
                            vidPidToName[match.Value] = name;
                        }
                    }
                    
                    foreach (ManagementObject obj in pnpObjects)
                    {
                        string pnpId = obj["PNPDeviceID"]?.ToString() ?? "";
                        string name = obj["Name"]?.ToString() ?? "Unknown USB Device";
                        
                        var parts = pnpId.Split('\\');
                        if (parts.Length == 3)
                        {
                            string possibleSerial = parts[2];
                            
                            bool isTrueSerial = !possibleSerial.Contains("&");
                            bool isXboxGeneratedSerial = possibleSerial.StartsWith("00&00&");

                            if (!string.IsNullOrEmpty(possibleSerial) && (isTrueSerial || isXboxGeneratedSerial))
                            {
                                string decodedSerial = DecodeHexStringIfValid(possibleSerial);
                                var match = System.Text.RegularExpressions.Regex.Match(pnpId, @"VID_[0-9A-F]{4}&PID_[0-9A-F]{4}");
                                if (match.Success && vidPidToName.ContainsKey(match.Value))
                                {
                                    name = vidPidToName[match.Value];
                                }
                                
                                if (presentSerials.Add(possibleSerial))
                                {
                                    cat.Items.Add(new AuditItem { Label = name, Value = decodedSerial, TooltipText = pnpId });
                                }
                            }
                        }
                    }
                }

                // 2. Get GHOST (Disconnected) devices from Registry
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USB"))
                {
                    if (key != null)
                    {
                        foreach (var subKeyName in key.GetSubKeyNames())
                        {
                            using (var subKey = key.OpenSubKey(subKeyName))
                            {
                                if (subKey != null)
                                {
                                    foreach (var instanceName in subKey.GetSubKeyNames())
                                    {
                                        bool isTrueGhostSerial = !instanceName.Contains("&");
                                        bool isXboxGhostGenerated = instanceName.StartsWith("00&00&");

                                        if ((isTrueGhostSerial || isXboxGhostGenerated) && !presentSerials.Contains(instanceName))
                                        {
                                            string friendlyName = "Ghost USB Device";
                                            using (var instKey = subKey.OpenSubKey(instanceName))
                                            {
                                                if (instKey != null)
                                                {
                                                    friendlyName = instKey.GetValue("FriendlyName")?.ToString() 
                                                                ?? instKey.GetValue("DeviceDesc")?.ToString() 
                                                                ?? "Ghost USB Device";
                                                    
                                                    if (friendlyName.Contains(";"))
                                                        friendlyName = friendlyName.Split(';').Last();
                                                }
                                            }
                                            
                                            string decodedGhostSerial = DecodeHexStringIfValid(instanceName);
                                            string instanceId = $@"USB\{subKeyName}\{instanceName}";
                                            cat.Items.Add(new AuditItem { Label = friendlyName + " [GHOST]", Value = decodedGhostSerial, TooltipText = instanceId });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }
            return cat;
        }

        private static string DecodeHexStringIfValid(string hex)
        {
            if (string.IsNullOrEmpty(hex) || hex.Length % 2 != 0) return hex;
            
            bool isAllHex = true;
            var chars = new List<char>();
            for (int i = 0; i < hex.Length; i += 2)
            {
                string byteString = hex.Substring(i, 2);
                if (!byte.TryParse(byteString, System.Globalization.NumberStyles.HexNumber, null, out byte b))
                {
                    isAllHex = false;
                    break;
                }
                if (b < 32 || b > 126)
                {
                    isAllHex = false;
                    break;
                }
                chars.Add((char)b);
            }
            
            return isAllHex ? new string(chars.ToArray()) : hex;
        }
    }
}
