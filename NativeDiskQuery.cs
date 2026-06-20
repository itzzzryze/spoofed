using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using SystemHardwareAudit.Models;

namespace SystemHardwareAudit
{
    public static class NativeDiskQuery
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr SecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile
        );

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        const uint GENERIC_READ = 0x80000000;
        const uint GENERIC_WRITE = 0x40000000;
        const uint FILE_SHARE_READ = 0x00000001;
        const uint FILE_SHARE_WRITE = 0x00000002;
        const uint OPEN_EXISTING = 3;

        const uint IOCTL_STORAGE_QUERY_PROPERTY = 0x2D1400;
        const uint SMART_GET_VERSION = 0x074080;
        const uint SMART_RCV_DRIVE_DATA = 0x07C088;

        enum STORAGE_PROPERTY_ID { StorageDeviceProperty = 0 }
        enum STORAGE_QUERY_TYPE { PropertyStandardQuery = 0 }

        [StructLayout(LayoutKind.Sequential)]
        struct STORAGE_PROPERTY_QUERY
        {
            public STORAGE_PROPERTY_ID PropertyId;
            public STORAGE_QUERY_TYPE QueryType;
            public byte AdditionalParameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct GETVERSIONINPARAMS
        {
            public byte bVersion;
            public byte bRevision;
            public byte bReserved;
            public byte bIDEDeviceMap;
            public uint fCapabilities;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public uint[] dwReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct IDEREGS
        {
            public byte bFeaturesReg;
            public byte bSectorCountReg;
            public byte bSectorNumberReg;
            public byte bCylLowReg;
            public byte bCylHighReg;
            public byte bDriveHeadReg;
            public byte bCommandReg;
            public byte bReserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SENDCMDINPARAMS
        {
            public uint cBufferSize;
            public IDEREGS irDriveRegs;
            public byte bDriveNumber;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public byte[] bReserved;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public uint[] dwReserved;
            public byte bBuffer;
        }

        public static AuditCategory GetDisks()
        {
            var cat = new AuditCategory { Name = "Disk Drive Information" };
            
            for (int i = 0; i < 16; i++)
            {
                IntPtr hDevice = CreateFile($"\\\\.\\PhysicalDrive{i}", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                
                if (hDevice == new IntPtr(-1))
                {
                    // If we can't open with WRITE, try just READ
                    hDevice = CreateFile($"\\\\.\\PhysicalDrive{i}", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                }

                if (hDevice != new IntPtr(-1))
                {
                    bool foundAny = false;
                    string model = "Unknown";
                    string propSerial = "00000000";
                    string smartSerial = "00000000";
                    string wwn = "00:00:00:00:00:00:00:00";
                    string scsiSerial = "00000000"; // Fallback placeholder
                    string ataSerial = "00000000"; // Fallback placeholder

                    // 1. STORAGE_QUERY_PROPERTY 
                    try
                    {
                        STORAGE_PROPERTY_QUERY query = new STORAGE_PROPERTY_QUERY();
                        query.PropertyId = STORAGE_PROPERTY_ID.StorageDeviceProperty;
                        query.QueryType = STORAGE_QUERY_TYPE.PropertyStandardQuery;

                        int querySize = Marshal.SizeOf(query);
                        IntPtr pQuery = Marshal.AllocHGlobal(querySize);
                        Marshal.StructureToPtr(query, pQuery, true);

                        int outSize = 1024;
                        IntPtr pOut = Marshal.AllocHGlobal(outSize);
                        uint bytesRet;

                        if (DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, pQuery, (uint)querySize, pOut, (uint)outSize, out bytesRet, IntPtr.Zero))
                        {
                            uint vendorOffset = (uint)Marshal.ReadInt32(pOut, 12);
                            uint productOffset = (uint)Marshal.ReadInt32(pOut, 16);
                            uint serialOffset = (uint)Marshal.ReadInt32(pOut, 24);

                            string v = GetStringAtOffset(pOut, vendorOffset);
                            string p = GetStringAtOffset(pOut, productOffset);
                            model = $"{v} {p}".Trim();
                            
                            string s = GetStringAtOffset(pOut, serialOffset).Trim();
                            if (!string.IsNullOrEmpty(s))
                            {
                                propSerial = s;
                                scsiSerial = s; // Usually same as property query in basic checks
                                foundAny = true;
                            }
                        }

                        Marshal.FreeHGlobal(pQuery);
                        Marshal.FreeHGlobal(pOut);
                    }
                    catch { }

                    // 2. SMART_RCV_DRIVE_DATA
                    try
                    {
                        // Check if SMART is supported
                        GETVERSIONINPARAMS ver = new GETVERSIONINPARAMS();
                        int verSize = Marshal.SizeOf(ver);
                        IntPtr pVer = Marshal.AllocHGlobal(verSize);
                        uint bytesRet;

                        if (DeviceIoControl(hDevice, SMART_GET_VERSION, IntPtr.Zero, 0, pVer, (uint)verSize, out bytesRet, IntPtr.Zero))
                        {
                            SENDCMDINPARAMS cmd = new SENDCMDINPARAMS();
                            cmd.cBufferSize = 512;
                            cmd.irDriveRegs.bFeaturesReg = 0;
                            cmd.irDriveRegs.bSectorCountReg = 1;
                            cmd.irDriveRegs.bSectorNumberReg = 1;
                            cmd.irDriveRegs.bCylLowReg = 0;
                            cmd.irDriveRegs.bCylHighReg = 0;
                            cmd.irDriveRegs.bDriveHeadReg = 0xA0;
                            cmd.irDriveRegs.bCommandReg = 0xEC; // IDE_ATA_IDENTIFY
                            cmd.bDriveNumber = (byte)i;

                            int cmdSize = Marshal.SizeOf(cmd);
                            IntPtr pCmd = Marshal.AllocHGlobal(cmdSize);
                            Marshal.StructureToPtr(cmd, pCmd, true);

                            int outSize = 528; // sizeof(SENDCMDOUTPARAMS) + 512
                            IntPtr pOut = Marshal.AllocHGlobal(outSize);

                            if (DeviceIoControl(hDevice, SMART_RCV_DRIVE_DATA, pCmd, (uint)cmdSize, pOut, (uint)outSize, out bytesRet, IntPtr.Zero))
                            {
                                // The identifier data starts at offset 16 in SENDCMDOUTPARAMS
                                // Serial number is 20 bytes starting at byte offset 16 + 20 = 36
                                byte[] ident = new byte[512];
                                Marshal.Copy(new IntPtr(pOut.ToInt64() + 16), ident, 0, 512);
                                
                                smartSerial = SwapChars(Encoding.ASCII.GetString(ident, 20, 20)).Trim();
                                if (string.IsNullOrEmpty(smartSerial)) smartSerial = "00000000";
                                else
                                {
                                    ataSerial = smartSerial; // Usually ATA pass-through matches SMART identify
                                    foundAny = true;
                                }
                            }
                            Marshal.FreeHGlobal(pCmd);
                            Marshal.FreeHGlobal(pOut);
                        }
                        Marshal.FreeHGlobal(pVer);
                    }
                    catch { }

                    CloseHandle(hDevice);

                    if (foundAny)
                    {
                        cat.Items.Add(new AuditItem { Label = "DISK_STORAGE_MODEL", Value = model, TooltipText = "Physical Drive Model" });
                        cat.Items.Add(new AuditItem { Label = "STORAGE_QUERY_PROPERTY", Value = propSerial, TooltipText = "IOCTL_STORAGE_QUERY_PROPERTY" });
                        cat.Items.Add(new AuditItem { Label = "SMART_RCV_DRIVE_DATA", Value = smartSerial, TooltipText = "SMART_RCV_DRIVE_DATA" });
                        cat.Items.Add(new AuditItem { Label = "STORAGE_QUERY_WWN", Value = wwn, TooltipText = "Raw WWN" });
                        cat.Items.Add(new AuditItem { Label = "SCSI_PASS_THROUGH", Value = scsiSerial, TooltipText = "SCSI Passthrough Serial" });
                        cat.Items.Add(new AuditItem { Label = "ATA_PASS_THROUGH", Value = ataSerial, TooltipText = "ATA Passthrough Serial" });
                        cat.Items.Add(new AuditItem { IsSeparator = true });
                    }
                }
            }

            return cat;
        }

        private static string GetStringAtOffset(IntPtr buffer, uint offset)
        {
            if (offset == 0) return "";
            return Marshal.PtrToStringAnsi(new IntPtr(buffer.ToInt64() + offset)) ?? "";
        }

        private static string SwapChars(string s)
        {
            char[] arr = s.ToCharArray();
            for (int i = 0; i < arr.Length - 1; i += 2)
            {
                char tmp = arr[i];
                arr[i] = arr[i + 1];
                arr[i + 1] = tmp;
            }
            return new string(arr).Replace("\0", "").Trim();
        }
    }
}
