using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using SystemHardwareAudit.Models;

namespace SystemHardwareAudit
{
    public static class NativeDiskQuery
    {
        private static readonly IntPtr InvalidHandleValue = new IntPtr(-1);
        private const string UnsupportedValue = "00000000";

        private const uint GenericRead = 0x80000000;
        private const uint GenericWrite = 0x40000000;
        private const uint FileShareRead = 0x00000001;
        private const uint FileShareWrite = 0x00000002;
        private const uint OpenExisting = 3;

        private const uint IoctlStorageQueryProperty = 0x002D1400;
        private const uint SmartGetVersion = 0x00074080;
        private const uint SmartReceiveDriveData = 0x0007C088;
        private const uint IoctlScsiPassThrough = 0x0004D004;
        private const uint IoctlAtaPassThrough = 0x0004D02C;

        private const ushort AtaFlagsDataIn = 0x02;
        private const byte ScsiIoctlDataIn = 1;
        private const int BusTypeAtapi = 2;
        private const int BusTypeNvme = 17;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr CreateFile(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr securityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        private enum StoragePropertyId
        {
            StorageDeviceProperty = 0,
            StorageDeviceIdProperty = 2
        }

        private enum StorageQueryType
        {
            PropertyStandardQuery = 0
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct StoragePropertyQuery
        {
            public StoragePropertyId PropertyId;
            public StorageQueryType QueryType;
            public byte AdditionalParameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct GetVersionInParams
        {
            public byte Version;
            public byte Revision;
            public byte Reserved;
            public byte IdeDeviceMap;
            public uint Capabilities;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public uint[] ReservedValues;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IdeRegisters
        {
            public byte Features;
            public byte SectorCount;
            public byte SectorNumber;
            public byte CylinderLow;
            public byte CylinderHigh;
            public byte DriveHead;
            public byte Command;
            public byte Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SendCommandInParams
        {
            public uint BufferSize;
            public IdeRegisters DriveRegisters;
            public byte DriveNumber;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            public byte[] ReservedBytes;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public uint[] ReservedValues;

            public byte Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct AtaPassThroughEx
        {
            public ushort Length;
            public ushort AtaFlags;
            public byte PathId;
            public byte TargetId;
            public byte Lun;
            public byte ReservedAsByte;
            public uint DataTransferLength;
            public uint TimeOutValue;
            public uint ReservedAsUInt;
            public UIntPtr DataBufferOffset;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] PreviousTaskFile;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] CurrentTaskFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ScsiPassThrough
        {
            public ushort Length;
            public byte ScsiStatus;
            public byte PathId;
            public byte TargetId;
            public byte Lun;
            public byte CdbLength;
            public byte SenseInfoLength;
            public byte DataIn;
            public uint DataTransferLength;
            public uint TimeOutValue;
            public UIntPtr DataBufferOffset;
            public uint SenseInfoOffset;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] Cdb;
        }

        private sealed class DeviceDescriptorData
        {
            public string Model { get; init; } = "Unknown";
            public string Serial { get; init; } = UnsupportedValue;
            public int BusType { get; init; }
            public bool WasReturned { get; init; }
        }

        private sealed class AtaIdentifyData
        {
            public string Serial { get; init; } = UnsupportedValue;
            public string Model { get; init; } = "";
        }

        public static AuditCategory GetDisks()
        {
            var category = new AuditCategory { Name = "Disk Drive Information" };

            for (int driveNumber = 0; driveNumber < 32; driveNumber++)
            {
                string devicePath = $"\\\\.\\PhysicalDrive{driveNumber}";
                bool hasReadWriteAccess = true;
                IntPtr handle = CreateFile(
                    devicePath,
                    GenericRead | GenericWrite,
                    FileShareRead | FileShareWrite,
                    IntPtr.Zero,
                    OpenExisting,
                    0,
                    IntPtr.Zero);

                if (handle == InvalidHandleValue)
                {
                    hasReadWriteAccess = false;
                    handle = CreateFile(
                        devicePath,
                        0,
                        FileShareRead | FileShareWrite,
                        IntPtr.Zero,
                        OpenExisting,
                        0,
                        IntPtr.Zero);
                }

                if (handle == InvalidHandleValue)
                    continue;

                try
                {
                    DeviceDescriptorData descriptor = QueryDeviceDescriptor(handle);
                    string propertySerial = NormalizeOrUnsupported(descriptor.Serial);
                    string wwn = NormalizeOrUnsupported(QueryStorageDeviceIdentifier(handle));
                    string smartSerial = UnsupportedValue;
                    string scsiSerial = UnsupportedValue;
                    AtaIdentifyData ataData = new AtaIdentifyData();

                    if (hasReadWriteAccess)
                    {
                        smartSerial = NormalizeOrUnsupported(QuerySmartSerial(handle, driveNumber));
                        scsiSerial = NormalizeOrUnsupported(QueryScsiUnitSerial(handle));

                        if (descriptor.BusType != BusTypeNvme)
                        {
                            ataData = QueryAtaIdentify(handle, descriptor.BusType == BusTypeAtapi);
                        }
                    }

                    string ataSerial = NormalizeOrUnsupported(ataData.Serial);
                    string model = descriptor.Model;
                    if ((string.IsNullOrWhiteSpace(model) || model == "Unknown") && !string.IsNullOrWhiteSpace(ataData.Model))
                    {
                        model = ataData.Model;
                    }

                    bool foundDrive = descriptor.WasReturned ||
                                      propertySerial != UnsupportedValue ||
                                      smartSerial != UnsupportedValue ||
                                      wwn != UnsupportedValue ||
                                      scsiSerial != UnsupportedValue ||
                                      ataSerial != UnsupportedValue;

                    if (!foundDrive)
                        continue;

                    category.Items.Add(new AuditItem { Label = "DISK_STORAGE_MODEL", Value = model, TooltipText = $"PhysicalDrive{driveNumber} model" });
                    category.Items.Add(new AuditItem { Label = "STORAGE_QUERY_PROPERTY", Value = propertySerial, TooltipText = "IOCTL_STORAGE_QUERY_PROPERTY / StorageDeviceProperty" });
                    category.Items.Add(new AuditItem { Label = "SMART_RCV_DRIVE_DATA", Value = smartSerial, TooltipText = "SMART_RCV_DRIVE_DATA / ATA IDENTIFY" });
                    category.Items.Add(new AuditItem { Label = "STORAGE_QUERY_WWN", Value = wwn, TooltipText = "IOCTL_STORAGE_QUERY_PROPERTY / StorageDeviceIdProperty (VPD page 0x83)" });
                    category.Items.Add(new AuditItem { Label = "SCSI_PASS_THROUGH", Value = scsiSerial, TooltipText = "IOCTL_SCSI_PASS_THROUGH / INQUIRY VPD page 0x80" });
                    category.Items.Add(new AuditItem { Label = "ATA_PASS_THROUGH", Value = ataSerial, TooltipText = "IOCTL_ATA_PASS_THROUGH / IDENTIFY DEVICE" });
                    category.Items.Add(new AuditItem { IsSeparator = true });
                }
                catch
                {
                    // A single storage driver should not prevent the rest of the audit from loading.
                }
                finally
                {
                    CloseHandle(handle);
                }
            }

            return category;
        }

        private static DeviceDescriptorData QueryDeviceDescriptor(IntPtr handle)
        {
            byte[]? data = QueryStorageProperty(handle, StoragePropertyId.StorageDeviceProperty);
            if (data == null || data.Length < 36)
                return new DeviceDescriptorData();

            uint vendorOffset = BitConverter.ToUInt32(data, 12);
            uint productOffset = BitConverter.ToUInt32(data, 16);
            uint serialOffset = BitConverter.ToUInt32(data, 24);
            int busType = BitConverter.ToInt32(data, 28);

            string vendor = ReadNullTerminatedString(data, vendorOffset);
            string product = ReadNullTerminatedString(data, productOffset);
            string serial = ReadNullTerminatedString(data, serialOffset);
            string model = $"{vendor} {product}".Trim();

            return new DeviceDescriptorData
            {
                Model = string.IsNullOrWhiteSpace(model) ? "Unknown" : model,
                Serial = serial,
                BusType = busType,
                WasReturned = true
            };
        }

        private static byte[]? QueryStorageProperty(IntPtr handle, StoragePropertyId propertyId)
        {
            var query = new StoragePropertyQuery
            {
                PropertyId = propertyId,
                QueryType = StorageQueryType.PropertyStandardQuery,
                AdditionalParameters = 0
            };

            int querySize = Marshal.SizeOf<StoragePropertyQuery>();
            IntPtr queryBuffer = Marshal.AllocHGlobal(querySize);
            IntPtr outputBuffer = IntPtr.Zero;

            try
            {
                Marshal.StructureToPtr(query, queryBuffer, false);
                int outputSize = 4096;

                for (int attempt = 0; attempt < 2; attempt++)
                {
                    if (outputBuffer != IntPtr.Zero)
                        Marshal.FreeHGlobal(outputBuffer);

                    outputBuffer = Marshal.AllocHGlobal(outputSize);
                    ZeroMemory(outputBuffer, outputSize);

                    if (!DeviceIoControl(
                            handle,
                            IoctlStorageQueryProperty,
                            queryBuffer,
                            (uint)querySize,
                            outputBuffer,
                            (uint)outputSize,
                            out uint bytesReturned,
                            IntPtr.Zero))
                    {
                        return null;
                    }

                    int reportedSize = bytesReturned >= 8 ? Marshal.ReadInt32(outputBuffer, 4) : 0;
                    if (reportedSize > outputSize && reportedSize <= 1024 * 1024)
                    {
                        outputSize = reportedSize;
                        continue;
                    }

                    int dataLength = (int)Math.Min(bytesReturned, (uint)outputSize);
                    if (reportedSize > 0)
                        dataLength = Math.Min(dataLength, reportedSize);

                    if (dataLength <= 0)
                        return null;

                    byte[] result = new byte[dataLength];
                    Marshal.Copy(outputBuffer, result, 0, dataLength);
                    return result;
                }

                return null;
            }
            finally
            {
                Marshal.FreeHGlobal(queryBuffer);
                if (outputBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(outputBuffer);
            }
        }

        private static string QueryStorageDeviceIdentifier(IntPtr handle)
        {
            byte[]? data = QueryStorageProperty(handle, StoragePropertyId.StorageDeviceIdProperty);
            if (data == null || data.Length < 12)
                return UnsupportedValue;

            uint identifierCount = BitConverter.ToUInt32(data, 8);
            int offset = 12;
            var identifiers = new List<(int Score, string Value)>();

            for (uint index = 0; index < identifierCount && offset + 16 <= data.Length; index++)
            {
                int codeSet = BitConverter.ToInt32(data, offset);
                int type = BitConverter.ToInt32(data, offset + 4);
                ushort identifierSize = BitConverter.ToUInt16(data, offset + 8);
                ushort nextOffset = BitConverter.ToUInt16(data, offset + 10);
                int association = BitConverter.ToInt32(data, offset + 12);
                int identifierOffset = offset + 16;

                if (association == 0 && identifierSize > 0 && identifierOffset + identifierSize <= data.Length)
                {
                    byte[] identifier = new byte[identifierSize];
                    Buffer.BlockCopy(data, identifierOffset, identifier, 0, identifierSize);
                    string value = FormatStorageIdentifier(codeSet, identifier);
                    if (!string.IsNullOrWhiteSpace(value) && identifier.Any(valueByte => valueByte != 0))
                    {
                        int score = type switch
                        {
                            2 => 0, // EUI-64
                            3 => 1, // FC-PH name
                            8 => 2, // SCSI name string (often naa.* or eui.*)
                            1 => 3, // T10 vendor ID
                            _ => 4
                        };
                        identifiers.Add((score, value));
                    }
                }

                if (nextOffset == 0)
                    break;

                int next = offset + nextOffset;
                if (next <= offset || next > data.Length)
                    break;

                offset = next;
            }

            return identifiers.OrderBy(identifier => identifier.Score).Select(identifier => identifier.Value).FirstOrDefault() ?? UnsupportedValue;
        }

        private static string FormatStorageIdentifier(int codeSet, byte[] identifier)
        {
            if (codeSet == 2)
                return Encoding.ASCII.GetString(identifier).Trim('\0', ' ');

            if (codeSet == 3)
                return Encoding.UTF8.GetString(identifier).Trim('\0', ' ');

            return string.Join(":", identifier.Select(value => value.ToString("X2")));
        }

        private static AtaIdentifyData QueryAtaIdentify(IntPtr handle, bool isAtapi)
        {
            int headerSize = Marshal.SizeOf<AtaPassThroughEx>();
            int dataOffset = Align(headerSize, IntPtr.Size);
            const int identifySize = 512;
            int bufferSize = dataOffset + identifySize;
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                ZeroMemory(buffer, bufferSize);
                var request = new AtaPassThroughEx
                {
                    Length = (ushort)headerSize,
                    AtaFlags = AtaFlagsDataIn,
                    DataTransferLength = identifySize,
                    TimeOutValue = 5,
                    DataBufferOffset = (UIntPtr)(uint)dataOffset,
                    PreviousTaskFile = new byte[8],
                    CurrentTaskFile = new byte[8]
                };
                request.CurrentTaskFile[5] = 0xA0;
                request.CurrentTaskFile[6] = isAtapi ? (byte)0xA1 : (byte)0xEC;
                Marshal.StructureToPtr(request, buffer, false);

                if (!DeviceIoControl(
                        handle,
                        IoctlAtaPassThrough,
                        buffer,
                        (uint)bufferSize,
                        buffer,
                        (uint)bufferSize,
                        out uint bytesReturned,
                        IntPtr.Zero) ||
                    bytesReturned < dataOffset + identifySize)
                {
                    return new AtaIdentifyData();
                }

                byte[] identify = new byte[identifySize];
                Marshal.Copy(IntPtr.Add(buffer, dataOffset), identify, 0, identifySize);
                return new AtaIdentifyData
                {
                    Serial = ReadAtaIdentifyString(identify, 10, 10),
                    Model = ReadAtaIdentifyString(identify, 27, 20)
                };
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static string QuerySmartSerial(IntPtr handle, int driveNumber)
        {
            int versionSize = Marshal.SizeOf<GetVersionInParams>();
            IntPtr versionBuffer = Marshal.AllocHGlobal(versionSize);

            try
            {
                ZeroMemory(versionBuffer, versionSize);
                if (!DeviceIoControl(
                        handle,
                        SmartGetVersion,
                        IntPtr.Zero,
                        0,
                        versionBuffer,
                        (uint)versionSize,
                        out _,
                        IntPtr.Zero))
                {
                    return UnsupportedValue;
                }

                var request = new SendCommandInParams
                {
                    BufferSize = 512,
                    DriveNumber = (byte)driveNumber,
                    ReservedBytes = new byte[3],
                    ReservedValues = new uint[4],
                    DriveRegisters = new IdeRegisters
                    {
                        SectorCount = 1,
                        SectorNumber = 1,
                        DriveHead = (byte)(0xA0 | ((driveNumber & 1) << 4)),
                        Command = 0xEC
                    }
                };

                int requestBufferSize = Marshal.SizeOf<SendCommandInParams>();
                int requestInputSize = Marshal.OffsetOf<SendCommandInParams>(nameof(SendCommandInParams.Buffer)).ToInt32();
                IntPtr requestBuffer = Marshal.AllocHGlobal(requestBufferSize);
                const int outputHeaderSize = 16;
                const int identifySize = 512;
                int outputSize = outputHeaderSize + identifySize;
                IntPtr outputBuffer = Marshal.AllocHGlobal(outputSize);

                try
                {
                    ZeroMemory(requestBuffer, requestBufferSize);
                    ZeroMemory(outputBuffer, outputSize);
                    Marshal.StructureToPtr(request, requestBuffer, false);

                    if (!DeviceIoControl(
                            handle,
                            SmartReceiveDriveData,
                            requestBuffer,
                            (uint)requestInputSize,
                            outputBuffer,
                            (uint)outputSize,
                            out uint bytesReturned,
                            IntPtr.Zero) ||
                        bytesReturned < outputHeaderSize + identifySize)
                    {
                        return UnsupportedValue;
                    }

                    byte[] identify = new byte[identifySize];
                    Marshal.Copy(IntPtr.Add(outputBuffer, outputHeaderSize), identify, 0, identifySize);
                    return ReadAtaIdentifyString(identify, 10, 10);
                }
                finally
                {
                    Marshal.FreeHGlobal(requestBuffer);
                    Marshal.FreeHGlobal(outputBuffer);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(versionBuffer);
            }
        }

        private static string QueryScsiUnitSerial(IntPtr handle)
        {
            int headerSize = Marshal.SizeOf<ScsiPassThrough>();
            const int senseSize = 32;
            const int dataSize = 252;
            int senseOffset = headerSize;
            int dataOffset = Align(senseOffset + senseSize, IntPtr.Size);
            int bufferSize = dataOffset + dataSize;
            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            try
            {
                ZeroMemory(buffer, bufferSize);
                var request = new ScsiPassThrough
                {
                    Length = (ushort)headerSize,
                    CdbLength = 6,
                    SenseInfoLength = senseSize,
                    DataIn = ScsiIoctlDataIn,
                    DataTransferLength = dataSize,
                    TimeOutValue = 5,
                    DataBufferOffset = (UIntPtr)(uint)dataOffset,
                    SenseInfoOffset = (uint)senseOffset,
                    Cdb = new byte[16]
                };
                request.Cdb[0] = 0x12; // INQUIRY
                request.Cdb[1] = 0x01; // EVPD
                request.Cdb[2] = 0x80; // Unit serial number page
                request.Cdb[4] = dataSize;
                Marshal.StructureToPtr(request, buffer, false);

                if (!DeviceIoControl(
                        handle,
                        IoctlScsiPassThrough,
                        buffer,
                        (uint)bufferSize,
                        buffer,
                        (uint)bufferSize,
                        out uint bytesReturned,
                        IntPtr.Zero) ||
                    bytesReturned < dataOffset + 4)
                {
                    return UnsupportedValue;
                }

                byte[] page = new byte[dataSize];
                Marshal.Copy(IntPtr.Add(buffer, dataOffset), page, 0, dataSize);
                if (page[1] != 0x80)
                    return UnsupportedValue;

                int serialLength = Math.Min((page[2] << 8) | page[3], dataSize - 4);
                if (serialLength <= 0)
                    return UnsupportedValue;

                return Encoding.ASCII.GetString(page, 4, serialLength).Trim('\0', ' ');
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static string ReadAtaIdentifyString(byte[] identify, int startWord, int wordCount)
        {
            int offset = startWord * 2;
            int length = wordCount * 2;
            if (offset < 0 || offset + length > identify.Length)
                return UnsupportedValue;

            byte[] textBytes = new byte[length];
            for (int index = 0; index < length; index += 2)
            {
                textBytes[index] = identify[offset + index + 1];
                textBytes[index + 1] = identify[offset + index];
            }

            return Encoding.ASCII.GetString(textBytes).Trim('\0', ' ');
        }

        private static string ReadNullTerminatedString(byte[] data, uint offset)
        {
            if (offset == 0 || offset >= data.Length)
                return "";

            int start = (int)offset;
            int end = start;
            while (end < data.Length && data[end] != 0)
                end++;

            return Encoding.ASCII.GetString(data, start, end - start).Trim();
        }

        private static string NormalizeOrUnsupported(string? value)
        {
            return string.IsNullOrWhiteSpace(value) ? UnsupportedValue : value.Trim();
        }

        private static int Align(int value, int alignment)
        {
            return (value + alignment - 1) & ~(alignment - 1);
        }

        private static void ZeroMemory(IntPtr buffer, int length)
        {
            for (int index = 0; index < length; index++)
                Marshal.WriteByte(buffer, index, 0);
        }
    }
}
