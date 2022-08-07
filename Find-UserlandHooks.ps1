<#
    .SYNOPSIS
        Find NTDLL functions that may be hooked by AV or EDR.
    .DESCRIPTION
        Antivirus and EDR solutions may detect some malicious behaviors by hooking Win32 API functions at the lowest level 
        of user mode since Kernel Patch Protection prohibits patching functions at the kernel level. As these hooks typically
        place a 'jmp' instruction at the start of the function, we may detect these hooks by enumerating all functions and 
        comparing the prologue with what exists in 'ntdll.dll' on disk.
    .EXAMPLE
        Get the hooked results of all Nt/Zw functions

        PS> Find-UserlandHooks
    .EXAMPLE
        Only show Nt/Zw functions that are hooked and include the expected/actual prologues

        PS> Find-UserlandHooks -HookedOnly -ShowPrologues
    .EXAMPLE
        Get the hooked results of all functions in 'ntdll.dll'

        PS> Find-UserlandHooks -BeyondNtZwFunctions -ShowPrologues
    .EXAMPLE
        Searching for a specific function

        PS> $Results = Find-UserlandHooks
        PS> $Results | Where-Object Function -eq 'NtCreateProcess'
    .NOTES
        https://github.com/0x00Check
#>
function Find-UserlandHooks {
    [CmdletBinding()]
    param(
        # Only return functions that are hooked
        [Parameter(Mandatory = $False)]
        [switch]
        $HookedOnly,

        # Include the expect and actual function prologue values
        [Parameter(Mandatory = $False)]
        [switch]
        $ShowPrologues,

        # Include functions even if they don't begin with Nt or Zw
        [Parameter(Mandatory = $False)]
        [switch]
        $BeyondNtZwFunctions
    )
    begin {
        Write-Verbose "Begin $($MyInvocation.MyCommand)"
        $ErrorActionPreference = "Stop"

        if ($BeyondNtZwFunctions) {
            Write-Warning "The '-BeyondNtZwFunctions' flag is experimental, you may encounter false positives.`n`n"
        }

        # PInvoke necessary Win32 APIs
        Add-Type -MemberDefinition @"
[DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern IntPtr GetModuleHandle([MarshalAs(UnmanagedType.LPWStr)]string lpModuleName);

[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_DOS_HEADER {
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
    public char[] e_magic;    // Magic number
    public UInt16 e_cblp;     // Bytes on last page of file
    public UInt16 e_cp;       // Pages in file
    public UInt16 e_crlc;     // Relocations
    public UInt16 e_cparhdr;  // Size of header in paragraphs
    public UInt16 e_minalloc; // Minimum extra paragraphs needed
    public UInt16 e_maxalloc; // Maximum extra paragraphs needed
    public UInt16 e_ss;       // Initial (relative) SS value
    public UInt16 e_sp;       // Initial SP value
    public UInt16 e_csum;     // Checksum
    public UInt16 e_ip;       // Initial IP value
    public UInt16 e_cs;       // Initial (relative) CS value
    public UInt16 e_lfarlc;   // File address of relocation table
    public UInt16 e_ovno;     // Overlay number

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public UInt16[] e_res1;   // Reserved words
    public UInt16 e_oemid;    // OEM identifier (for e_oeminfo)
    public UInt16 e_oeminfo;  // OEM information; e_oemid specific

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
    public UInt16[] e_res2;   // Reserved words
    public Int32 e_lfanew;    // File address of new exe header

    private string _e_magic {
        get {
            return new string(e_magic);
        }
    }

    public bool isValid {
        get {
            return _e_magic == "MZ";
        }
    }
}

[StructLayout(LayoutKind.Explicit)]
public struct IMAGE_NT_HEADERS32 {
    [FieldOffset(0)]
    public UInt32 Signature;

    [FieldOffset(4)]
    public IMAGE_FILE_HEADER FileHeader;

    [FieldOffset(24)]
    public IMAGE_OPTIONAL_HEADER32 OptionalHeader;

    private string _Signature {
        get {
            return Signature.ToString();
        }
    }

    public bool isValid {
        get {
            return _Signature == "PE\0\0" && OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        }
    }
}

[StructLayout(LayoutKind.Explicit)]
public struct IMAGE_NT_HEADERS64 {
    [FieldOffset(0)]
    public UInt32 Signature;

    [FieldOffset(4)]
    public IMAGE_FILE_HEADER FileHeader;

    [FieldOffset(24)]
    public IMAGE_OPTIONAL_HEADER64 OptionalHeader;

    private string _Signature {
        get {
            return Signature.ToString();
        }
    }

    public bool isValid {
        get {
            return _Signature == "PE\0\0" && OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        }
    }
}

[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_FILE_HEADER {
    public UInt16 Machine;
    public UInt16 NumberOfSections;
    public UInt32 TimeDateStamp;
    public UInt32 PointerToSymbolTable;
    public UInt32 NumberOfSymbols;
    public UInt16 SizeOfOptionalHeader;
    public UInt16 Characteristics;
}

public enum MachineType : ushort {
    Unknown = 0x0000,
    I386 = 0x014c,
    R3000 = 0x0162,
    R4000 = 0x0166,
    R10000 = 0x0168,
    WCEMIPSV2 = 0x0169,
    Alpha = 0x0184,
    SH3 = 0x01a2,
    SH3DSP = 0x01a3,
    SH4 = 0x01a6,
    SH5 = 0x01a8,
    ARM = 0x01c0,
    Thumb = 0x01c2,
    ARMNT = 0x01c4,
    AM33 = 0x01d3,
    PowerPC = 0x01f0,
    PowerPCFP = 0x01f1,
    IA64 = 0x0200,
    MIPS16 = 0x0266,
    M68K = 0x0268,
    Alpha64 = 0x0284,
    MIPSFPU = 0x0366,
    MIPSFPU16 = 0x0466,
    EBC = 0x0ebc,
    RISCV32 = 0x5032,
    RISCV64 = 0x5064,
    RISCV128 = 0x5128,
    AMD64 = 0x8664,
    ARM64 = 0xaa64,
    LoongArch32 = 0x6232,
    LoongArch64 = 0x6264,
    M32R = 0x9041
}

public enum MagicType : ushort {
    IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
}

public enum SubSystemType : ushort {
    IMAGE_SUBSYSTEM_UNKNOWN = 0,
    IMAGE_SUBSYSTEM_NATIVE = 1,
    IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
    IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
    IMAGE_SUBSYSTEM_POSIX_CUI = 7,
    IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
    IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
    IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
    IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
    IMAGE_SUBSYSTEM_EFI_ROM = 13,
    IMAGE_SUBSYSTEM_XBOX = 14
}

public enum DllCharacteristicsType : ushort {
    RES_0 = 0x0001,
    RES_1 = 0x0002,
    RES_2 = 0x0004,
    RES_3 = 0x0008,
    IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
    IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
    IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
    IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
    RES_4 = 0x1000,
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
}

public enum DataSectionFlags : uint {
    TypeReg = 0x00000000,
    TypeDsect = 0x00000001,
    TypeNoLoad = 0x00000002,
    TypeGroup = 0x00000004,
    TypeNoPadded = 0x00000008,
    TypeCopy = 0x00000010,
    ContentCode = 0x00000020,
    ContentInitializedData = 0x00000040,
    ContentUninitializedData = 0x00000080,
    LinkOther = 0x00000100,
    LinkInfo = 0x00000200,
    TypeOver = 0x00000400,
    LinkRemove = 0x00000800,
    LinkComDat = 0x00001000,
    NoDeferSpecExceptions = 0x00004000,
    RelativeGP = 0x00008000,
    MemPurgeable = 0x00020000,
    Memory16Bit = 0x00020000,
    MemoryLocked = 0x00040000,
    MemoryPreload = 0x00080000,
    Align1Bytes = 0x00100000,
    Align2Bytes = 0x00200000,
    Align4Bytes = 0x00300000,
    Align8Bytes = 0x00400000,
    Align16Bytes = 0x00500000,
    Align32Bytes = 0x00600000,
    Align64Bytes = 0x00700000,
    Align128Bytes = 0x00800000,
    Align256Bytes = 0x00900000,
    Align512Bytes = 0x00A00000,
    Align1024Bytes = 0x00B00000,
    Align2048Bytes = 0x00C00000,
    Align4096Bytes = 0x00D00000,
    Align8192Bytes = 0x00E00000,
    LinkExtendedRelocationOverflow = 0x01000000,
    MemoryDiscardable = 0x02000000,
    MemoryNotCached = 0x04000000,
    MemoryNotPaged = 0x08000000,
    MemoryShared = 0x10000000,
    MemoryExecute = 0x20000000,
    MemoryRead = 0x40000000,
    MemoryWrite = 0x80000000
}

[StructLayout(LayoutKind.Explicit)]
public struct IMAGE_OPTIONAL_HEADER32 {
    [FieldOffset(0)]
    public MagicType Magic;

    [FieldOffset(2)]
    public byte MajorLinkerVersion;

    [FieldOffset(3)]
    public byte MinorLinkerVersion;

    [FieldOffset(4)]
    public uint SizeOfCode;

    [FieldOffset(8)]
    public uint SizeOfInitializedData;

    [FieldOffset(12)]
    public uint SizeOfUninitializedData;

    [FieldOffset(16)]
    public uint AddressOfEntryPoint;

    [FieldOffset(20)]
    public uint BaseOfCode;

    // PE32 contains this additional field
    [FieldOffset(24)]
    public uint BaseOfData;

    [FieldOffset(28)]
    public uint ImageBase;

    [FieldOffset(32)]
    public uint SectionAlignment;

    [FieldOffset(36)]
    public uint FileAlignment;

    [FieldOffset(40)]
    public ushort MajorOperatingSystemVersion;

    [FieldOffset(42)]
    public ushort MinorOperatingSystemVersion;

    [FieldOffset(44)]
    public ushort MajorImageVersion;

    [FieldOffset(46)]
    public ushort MinorImageVersion;

    [FieldOffset(48)]
    public ushort MajorSubsystemVersion;

    [FieldOffset(50)]
    public ushort MinorSubsystemVersion;

    [FieldOffset(52)]
    public uint Win32VersionValue;

    [FieldOffset(56)]
    public uint SizeOfImage;

    [FieldOffset(60)]
    public uint SizeOfHeaders;

    [FieldOffset(64)]
    public uint CheckSum;

    [FieldOffset(68)]
    public SubSystemType Subsystem;

    [FieldOffset(70)]
    public DllCharacteristicsType DllCharacteristics;

    [FieldOffset(72)]
    public uint SizeOfStackReserve;

    [FieldOffset(76)]
    public uint SizeOfStackCommit;

    [FieldOffset(80)]
    public uint SizeOfHeapReserve;

    [FieldOffset(84)]
    public uint SizeOfHeapCommit;

    [FieldOffset(88)]
    public uint LoaderFlags;

    [FieldOffset(92)]
    public uint NumberOfRvaAndSizes;

    [FieldOffset(96)]
    public IMAGE_DATA_DIRECTORY ExportTable;

    [FieldOffset(104)]
    public IMAGE_DATA_DIRECTORY ImportTable;

    [FieldOffset(112)]
    public IMAGE_DATA_DIRECTORY ResourceTable;

    [FieldOffset(120)]
    public IMAGE_DATA_DIRECTORY ExceptionTable;

    [FieldOffset(128)]
    public IMAGE_DATA_DIRECTORY CertificateTable;

    [FieldOffset(136)]
    public IMAGE_DATA_DIRECTORY BaseRelocationTable;

    [FieldOffset(144)]
    public IMAGE_DATA_DIRECTORY Debug;

    [FieldOffset(152)]
    public IMAGE_DATA_DIRECTORY Architecture;

    [FieldOffset(160)]
    public IMAGE_DATA_DIRECTORY GlobalPtr;

    [FieldOffset(168)]
    public IMAGE_DATA_DIRECTORY TLSTable;

    [FieldOffset(176)]
    public IMAGE_DATA_DIRECTORY LoadConfigTable;

    [FieldOffset(184)]
    public IMAGE_DATA_DIRECTORY BoundImport;

    [FieldOffset(192)]
    public IMAGE_DATA_DIRECTORY IAT;

    [FieldOffset(200)]
    public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

    [FieldOffset(208)]
    public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

    [FieldOffset(216)]
    public IMAGE_DATA_DIRECTORY Reserved;
}

[StructLayout(LayoutKind.Explicit)]
public struct IMAGE_OPTIONAL_HEADER64 {
    [FieldOffset(0)]
    public MagicType Magic;

    [FieldOffset(2)]
    public byte MajorLinkerVersion;

    [FieldOffset(3)]
    public byte MinorLinkerVersion;

    [FieldOffset(4)]
    public uint SizeOfCode;

    [FieldOffset(8)]
    public uint SizeOfInitializedData;

    [FieldOffset(12)]
    public uint SizeOfUninitializedData;

    [FieldOffset(16)]
    public uint AddressOfEntryPoint;

    [FieldOffset(20)]
    public uint BaseOfCode;

    [FieldOffset(24)]
    public ulong ImageBase;

    [FieldOffset(32)]
    public uint SectionAlignment;

    [FieldOffset(36)]
    public uint FileAlignment;

    [FieldOffset(40)]
    public ushort MajorOperatingSystemVersion;

    [FieldOffset(42)]
    public ushort MinorOperatingSystemVersion;

    [FieldOffset(44)]
    public ushort MajorImageVersion;

    [FieldOffset(46)]
    public ushort MinorImageVersion;

    [FieldOffset(48)]
    public ushort MajorSubsystemVersion;

    [FieldOffset(50)]
    public ushort MinorSubsystemVersion;

    [FieldOffset(52)]
    public uint Win32VersionValue;

    [FieldOffset(56)]
    public uint SizeOfImage;

    [FieldOffset(60)]
    public uint SizeOfHeaders;

    [FieldOffset(64)]
    public uint CheckSum;

    [FieldOffset(68)]
    public SubSystemType Subsystem;

    [FieldOffset(70)]
    public DllCharacteristicsType DllCharacteristics;

    [FieldOffset(72)]
    public ulong SizeOfStackReserve;

    [FieldOffset(80)]
    public ulong SizeOfStackCommit;

    [FieldOffset(88)]
    public ulong SizeOfHeapReserve;

    [FieldOffset(96)]
    public ulong SizeOfHeapCommit;

    [FieldOffset(104)]
    public uint LoaderFlags;

    [FieldOffset(108)]
    public uint NumberOfRvaAndSizes;

    [FieldOffset(112)]
    public IMAGE_DATA_DIRECTORY ExportTable;

    [FieldOffset(120)]
    public IMAGE_DATA_DIRECTORY ImportTable;

    [FieldOffset(128)]
    public IMAGE_DATA_DIRECTORY ResourceTable;

    [FieldOffset(136)]
    public IMAGE_DATA_DIRECTORY ExceptionTable;

    [FieldOffset(144)]
    public IMAGE_DATA_DIRECTORY CertificateTable;

    [FieldOffset(152)]
    public IMAGE_DATA_DIRECTORY BaseRelocationTable;

    [FieldOffset(160)]
    public IMAGE_DATA_DIRECTORY Debug;

    [FieldOffset(168)]
    public IMAGE_DATA_DIRECTORY Architecture;

    [FieldOffset(176)]
    public IMAGE_DATA_DIRECTORY GlobalPtr;

    [FieldOffset(184)]
    public IMAGE_DATA_DIRECTORY TLSTable;

    [FieldOffset(192)]
    public IMAGE_DATA_DIRECTORY LoadConfigTable;

    [FieldOffset(200)]
    public IMAGE_DATA_DIRECTORY BoundImport;

    [FieldOffset(208)]
    public IMAGE_DATA_DIRECTORY IAT;

    [FieldOffset(216)]
    public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

    [FieldOffset(224)]
    public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

    [FieldOffset(232)]
    public IMAGE_DATA_DIRECTORY Reserved;
}

[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_DATA_DIRECTORY {
    public UInt32 VirtualAddress;
    public UInt32 Size;
}

[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_EXPORT_DIRECTORY {
    public UInt32 Characteristics;
    public UInt32 TimeDateStamp;
    public UInt16 MajorVersion;
    public UInt16 MinorVersion;
    public UInt32 Name;
    public UInt32 Base;
    public UInt32 NumberOfFunctions;
    public UInt32 NumberOfNames;
    public UInt32 AddressOfFunctions;    // RVA from base of image
    public UInt32 AddressOfNames;        // RVA from base of image
    public UInt32 AddressOfNameOrdinals; // RVA from base of image
}

[StructLayout(LayoutKind.Sequential)]
public struct IMAGE_SECTION_HEADER {
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
    public string Name;
    public UInt32 VirtualSize;
    public UInt32 VirtualAddress;
    public UInt32 SizeOfRawData;
    public UInt32 PointerToRawData;
    public UInt32 PointerToRelocations;
    public UInt32 PointerToLinenumbers;
    public UInt16 NumberOfRelocations;
    public UInt16 NumberOfLinenumbers;
    public DataSectionFlags Characteristics;
}
"@ -Name "Kernel32" -Namespace "Win32" -PassThru | Out-Null
    }
    process {
        Write-Host "[+] Reading all bytes from 'ntdll.dll'.."
        try {
            $CleanNtdllBytes = [IO.File]::ReadAllBytes("C:\Windows\System32\ntdll.dll")
        } catch {
            throw "Failed to read bytes from 'ntdll.dll' : $($_)"
        }

        Write-Host "[+] Allocating and copying buffer to unmanaged memory.."
        try {
            $AddressOfCleanNtdll = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($CleanNtdllBytes.Length)
            [System.Runtime.InteropServices.Marshal]::Copy($CleanNtdllBytes, 0, $AddressOfCleanNtdll, $CleanNtdllBytes.Length)
        } catch {
            throw "Failed to allocate and copy buffer : $($_)"
        }

        Write-Host "[+] Getting DOS and NT headers.."
        try {
            $CleanDOSHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($AddressOfCleanNtdll, [type][Win32.Kernel32+IMAGE_DOS_HEADER])
            if ($null -eq $CleanDOSHeader) {
                throw "Failed to get DOS header"
            }
            $CleanDOSHeader | Format-Table | Out-String | Write-Verbose

            $AddressOfCleanNTHeaders = [System.IntPtr]::Add($AddressOfCleanNtdll, $CleanDOSHeader.e_lfanew)
            $CleanNTHeaders = [System.Runtime.InteropServices.Marshal]::PtrToStructure($AddressOfCleanNTHeaders, [type][Win32.Kernel32+IMAGE_NT_HEADERS64])
            if ($null -eq $CleanNTHeaders) {
                throw "Failed to get NT headers"
            }
            $CleanNTHeaders | Format-Table | Out-String | Write-Verbose
            $CleanNTHeaders.FileHeader | Format-Table | Out-String | Write-Verbose
            $CleanNTHeaders.OptionalHeader | Format-Table | Out-String | Write-Verbose
        } catch {
            throw $_
        }

        $SizeOfNTHeaders = [System.Runtime.InteropServices.Marshal]::SizeOf([type][Win32.Kernel32+IMAGE_NT_HEADERS64])
        $SizeOfImageSectionHeaders = [System.Runtime.InteropServices.Marshal]::SizeOf([type][Win32.Kernel32+IMAGE_SECTION_HEADER])

        Write-Host "[+] Getting all section headers.."
        try {
            $CleanSectionHeaders = New-Object PSObject[]($CleanNTHeaders.FileHeader.NumberOfSections)
            $AddressOfFirstSection = [System.IntPtr]::Add($AddressOfCleanNTHeaders, $SizeOfNTHeaders)
            foreach ($i in 0..($CleanNTHeaders.FileHeader.NumberOfSections - 1)) {
                $CleanSectionHeaders[$i] = [System.Runtime.InteropServices.Marshal]::PtrToStructure(([IntPtr]::Add($AddressOfFirstSection, ($i * $SizeOfImageSectionHeaders))), [type][Win32.Kernel32+IMAGE_SECTION_HEADER])
            }
            $CleanSectionHeaders | Format-Table | Out-String | Write-Verbose
        } catch {
            throw "Failed to get section header : $($_)"
        }

        Write-Host "[+] Locating the export address table.."
        try {
            $CleanExportDirectoryRVA = [System.IntPtr]::New($CleanNTHeaders.OptionalHeader.ExportTable.VirtualAddress)
            $RVAInSection = $CleanSectionHeaders | Where-Object { $_.VirtualAddress -le $CleanExportDirectoryRVA.ToInt64() -and ($_.VirtualAddress + $_.VirtualSize) -gt $CleanExportDirectoryRVA.ToInt64() }
            $CleanExportDirectoryOffset = $CleanExportDirectoryRVA - [System.IntPtr]::new($RVAInSection.VirtualAddress) + $RVAInSection.PointerToRawData
            $CleanImageExportDirectory = [System.Runtime.InteropServices.Marshal]::PtrToStructure([System.IntPtr]::Add($AddressOfCleanNtdll, $CleanExportDirectoryOffset), [type][Win32.Kernel32+IMAGE_EXPORT_DIRECTORY])
            if ($null -eq $CleanImageExportDirectory) {
                throw "Failed to get ImageExportDirectory structure"
            }
            $CleanImageExportDirectory | Format-Table | Out-String | Write-Verbose
        } catch {
            throw "Failed to locate the image export directory : $($_)"
        }

        Write-Host "[+] Calculating offsets to exported functions.."
        try {
            $CleanAddressOfFunctionsRVA = [System.IntPtr]::new($CleanImageExportDirectory.AddressOfFunctions)
            $RVAInSection = $CleanSectionHeaders | Where-Object { $_.VirtualAddress -le $CleanAddressOfFunctionsRVA.ToInt64() -and ($_.VirtualAddress + $_.VirtualSize) -gt $CleanAddressOfFunctionsRVA.ToInt64() }
            $CleanAddressOfFunctionsOffset = $CleanAddressOfFunctionsRVA - [System.IntPtr]::new($RVAInSection.VirtualAddress) + $RVAInSection.PointerToRawData
            $CleanAddressOfFunctions = [System.IntPtr]::Add($AddressOfCleanNtdll, $CleanAddressOfFunctionsOffset)

            $CleanAddressOfNamesRVA = [System.IntPtr]::new($CleanImageExportDirectory.AddressOfNames)
            $RVAInSection = $CleanSectionHeaders | Where-Object { $_.VirtualAddress -le $CleanAddressOfNamesRVA.ToInt64() -and ($_.VirtualAddress + $_.VirtualSize) -gt $CleanAddressOfNamesRVA.ToInt64() }
            $CleanAddressOfNamesOffset = $CleanAddressOfNamesRVA - [System.IntPtr]::new($RVAInSection.VirtualAddress) + $RVAInSection.PointerToRawData
            $CleanAddressOfNames = [System.IntPtr]::Add($AddressOfCleanNtdll, $CleanAddressOfNamesOffset)

            $CleanAddressOfNameOrdinalsRVA = [System.IntPtr]::new($CleanImageExportDirectory.AddressOfNameOrdinals)
            $RVAInSection = $CleanSectionHeaders | Where-Object { $_.VirtualAddress -le $CleanAddressOfNameOrdinalsRVA.ToInt64() -and ($_.VirtualAddress + $_.VirtualSize) -gt $CleanAddressOfNameOrdinalsRVA.ToInt64() }
            $CleanAddressOfNameOrdinalsOffset = $CleanAddressOfNameOrdinalsRVA - [System.IntPtr]::new($RVAInSection.VirtualAddress) + $RVAInSection.PointerToRawData
            $CleanAddressOfNameOrdinals = [System.IntPtr]::Add($AddressOfCleanNtdll, $CleanAddressOfNameOrdinalsOffset)
            [PSCustomObject]@{
                AddressOfFunctions    = "{0:X16}" -f [long]$CleanAddressOfFunctions
                AddressOfNames        = "{0:X16}" -f [long]$CleanAddressOfNames
                AddressOfNameOrdinals = "{0:X16}" -f [long]$CleanAddressOfNameOrdinals
            } | Format-Table | Out-String | Write-Verbose
        } catch {
            throw "Failed to calculate offsets : $($_)"
        }

        $CleanPrologues = @()

        Write-Host "[+] Looping and saving the unhooked prologue for each function.."
        try {
            for ($i = 0; $i -lt $CleanImageExportDirectory.NumberOfNames; $i++) {
                Write-Progress -Activity "Saving clean function prologues.." -Status "$i/$($CleanImageExportDirectory.NumberOfNames) Completed" -PercentComplete (($i / $CleanImageExportDirectory.NumberOfNames) * 100)
                $CleanFunctionNameRVA = [System.Runtime.InteropServices.Marshal]::ReadInt32([System.IntPtr]::Add($CleanAddressOfNames, 4 * $i))
                $RVAInSection = $CleanSectionHeaders | Where-Object { $_.VirtualAddress -le $CleanFunctionNameRVA -and ($_.VirtualAddress + $_.VirtualSize) -gt $CleanFunctionNameRVA }
                $CleanFunctionNameOffset = $CleanFunctionNameRVA - [System.IntPtr]::new($RVAInSection.VirtualAddress) + $RVAInSection.PointerToRawData
                $CleanFunctionNameAddr = [System.IntPtr]::Add($AddressOfCleanNtdll, $CleanFunctionNameOffset)
                $CleanFunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($CleanFunctionNameAddr)

                $CleanNameOrdinalRVA = [System.Runtime.InteropServices.Marshal]::ReadInt16([System.IntPtr]::Add($CleanAddressOfNameOrdinals, 2 * $i))

                $CleanFunctionAddressRVA = [System.Runtime.InteropServices.Marshal]::ReadInt32([System.IntPtr]::Add($CleanAddressOfFunctions, $CleanNameOrdinalRVA * 4))
                $RVAInSection = $CleanSectionHeaders | Where-Object { $_.VirtualAddress -le $CleanFunctionAddressRVA -and ($_.VirtualAddress + $_.VirtualSize) -gt $CleanFunctionAddressRVA }
                $CleanFunctionAddressOffset = $CleanFunctionAddressRVA - [System.IntPtr]::new($RVAInSection.VirtualAddress) + $RVAInSection.PointerToRawData
                $CleanFunctionAddress = [System.IntPtr]::Add($AddressOfCleanNtdll, $CleanFunctionAddressOffset)

                $CleanFunctionPrologue = @()
                foreach ($b in 0..3) {
                    $CleanFunctionPrologue += "0x{0:X2}" -f [long]([System.Runtime.InteropServices.Marshal]::ReadByte([System.IntPtr]::Add($CleanFunctionAddress, $b)))
                }

                $CleanPrologues += [PSCustomObject]@{
                    Function = $CleanFunctionName
                    Prologue = $CleanFunctionPrologue
                }
            }
        } catch {
            throw "Failed to grab function prologues : $($_)"
        }
        
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($AddressOfCleanNtdll)

        try {
            Write-Host "[+] Getting handle to NTDLL module.."
            $NtdllLibrary = [Win32.Kernel32]::GetModuleHandle("ntdll");
            if ($NtdllLibrary -eq [System.IntPtr]::Zero) {
                throw "Failed to load module"
            }
            [PSCustomObject]@{
                Address = "{0:X16}" -f [long]$NtdllLibrary
            } | Format-Table | Out-String | Write-Verbose

            Write-Host "[+] Getting module DOS header.."
            $NtdllDOSHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtdllLibrary, [type][Win32.Kernel32+IMAGE_DOS_HEADER])
            if ($null -eq $NtdllDOSHeader) {
                throw "Failed to get module DOS header"
            }
            $NtdllDOSHeader | Format-Table | Out-String | Write-Verbose

            Write-Host "[+] Getting module NT headers.."
            $NtdllNTHeaders = [System.Runtime.InteropServices.Marshal]::PtrToStructure([System.IntPtr]::Add($ntdllLibrary, $NtdllDOSHeader.e_lfanew), [type][Win32.Kernel32+IMAGE_NT_HEADERS64])
            if ($null -eq $NtdllNTHeaders) {
                throw "Failed to get module NT headers"
            }
            $NtdllNTHeaders | Format-Table | Out-String | Write-Verbose

            Write-Host "[+] Locating module export address table.."
            $ExportDirectoryRVA = $NtdllNTHeaders.OptionalHeader.ExportTable.VirtualAddress
            $ImageExportDirectory = [System.Runtime.InteropServices.Marshal]::PtrToStructure([System.IntPtr]::Add($NtdllLibrary, $ExportDirectoryRVA), [type][Win32.Kernel32+IMAGE_EXPORT_DIRECTORY])
            if ($null -eq $ExportDirectoryRVA -or $null -eq $ImageExportDirectory) {
                throw "Failed to locate module export address table"
            }
            $ImageExportDirectory | Format-Table | Out-String | Write-Verbose

            Write-Host "[+] Calculating offsets to exported functions.."
            $AddressOfFunctionsRVA = [System.IntPtr]::Add($NtdllLibrary, $ImageExportDirectory.AddressOfFunctions)
            $AddressOfNamesRVA = [System.IntPtr]::Add($NtdllLibrary, $ImageExportDirectory.AddressOfNames)
            $AddressOfNameOrdinalsRVA = [System.IntPtr]::Add($NtdllLibrary, $ImageExportDirectory.AddressOfNameOrdinals)
            [PSCustomObject]@{
                AddressOfFunctionsRVA    = "{0:X16}" -f [long]$AddressOfFunctionsRVA
                AddressOfNamesRVA        = "{0:X16}" -f [long]$AddressOfNamesRVA
                AddressOfNameOrdinalsRVA = "{0:X16}" -f [long]$AddressOfNameOrdinalsRVA
            } | Format-Table | Out-String | Write-Verbose

            $HookedResults = @()
            Write-Host "[+] Comparing each function prologue with unhooked prologues.."
            for ($i = 0; $i -lt $ImageExportDirectory.NumberOfNames; $i++) {
                Write-Progress -Activity "Comparing each function prologue.." -Status "$i/$($ImageExportDirectory.NumberOfNames) Completed" -PercentComplete (($i / $ImageExportDirectory.NumberOfNames) * 100)
                $FunctionNameRVA = [System.Runtime.InteropServices.Marshal]::ReadInt32([System.IntPtr]::Add($AddressOfNamesRVA, 4 * $i))
                $FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi([System.IntPtr]::Add($NtdllLibrary, $FunctionNameRVA))

                $NameOrdinal = [System.Runtime.InteropServices.Marshal]::ReadInt16([System.IntPtr]::Add($AddressOfNameOrdinalsRVA, 2 * $i))
                $FunctionAddressRVA = [System.Runtime.InteropServices.Marshal]::ReadInt32([System.IntPtr]::Add($AddressOfFunctionsRVA, $NameOrdinal * 4))
                $FunctionAddress = [System.IntPtr]::Add($NtdllLibrary, $FunctionAddressRVA)

                $IsHooked = $False
                $FunctionPrologue = @()
                $ExpectedPrologue = $CleanPrologues | Where-Object Function -eq $FunctionName | Select-Object -ExpandProperty Prologue
                foreach ($b in 0..3) {
                    $FunctionPrologue += "0x{0:X2}" -f [long]([System.Runtime.InteropServices.Marshal]::ReadByte([System.IntPtr]::Add($FunctionAddress, $b)))
                    if ($FunctionPrologue[$b] -ne $ExpectedPrologue[$b]) {
                        $IsHooked = $True
                    }
                }
                $HookedResults += [PSCustomObject]@{
                    Function = $FunctionName
                    Expected = $ExpectedPrologue
                    Actual   = $FunctionPrologue
                    Hooked   = $IsHooked
                }
                $HookedResults[-1] | Format-Table | Out-String | Write-Verbose
            }
        } catch {
            Write-Error $_
        }

        if (-not $BeyondNtZwFunctions) {
            $HookedResults = $HookedResults | Where-Object Function -match "^(Nt|Zw)(?!dll).+$"
        }
        if ($HookedOnly) {
            $HookedResults = $HookedResults | Where-Object Hooked -eq $True
        }

        if ($HookedResults.Length -eq 0) {
            Write-Host "`n[!] No results"
        } else {
            if ($ShowPrologues) {
                $HookedResults
            } else {
                $HookedResults | Select-Object Function, Hooked
            }
        }
    }
    end {
        Write-Verbose "End $($MyInvocation.MyCommand)"
    }
}