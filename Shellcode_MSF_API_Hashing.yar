rule Shellcode_MSF_API_Hashing {
    meta:
        tlp = "amber"
        author = "Jeremy Humble"
        date = "2022-03-2"
        description = "Detects known MSF hashes of windows API names"
        references = "https://github.com/snus-b/Metasploit_Function_Hashes"
        hashes = "794eb0e85c59c649e4265d055c03a42b"
        scope = "detection"
        platform = "ICET,FDR"

    strings:
        $NtCreateSection = {1C F4 F4 E3}
        $RtlAllocateHeap = {67 CC 08 18}
        $NtClose = {A1 98 FD F1}
        $NtOpenThread = {32 FC E2 77}
        $LdrGetProcedureAddress  = {5E D9 41 B5}
        $LdrLoadDll = {BD BF 9C 13} 
        $GetProcAddress = {78 02 F7 49}
        $LoadLibraryA = {07 26 77 4C}
        $LoadResource = {8E 8B B1 4A}
        $VirtualAlloc = {E5 53 A4 58}
        $VirtualAllocEx = {3F 92 87 AE}
        $VirtualAllocExNuma = {B6 C9 5C E9}
        $VirtualProtect = {C3 8A E1 10}
        $VirtualProtectEx = {CD 61 B5 A6}
        $ZwAllocateVirtualMemory = {96 08 B1 39}
        $ZwProtectVirtualMemory = {AA E7 F9 49}
        $ZwCreateSection = {9C F5 00 E5}
        $NtMapViewOfSection = {1B 40 BF FB}
        $ZwMapViewOfSection = {1E 40 C0 13}

        $NtCreateSection_be = {E3 F4 F4 1C}
        $RtlAllocateHeap_be = {18 08 CC 67}
        $NtClose_be = {F1 FD 98 A1}
        $NtOpenThread_be = {77 E2 FC 32}
        $LdrGetProcedureAddress_be = {B5 41 D9 5E}
        $LdrLoadDll_be = {13 9C BF BD} 
        $GetProcAddress_be = {49 F7 02 78}
        $LoadLibraryA_be = {4C 77 26 07}
        $LoadResource_be = {4A B1 8B 8E}
        $VirtualAlloc_be = {58 A4 53 E5}
        $VirtualAllocEx_be = {AE 87 92 3F}
        $VirtualAllocExNuma_be = {E9 5C C9 B6}
        $VirtualProtect_be = {10 E1 8A C3}
        $VirtualProtectEx_be = {A6 B5 61 CD}
        $ZwAllocateVirtualMemory_be = {39 B1 08 96}
        $ZwProtectVirtualMemory_be = {49 F9 E7 AA}
        $ZwCreateSection_be = {E5 00 FC 9C}
        $NtMapViewOfSection_be = {FB BF 40 1B}
        $ZwMapViewOfSection_be = {13 C0 40 1E}

    condition:
        (2 of them and filesize < 3MB) or
        (3 of them and filesize < 10MB) or
        (4 of them and filesize < 20MB) or
        (5 of them and filesize < 50MB) or
        7 of them
}
