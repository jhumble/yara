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
        $NtMapViewOfSection = {1B 40 BF FB}
        $RtlAllocateHeap = {67 CC 08 18}
        $NtClose = {A1 98 FD F1}
        $NtOpenThread = {32 FC E2 77}
        $LdrGetProcedureAddress  = {7D EA 02 4A}
        $LdrLoadDll = {7D EA EA FA} 
        $GetProcAddress = {7D D7 12 22}
        $LoadLibraryA = {7D D7 49 77}
        $LoadResource = {7D DF 38 8B}
        $VirtualAlloc = {7D D7 18 26}
        $VirtualAllocEx = {7D D8 D9 98}
        $VirtualAllocExNuma = {7D DF 4D 2F}
        $VirtualProtect = {7D D7 42 FF}
        $VirtualProtectEx = {7D DF 4D 3F}
        $ZwAllocateVirtualMemory = {7D E8 FA D0}
        $ZwProtectVirtualMemory = {7D E9 00 48}

        $NtCreateSection_be = {E3 F4 F4 1C}
        $NtMapViewOfSection_be = {FB BF 40 1B}
        $RtlAllocateHeap_be = {18 08 CC 67}
        $NtClose_be = {F1 FD 98 A1}
        $NtOpenThread_be = {77 E2 FC 32}
        $LdrGetProcedureAddress_be  = {4A 02 EA 7D}
        $LdrLoadDll_be = {FA EA EA 7D} 
        $GetProcAddress_be = {22 12 D7 7D}
        $LoadLibraryA_be = {77 49 D7 7D}
        $LoadResource_be = {8B 38 DF 7D}
        $VirtualAlloc_be = {26 18 D7 7D}
        $VirtualAllocEx_be = {98 D9 D8 7D}
        $VirtualAllocExNuma_be = {2F 4D DF 7D}
        $VirtualProtect_be = {FF 42 D7 7D}
        $VirtualProtectEx_be = {3F 4D DF 7D}
        $ZwAllocateVirtualMemory_be = {D0 FA E8 7D}
        $ZwProtectVirtualMemory_be = {48 00 E9 7D}

    condition:
        (2 of them and filesize < 3MB) or
        (3 of them and filesize < 10MB) or
        (4 of them and filesize < 20MB) or
        (5 of them and filesize < 50MB) or
        7 of them
}
