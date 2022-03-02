rule Shellcode_FNV_API_Hashing {
    meta:
        author = "Jeremy Humble"
        date = "2021-11-17"
        description = "Detects known FNV32 hashes of windows API names"
        hashes = "8353cc7f75bdbe9de0271b29718237be"

    strings:
        /*
            >>> from fnvhash import fnv1a_32
            >>> hex(fnv1a_32(b'CreateMutexA'))
            '0x3b6ed297'
        */
        $CreateMutexA_le              = { 3B 6E D2 97 }
        $GetLastError_le              = { 50 56 DF 37 }
        $PathIsDirectoryA_le          = { B9 CF 22 68 }
        $K32EnumProcesses_le          = { CD 5E 8A 97 }
        $CreateDirectoryA_le          = { B0 C9 8C 53 }
        $lstrcat_le                   = { 1A 11 E7 75 }
        $InternetCheckConnectionA_le  = { 52 58 82 3F }
        $InternetOpenA_le             = { E2 3B 96 E7 }
        $InternetOpenUrlA_le          = { F4 CF 8B BC }
        $VirtualAlloc_le              = { 03 28 55 01 }
        $InternetReadFile_le          = { 96 0C B4 C6 }
        $InternetCloseHandle_le       = { 4D DD e9 66 }

        $CreateMutexA_be              = { 97 D2 6E 3B }
        $GetLastError_be              = { 37 DF 56 50 }
        $PathIsDirectoryA_be          = { 68 22 CF B9 }
        $K32EnumProcesses_be          = { 97 8A 5E CD }
        $CreateDirectoryA_be          = { 53 8C C9 B0 }
        $lstrcat_be                   = { 75 E7 11 1A }
        $InternetCheckConnectionA_be  = { 3F 82 58 52 }
        $InternetOpenA_be             = { E7 96 3B E2 }
        $InternetOpenUrlA_be          = { BC 8B CF F4 }
        $VirtualAlloc_be              = { 01 55 28 03 }
        $InternetReadFibe_be          = { C6 B4 0C 96 }
        $InternetCloseHandbe_be       = { 66 E9 DD 4D }
        

    condition:
        (filesize < 10MB and 3 of them) or
        (filesize < 25MB and 4 of them) or
        (filesize < 50MB and 5 of them) or
        6 of them

}
