import "pe"

rule Shellcode_Alloc_RWX_Mem {

    meta:
        author = "Jeremy Humble"
        date = "2021-09-22"
        description = "Detects allocation via VirtualAllocEx with Read/Write/Exec permissions. Seen across a wide variety of malware and shellcode. Due to the wide-net approach, this a low-medium confidence signature"
        references = ""
        hashes = "a4dfd173610d318acb4784645cf5e712d552b51d0c8cf10b2c4414d0486af27d,23f8aa94ffb3c08a62735fe7fee5799880a8f322ce1d55ec49a13a3f85312db2,edd98c786c6e3a65897d93235b833dd4c19b07cfc83ee6210e7366d1159df2cb,6ff933c5a25fac2fb86dd79adf579966c7d6627201e202a3fbff290c0fdfc244"
    
    strings:
        /*
            000007FEF592149A | FF15 781B0000                     | call qword ptr ds:[<&GetCurrentProcess>]                                           |
            000007FEF59214A0 | 33D2                              | xor edx,edx                                                                        |
            000007FEF59214A2 | C74424 20 40000000                | mov dword ptr ss:[rsp+20],40                                                       | 40:'@'
            000007FEF59214AA | 48:8BC8                           | mov rcx,rax                                                                        |
            000007FEF59214AD | 41:B9 00300000                    | mov r9d,3000                                                                       |
            000007FEF59214B3 | 41:B8 00FC0300                    | mov r8d,3FC00                                                                      |
            000007FEF59214B9 | 4C:8BF0                           | mov r14,rax                                                                        |
            000007FEF59214BC | FF15 661B0000                     | call qword ptr ds:[<&VirtualAllocEx>]                                              |


            0000000000401086 | 49:C7C0 00300000         | mov r8,3000                             |
            000000000040108D | 49:C7C1 40000000         | mov r9,40                               | 40:'@'
                00007FF6DD8F132E | 44:8D49 40              | lea r9d,qword ptr ds:[rcx+40]           |
            0000000000401094 | FFD0                     | call rax                                |
        */
        $Alloc_RWX_Perm0_x64 =   {
                                    49 C7 C0 00 (30|10) 00 00                   [0-8]
                                    (
                                        49 C7 C1 40 00 00 00 |                              // mov r9, 0x40           
                                        (49|44) 8D (48|49|4A|4B|4D|4E|4F) 40                // mov r9/r9d, [<reg> + 0x40]
                                    )                                           [0-12]
                                    (FF 15 | FF D? | E8)
                                }

        $Alloc_RWX_Perm1_x64 =   {
                                    41 B8 00 (30|10) 00 00                      [0-8]
                                    (
                                        49 C7 C1 40 00 00 00 |                              // mov r9, 0x40           
                                        (49|44) 8D (48|49|4A|4B|4D|4E|4F) 40                // mov r9/r9d, [<reg> + 0x40]
                                    )                                           [0-12]
                                    (FF 15 | FF D? | E8)
                                }

        $Alloc_RWX_Perm2_x64 =   {
                                    49 B8 00 (30|10) 00 00                      [0-8]
                                    (
                                        49 C7 C1 40 00 00 00 |                              // mov r9, 0x40           
                                        (49|44) 8D (48|49|4A|4B|4D|4E|4F) 40                // mov r9/r9d, [<reg> + 0x40]
                                    )                                           [0-12]
                                    (FF 15 | FF D? | E8)
                                }

        $Alloc_RWX_Perm3_x64 =  { 
                                    C7 44 24 20 40 00 00 00         [0-48]      // flProtect = PAGE_EXECUTE_READWRITE   
                                    41 B9 00 30 00 00               [0-32]      // flAllocationType = MEM_COMMIT | MEM_RESERVE
                                    (FF 15 | FF D? | E8)                        // Call
                                }

        $Alloc_RWX_Perm4_x64 = { 
                                    41 B9 00 30 00 00               [0-48]      // flAllocationType = MEM_COMMIT | MEM_RESERVE
                                    C7 44 24 20 40 00 00 00         [0-32]      // flProtect = PAGE_EXECUTE_READWRITE   
                                    (FF 15 | FF D? | E8)                        // Call
                                }

        /*
            00007FF62E4111EE | 41:B9 00300000           | mov r9d,3000                            |
            00007FF62E4111F4 | 48:8B53 30               | mov rdx,qword ptr ds:[rbx+30]           |
            00007FF62E4111F8 | 48:8B4C24 50             | mov rcx,qword ptr ss:[rsp+50]           |
            00007FF62E4111FD | 4C:89A424 20050000       | mov qword ptr ss:[rsp+520],r12          |
            00007FF62E411205 | 4C:89B424 30050000       | mov qword ptr ss:[rsp+530],r14          |
            00007FF62E41120D | 4C:89BC24 F0040000       | mov qword ptr ss:[rsp+4F0],r15          |
            00007FF62E411215 | C74424 20 40000000       | mov dword ptr ss:[rsp+20],40            | 40:'@'
            00007FF62E41121D | FF15 2DCE0000            | call qword ptr ds:[<&VirtualAllocEx>]   |
        */

        // ZwAllocateVirtualMemory versions
        /*
            0000000000240D79 | 4C:8BB5 A8000000         | mov r14,qword ptr ss:[rbp+A8]                    | [rbp+A8]:"PE"
            0000000000240D80 | 4C:8D4C24 50             | lea r9,qword ptr ss:[rsp+50]                     |
            0000000000240D85 | C74424 28 40000000       | mov dword ptr ss:[rsp+28],40                     | 40:'@'
            0000000000240D8D | 48:8D95 98000000         | lea rdx,qword ptr ss:[rbp+98]                    |
            0000000000240D94 | 45:33C0                  | xor r8d,r8d                                      |
            0000000000240D97 | C74424 20 00300000       | mov dword ptr ss:[rsp+20],3000                   |
            0000000000240D9F | 48:83C9 FF               | or rcx,FFFFFFFFFFFFFFFF                          |
            0000000000240DA3 | 49:8B46 30               | mov rax,qword ptr ds:[r14+30]                    |
            0000000000240DA7 | 48:8985 98000000         | mov qword ptr ss:[rbp+98],rax                    |
            0000000000240DAE | FF55 F8                  | call qword ptr ss:[rbp-8]                        |
        */
        $Alloc_RWX_Perm7_x64 =  {
                                    C7 44 24 20 00 30 00 00     [0-16]      // mov [rsp+20],  0x3000
                                    C7 44 24 28 40 00 00 00     [0-24]      // mov [rsp+28],  0x40
                                    (
                                        FF 15 |
                                        E8 |
                                        FF D? |
                                        FF 5?
                                    )
                                }

        $Alloc_RWX_Perm8_x64 =  {
                                    C7 44 24 28 40 00 00 00     [0-16]      // mov [rsp+28],  0x40
                                    C7 44 24 20 00 30 00 00     [0-24]      // mov [rsp+20],  0x3000
                                    (
                                        FF 15 |
                                        E8 |
                                        FF D? |
                                        FF 5?
                                    )
                                }

        /*
            0040220A | 6A 40                           | push 40                                 |
            0040220C | 68 00300000                     | push 3000                               |
            00402211 | 68 B9050000                     | push 5B9                                |
            00402216 | 8B45 EC                         | mov eax,dword ptr ss:[ebp-14]           |
            00402219 | 50                              | push eax                                |
            0040221A | FF15 44404000                   | call dword ptr ds:[<&VirtualAlloc>]     |
        */
        $Alloc_RWX_x86 = { 
                                (
                                    6A 40 |                                                     // PUSH 0x40
                                    68 40 00 00 00 |                                            // PUSH 0x00000040
                                    (c6|c7) 44 24 0C 40                                         // mov byte ptr ss:[esp+C], 40
                                )                                           [0-8]
                                (
                                    68 00 30 00 00 |                                            // PUSH 0x3000
                                    C7 44 24 08 00 30 00 00                                     // mov byte ptr ss:[esp+8], 3000
                                )                                           [0-8]
                                (                                                               // Various methods of pushing args to stack
                                    (50|51|52|53|55|56|57) |                                    // push <reg>
                                    FF (30|31|32|33|35|36|37) |                                 // push [<reg>]
                                    FF (70|71|72|73|75|76|77) |                                 // push [<reg> + offset]
                                    FF (B0|B1|B2|B3|B5|B6|B7) ?? ?? ?? ?? |                     // push [<reg> + long_offset]
                                    89 (44|4c|54|5c|6c|74|7c) 24 ?? |                           // mov [esp+8], reg
                                    68 ?? ?? 0? 00                                              // push dword
                                )                                           [0-8]
                                (                                                               // Various methods of pushing args to stack
                                    (50|51|52|53|55|56|57) |                                    // push <reg>
                                    FF (30|31|32|33|35|36|37) |                                 // push [<reg>]
                                    FF (70|71|72|73|75|76|77) |                                 // push [<reg> + offset]
                                    FF (B0|B1|B2|B3|B5|B6|B7) ?? ?? ?? ?? |                     // push [<reg> + long_offset]
                                    89 (44|4c|54|5c|6c|74|7c) 24 ?? |                           // mov [esp+8], reg
                                    6A 00                                                       // push NULL
                                )                                           [0-8]
                                (FF 15 | FF D? | E8) ?? ?? ?? ??                                           // Call
                            }

        // VirtualAlloc call followed by a call <reg>
        $Call_Alloc_RWX_x86 = { 
                                (
                                    6A 40 |                                                     // PUSH 0x40
                                    68 40 00 00 00 |                                            // PUSH 0x00000040
                                    (c6|c7) 44 24 0C 40                                         // mov byte ptr ss:[esp+C], 40
                                )                                           [0-8]
                                (
                                    68 00 30 00 00 |                                            // PUSH 0x3000
                                    C7 44 24 08 00 30 00 00                                     // mov byte ptr ss:[esp+8], 3000
                                )                                           [0-8]
                                (                                                               // Various methods of pushing args to stack
                                    (50|51|52|53|55|56|57) |                                    // push <reg>
                                    FF (30|31|32|33|35|36|37) |                                 // push [<reg>]
                                    FF (70|71|72|73|75|76|77) |                                 // push [<reg> + offset]
                                    FF (B0|B1|B2|B3|B5|B6|B7) ?? ?? ?? ?? |                     // push [<reg> + long_offset]
                                    89 (44|4c|54|5c|6c|74|7c) 24 ?? |                           // mov [esp+8], reg
                                    68 ?? ?? 0? 00                                              // push dword
                                )                                           [0-8]
                                (                                                               // Various methods of pushing args to stack
                                    (50|51|52|53|55|56|57) |                                    // push <reg>
                                    FF (30|31|32|33|35|36|37) |                                 // push [<reg>]
                                    FF (70|71|72|73|75|76|77) |                                 // push [<reg> + offset]
                                    FF (B0|B1|B2|B3|B5|B6|B7) ?? ?? ?? ?? |                     // push [<reg> + long_offset]
                                    89 (44|4c|54|5c|6c|74|7c) 24 ?? |                           // mov [esp+8], reg
                                    6A 00                                                       // push NULL
                                )                                           [0-8]
                                (FF 15 | FF D? | E8)                        [0-64]              // Call
                                FF (D0|D1|D2|D3|D5|D6|D7)                                       // Call <reg>
                            
                            }

        $AllocEx_RWX_x86 = { 
                                (
                                    6A 40 |                                                     // PUSH 0x40
                                    68 40 00 00 00 |                                            // PUSH 0x00000040
                                    (c6|c7) 44 24 (10|14) 40                                    // mov byte ptr ss:[esp+10], 40
                                )                                           [0-8]
                                (
                                    68 00 30 00 00 |                                            // PUSH 0x3000
                                    C7 44 24 (10|0c) 00 30 00 00                                // mov byte ptr ss:[esp+C], 3000
                                )                                           [0-8]
                                (                                                               // Various methods of pushing args to stack
                                    (50|51|52|53|55|56|57) |                                    // push <reg>
                                    FF (30|31|32|33|35|36|37) |                                 // push [<reg>]
                                    FF (70|71|72|73|75|76|77) |                                 // push [<reg> + offset]
                                    FF (B0|B1|B2|B3|B5|B6|B7) ?? ?? ?? ?? |                     // push [<reg> + long_offset]
                                    89 (44|4c|54|5c|6c|74|7c) 24 ?? |                           // mov [esp+8], reg
                                    68 ?? ?? 0? 00                                              // push dword
                                )                                           [0-8]
                                (                                                               // Various methods of pushing args to stack
                                    (50|51|52|53|55|56|57) |                                    // push <reg>
                                    FF (30|31|32|33|35|36|37) |                                 // push [<reg>]
                                    FF (70|71|72|73|75|76|77) |                                 // push [<reg> + offset]
                                    FF (B0|B1|B2|B3|B5|B6|B7) ?? ?? ?? ?? |                     // push [<reg> + long_offset]
                                    89 (44|4c|54|5c|6c|74|7c) 24 ?? |                           // mov [esp+8], reg
                                    6A 00                                                       // push NULL
                                )                                           [0-8]
                                (                                                               // Various methods of pushing args to stack
                                    (50|51|52|53|55|56|57) |                                    // push <reg>
                                    FF (30|31|32|33|35|36|37) |                                 // push [<reg>]
                                    FF (70|71|72|73|75|76|77) |                                 // push [<reg> + offset]
                                    FF (B0|B1|B2|B3|B5|B6|B7) ?? ?? ?? ?? |                     // push [<reg> + long_offset]
                                    89 (44|4c|54|5c|6c|74|7c) 24 ?? |                           // mov [esp+8], reg
                                    6A 00                                                       // push NULL
                                )                                           [0-8]
                                (FF 15 | FF D? | E8)                                            // Call
                            }

        /*
            Seen in variants of Clop ransomware. constants like 40 created dynmically /w 1 << 6 or 2 << 4
            00401108 | 8B55 A4                  | mov edx,dword ptr ss:[ebp-5C]           |
            0040110B | C1E2 06                  | shl edx,6                               |
            0040110E | 52                       | push edx                                |
            0040110F | A1 B0FB4300              | mov eax,dword ptr ds:[43FBB0]           |
            00401114 | 50                       | push eax                                |
            00401115 | 8B4D F4                  | mov ecx,dword ptr ss:[ebp-C]            |
            00401118 | D1E1                     | shl ecx,1                               |
            0040111A | 51                       | push ecx                                |
            0040111B | 8B55 A8                  | mov edx,dword ptr ss:[ebp-58]           |
            0040111E | 52                       | push edx                                |
            0040111F | 8B45 C4                  | mov eax,dword ptr ss:[ebp-3C]           |
            00401122 | 50                       | push eax                                |
            00401123 | FF15 38604200            | call dword ptr ds:[<&VirtualAllocEx>]   |
        */

        $Alloc_RWX_g_x86 = { 
                                (
                                    (c6|c7) 44 24 0C 40 |                                       // mov byte ptr ss:[esp+C], 40
                                    6A 40 |                                                     // PUSH 0x40
                                    68 40 00 00 00 |                                            // PUSH 0x00000040
                                    C1 (
                                        E0 (01|02|04|06) 50|                                               // shl eax, 6; push eax
                                        E1 (01|02|04|06) 51|                                               // shl ecx, 6; push ecx
                                        E2 (01|02|04|06) 52|                                               // .. etc
                                        E3 (01|02|04|06) 53|
                                        E5 (01|02|04|06) 55|
                                        E6 (01|02|04|06) 56|
                                        E7 (01|02|04|06) 57
                                       )                                                        // mov <reg>, const; const << 6
                                )                                           [0-8]
                                (
                                    FF 35 (?? ?? 4? 00| ?? ?? 0? 10 ) |                         // flNewProtect == *0x3000 (checked by condition)
                                    A1 (?? ?? 4? 00| ?? ?? 0? 10 ) |                            // mov <reg> [local_addr]; push; -- condition checks *local_addr == 0x3000
                                    (8B|8D) (05|0D|15|1D|2D|35|3D) (?? ?? 4? 00| ?? ?? 0? 10 )  [0-16]
                                    (
                                        (50|51|52|53|55|56|57) |
                                        89 (44|4c|54|5c|6c|74|7c) 24 ??                         // mov [esp+8], reg
                                    )
                                )                                           [0-12]
                                (                                                               // Various methods of pushing args to stack
                                    (50|51|52|53|55|56|57) |                                    // push <reg>
                                    FF (30|31|32|33|35|36|37) |                                 // push [<reg>]
                                    FF (70|71|72|73|75|76|77) |                                 // push [<reg> + offset]
                                    FF (B0|B1|B2|B3|B5|B6|B7) ?? ?? ?? ?? |                     // push [<reg> + long_offset]
                                    89 (44|4c|54|5c|6c|74|7c) 24 ?? |                           // mov [esp+8], reg
                                    68 ?? ?? 0? 00                                              // push dword
                                )                                           [0-8]
                                (                                                               // Various methods of pushing args to stack
                                    (50|51|52|53|55|56|57) |                                    // push <reg>
                                    FF (30|31|32|33|35|36|37) |                                 // push [<reg>]
                                    FF (70|71|72|73|75|76|77) |                                 // push [<reg> + offset]
                                    FF (B0|B1|B2|B3|B5|B6|B7) ?? ?? ?? ?? |                     // push [<reg> + long_offset]
                                    89 (44|4c|54|5c|6c|74|7c) 24 ?? |                           // mov [esp+8], reg
                                    6A 00                                                       // push NULL
                                )                                           [0-24]
                                (FF 15 | FF D? | E8)                                            // Call
                            }

        $Alloc_RWX_g2_x86 = { 
                                (
                                    FF 35 (?? ?? 4? 00| ?? ?? 0? 10 ) |                         // flNewProtect == *0x3000 (checked by condition)
                                    A1 (?? ?? 4? 00| ?? ?? 0? 10 ) |                            // mov <reg> [local_addr]; push; -- condition checks *local_addr == 0x3000
                                    (8B|8D) (05|0D|15|1D|2D|35|3D) (?? ?? 4? 00| ?? ?? 0? 10 ) [0-16]
                                    (
                                        (50|51|52|53|55|56|57) |
                                        89 (44|4c|54|5c|6c|74|7c) 24 ??                         // mov [esp+8], reg
                                    )
                                )                                           [0-16]
                                (
                                    (c6|c7) 44 24 0C 40 |                                       // mov byte ptr ss:[esp+C], 40
                                    6A 40 |                                                     // PUSH 0x40
                                    68 40 00 00 00 |                                            // PUSH 0x00000040
                                    C1 (
                                        E0 (01|02|04|06) 50|                                               // shl eax, 6; push eax
                                        E1 (01|02|04|06) 51|                                               // shl ecx, 6; push ecx
                                        E2 (01|02|04|06) 52|                                               // .. etc
                                        E3 (01|02|04|06) 53|
                                        E5 (01|02|04|06) 55|
                                        E6 (01|02|04|06) 56|
                                        E7 (01|02|04|06) 57
                                       )                                                        // mov <reg>, const; const << 6
                                )                                           [0-8]
                                (                                                               // Various methods of pushing args to stack
                                    (50|51|52|53|55|56|57) |                                    // push <reg>
                                    FF (30|31|32|33|35|36|37) |                                 // push [<reg>]
                                    FF (70|71|72|73|75|76|77) |                                 // push [<reg> + offset]
                                    FF (B0|B1|B2|B3|B5|B6|B7) ?? ?? ?? ?? |                     // push [<reg> + long_offset]
                                    89 (44|4c|54|5c|6c|74|7c) 24 ?? |                           // mov [esp+8], reg
                                    68 ?? ?? 0? 00                                              // push dword
                                )                                           [0-8]
                                (                                                               // Various methods of pushing args to stack
                                    (50|51|52|53|55|56|57) |                                    // push <reg>
                                    FF (30|31|32|33|35|36|37) |                                 // push [<reg>]
                                    FF (70|71|72|73|75|76|77) |                                 // push [<reg> + offset]
                                    FF (B0|B1|B2|B3|B5|B6|B7) ?? ?? ?? ?? |                     // push [<reg> + long_offset]
                                    89 (44|4c|54|5c|6c|74|7c) 24 ?? |                           // mov [esp+8], reg
                                    6A 00                                                       // push NULL
                                )                                           [0-24]
                                (FF 15 | FF D? | E8)                                            // Call
                            }


        $FP_Alloc_RWX0_x86 = {6A 40 68 00 30 00 00 68 00 00 01 00 }
        /*
                    │   0x00000013      8b442410       mov eax, dword [esp + 0x10]       
                    │   0x00000017      8b4050         mov eax, dword [eax + 0x50] 
        */
        $FP_Alloc_RWX1_x86 = { 
                                (
                                    (68|6a) 40 |                                                // PUSH 0x40
                                    (c6|c7) 44 24 10 40                                         // mov byte ptr ss:[esp+10], 40
                                )                                           [0-8]
                                (
                                    68 00 30 00 00 |                                            // PUSH 0x3000
                                    C7 44 24 0c 00 30 00 00                                     // mov byte ptr ss:[esp+C], 3000
                                )                                           [0-8]
                                8B [1-2] (10|F0|50)                                             // FP mov <reg>, [<reg> +/- 0x10/0x50]
                                8B [1-2] (50|B0|34)                         [0-8]               // FP mov <reg>, [<reg> +/- 0x50/0x34]
                                (                                                               // Various methods of pushing args to stack
                                    (50|51|52|53|55|56|57) |                                    // push <reg>
                                    FF (30|31|32|33|35|36|37) |                                 // push [<reg>]
                                    FF (70|71|72|73|75|76|77) |                                 // push [<reg> + offset]
                                    FF (B0|B1|B2|B3|B5|B6|B7) ?? ?? ?? ?? |                     // push [<reg> + long_offset]
                                    89 (44|4c|54|5c|6c|74|7c) 24 ?? |                           // mov [esp+8], reg
                                    68 ?? ?? 0? 00                                              // push dword
                                ) [0-8]
                                (                                                               // Various methods of pushing args to stack
                                    (50|51|52|53|55|56|57) |                                    // push <reg>
                                    FF (30|31|32|33|35|36|37) |                                 // push [<reg>]
                                    FF (70|71|72|73|75|76|77) |                                 // push [<reg> + offset]
                                    FF (B0|B1|B2|B3|B5|B6|B7) ?? ?? ?? ?? |                     // push [<reg> + long_offset]
                                    89 (44|4c|54|5c|6c|74|7c) 24 ?? |                           // mov [esp+8], reg
                                    6A 00                                                       // push byte
                                ) [0-8]
                                (FF 15 | E8)                                                    // Call
                            }

        $FP_Alloc_RWX2_x86 = { 
                                (
                                    (68|6a) 40 |                                                // PUSH 0x40
                                    (c6|c7) 44 24 10 40                                         // mov byte ptr ss:[esp+10], 40
                                )                                           [0-8]
                                (
                                    68 00 30 00 00 |                                            // PUSH 0x3000
                                    C7 44 24 0c 00 30 ?? ??                                     // mov byte ptr ss:[esp+C], 3000
                                )                                           [0-8]
                                8B [1-2] (10|F0|50)                                             // FP mov <reg>, [<reg> +/- 0x10/0x50]
                                (                                                               // Various methods of pushing args to stack
                                    (50|51|52|53|55|56|57) |                                    // push <reg>
                                    FF (30|31|32|33|35|36|37) |                                 // push [<reg>]
                                    FF (70|71|72|73|75|76|77) |                                 // push [<reg> + offset]
                                    FF (B0|B1|B2|B3|B5|B6|B7) ?? ?? ?? ?? |                     // push [<reg> + long_offset]
                                    89 (44|4c|54|5c|6c|74|7c) 24 ?? |                           // mov [esp+8], reg
                                    68 ?? ?? 0? 00                                              // push dword
                                ) [0-8]
                                8B [1-2] (50|B0|34)                         [0-8]               // FP mov <reg>, [<reg> +/- 0x50/0x34]
                                (                                                               // Various methods of pushing args to stack
                                    (50|51|52|53|55|56|57) |                                    // push <reg>
                                    FF (30|31|32|33|35|36|37) |                                 // push [<reg>]
                                    FF (70|71|72|73|75|76|77) |                                 // push [<reg> + offset]
                                    FF (B0|B1|B2|B3|B5|B6|B7) ?? ?? ?? ?? |                     // push [<reg> + long_offset]
                                    89 (44|4c|54|5c|6c|74|7c) 24 ?? |                           // mov [esp+8], reg
                                    6A 00                                                       // push NULL
                                ) [0-8]
                                (FF 15 | E8)                                                    // Call
                            }

        /*
            70DD1962 | 6A 40                    | push 40                                |
            70DD1964 | 68 00300000              | push 3000                              |
            70DD1969 | 8B43 34                  | mov eax,dword ptr ds:[ebx+34]          | eax:&"MZ", [ebx+34]:"MZ"
            70DD196C | 8945 F8                  | mov dword ptr ss:[ebp-8],eax           | [ebp-8]:"MZ"
            70DD196F | 8D45 CC                  | lea eax,dword ptr ss:[ebp-34]          |
            70DD1972 | 50                       | push eax                               | eax:&"MZ"
            70DD1973 | 6A 00                    | push 0                                 |
            70DD1975 | 8D45 F8                  | lea eax,dword ptr ss:[ebp-8]           | [ebp-8]:"MZ"
            70DD1978 | 50                       | push eax                               | eax:&"MZ"
            70DD1979 | 6A FF                    | push FFFFFFFF                          |
            70DD197B | FF55 B0                  | call dword ptr ss:[ebp-50]             |
        */
        $ZwAlloc_RWX_x32 =  {
                                (
                                    6A 40 |                                                     // PUSH 0x40
                                    68 40 00 00 00 |                                            // PUSH 0x00000040
                                    (c6|c7) 44 24 (10|14) 40                                    // mov byte ptr ss:[esp+10], 40
                                )                                           [0-8]
                                (
                                    68 00 30 00 00 |                                            // PUSH 0x3000
                                    C7 44 24 (10|0c) 00 30 00 00                                // mov byte ptr ss:[esp+C], 3000
                                )                                           [0-12]
                                (                                                               // Various methods of pushing args to stack
                                    (50|51|52|53|55|56|57) |                                    // push <reg>
                                    FF (30|31|32|33|35|36|37) |                                 // push [<reg>]
                                    FF (70|71|72|73|75|76|77) |                                 // push [<reg> + offset]
                                    FF (B0|B1|B2|B3|B5|B6|B7) ?? ?? ?? ?? |                     // push [<reg> + long_offset]
                                    89 (44|4c|54|5c|6c|74|7c) 24 ?? |                           // mov [esp+8], reg
                                    68 ?? ?? 0? 00                                              // push dword
                                )                                           [0-8]
                                (                                                               // Various methods of pushing args to stack
                                    (50|51|52|53|55|56|57) |                                    // push <reg>
                                    FF (30|31|32|33|35|36|37) |                                 // push [<reg>]
                                    FF (70|71|72|73|75|76|77) |                                 // push [<reg> + offset]
                                    FF (B0|B1|B2|B3|B5|B6|B7) ?? ?? ?? ?? |                     // push [<reg> + long_offset]
                                    89 (44|4c|54|5c|6c|74|7c) 24 ?? |                           // mov [esp+8], reg
                                    68 ?? ?? 0? 00                                              // push dword
                                )                                           [0-12]
                                (                                                               // Various methods of pushing args to stack
                                    (50|51|52|53|55|56|57) |                                    // push <reg>
                                    FF (30|31|32|33|35|36|37) |                                 // push [<reg>]
                                    FF (70|71|72|73|75|76|77) |                                 // push [<reg> + offset]
                                    FF (B0|B1|B2|B3|B5|B6|B7) ?? ?? ?? ?? |                     // push [<reg> + long_offset]
                                    89 (44|4c|54|5c|6c|74|7c) 24 ?? |                           // mov [esp+8], reg
                                    68 ?? ?? 0? 00                                              // push dword
                                )                                           [0-12]
                                (
                                    6A FF |                                                     // push 0xFFFFFFFF
                                    E8 ?? ?? ?? ?? 50                                           // call GetCurrentProcess; push eax
                                )                                           [0-12]
                                (FF 15 | FF D? | E8)                                            // Call
                                
                            }

                                                
        $Alloc_RW_Perm1_x64 =   { 
                                    48 8B (C8|C9|CA|CB|CD|CE|CF)    [0-12]      // hProcess = GetCurrentProcess()
                                    C7 44 24 20 04 00 00 00         [0-12]      // flProtect = PAGE_READWRITE   
                                    41 B9 00 30 00 00               [0-12]      // flAllocationType = MEM_COMMIT | MEM_RESERVE
                                    (FF 15|E8)                                  // Call
                                }


        $Alloc_RW_Perm2_x64 =   { 
                                    48 8B (C8|C9|CA|CB|CD|CE|CF)    [0-12]      // hProcess = GetCurrentProcess()
                                    41 B9 00 30 00 00               [0-12]      // flAlloc_RWationType = MEM_COMMIT | MEM_RESERVE
                                    C7 44 24 20 04 00 00 00         [0-12]      // flProtect = PAGE_READWRITE   
                                    (FF 15|E8)                                  // Call
                                }

        $Alloc_RW_Perm3_x64 =   { 
                                    C7 44 24 20 04 00 00 00         [0-12]      // flProtect = PAGE_READWRITE   
                                    48 8B (C8|C9|CA|CB|CD|CE|CF)    [0-12]      // hProcess = GetCurrentProcess()
                                    41 B9 00 30 00 00               [0-12]      // flAlloc_RWationType = MEM_COMMIT | MEM_RESERVE
                                    (FF 15|E8)                                  // Call
                                }

        $Alloc_RW_Perm4_x64 =   { 
                                    C7 44 24 20 04 00 00 00         [0-12]      // flProtect = PAGE_READWRITE   
                                    41 B9 00 30 00 00               [0-12]      // flAlloc_RWationType = MEM_COMMIT | MEM_RESERVE
                                    48 8B (C8|C9|CA|CB|CD|CE|CF)    [0-12]      // hProcess = GetCurrentProcess()
                                    (FF 15|E8)                                  // Call
                                }

        $Alloc_RW_Perm5_x64 =   { 
                                    41 B9 00 30 00 00               [0-12]      // flAlloc_RWationType = MEM_COMMIT | MEM_RESERVE
                                    48 8B (C8|C9|CA|CB|CD|CE|CF)    [0-12]      // hProcess = GetCurrentProcess()
                                    C7 44 24 20 04 00 00 00         [0-12]      // flProtect = PAGE_READWRITE   
                                    (FF 15|E8)                                  // Call
                                }

        $Alloc_RW_Perm6_x64 =   { 
                                    41 B9 00 30 00 00               [0-12]      // flAlloc_RWationType = MEM_COMMIT | MEM_RESERVE
                                    C7 44 24 20 04 00 00 00         [0-12]      // flProtect = PAGE_READWRITE   
                                    48 8B (C8|C9|CA|CB|CD|CE|CF)    [0-12]      // hProcess = GetCurrentProcess()
                                    (FF 15|E8)                                  // Call
                                }

        $VirtualProtect_X_x64 = {
                                    41 B8 (20|40) 00 00 00   [0-12]      // PAGE_EXECUTE_READ or PAGE_EXECUTE_READWRITE
                                    FF 15
                                }

        /*
            70C323D5 | 68 8CBBC970              | push zloader.70C9BB8C                      |
            70C323DA | FF35 14E9C870            | push dword ptr ds:[70C8E914]               |
            70C323E0 | 68 45310000              | push 3145                                  |
            70C323E5 | FF35 D808C970            | push dword ptr ds:[70C908D8]               |
            70C323EB | FF15 0000C870            | call dword ptr ds:[<&VirtualProtect>]      |
        */
        // Base == 0x10000000
        $VP_G_RWX1_x86 =    {
                                (
                                    FF 35 ?? ?? 0? 10 |                                 // flNewProtect == *0x40 (checked by condition)
                                    (A1 ?? ?? 0? 10 |
                                    (8B|8D) (05|0D|15|1D|2D|35|3D) ?? ?? 0? 10)
                                    (50|51|52|53|55|56|57)
                                )                                               [0-6]
                                (
                                    68 ?? ?? 0? 00 |             
                                    FF 35 ?? ?? 0? 10 |
                                    (50|51|52|53|55|56|57) |
                                    FF (74 24| 75) ??
                                )                                               [0-6]   // dwSize
                                (
                                    FF 35 ?? ?? 0? 10 |                                 // lpAddress
                                    (50|51|52|53|55|56|57) |
                                    FF (74 24| 75) ?? |
                                    6a 00
                                )                                               [0-6]
                                (FF 15 | FF D?)
                            } 

        // Base == 0x00400000
        $VP_G_RWX2_x86 =   {
                                (
                                    FF 35 ?? ?? 4? 00 |                                 // flNewProtect == *0x40 (checked by condition)
                                    (A1 ?? ?? 4? 00 |
                                    (8B|8D) (05|0D|15|1D|2D|35|3D) ?? ?? 4? 00)
                                    (50|51|52|53|55|56|57)
                                )                                               [0-6]
                                (
                                    68 ?? ?? 0? 00 |             
                                    FF 35 ?? ?? 4? 00 |
                                    (50|51|52|53|55|56|57) |
                                    FF (74 24| 75) ??
                                )                                               [0-6]   // dwSize
                                (
                                    FF 35 ?? ?? 4? 00 |                                 // lpAddress
                                    (50|51|52|53|55|56|57) |
                                    FF (74 24| 75) ?? |
                                    6a 00
                                )                                               [0-6]
                                (FF 15 | FF D?)
                            } 
        /*
            71F8B455 | 68 F0A4FE71              | push errors.71FEA4F0                    |
            71F8B45A | 6A 40                    | push 40                                 |
            71F8B45C | 68 86300000              | push 3086                               |
            71F8B461 | 52                       | push edx                                | edx:"-CÐ"
            71F8B462 | 6A FF                    | push FFFFFFFF                           |
            71F8B464 | A3 F088FE71              | mov dword ptr ds:[71FE88F0],eax         |
            71F8B469 | 8955 F8                  | mov dword ptr ss:[ebp-8],edx            | [ebp-8]:"-CÐ"
            71F8B46C | FF15 3CE0FB71            | call dword ptr ds:[<&VirtualProtectEx>] |
        */
        $VirtualProtectEx_x86 = {
                                    6A 40               [0-8]           // push  0x40
                                    68 ?? ?? 0? 00      [0-16]          // push  size
                                    6A FF               [0-12]          // push -1 (self)
                                    (FF 15 | FF D?)
                                }

        $parse_pe_1 =   {   (3D |81 (F8|F9|FA|FB|FD|FE|FF)) 4D 5A 00 00 [0-48]  
                            (
                                81 (38|39|3A|3B|3D|3E|3F) 50 45 00 00 |
                                (3D | 81 (F8|F9|FA|FB|FD|FE|FF)) 50 45 00 00
                            )
                        }

        $parse_pe_2 =   {   81 (38|39|3A|3B|3D|3E|3F) 4D 5A 00 00 [0-48]  
                            (
                                81 (38|39|3A|3B|3D|3E|3F) 50 45 00 00 |
                                (3D | 81 (F8|F9|FA|FB|FD|FE|FF)) 50 45 00 00
                            )
                        }
                                            
                    
    condition:
        $Call_Alloc_RWX_x86 or
        any of ($Alloc_RWX_Perm*) or
        for any i in (1 .. #VP_G_RWX1_x86):
        (
            uint32(pe.rva_to_offset(uint32(@VP_G_RWX1_x86[i] + 2) - 0x10000000)) == 0x40 or// PAGE_EXECUTE_READWRITE
            uint32(pe.rva_to_offset(uint32(@VP_G_RWX1_x86[i] + 1) - 0x10000000)) == 0x40 // PAGE_EXECUTE_READWRITE
        ) or
        for any i in (1 .. #VP_G_RWX2_x86):
        (
            uint32(pe.rva_to_offset(uint32(@VP_G_RWX2_x86[i] + 2) - 0x00400000)) == 0x40 or // PAGE_EXECUTE_READWRITE
            uint32(pe.rva_to_offset(uint32(@VP_G_RWX2_x86[i] + 1) - 0x00400000)) == 0x40 // PAGE_EXECUTE_READWRITE
        ) or 
        // check that second arg is a ptr to 0x3000 or 0x1000
        for any of ($Alloc_RWX_g*):
        (
            for any j in (1 .. 20): // rule starts with 2-5 byte instr, up to 6 byte wildcard, then mov [*ptr], so max offset is 11
            (
                (   // mov eax, ptr;
                    uint8(@+j) == 0xA1 and 
                    // *ptr == 0x3000
                    uint32(pe.rva_to_offset(uint32(@ +j + 1) - pe.image_base)) == 0x3000 or
                    uint32(pe.rva_to_offset(uint32(@ +j + 1) - pe.image_base)) == 0x1000
                ) or 
                (
                    // push ptr;
                    uint8(@+j) == 0xFF and 
                    uint8(@ + j + 1) == 0x35 and 
                    // *ptr == 0x3000
                    uint32(pe.rva_to_offset(uint32(@ + j + 2) - pe.image_base)) == 0x3000 or
                    uint32(pe.rva_to_offset(uint32(@ + j + 2) - pe.image_base)) == 0x1000
                ) or
                (
                    // mov reg, ptr
                    uint8(@+j) == 0x8B and
                    (uint8(@+j+1) & 0xC5) == 05 and       // register encoded in bits b 00XXX101
                    // *ptr = 0x3000
                    uint32(pe.rva_to_offset(uint32(@ +j + 2) - pe.image_base)) == 0x3000 or
                    uint32(pe.rva_to_offset(uint32(@ +j + 2) - pe.image_base)) == 0x1000
                )  
            )
        ) or
        (
            // too noisy unless we require that VirtualAlloc is run dynamically
            ($Alloc_RWX_x86 or $AllocEx_RWX_x86) and 
            not pe.imports(/kernel32.dll/i, /VirtualAlloc/) and
            not any of ($FP_Alloc_RWX*)
        ) or 
        (
            any of ($parse_pe*) and
            $Alloc_RWX_x86
        ) or
        any of ($ZwAlloc*) or
        any of ($VirtualProtectEx*) or
        1 of ($VirtualProtect_X*) and 1 of ($Alloc_RW_*)

}
