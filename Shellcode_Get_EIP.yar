rule Shellcode_Get_Eip {
    meta:
        author = "Jeremy Humble"
        last_update = "2020-07-29"
        description = "Shellcode get EIP"
        references = "https://github.com/securitykitten/msf_testing.git"
        hashes = "b100e405e8c6abcb5d83b03b724a2024,2202532966dd81fd0410fc7862d20596,f570505a7d26997dc1d2f62305dd4adb" 


    strings:
        /*
        floating mov, fnstenv to esp, pop
        0x00000005   2                     dbde  fcmovnu st(0), st(6)
        0x00000007   4                 d97424f4  fnstenv [esp - 0xc]
        0x0000000b   1                       5a  pop edx

        mov/pushmov, float instr, fnstenv to non-esp, pop
        0x00000000   2                     89e3  mov ebx, esp
        0x00000002   2                     d9cb  fxch st(3)
        0x00000004   3                   d973f4  fnstenv [ebx - 0xc]
        0x00000007   1                       59  pop ecx

        0x00000020   2                     dac1  fcmovb st(0), st(1)
        0x00000022   2                     2bc9  sub ecx, ecx
        0x00000024   4                 d97424f4  fnstenv [esp - 0xc]
        0x00000028   4                 66b94eab  mov cx, 0xab4e
        0x0000002c   1                       5f  pop edi

        */

        $get_eip_fnstenv_esp_x86 = {(D9 | DA | DB | DD) (C? | D? | E?) [0-5] D9 74 24 F4 [0-5] (58 | 59 | 5A | 5B | 5C | 5D | 5E | 5F)}

        $get_eip_fnstenv_eax_x86 = {
                                        (                                           // mov eax, esp
                                            8B C4 |
                                            89 E0 |
                                            54 [0-6] 58                             // push esp, pop eax
                                        ) [0-6]
                                        (D9|DA|DB|DD) (C?|D?|E?)                    // float instr
                                        D9 70 F4                    [0-6]           // fnstenv [eax - 0xc]
                                        (58|59|5A|5B|5C|5D|5E|5F)                   // pop
                                    }

        $get_eip_fnstenv_ecx_x86 = {
                                        (                                           // mov ecx, esp
                                            8B CC |
                                            89 E1 |
                                            54 [0-6] 59                             // push esp, pop ecx
                                        ) [0-6]
                                        (D9|DA|DB|DD) (C?|D?|E?)                    // float instr
                                        D9 70 F4                    [0-6]           // fnstenv [ecx - 0xc]
                                        (58|59|5A|5B|5C|5D|5E|5F)                   // pop
                                    }

        $get_eip_fnstenv_edx_x86 = {
                                        (                                           // mov edx, esp
                                            8B D4 |
                                            89 E2 |
                                            54 [0-6] 5A                             // push esp, pop edx
                                        ) [0-6]
                                        (D9|DA|DB|DD) (C?|D?|E?)                    // float instr
                                        D9 70 F4                    [0-6]           // fnstenv [edx - 0xc]
                                        (58|59|5A|5B|5C|5D|5E|5F)                   // pop
                                    }

        $get_eip_fnstenv_ebx_x86 = {
                                        (                                           // mov ebx, esp
                                            8B DD |
                                            89 E3 |
                                            54 [0-6] 5B                             // push esp, pop ebx
                                        ) [0-6]
                                        (D9|DA|DB|DD) (C?|D?|E?)                    // float instr
                                        D9 70 F4                    [0-6]           // fnstenv [ebx - 0xc]
                                        (58|59|5A|5B|5C|5D|5E|5F)                   // pop
                                    }

        $get_eip_fnstenv_ebp_x86 = {
                                        (                                           // mov ebp, esp
                                            8B ED |
                                            89 E5 |
                                            54 [0-6] 5D                             // push esp, pop ebp
                                        ) [0-6]
                                        (D9|DA|DB|DD) (C?|D?|E?)                    // float instr
                                        D9 70 F4                    [0-6]           // fnstenv [ebp - 0xc]
                                        (58|59|5A|5B|5C|5D|5E|5F)                   // pop
                                    }

        $get_eip_fnstenv_esi_x86 = {
                                        (                                           // mov esi, esp
                                            8B F4 |
                                            89 E6 |
                                            54 [0-6] 5E                             // push esp, pop esi
                                        ) [0-6]
                                        (D9|DA|DB|DD) (C?|D?|E?)                    // float instr
                                        D9 70 F4                    [0-6]           // fnstenv [esi - 0xc]
                                        (58|59|5A|5B|5C|5D|5E|5F)                   // pop
                                    }

        $get_eip_fnstenv_edi_x86 = {
                                        (                                           // mov edi, esp
                                            8B FD |
                                            89 E7 |
                                            54 [0-6] 5F                             // push esp, pop edi
                                        ) [0-6]
                                        (D9|DA|DB|DD) (C?|D?|E?)                    // float instr
                                        D9 70 F4                    [0-6]           // fnstenv [edi - 0xc]
                                        (58|59|5A|5B|5C|5D|5E|5F)                   // pop
                                    }
        /*
        Get addr of instruction following the retn
        009038FB    CC              INT3
        009038FC    E8 00000000     CALL 00903901
        00903901    58              POP EAX
        00903902    83C0 05         ADD EAX,5
        00903905    C3              RETN
        */

        // Could add a C3 to the end to tighten a bit if needed, but seems to work just fine without it.
        // Removed 2020-06-17 - Relatively noisy and an uncommon technique. Replaced with reg specific versions below
        /*
        $get_eip_call_pop_add = {   E8 00 00 00 00
                                    (58 | 59 | 5A | 5B | 5C | 5D | 5E | 5F)
                                    83 (c? | d? | e? | f?) 05 }
        */

        // <reg> + 5 in last instruction will give address of next instruction
        $get_eip_call_pop_sub_eax_x86 = {   
                                            E8 00 00 00 00              // call $+5
                                            58                  [0-5]   // pop eax
                                            83 (C0 FB | E8 05)          // sub eax, 5 or add eax, -5
                                        }

        $get_eip_call_pop_sub_ecx_x86 = {   
                                            E8 00 00 00 00              // call $+5
                                            59                  [0-5]   // pop ecx
                                            83 (C1 FB | E9 05)          // sub ecx, 5 or add ecx, -5
                                        }

        $get_eip_call_pop_sub_edx_x86 = {   
                                            E8 00 00 00 00              // call $+5
                                            5a                  [0-5]   // pop edx
                                            83 (C2 FB | EA 05)          // sub edx, 5 or add edx, -5
                                        }

        $get_eip_call_pop_sub_ebx_x86 = {   
                                            E8 00 00 00 00              // call $+5
                                            5b                  [0-5]   // pop ebx
                                            83 (C3 FB | EB 05)          // sub ebx, 5 or add ebx, -5
                                        }

        $get_eip_call_pop_sub_ebp_x86 = {   
                                            E8 00 00 00 00              // call $+5
                                            5d                  [0-5]   // pop esi
                                            83 (C5 FB | ED 05)          // sub esi, 5 or add esi, -5
                                        }

        $get_eip_call_pop_sub_esi_x86 = {   
                                            E8 00 00 00 00              // call $+5
                                            5e                  [0-5]   // pop esi
                                            83 (C6 FB | EE 05)          // sub esi, 5 or add esi, -5
                                        }

        $get_eip_call_pop_sub_edi_x86 = {   
                                            E8 00 00 00 00              // call $+5
                                            5f                  [0-5]   // pop edi
                                            83 (C7 FB | EF 05)          // sub edi, 5 or add edi, -5
                                        }

        /*
        Get addr of the call instruction (which is typically start of SC)
        00685000  | E8 00 00 00 00             | call bdbdfc7d
        00685005  | 58                         | pop eax
        00685006  | 6A 05                      | push 5
        00685008  | 5A                         | pop edx
        00685009  | 2B C2                      | sub eax,edx

        sub 5 methods:
        sub <reg>, 5                83 E? 05

        add <reg>, -5               83 C? FB

        push 05                     6A 05
        pop <reg>                   5?
        sub <reg>, <reg>            (2B | 29) (C? | D? | E?| F?)

        push -5                     6A FB
        pop <reg>                   5?
        add <reg>,<reg>             (01 | 03) (C? | D? | E?| F?)
        */

        $get_eip_of_call_1_x86 =    {   
                                        E8 00 00 00 00
                                        (58 |59 | 5A | 5B | 5C | 5D | 5E | 5F)
                                        83 (E? | C?) FB 
                                    }

        $get_eip_of_call_2_x86 =    {     
                                        E8 00 00 00 00
                                        (58 |59 | 5A | 5B | 5C | 5D | 5E | 5F)
                                        6A (05 | FB)
                                        (58 |59 | 5A | 5B | 5C | 5D | 5E | 5F)
                                        (01 | 03 | 29 | 2B ) (C? | D? | E?| F?)
                                    }
        /*
            00401000 | 4D                        | dec ebp                                 |
            00401001 | 5A                        | pop edx                                 |
            00401002 | 52                        | push edx                                |
            00401003 | 45                        | inc ebp                                 |
            00401004 | E8 00000000               | call cactus_torch_payload.401009        | call $0
            00401009 | 5B                        | pop ebx                                 | ebx:"U‹ìƒìTWÇEÄ"
            0040100A | 89DF                      | mov edi,ebx                             | ebx:"U‹ìƒìTWÇEÄ"
            0040100C | 55                        | push ebp                                |
            0040100D | 89E5                      | mov ebp,esp                             |
            0040100F | 81C3 147C0000             | add ebx,7C14                            | ebx:"U‹ìƒìTWÇEÄ"
            00401015 | FFD3                      | call ebx                                |
            00401017 | 68 F0B5A256               | push 56A2B5F0                           |
        */
        $get_eip_of_call_3_x86 = {
                                    E8 00 00 00 00                          // call $+5
                                    (58|59|5A|5B|5C|5D|5E|5F)   [0-16]      // pop <reg>
                                    FF (D0|D1|D2|D3|D5|D6|D7)               // call <reg>
                                }
                        

        /*
        012C1106  | E8 FF FF FF FF             | call x32dbg.12C110A            // Call $+4
        012C110B  | C1 5E 30 4C                | rcr dword ptr ds:[esi+30],4C

        The call jumps "inside" the call instruction, landing on the last ff inside it so that the landing spot looks like:

        012C110A  | FF C1                      | inc ecx
        012C110C  | 5E                         | pop esi
        */
        $get_eip_call_inside_instr_x86 = {E8 FF FF FF FF (C1 | C0) (58 | 59 | 5A | 5B | 5C | 5D | 5E | 5F)}


        /*
        012C1000  | E8 89 00 00 00             | call x32dbg.12C108E
        012C1005  | 60                         | pushad
        012C1006  | 89 E5                      | mov ebp,esp
        Last 3 instructions could easily change, but dont' appear to over a wide variety of samples.
        Keeping, because it's too noisy otherwise.
        */
        $get_eip_call_forward_x86 = {e8 (2? | 3? | 4? | 5? | 6? | 7? | 8? | 9?) 00 00 00 60 89 E5 31}

         /*
        012C1000  | EB 19                      | jmp x32dbg.12C101B
        012C1002  | 5E                         | pop esi
        012C1003  | 8B FE                      | mov edi,esi
        012C1005  | 83 C7 4C                   | add edi,4C
        012C1008  | 8B D7                      | mov edx,edi
        012C100A  | 3B F2                      | cmp esi,edx
        012C100C  | 7D 0B                      | jge x32dbg.12C1019
        012C100E  | B0 7B                      | mov al,7B
        012C1010  | F2 AE                      | repne scasb al,byte ptr es:[edi]
        012C1012  | FF CF                      | dec edi
        012C1014  | AC                         | lodsb al,byte ptr ds:[esi]
        012C1015  | 28 07                      | sub byte ptr ds:[edi],al
        012C1017  | EB F1                      | jmp x32dbg.12C100A
        012C1019  | EB 51                      | jmp x32dbg.12C106C
        012C101B  | E8 E2 FF FF FF             | call x32dbg.12C1002

        Condition for this one is kind of a mess, but is necessary to keep FP levels manageable. It checks that that the
        initial offset in the first jmp leads to the call and that the call leads back to the pop after the first jump.
        */
        $jmp_forward_call_back_x86 = {eb ?? (58 | 59 | 5A | 5B | 5C | 5D | 5E | 5F) [10-200] e8 ?? ff ff ff }

        // jmp_offset: uint8(@+1)
        // call instr: uint8(@ + jmp_offset + 4 )
        // call instr_offset: uint8(@ + jmp_offset +5)

        //((256 - uint8(@ + uint8(@+1) + 3)) - uint8(@+1) == 5) and  uint8(@ + uint8(@+1) + 2) == 0xe8)

        /*
            in x64 we can address relative to RIP. This looks for any adressing of the current instr or next instr
            followed by a mov/lea relative to what was just loaded
        */
        $relative_rip_sub_x64 = {
                                    (48|4c) 8d (05|0d|15|1d|25|2d|35|3d) [4] [0-8]
                                    (48 2d | (48|49) 81 (e8|e9|ea|eb|ec|ed|ee|ef))
                                }

        $relative_rip_lea_x64 = {
                                    (48|4c) 8d (05|0d|15|1d|25|2d|35|3d) EA FF FF FF    [0-16]
                                    FF (D0|D1|D2|D3|D5|D6|D7)
                                }

        $relative_rip_cobalt_x64 =  {
                                        4D 5A 41 52                                     [0-16]
                                        (48|4c) 8d (05|0d|15|1d|25|2d|35|3d) EA FF FF FF
                                    }

        // Unfortunately, way too noisy
        //$get_eip_call_rtn_x64 = { 48 8B 04 24 C3} // mov rax, [rsp]; ret

    condition:
        any of ($get_eip*) or
        $relative_rip_lea_x64 or
        $relative_rip_cobalt_x64 or
        for any i in (1 .. #jmp_forward_call_back_x86): (
            ((256 - uint8(@jmp_forward_call_back_x86[i] + uint8(@jmp_forward_call_back_x86[i]+1) + 3)) - int8(@jmp_forward_call_back_x86[i]+1)) == 5 
            and uint8(@jmp_forward_call_back_x86[i] + uint8(@jmp_forward_call_back_x86[i]+1) + 2) == 0xe8
        ) or
        for any i in (1 .. #relative_rip_sub_x64): (
            uint8(@relative_rip_sub_x64[i] + 3) == uint8(@relative_rip_sub_x64[i] + !relative_rip_sub_x64[i]) and
            uint8(@relative_rip_sub_x64[i] + 3 + 1) == uint8(@relative_rip_sub_x64[i] + !relative_rip_sub_x64[i] + 1) and
            uint8(@relative_rip_sub_x64[i] + 3 + 2) == uint8(@relative_rip_sub_x64[i] + !relative_rip_sub_x64[i] + 2)
        )
}
