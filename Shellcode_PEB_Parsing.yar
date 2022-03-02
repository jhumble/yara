import "pe"

rule Shellcode_PEB_Parsing
{
  meta:
    author = "Jeremy Humble"
    date = "2020-07-29"
    description = "Matches code that uses the FS segment register to access the PEB/TIB and crawl pointers until it reaches LdrData. This can be used to dynamically find libraries without calling LoadLibrary. Often combined with api hashing to find specific api functions without calling GetProcAddress. Extremely common in a wide variety of malicious code"
    references = "https://idafchev.github.io/images/windows_shellcode/locate_dll.png,http://mcdermottcybersecurity.com/articles/windows-x64-shellcode"
    hashes = "2202532966dd81fd0410fc7862d20596,45ff06f048cf773d37aeefcd9206781e,7de0646fc2fdcdec95c01fe6b52d08dc" // cobaltstrike atm implant, dridex dump, unpacked trickbot

  strings:
    /*
    push   30h
    pop    eax

    mov    eax, [fs:eax]  ; eax = (PPEB) __readfsdword(0x30);
    mov    eax, [eax+0ch] ; eax = (PMY_PEB_LDR_DATA)peb->Ldr
    mov    edi, [eax+0ch] ; edi = ldr->InLoadOrderModuleList.Flink

	// Direct
	1000102C | 64 A1 30 00 00 00                | mov eax,dword ptr fs:[30]                     |
	10001032 | 64 8B 3D 30 00 00 00             | mov edi,dword ptr fs:[30]                     |
	// Direct with null reg
	1000104B | 64 8B 40 30                      | mov eax,dword ptr fs:[eax+30]                 |
	1000104F | 64 8B 7F 30                      | mov edi,dword ptr fs:[edi+30]                 |

	// Via reg
	mov push/pop 30 then:
	10001039 | 64 8B 00                         | mov eax,dword ptr fs:[eax]                    |
	1000103C | 64 8B 08                         | mov ecx,dword ptr fs:[eax]                    |
	1000103F | 64 8B 18                         | mov ebx,dword ptr fs:[eax]                    |
	10001042 | 64 8B 39                         | mov edi,dword ptr fs:[ecx]                    |
	10001045 | 64 8B 3B                         | mov edi,dword ptr fs:[ebx]                    |
	10001048 | 64 8B 3F                         | mov edi,dword ptr fs:[edi]                    |

    // Via TIB[0x18] 
    │   0x00000028      64a118000000   mov eax, dword fs:[0x18]
    │   0x0000002e      53             push ebx
    │   0x0000002f      56             push esi
    │   0x00000030      8955e8         mov dword [ebp - 0x18], edx
    │   0x00000033      8b4030         mov eax, dword [eax + 0x30]
    │   0x00000036      57             push edi
    │   0x00000037      894df0         mov dword [ebp - 0x10], ecx
    │   0x0000003a      8b400c         mov eax, dword [eax + 0xc]
    │   0x0000003d      8b4014         mov eax, dword [eax + 0x14]


	Detects:
		mov <reg>, FS:[any imm32 or r/m]
		mov <reg> [<reg> + 0x0c]
		short jmp (obfuscation) or mov/lea <reg> [<reg> + 0x0c/0x14/0x1c]    0x0C/0x14/0x1c
    */

    /*
        Method 1, directly access fs:[0x30]. These per register sigs ensure
        the register storing *PEB in the first instr, is the same reg used to access LdrData
        In the second instruction

    */
    $get_ldr_data_direct_eax_x86 =  {
                                        64 A1 30 00 00 00 [0-40] 
                                        (8B|8D) (40|48|50|58|68|70|78) 0C [0-10]
                                        (8B|8D) (4?|5?|6?|7?) (0C|14|1C) 
                                    }

    $get_ldr_data_direct_eax2_x86 =  {
                                        64 8B (05|40|41|42|43|45|46|47) 30 [0-40] 
                                        (8B|8D) (40|48|50|58|68|70|78) 0C [0-10]
                                        (8B|8D) (4?|5?|6?|7?) (0C|14|1C) 
                                    }

    $get_ldr_data_direct_ecx_x86 =  {
                                        64 8B (0D|48|49|4A|4B|4D|4E|4F) 30 [0-40] 
                                        (8B|8D) (41|49|51|59|69|71|79) 0C [0-10]
                                        (8B|8D) (4?|5?|6?|7?) (0C|14|1C) 
                                    }

    $get_ldr_data_direct_edx_x86 =  {
                                        64 8B (15|50|51|52|53|55|56|57) 30 [0-40] 
                                        (8B|8D) (42|4a|52|5a|6a|72|7a) 0C [0-10]
                                        (8B|8D) (4?|5?|6?|7?) (0C|14|1C) 
                                    }

    $get_ldr_data_direct_ebx_x86 =  {
                                        64 8B (1D|58|59|5A|5B|5D|5E|5F) 30 [0-40] 
                                        (8B|8D) (43|4b|53|5b|6b|73|7b) 0C [0-10]
                                        (8B|8D) (4?|5?|6?|7?) (0C|14|1C) 
                                    }

    $get_ldr_data_direct_ebp_x86 =  {
                                        64 8B (2D|68|69|6A|6B|6D|6E|6F) 30 [0-40] 
                                        (8B|8D) (45|4d|55|5d|6d|75|7d) 0C [0-10]
                                        (8B|8D) (4?|5?|6?|7?) (0C|14|1C) 
                                    }

    $get_ldr_data_direct_esi_x86 =  {
                                        64 8B (35|70|71|72|73|75|76|77) 30 [0-40] 
                                        (8B|8D) (46|4e|56|5e|6e|76|7e) 0C [0-10]
                                        (8B|8D) (4?|5?|6?|7?) (0C|14|1C) 
                                    }

    $get_ldr_data_direct_edi_x86 =  {
                                        64 8B (3D|78|79|7A|7B|7D|7E|7F) 30 [0-40] 
                                        (8B|8D) (47|4f|57|5f|6f|77|7f) 0C [0-10]
                                        (8B|8D) (4?|5?|6?|7?) (0C|14|1C)
                                    }


    // Method 2. TIB->PEB->LdrData
	$get_ldr_data_via_TIB_eax_x86 = { 
                                            (64 a1 18 00 00 00 | 64 (8B|8D) (0d|15|1d|25|2d|35|3d) 18 00 00 00)     [0-40]     // mov <reg> FS:[0x18] &
                                            (8B|8D) (40|41|42|43|46|47) 30                                          [0-16]     // mov eax [reg+0x30]
                                            (8B|8D) (40|48|50|58|70|78) 0C                                          [0-16]     // mov <reg> [eax + 0x0C] *LdrData 
                                        ( 
                                            E8|E9|EB|7?|                                                                       // jmp/call
                                            (8B|8D) (4?|5?|6?|7?) (0C|14|1C)                                                   // mov <reg> [<reg> + 0x0C/0x14/0x1C]
                                        )
                                    }

	$get_ldr_data_via_TIB_ecx_x86 = { 
                                            (64 a1 18 00 00 00 | 64 (8B|8D) (0d|15|1d|25|2d|35|3d) 18 00 00 00)     [0-40]     // mov <reg> FS:[0x18] &
                                            (8B|8D) (48|49|4a|4b|4e|4f) 30                                          [0-16]     // mov ecx [reg+0x30]
                                            (8B|8D) (41|49|51|59|71|79) 0C                                          [0-16]     // mov <reg> [ecx + 0x0C] *LdrData 
                                        ( 
                                            E8|E9|EB|7?|                                                                       // jmp/call
                                            (8B|8D) (4?|5?|6?|7?) (0C|14|1C)                                                   // mov <reg> [<reg> + 0x0C/0x14/0x1C]
                                        )
                                    }

	$get_ldr_data_via_TIB_edx_x86 = { 
                                            (64 a1 18 00 00 00 | 64 (8B|8D) (0d|15|1d|25|2d|35|3d) 18 00 00 00)     [0-40]     // mov <reg> FS:[0x18] &
                                            (8B|8D) (50|51|52|53|56|57) 30                                          [0-16]     // mov edx [reg+0x30]
                                            (8B|8D) (42|4a|52|5a|72|7a) 0C                                          [0-16]     // mov <reg> [edx + 0x0C] *LdrData 
                                        ( 
                                            E8|E9|EB|7?|                                                                       // jmp/call
                                            (8B|8D) (4?|5?|6?|7?) (0C|14|1C)                                                   // mov <reg> [<reg> + 0x0C/0x14/0x1C]
                                        )
                                    }

	$get_ldr_data_via_TIB_ebx_x86 = { 
                                            (64 a1 18 00 00 00 | 64 (8B|8D) (0d|15|1d|25|2d|35|3d) 18 00 00 00)     [0-40]     // mov <reg> FS:[0x18] &
                                            (8B|8D) (58|59|5a|5b|5e|4f) 30                                          [0-16]     // mov ebx [reg+0x30]
                                            (8B|8D) (43|4b|53|5b|73|7b) 0C                                          [0-16]     // mov <reg> [ebx + 0x0C] *LdrData 
                                        ( 
                                            E8|E9|EB|7?|                                                                       // jmp/call
                                            (8B|8D) (4?|5?|6?|7?) (0C|14|1C)                                                   // mov <reg> [<reg> + 0x0C/0x14/0x1C]
                                        )
                                    }

	$get_ldr_data_via_TIB_ebp_x86 = { 
                                            (64 a1 18 00 00 00 | 64 (8B|8D) (0d|15|1d|25|2d|35|3d) 18 00 00 00)     [0-40]     // mov <reg> FS:[0x18] &
                                            (8B|8D) (68|69|6a|6b|6d|6e|6f) 30                                       [0-16]     // mov ebp [reg+0x30]
                                            3E (8B|8D) (45|4d|55|5d|6d|75|7d) 0C                                    [0-16]     // mov <reg> [ebp + 0x0C] *LdrData 
                                        ( 
                                            E8|E9|EB|7?|                                                                       // jmp/call
                                            (8B|8D) (4?|5?|6?|7?) (0C|14|1C)                                                   // mov <reg> [<reg> + 0x0C/0x14/0x1C]
                                        )
                                    }

	$get_ldr_data_via_TIB_esi_x86 = { 
                                            (64 a1 18 00 00 00 | 64 (8B|8D) (0d|15|1d|25|2d|35|3d) 18 00 00 00)     [0-40]     // mov <reg> FS:[0x18] &
                                            (8B|8D) (70|71|72|73|76|77) 30                                          [0-16]     // mov esi [reg+0x30]
                                            (8B|8D) (46|4e|56|5e|76|7e) 0C                                          [0-16]     // mov <reg> [esi + 0x0C] *LdrData 
                                        ( 
                                            E8|E9|EB|7?|                                                                       // jmp/call
                                            (8B|8D) (4?|5?|6?|7?) (0C|14|1C)                                                   // mov <reg> [<reg> + 0x0C/0x14/0x1C]
                                        )
                                    }

	$get_ldr_data_via_TIB_edi_x86 = { 
                                            (64 a1 18 00 00 00 | 64 (8B|8D) (0d|15|1d|25|2d|35|3d) 18 00 00 00)     [0-40]     // mov <reg> FS:[0x18] &
                                            (8B|8D) (78|79|7a|7b|7e|7f) 30                                          [0-16]     // mov edi [reg+0x30]
                                            (8B|8D) (47|4f|57|5f|77|7f) 0C                                          [0-16]     // mov <reg> [edi + 0x0C] *LdrData 
                                        ( 
                                            E8|E9|EB|7?|                                                                       // jmp/call
                                            (8B|8D) (4?|5?|6?|7?) (0C|14|1C)                                                   // mov <reg> [<reg> + 0x0C/0x14/0x1C]
                                        )
                                    }




    // Method 3 reg = 30, *PEB = fs:[reg]
	$get_ldr_data_via_reg_x86 = {                                                                                                   // Method 3:
                                    ((b8|b9|ba|bb|bc|bd|be|bf) 30 | 6A 30 [0-8] (58|59|5a|5b|5c|5d|5e|5f))  [0-8]                   // mov <reg>, 0x30 or push 0x30/pop <reg> & 
                                    (64 8b (0?|1?|2?|3?) | 64 8b (04|0c|14|1c|24|2c|34|3c|45|4d|55|5d|65|6d|75|7d) (00|24)) [0-10]  // mov <reg> FS:[<reg>]
                                    ((8B|8D) (4?|5?|6?|7?) 0C | (8B|8D) (44|4c|54|5c|64|6c|74|7c) 24 0C) [0-10]                     // mov <reg> [<reg> + 0x0C] 
                                    ( 
                                        E8|E9|EB|7?|                                                                                // jmp/call
                                        ((8B|8D) (4?|5?|6?|7?) (0C|14|1C) | (8B|8D) (44|4c|54|5c|64|6c|74|7c) 24 (0C|14|1C))        // mov <reg> [<reg> + 0x0C/0x14/0x1C]
                                    )
                                }
    // This along with the signature condition below removes a persistent FP caused by Application Verifier 
    // https://docs.microsoft.com/en-us/previous-versions/visualstudio/visual-studio-2008/ms220948(v=vs.90)?redirectedfrom=MSDN
    // TODO YARA 4.0 should be able to reference pdb path with pe.pdb_path
    //$pdb = "vrfcore.pdb" 

    /*
        Common pattern in windows libraries for getting PEB.SessionID that causes some FPs
        0x00000009      64a118000000   mov eax, dword fs:[0x18]
        0x0000000f      8b4030         mov eax, dword [eax + 0x30]
        0x00000012      8bb8d4010000   mov edi, dword [eax + 0x1d4]
    */
    $fp_get_session_id = {
                        (64 a1 18 00 00 00 | 64 (8B|8D) (0d|15|1d|25|2d|35|3d) 18 00 00 00)              // mov <reg> FS:[0x18] &
                        ((8B|8D) (4?|5?|6?|7?) 30 | (8B|8D) (44|4c|54|5c|64|6c|74|7c) 24 30)             // mov <reg>, [reg+0x30]
                        ((8B|8D) (8?|9?|a?|b?) d4 01 00 00 )                                             // mov <reg>, [reg+0x1d4]
                      }
    


    $Trickbot_split_PEB = {   E8 ?? ?? ?? ??                          [0-12]
                        (8B|8D) (40|48|50|58|68|70|78) 0C       [0-13]
                        ( 
                            (E8|E9|EB|7?) | 
                            (8B|8D) (4?|5?|6?|7?) (0C|14|1C) 
                        )
                    }

  condition:
    any of ($get*) and not any of ($fp*)
    or for any of ($Trickbot_split_PEB*):
    (
        for any j in (0..16): // follow the relative call offset and see if that function contains a mov <reg>, fs:[30]
        (
            uint32be(@ + 5 + int32(@+1)+j) == 0x64A13000 or
            (uint32be(@ + 5 + int32(@+1)+j) & 0xFFFF05FF) == 0x648B0530 // & 0xFFFF05FF masks off the reg part of the op
        )
    )
            
}
