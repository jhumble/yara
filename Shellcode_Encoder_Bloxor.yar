rule Shellcode_Encoder_Bloxor {
  meta:
    author = "Jeremy Humble"
    family = "Meterpreter"
    description = "Shellcode Encoder"
    reference = "https://github.com/securitykitten/msf_testing/tree/master/payloads,https://github.com/rapid7/metasploit-framework/blob/master/modules/encoders/x86/bloxor.rb"
    rule_creation_reference = "http://ref.x86asm.net/geek.html#modrm_byte_32" // for dissecting xor instr to find non clears

  strings:
    /*
    This encoder is highly polymorphic, but all variants perform the 3 following operations in order:
    add 2
        83 C? 02                                            add 2
        83 E? FE                                            sub -2
        81 E? FE FF FF FF                                   sub -2
        6A 02 ... 03 ?? 24                                      push 2, add <reg>, [esp]
        8D ?? 02                                            lea <reg>, [<reg> + 2]
    (shl <reg, 0x10, shr <reg>, 0x10 ALWAYS BACK TO BACK) OR mov word
        2x C1 E? 10                                         shl/shr <reg>, 0x10
        0F B7 ??                                            mov <reg>, WORD ptr:[<reg>]
    add 2
    (shl <reg, 0x10, shr <reg>, 0x10 ALWAYS BACK TO BACK) OR mov word
    xor (not against self) or xor via - "or" "and" "not" "and"
        90 ?? 21 ?? F7 ?? 21 ??                             or, and, not, and           TODO could tighten this up further. I think all the ?? start with C?, D?, E?, F?
        (31 | 33) (absurdly long list)                      xor not against self (see
    store word
        66 89                                               mov <mem>, <reg16>
        66 5? ... 66 8F                                     push <reg16> ... pop WORD ptr:<reg16>

    Example:
    012C227D  | 29 C1               | sub ecx,eax                                                                         | start
    012C227F  | 83 C1 46            | add ecx,46                                                                          |
    012C2282  | 51                  | push ecx                                                                            |
    012C2283  | 5E                  | pop esi                                                                             |
    012C2284  | 8D 76 02            | lea esi,dword ptr ds:[esi+2]                                                        |
    012C2287  | 68 F7 00 00 00      | push F7                                                                             | length of encoded payload
    012C228C  | 5A                  | pop edx                                                                             |
    012C228D  | 0F B7 1E            | movzx ebx,word ptr ds:[esi]                                                         | read chunk from *src
    012C2290  | 81 EE FE FF FF FF   | sub esi,FFFFFFFE                                                                    | *src += 2
    012C2296  | 8B 39               | mov edi,dword ptr ds:[ecx]                                                          | read 4 bytes and use shl/shr to "cast" to 16-bit
    012C2298  | C1 E7 10            | shl edi,10                                                                          |
    012C229B  | C1 EF 10            | shr edi,10                                                                          |
    012C229E  | 89 F8               | mov eax,edi                                                                         |
    012C22A0  | 09 D8               | or eax,ebx                                                                          | convoluted xor
    012C22A2  | 21 DF               | and edi,ebx                                                                         |
    012C22A4  | F7 D7               | not edi                                                                             |
    012C22A6  | 21 C7               | and edi,eax                                                                         |
    012C22A8  | 66 89 39            | mov word ptr ds:[ecx],di                                                            | store WORD into *dst
    012C22AB  | 6A 02               | push 2                                                                              |
    012C22AD  | 03 0C 24            | add ecx,dword ptr ss:[esp]                                                          | *dst += 2
    012C22B0  | 58                  | pop eax                                                                             |
    012C22B1  | 4A                  | dec edx                                                                             |
    012C22B2  | 85 D2               | test edx,edx                                                                        |
    012C22B4  | 0F 85 D3 FF FF FF   | jne x32dbg.12C228D                                                                  |
    */

    $bloxor = {
                (                                           // *** add primitive ***
                    83 (E8|E9|EA|EB|ED|EE|EF) FE |              // 1 byte SUB -2
                    83 (C0|C1|C2|C3|C5|C6|C7) 02 |              // 1 byte ADD 2
                    2D (FE FF FF FF | 02 00 00 00) |            // 4 byte ADD/SUB implicit eax
                    81 (E8|E9|EA|EB|ED|EE|EF) FE FF FF FF |     // 4 byte SUB -2
                    83 (C0|C1|C2|C3|C5|C6|C7) 02 00 00 00 |     // 4 byte ADD 2
                    (   // add 2, via 3 instr
                        6A (02|FE) [0-4]                        // PUSH 2/-2
                        (03|2B) (04|0C|14|1C|2C|34|3C) 24 [0-4] // ADD/sub <reg>, dword ptr:[esp]
                        (58|59|5a|5b|5d|5e|5f)                  // POP
                    ) | 
                    8D (4?|5?|6?|7?) 02                         // LEA <reg>, [<reg> + 2]
                ) [0-16]
                (
                    C1 E? 10 C1 E? 10 | 
                    0F B7 ??
                )   [0-8]
                (
                    83 C? 02 | 
                    81 E? FE FF FF FF | 
                    2D FE FF FF FF | 
                    83 E? FE | 
                    6A 02 [0-4] 03 ?? 24| 
                    8D ?? 02
                ) [0-8]
                (
                    C1 E? 10 C1 E? 10 | 
                    0F B7 ??
                )   [0-16]
                (
                    09 ?? 21 ?? F7 ?? 21 ?? | 
                    (31|33) (C1|C2|C3|C4|C5|C6|C7|C8|CA|CB|CC|CD|CE|CF|
                             D0|D1|D3|D4|D5|D6|D7|D8|D9|DA|DC|DD|DE|DF|
                             E0|E1|E2|E3|E5|E6|E7|E8|E9|EA|EB|EC|EE|EF|
                             F0|F1|F2|F3|F4|F5|F7|F8|F9|FA|FB|FC|FD|FE)
                )[0-8]
                  (
                    66 89 | 
                    66 5? [0-6] 66 8F
                  )
              }


  condition:
    any of them
}
