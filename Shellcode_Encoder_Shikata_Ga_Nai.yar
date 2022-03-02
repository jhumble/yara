rule Shellcode_Encoder_Shikata_Ga_Nai {
  meta:
    tlp = "green"
    author = "Jeremy Humble / Nick Hoffman"
    date = "2018-10-26"
    description = "Catches shellcode encoded with MSF's Shikata Ga Nai"
    references = "https://www.boozallen.com/c/insight/blog/the-shikata-ga-nai-encoder.html, https://github.com/rapid7/metasploit-framework/blob/master/modules/encoders/x86/shikata_ga_nai.rb"
    hashes = "1dac677e4a44b1a706e81cef0e613d9e"

  strings:
    /*
    Steps:
      any fpu instruction
      fstenv
      pop (getcpu)
      clear_register
      add counter
      Decode loop
    */

$op_decoder = {  (
                    d9 (e8|e9|ea|eb|ec|ed|ee|c?|d0|e1|f6|f7|e5) |
                    (da|db) (c?|d?) |
                    dd (c0|c1|c2|c3|c4|c5|c6|c7)
                 ) [0-8]                             // FPU instruction
                 d9 74 24 f4 [0-8]                   // fnstenv
                 (58|59|5a|5b|5c|5d|5e|5f) [0-8]     // pop
                 (31|29|33|2b) c9 [0-8]              // clear register
                 (b1|69 b9 | b9) [0-8]               // add counter
                 (83 | 31 | 03) [1-8]                // xor/add/sub loop
                 (83 | 31 | 03) [1-8]                // xor/add/sub loop
                 (83 | 31 | 03)                      // xor/add/sub loop
                }


  condition:
    any of them
}
