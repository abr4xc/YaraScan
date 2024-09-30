/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2024-09-23
   Identifier: hola
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */



rule sliver_binary_native {

    meta:
        author = "Kev Breen @kevthehermit"
        description = "Detects unmodified Sliver implant generated for Windows, Linux or MacOS"

    strings: 
        $sliverpb = "sliverpb"
        $bishop_git = "github.com/bishopfox/"
        $encryption = "chacha20poly1305"


    condition:
        // This detects Go Headers for PE, ELF, Macho
        (
			(uint16(0) == 0x5a4d) or 
			(uint32(0)==0x464c457f) or 
			(uint32(0) == 0xfeedfacf) or 
			(uint32(0) == 0xcffaedfe) or 
			(uint32(0) == 0xfeedface) or 
			(uint32(0) == 0xcefaedfe) 
		)
        // String matches
        and $sliverpb
        or  $bishop_git
        or $encryption
}

rule sliver_memory {

    meta:
        author = "Kev Breen @kevthehermit"
        description = "Detects Sliver running in memory"

    strings: 
        $str1 = "sliverpb"


    condition:
        all of them
}