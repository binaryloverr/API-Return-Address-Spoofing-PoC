# API-Return-Address-Spoofing-PoC
WinSpoof is a proof-of-concept (PoC) demonstrating return address spoofing when calling Windows API functions. It utilizes dynamically generated shellcode to manipulate return addresses and execute API calls with spoofed execution flows. ( This project still needs a lot of work, dont treat as ready to paste. )

    api_spf spoofer;

    auto spoofed_MessageBoxA = ( decltype( &MessageBoxA ) )spoofer.get( "user32.dll", "MessageBoxA" );

    if ( spoofed_MessageBoxA ) 
    {
        spoofed_MessageBoxA( NULL, "Hello, Spoofed World!", "WinSpoof PoC", MB_OK );
    }

    return 0;


