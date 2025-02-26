# API-Return-Address-Spoofing-PoC
WinSpoof is a proof-of-concept (PoC) demonstrating return address spoofing when calling Windows API functions. It utilizes dynamically generated shellcode to manipulate return addresses and execute API calls with spoofed execution flows.

Features:
Executable Memory Allocation – Allocates memory for shellcode trampolines.
Dynamic Function Hooking – Redirects API calls through a spoofed execution flow.
Function Caching – Stores resolved API addresses for better performance.
Example Usage: Spoofed MessageBoxA Call

#include "api_spf.hpp"
#include <Windows.h>

int main() {
    api_spf spoofer;

    auto spoofed_MessageBoxA = (decltype(&MessageBoxA))spoofer.get("user32.dll", "MessageBoxA");

    if (spoofed_MessageBoxA) {
        spoofed_MessageBoxA(NULL, "Hello, Spoofed World!", "WinSpoof PoC", MB_OK);
    }

    return 0;
}
