#include "api_spf.hpp"
#include <intrin.h>
#include <string>
#include <vector>
#include <Psapi.h>
#include <iostream>
#include <random>

unsigned char jump_shellcode[ ] =
{
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 
    0xFF, 0xE0 //jmp rax
};
unsigned char stub_shellcode[ ] =
{
    0x48, 0x89, 0x4C, 0x24, 0x08,           // mov [rsp+8], rcx  
    0x48, 0x89, 0x54, 0x24, 0x10,           // mov [rsp+16], rdx 
    0x4C, 0x89, 0x44, 0x24, 0x18,           // mov [rsp+24], r8  
    0x4C, 0x89, 0x4C, 0x24, 0x20,           // mov [rsp+32], r9  
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,     // mov rax, func
    0x00, 0x00, 0x00, 0x00,
    0xFF, 0xE0                              // jmp rax
};
unsigned char return_spoof_shellcode[ ] =
{
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax,
    0x50,                                                         // push rax
    0xC3                                                          // ret
};
void* api_spf::allocate_executable_memory( size_t size )
{
    return VirtualAlloc( nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
}

void* api_spf::setup_spoofed_return( void* fake_ret_address ) {
    void* exec_mem = allocate_executable_memory( 32 );
    if ( !exec_mem ) return nullptr;

    memcpy( return_spoof_shellcode + 2, &fake_ret_address, sizeof( void* ) );
    memcpy( exec_mem, return_spoof_shellcode, sizeof( return_spoof_shellcode ) );

    DWORD oldProtect;
    VirtualProtect( exec_mem, sizeof( return_spoof_shellcode ), PAGE_EXECUTE_READ, &oldProtect );

    return exec_mem;
}


FARPROC api_spf::create_trampoline( FARPROC function )
{
    std::cout << "[DEBUG] Creating trampoline for function at: " << ( void* )function << std::endl;

    void* trampoline = VirtualAlloc( nullptr, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );

    if ( !trampoline )
    {
        std::cout << "[-] ERROR: Failed to allocate trampoline memory!\n";
        return nullptr;
    }

    std::cout << "[DEBUG] Allocated trampoline memory at: " << trampoline << std::endl;

    std::cout << "[DEBUG] Original bytes at target function:";

    for ( int i = 0; i < 10; i++ )
    {
        printf(" %02X", ( ( unsigned char* )function )[ i ] );
    }
    std::cout << std::endl;

    memcpy( &stub_shellcode[22], &function, sizeof( void* ) );
    memcpy( trampoline, stub_shellcode, sizeof (stub_shellcode ) );

    std::cout << "[DEBUG] Trampoline bytes:";
    for ( int i = 0; i < sizeof( stub_shellcode ); i++ )
    {
        printf( " %02X", ( ( unsigned char* )trampoline )[ i ] );
    }
    std::cout << std::endl;

    DWORD protect;
    VirtualProtect( trampoline, sizeof( stub_shellcode ), PAGE_EXECUTE_READ, &protect );

    std::cout << "[DEBUG] Trampoline creation complete. Trampoline at: " << trampoline << std::endl;
    return ( FARPROC )trampoline;
}

FARPROC api_spf::get( const std::string& module_name, const std::string& api_name )
{
    std::cout << "\n[DEBUG] Resolving " << api_name << " from " << module_name << std::endl;

    auto cache_it = this->api_cache.find( api_name );
    if (cache_it != this->api_cache.end( ) )
    {
        std::cout << "[DEBUG] Found in cache at: " << ( void* )cache_it->second << std::endl;
        return cache_it->second;
    }

    HMODULE h_module = nullptr;
    auto module_it = this->module_cache.find( module_name );
    if ( module_it != this->module_cache.end( ) )
    {
        h_module = module_it->second;
        std::cout << "[DEBUG] Found module in cache at: " << ( void* )h_module << std::endl;
    }
    else
    {
        h_module = LoadLibraryA( module_name.c_str( ) );

        if ( h_module )
        {
            module_cache[ module_name ] = h_module;
            std::cout << "[DEBUG] Loaded new module at: " << ( void* )h_module << std::endl;
        }
    }

    if ( !h_module )
    {
        std::cout << "[-] Failed to load module: " << module_name << std::endl;
        return nullptr;
    }

    FARPROC original_function = GetProcAddress( h_module, api_name.c_str( ) );

    if ( !original_function )
    {
        std::cout << "[-] Failed to get address for: " << api_name << std::endl;
        return nullptr;
    }

    std::cout << "[DEBUG] Original function address: " << ( void* )original_function << std::endl;

    FARPROC trampoline = this->create_trampoline ( original_function );
    if ( !trampoline )
    {
        std::cout << "[-] Trampoline creation failed, falling back to original function" << std::endl;
        api_cache[ api_name ] = original_function;
        return original_function;
    }

    api_cache[ api_name ] = trampoline;
    return trampoline;
}
