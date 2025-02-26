#include <windows.h>
#include <iostream>
#include <unordered_map>
#include "include.hpp"

class api_spf {
private:
    std::unordered_map<std::string, FARPROC> api_cache;
    std::unordered_map<std::string, HMODULE> module_cache;
    std::vector<void*> executable_pages;
    std::vector<void*> rwx_addresses;
public:
    void find_executable_memory( );

    void* get_random_exec_page( );

    FARPROC create_trampoline( FARPROC );

    void* allocate_executable_memory( size_t );

    void* setup_spoofed_return( void* );

    api_spf( ) 
    {
            
        
    }

    FARPROC get( const std::string&, const std::string& );
};
