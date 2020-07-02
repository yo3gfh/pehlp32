/*
    PEHLP32, a PE (portable executable) helper library v. 1.1
    ----------------------------------------------------------
    Copyright (c) 2020 Adrian Petrila, YO3GFH
    Original code "imported" with small changes from PEDump utility,
    (c) 1994-2001 Matt Pietrek.
    
    http://bytepointer.com/resources/pietrek_in_depth_look_into_pe_format_pt1.htm

    I've organized bits and pieces from the original PEDump code in this DLL as part
    of a university lab project (a task manager). Thanks to Matt for all of his work in
    bringing the MS Windows guts to more light. Please note that this is cca. 20 years
    old code. I digged it from the bowels of my drive and spiff it a little bit to 
    compile with Pelles's C compiler and to generate a 64 bit version as well. It was
    good fun, make what you want of it. I've included the archive with the PEDump code
    as well.
    
                                * * *
                                
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

                                * * *

    It's taylored to my own needs, modify it to suit your own. I'm not a professional programmer,
    so this isn't the best code you'll find on the web, you have been warned :-))

    All the bugs are guaranteed to be genuine, and are exclusively mine =)
*/

#include <windows.h>
#include "__pehlp32.h"

static const            TCHAR      Alphabet[] = TEXT("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");

static                  DWORD      undiv                    ( DWORD val, DWORD * quot );
static                  TCHAR      * untoa                  ( DWORD value, TCHAR * buffer, int radix );
static                  TCHAR      * intoa                  ( int value, TCHAR * buffer, int radix );


static BOOL TimeToFileTime ( long time, FILETIME * pft );

// EXPORTED FUNCTIONS

BOOL                    WINAPI PE_OpenModule             ( TCHAR * modname, MOD_BASE * mod, BOOL readonly );
BOOL                    WINAPI PE_CloseModule            ( MOD_BASE * mod );
LPVOID                  WINAPI PE_RVAToPtr               ( DWORD rva, PIMAGE_NT_HEADERS pNTHeader, DWORD imageBase );
PIMAGE_SECTION_HEADER   WINAPI PE_GetSectionHeader       ( DWORD rva, PIMAGE_NT_HEADERS pNTHeader );
PIMAGE_SECTION_HEADER   WINAPI PE_FindSection            ( const TCHAR * name, PIMAGE_NT_HEADERS pNTHeader );
BOOL                    WINAPI PE_EnumImports            ( DWORD base, ENUMIMPORTMODPROC enummod, ENUMIMPORTFNSPROC enumfns, DWORD lParam );
BOOL                    WINAPI PE_EnumExports            ( DWORD base, GETEXPORTINFOPROC getinfo, ENUMEXPORTFNSPROC enumfns, DWORD lParam );
BOOL                    WINAPI PE_EnumSections           ( DWORD base, ENUMSECTIONSPROC enumsections, DWORD lParam );
BOOL                    WINAPI PE_EnumCharacteristics    ( DWORD base, ENUMFHATTRIBPROC enumattrib, DWORD lParam );
BOOL                    WINAPI PE_GetMachineType         ( DWORD machine, TCHAR * szoutbuf );
LPVOID                  WINAPI PE_GetFileHeader          ( DWORD base );
LPVOID                  WINAPI PE_GetOptionalHeader      ( DWORD base );
LPVOID                  WINAPI PE_GetNTHeader            ( DWORD base );
BOOL                    WINAPI PE_IsConsole              ( DWORD base );
BOOL                    WINAPI PE_IsGUI                  ( DWORD base );
BOOL                    WINAPI PE_HexDump                ( void * src, DWORD dwsrclen, HEXDUMPPROC hexdumpproc, DWORD lParam );


// DLL entrypoint

BOOL APIENTRY DllMain ( HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved )
/*****************************************************************************************************************/
{
    return TRUE;
}

// IMPLEMENTATION

BOOL WINAPI PE_OpenModule ( TCHAR * modname, MOD_BASE * mod, BOOL readonly )
/*****************************************************************************************************************/
/*  Open a PE module, memory map it and check if ok                                                              */
{
    HANDLE              hFile;
    HANDLE              hFileMapping;
    LPVOID              lpFileBase;
    PIMAGE_DOS_HEADER   dosHeader;
    PIMAGE_NT_HEADERS   pNTHeader;
    BOOL                result = FALSE;
    DWORD               flags[6] = { GENERIC_READ | GENERIC_WRITE, 
                                     GENERIC_READ, PAGE_READWRITE,
                                     PAGE_READONLY, FILE_MAP_WRITE,
                                     FILE_MAP_READ };
    ZeroMemory ( mod, sizeof ( MOD_BASE ) );

    hFile = CreateFile ( modname, flags[readonly], FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
                    
    if ( hFile == INVALID_HANDLE_VALUE ) { return FALSE; }

    hFileMapping = CreateFileMapping ( hFile, NULL, flags[readonly + 2], 0, 0, NULL );
    
    if ( ( hFileMapping == NULL) || ( GetLastError() == ERROR_ALREADY_EXISTS ) )
    {
        CloseHandle ( hFile );
        return FALSE;
    }
    
    lpFileBase = MapViewOfFile ( hFileMapping, flags[readonly + 4], 0, 0, 0 );

    if ( lpFileBase == NULL )
    {
        CloseHandle ( hFileMapping );
        CloseHandle ( hFile );
        return FALSE;
    }

    dosHeader = ( PIMAGE_DOS_HEADER )lpFileBase;
    pNTHeader = MakePtr ( PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew );

    // check for PE signature
    __try
    {
        if ( ( dosHeader->e_magic != IMAGE_DOS_SIGNATURE ) || ( pNTHeader->Signature != IMAGE_NT_SIGNATURE ) )
        {
            UnmapViewOfFile ( lpFileBase );
            CloseHandle ( hFileMapping );
            CloseHandle ( hFile );
            mod->type = T_OTHER;
            result = FALSE;
        }
        else
        {
            mod->type       = T_PE;
            mod->filebase   = lpFileBase;
            mod->ntheader   = pNTHeader;
            mod->hfile      = hFile;
            mod->hmap       = hFileMapping;
            result          = TRUE;
        }
    }
    __except ( TRUE )
    {
        UnmapViewOfFile ( lpFileBase );
        CloseHandle ( hFileMapping );
        CloseHandle ( hFile );
        mod->type = T_OTHER;
        result = FALSE;
    }

    return result;
}

BOOL WINAPI PE_CloseModule ( MOD_BASE * mod )
/*****************************************************************************************************************/
/* Cleanup                                                                                                       */
{
    if ( mod == NULL ) { return FALSE; }
    
    if ( mod->filebase == NULL || mod->hfile == NULL || mod->hmap == NULL ) { return FALSE; }

    UnmapViewOfFile ( mod->filebase );
    CloseHandle ( mod->hmap );
    CloseHandle ( mod->hfile );

    ZeroMemory ( mod, sizeof ( MOD_BASE ) );

    return TRUE;
}


LPVOID WINAPI PE_RVAToPtr ( DWORD rva, PIMAGE_NT_HEADERS pNTHeader, DWORD imageBase )
/*****************************************************************************************************************/
/* Convert a RVA (relative virtual address) into a usable pointer                                                */
{    
    PIMAGE_SECTION_HEADER   pSectionHdr;
    int                     delta;

    if  ( ( pNTHeader == NULL ) || ( imageBase == 0 ) ) { return NULL; }
        
    pSectionHdr = PE_GetSectionHeader ( rva, pNTHeader );
    if ( !pSectionHdr ) { return 0; }

    delta = ( int )( pSectionHdr->VirtualAddress - pSectionHdr->PointerToRawData );
    return ( PVOID )( imageBase + rva - delta );
}

PIMAGE_SECTION_HEADER WINAPI PE_GetSectionHeader ( DWORD rva, PIMAGE_NT_HEADERS pNTHeader )
/*****************************************************************************************************************/
/* Return a pointer to a section header                                                                          */
{
    PIMAGE_SECTION_HEADER   section;
    int                     i;
    DWORD                   watcom;

    if ( pNTHeader == NULL ) { return 0; }
    if ( ( section = IMAGE_FIRST_SECTION ( pNTHeader ) ) == NULL ) { return 0; }

    // in case you happen to open a module linked with Watcom tools :)
    // whih sets Misc.VirtualSize to 0..
    for ( i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++ )
    {
        if ( section->Misc.VirtualSize == 0 )
            watcom = section->SizeOfRawData;
        else
            watcom = section->Misc.VirtualSize;

        // check if provided RVA is in this section
        if ( ( rva >= section->VirtualAddress) && ( rva < ( section->VirtualAddress + watcom ))) { return section; }
    }
    return 0;
}

BOOL WINAPI PE_EnumImports ( DWORD base, ENUMIMPORTMODPROC enummod, ENUMIMPORTFNSPROC enumfns, DWORD lParam )
/*****************************************************************************************************************/
/* Enum imported modules as well as the coresponding imported functions                                          */
{
    PIMAGE_NT_HEADERS           pNTHeader;
    PIMAGE_DOS_HEADER           dosHeader;
    PIMAGE_IMPORT_DESCRIPTOR    importDesc;
    PIMAGE_SECTION_HEADER       pSection;
    PIMAGE_THUNK_DATA           thunk, thunkIAT = 0;
    PIMAGE_IMPORT_BY_NAME       pOrdinalName;
    DWORD                       importsStartRVA;
    IMPORT_INFO                 ii;
    FILETIME                    ft;
    SYSTEMTIME                  st;
    BOOL                        result = FALSE;

    if ( base == 0 ) { return FALSE; }

__try
{
    dosHeader = ( PIMAGE_DOS_HEADER )base;
    pNTHeader = MakePtr ( PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew );

    importsStartRVA = GetImgDirEntryRVA ( pNTHeader, IMAGE_DIRECTORY_ENTRY_IMPORT );
    if ( !importsStartRVA ) { return FALSE; }

    pSection = PE_GetSectionHeader( importsStartRVA, pNTHeader );
    if ( !pSection ) { return FALSE; }

    importDesc = ( PIMAGE_IMPORT_DESCRIPTOR )PE_RVAToPtr ( importsStartRVA, pNTHeader, base );
    if ( !importDesc ) { return FALSE; }

    while ( 1 )
    {
        if ( ( importDesc->TimeDateStamp == 0 ) && ( importDesc->Name == 0 ) )
            break;

        lstrcpy ( ii.name, PE_RVAToPtr ( importDesc->Name, pNTHeader, base ) );
        ii.characteristix = importDesc->Characteristics;

        TimeToFileTime ( ( long )importDesc->TimeDateStamp, &ft );
        FileTimeToSystemTime ( &ft, &st );
        wsprintf ( ii.timedate, TEXT("%0.2lu/%0.2lu/%lu, %0.2lu:%0.2lu:%0.2lu"),
                   st.wDay, st.wMonth, st.wYear,
                   st.wHour, st.wMinute, st.wSecond );

        ii.timestamp = importDesc->TimeDateStamp;        
        ii.forwarderchain = importDesc->ForwarderChain;
        ii.firstthunkrva = importDesc->FirstThunk;

        thunk = ( PIMAGE_THUNK_DATA )importDesc->Characteristics;
        thunkIAT = ( PIMAGE_THUNK_DATA )importDesc->FirstThunk;

        // do we have a null "Characteristics" ?
        if ( thunk == 0 )
        {
            // if yes, FirstThunk should not be null
            thunk = thunkIAT;
            
            if ( thunk == 0 ) { return FALSE; }
        }
        
        // get pointer to import table 
        thunk = ( PIMAGE_THUNK_DATA )PE_RVAToPtr ( ( DWORD )thunk, pNTHeader, ( DWORD )base );
        if ( !thunk ) { return FALSE; }

        thunkIAT = ( PIMAGE_THUNK_DATA )PE_RVAToPtr ( ( DWORD )thunkIAT, pNTHeader, base );
    
        // call the module user supplied callback function
        if ( enummod != NULL )
        {
            if ( enummod ( &ii, lParam ) == FALSE ) break;
        }
        
        // start enum functions
        while ( 1 )
        {
            if ( thunk->u1.AddressOfData == 0 )
                break;

            if ( thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG )
            {
                ii.ordinal = IMAGE_ORDINAL ( thunk->u1.Ordinal );
                lstrcpy ( ii.fnname, TEXT("N/A") );
            }
            else
            {
                pOrdinalName = ( PIMAGE_IMPORT_BY_NAME )( thunk->u1.AddressOfData );
                pOrdinalName = ( PIMAGE_IMPORT_BY_NAME )PE_RVAToPtr ( ( DWORD )pOrdinalName, pNTHeader, base );
                ii.ordinal = pOrdinalName->Hint;
                lstrcpy ( ii.fnname, pOrdinalName->Name );
            }
            
            // call the functions enum user supplied callback function
            if ( enumfns != NULL )
            {
                if ( enumfns ( &ii, lParam ) == FALSE )
                    break;
            }

            thunk++;
            thunkIAT++;
        }
        importDesc++;
    }
    result = TRUE;
}
    __except ( TRUE ) { result = FALSE; }
    return result;
}


BOOL WINAPI PE_EnumExports ( DWORD base, GETEXPORTINFOPROC getinfo, ENUMEXPORTFNSPROC enumfns, DWORD lParam )
/*****************************************************************************************************************/
/* If we have a DLL, enum exports                                                                                */
{
    PIMAGE_NT_HEADERS       pNTHeader;
    PIMAGE_DOS_HEADER       dosHeader;    
    PIMAGE_EXPORT_DIRECTORY exportDir;
    PIMAGE_SECTION_HEADER   header;
    TCHAR                   * filename;
    DWORD                   i, j;
    PDWORD                  functions;
    PWORD                   ordinals;
    DWORD                   * names;
    DWORD                   exportsStartRVA, exportsEndRVA, entryPointRVA;
    EXPORT_INFO             ei;
    FILETIME                ft;
    SYSTEMTIME              st;
    BOOL                    result = FALSE;

    if ( base == 0 ) { return FALSE; }

__try
{   
    dosHeader = ( PIMAGE_DOS_HEADER )base;
    pNTHeader = MakePtr ( PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew );

    exportsStartRVA = GetImgDirEntryRVA ( pNTHeader,IMAGE_DIRECTORY_ENTRY_EXPORT );
    exportsEndRVA   = exportsStartRVA + GetImgDirEntrySize ( pNTHeader, IMAGE_DIRECTORY_ENTRY_EXPORT );

    // get a IMAGE_SECTION_HEADER pointer 
    header = PE_GetSectionHeader ( exportsStartRVA, pNTHeader );
    if ( !header ) { return FALSE; }
        
    exportDir = ( PIMAGE_EXPORT_DIRECTORY ) PE_RVAToPtr ( exportsStartRVA, pNTHeader, base );
        
    filename = (TCHAR *)PE_RVAToPtr ( exportDir->Name, pNTHeader, base);
    lstrcpy ( ei.filename, filename );    
    ei.characteristix = exportDir->Characteristics;
    ei.timestamp = exportDir->TimeDateStamp;
    TimeToFileTime ( ( long )exportDir->TimeDateStamp, &ft );
    FileTimeToSystemTime ( &ft, &st );
    wsprintf ( ei.timedate, TEXT("%0.2lu/%0.2lu/%lu, %0.2lu:%0.2lu:%0.2lu"),
               st.wDay, st.wMonth, st.wYear,
               st.wHour, st.wMinute, st.wSecond );

    ei.majorver = exportDir->MajorVersion;
    ei.minorver = exportDir->MinorVersion;
    ei.ordbase = exportDir->Base;
    ei.nooffun = exportDir->NumberOfFunctions;
    ei.noofnames = exportDir->NumberOfNames;
    
    if ( getinfo != NULL )
    {
        if ( getinfo ( &ei, lParam ) == FALSE ) { return TRUE; }
    }

    // get pointers to function, ordinal and name tables
    functions = ( PDWORD )PE_RVAToPtr ( exportDir->AddressOfFunctions, pNTHeader, base );
    ordinals = ( PWORD )PE_RVAToPtr ( exportDir->AddressOfNameOrdinals, pNTHeader, base );
    names = ( DWORD* )PE_RVAToPtr ( exportDir->AddressOfNames, pNTHeader, base );

    for ( i = 0; i < exportDir->NumberOfFunctions; i++, functions++ )
    {
        entryPointRVA = *functions;

        // skip entrypoint 0 functions
        if ( entryPointRVA == 0 )
            continue;

        ei.entryptrva = entryPointRVA;
        ei.ordinal = i + exportDir->Base;
        lstrcpy ( ei.fnname, TEXT("N/A"));
        
        // check if our function is exported by name also
        for ( j=0; j < exportDir->NumberOfNames; j++ )
            if ( ordinals[j] == LOWORD(i) )
                lstrcpy ( ei.fnname, PE_RVAToPtr ( names[j], pNTHeader, base ) );

        // is it a forwarder? (from another DLL)
        // then entrypoint is in .edata section, and is an RVA to the DllName.EntryPointName
        if ( ( entryPointRVA >= exportsStartRVA ) && ( entryPointRVA <= exportsEndRVA ) )
        {
            ei.forwarder = ( DWORD )PE_RVAToPtr ( entryPointRVA, pNTHeader, base);
        }        

        // call user callback fun.
        if ( enumfns != NULL )
        {
            if ( enumfns ( &ei, lParam ) == FALSE )
                break;
        }
    }
    result = TRUE;
}
    __except ( TRUE ) { result = FALSE; }
    return result;
}

BOOL WINAPI PE_EnumSections ( DWORD base, ENUMSECTIONSPROC enumsections, DWORD lParam )
/*****************************************************************************************************************/
/* Enumerate sections                                                                                            */
{
    PIMAGE_NT_HEADERS       pNTHeader;
    PIMAGE_DOS_HEADER       dosHeader;
    PIMAGE_SECTION_HEADER   section;
    SECTION_INFO            si;
    unsigned                csections, i, j, k;
    BOOL                    result = FALSE;

    if ( ( base == 0 ) || ( enumsections == NULL ) ) { return FALSE; }

__try
{
    dosHeader = ( PIMAGE_DOS_HEADER ) base;
    pNTHeader = MakePtr ( PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew );
    section   = IMAGE_FIRST_SECTION ( pNTHeader );
    csections = pNTHeader->FileHeader.NumberOfSections;

    for ( i = 1; i <= csections; i++, section++ )
    {
        lstrcpyn ( si.name, section->Name, 9 );
        si.vsize        = section->Misc.VirtualSize;
        si.vaddr        = section->VirtualAddress;
        si.rdatasize    = section->SizeOfRawData;
        si.rdataoffs    = section->PointerToRawData;
        si.relocno      = section->NumberOfRelocations;
        si.relocoffs    = section->PointerToRelocations;
        si.chars        = section->Characteristics;
        k               = 0;
        for ( j = 0; j < NUMBER_SECTION_CHARACTERISTICS; j++ )
        {
            if ( section->Characteristics & SectionCharacteristics[j].flag )
            {
                lstrcpy ( si.szchars[k], SectionCharacteristics[j].name );
                k++;
            }
        }
        si.cchars = k;
        if ( enumsections ( &si, lParam ) == FALSE )
            break;
    }
    result = TRUE;
}
    __except( TRUE ) { result = FALSE; }
    return result;
}

PIMAGE_SECTION_HEADER WINAPI PE_FindSection ( const TCHAR * name, PIMAGE_NT_HEADERS pNTHeader )
/*****************************************************************************************************************/
/* Find a section by name                                                                                        */
{
    PIMAGE_SECTION_HEADER   section;
    int                     i;
    TCHAR                   tmp[16];

    if ( ( name == NULL ) || ( pNTHeader == NULL ) ) { return NULL; }
        
    section = IMAGE_FIRST_SECTION ( pNTHeader );
    
    for ( i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++ )
    {
        lstrcpyn ( tmp, section->Name, 9 );
        if ( 0 == lstrcmp ( tmp, name ) ) { return section; }
    }
    return NULL;
}

BOOL WINAPI PE_EnumCharacteristics ( DWORD base, ENUMFHATTRIBPROC enumattrib, DWORD lParam )
/*****************************************************************************************************************/
/* Enum module characteristics                                                                                   */
{
    PIMAGE_FILE_HEADER  pImageFileHeader;
    unsigned            i;
    TCHAR               buf[128];
    BOOL                result = FALSE;

    if ( ( base == 0 ) || ( enumattrib == NULL ) ) { return FALSE; }

__try
{
    pImageFileHeader = ( PIMAGE_FILE_HEADER )PE_GetFileHeader ( base );
    if ( pImageFileHeader == NULL ) { return FALSE; }

    for ( i = 0; i < NUMBER_IMAGE_HEADER_FLAGS; i++ )
    {
        if ( pImageFileHeader->Characteristics & ImageFileHeaderCharacteristics[i].flag )
        {
            lstrcpy ( buf, ImageFileHeaderCharacteristics[i].name );
            if ( enumattrib ( buf, lParam ) == FALSE )
                break;
        }
    }
    result = TRUE;
}
    __except ( TRUE ) { result = FALSE; }
    return result;
}

LPVOID WINAPI PE_GetFileHeader ( DWORD base )
/*****************************************************************************************************************/
/* Get a pointer to IMAGE_FILE_HEADER                                                                            */
{
    PIMAGE_NT_HEADERS       pNTHeader;
    PIMAGE_DOS_HEADER       dosHeader;

    if ( base == 0 ) { return NULL; }

    dosHeader = ( PIMAGE_DOS_HEADER ) base;
    pNTHeader = MakePtr ( PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew );

    return ( LPVOID )( ( PIMAGE_FILE_HEADER )&pNTHeader->FileHeader );
}

LPVOID WINAPI PE_GetOptionalHeader ( DWORD base )
/*****************************************************************************************************************/
/* Get a pointer to IMAGE_OPTIONAL_HEADER                                                                        */
{
    PIMAGE_NT_HEADERS       pNTHeader;
    PIMAGE_DOS_HEADER       dosHeader;

    if ( base == 0 ) { return NULL; }
    
    dosHeader = ( PIMAGE_DOS_HEADER ) base;
    pNTHeader = MakePtr ( PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew );

    return ( LPVOID )( ( PIMAGE_OPTIONAL_HEADER )&pNTHeader->OptionalHeader );
}

LPVOID WINAPI PE_GetNTHeader ( DWORD base )
/*****************************************************************************************************************/
/* Get a pointer to PIMAGE_NT_HEADERS                                                                            */
{
    PIMAGE_NT_HEADERS       pNTHeader;
    PIMAGE_DOS_HEADER       dosHeader;

    if ( base == 0 ) { return NULL; }
    
    dosHeader = ( PIMAGE_DOS_HEADER ) base;
    pNTHeader = MakePtr ( PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew );

    return ( LPVOID )pNTHeader;
}

BOOL  WINAPI PE_IsConsole ( DWORD base )
/*****************************************************************************************************************/
/* Do we a have a console app?                                                                                   */
{
    PIMAGE_NT_HEADERS       pNTHeader;
    PIMAGE_DOS_HEADER       dosHeader;
    PIMAGE_OPTIONAL_HEADER  pOptHeader;

    if ( base == 0 ) { return FALSE; }
    
    dosHeader = ( PIMAGE_DOS_HEADER ) base;
    pNTHeader = MakePtr ( PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew );

    pOptHeader = ( PIMAGE_OPTIONAL_HEADER )&pNTHeader->OptionalHeader;
    return ( ( pOptHeader->Subsystem ) == IMAGE_SUBSYSTEM_WINDOWS_CUI );
}

BOOL  WINAPI PE_IsGUI ( DWORD base )
/*****************************************************************************************************************/
/* Do we have a GUI app?                                                                                         */
{
    PIMAGE_NT_HEADERS       pNTHeader;
    PIMAGE_DOS_HEADER       dosHeader;
    PIMAGE_OPTIONAL_HEADER  pOptHeader;

    if ( base == 0 ) { return FALSE; }
    
    dosHeader = ( PIMAGE_DOS_HEADER ) base;
    pNTHeader = MakePtr ( PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew );

    pOptHeader = ( PIMAGE_OPTIONAL_HEADER )&pNTHeader->OptionalHeader;
    return ( ( pOptHeader->Subsystem ) == IMAGE_SUBSYSTEM_WINDOWS_GUI );
}

BOOL WINAPI PE_GetMachineType ( DWORD machine, TCHAR * szoutbuf )
/*****************************************************************************************************************/
/* Make IMAGE_FILE_HEADER->MachineType look pretty                                                               */
{
    BOOL result = TRUE;

    if ( szoutbuf == NULL ) { return FALSE; }

    switch ( machine )
    {
        case IMAGE_FILE_MACHINE_I386:
            lstrcpy ( szoutbuf, TEXT("i386") );
            break;

        case IMAGE_FILE_MACHINE_IA64:
            lstrcpy ( szoutbuf, TEXT("IA64") );
            break;

        case IMAGE_FILE_MACHINE_AMD64:
            lstrcpy ( szoutbuf, TEXT("AMD64") );
            break;

        case IMAGE_FILE_MACHINE_R3000:
            lstrcpy ( szoutbuf, TEXT("R3000") );
            break;

        case 0x160:
            lstrcpy ( szoutbuf, TEXT("R3000 big endian") );
            break;

        case IMAGE_FILE_MACHINE_R4000:
            lstrcpy ( szoutbuf, TEXT("R4000") );
            break;

        case IMAGE_FILE_MACHINE_R10000:
            lstrcpy ( szoutbuf, TEXT("R10000") );
            break;

        case IMAGE_FILE_MACHINE_ALPHA:
            lstrcpy ( szoutbuf, TEXT("Alpha") );
            break;

        case IMAGE_FILE_MACHINE_POWERPC:
            lstrcpy ( szoutbuf, TEXT("PowerPC") );
            break;

        default:
            lstrcpy ( szoutbuf, TEXT("unknown") );
            result = FALSE;
            break;

    }
    return result;
}

BOOL WINAPI PE_HexDump ( void * src, DWORD dwsrclen, HEXDUMPPROC hexdumpproc, DWORD lParam )
/*****************************************************************************************************************/
/* HEX dump dwsrclen bytes from src, calling hexdumpproc every time we have HEX_DUMP_WIDTH bytes prepared        */
{
    TCHAR   buffer[512];
    TCHAR   * buffPtr, * buffPtr2;
    DWORD   cOutput, i, rightlimit, bytesToGo;
    BYTE    value;
    char    * ptmp;

    if ( ( src == NULL ) || ( dwsrclen == 0 ) || ( hexdumpproc == NULL ) ) { return FALSE; }

    ptmp = ( char * )src;
        
    bytesToGo   = dwsrclen;
    rightlimit  = ( HEX_DUMP_WIDTH * 3 ) + ( HEX_DUMP_WIDTH >> 2 );

    while ( bytesToGo  )
    {
        cOutput = bytesToGo >= HEX_DUMP_WIDTH ? HEX_DUMP_WIDTH : bytesToGo;

        buffPtr = buffer;
        buffPtr += wsprintf ( buffPtr, TEXT("%08X:  "), dwsrclen - bytesToGo );
        buffPtr2 = buffPtr + rightlimit;
        
        for ( i = 0; i < HEX_DUMP_WIDTH; i++ )
        {
            value = *( ptmp + i );

            if ( i >= cOutput )
            {
                *buffPtr++ = TEXT(' ');
                *buffPtr++ = TEXT(' ');
                *buffPtr++ = TEXT(' ');
            }
            else
            {
                if ( value < 0x10 )
                {
                    *buffPtr++ = TEXT('0');
                    intoa ( value, buffPtr++, 16 );
                }
                else
                {
                    intoa ( value, buffPtr, 16 );
                    buffPtr+=2;
                }
                *buffPtr++ = TEXT(' ');
                *buffPtr2++ = isprint ( value ) ? value : TEXT('.');
            }
            if ( ( ( i + 1 ) & 3 ) == 0 )
                *buffPtr++ = TEXT(' ');
        }

        *buffPtr2 = TEXT('\0');  // Null terminate it.
        if ( !hexdumpproc ( buffer, lParam ) )
            break;

        bytesToGo -= cOutput;
        ptmp += HEX_DUMP_WIDTH;
    }

    return TRUE;
}

static BOOL TimeToFileTime ( long time, FILETIME * pft )
/*****************************************************************************************************************/
{
    LONGLONG    ll;
    
    if ( pft == NULL ) { return FALSE; }
    
    ll = Int32x32To64 ( time, 10000000 ) + 116444736000000000;
    pft->dwLowDateTime = ( DWORD ) ll;
    pft->dwHighDateTime = ll >> 32;

    return TRUE;
}

static TCHAR * untoa ( DWORD value, TCHAR * buffer, int radix )
/*****************************************************************************************************************/
{
    TCHAR   * p;
    char    * q;
    DWORD   rem;
    DWORD   quot;
    char    buf[64];      // only holds ASCII so 'char' is OK

    if ( ( buffer == NULL ) || ( radix == 0 ) ) { return NULL; }

    p = buffer;
    buf[0] = '\0';
    q = &buf[1];
    do
    {
        quot = radix;
        rem = undiv ( value, ( DWORD* )&quot );
        *q = Alphabet[rem];
        ++q;
        value = quot;
    }
    while ( value != 0 );
    while ( ( *p++ = ( TCHAR )*--q ) );
    return ( buffer );
}

static TCHAR * intoa ( int value, TCHAR * buffer, int radix )
/*****************************************************************************************************************/
{
    TCHAR * p;
    
    if ( ( buffer == NULL ) || ( radix == 0 ) ) { return NULL; }
        
    p = buffer;

    if ( radix == 10 )
    {
        if ( value < 0 )
        {
            *p++ = TEXT('-');
            value = - value;
        }
    }
    untoa ( value, p, radix );
    return ( buffer );
}

static DWORD undiv ( DWORD val, DWORD * quot )
/*****************************************************************************************************************/
{
    ldiv_t d;

    d = ldiv ( val, *quot );

    *quot = d.quot;
    return d.rem;
}
