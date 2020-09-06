/*
    PEHLP32, PE (portable executable) helper library v. 1.1
    ----------------------------------------------------------
    Copyright (c) 2020 Adrian Petrila, YO3GFH
    Original code "imported" with small changes from PEDump utility,
    (c) 1998-2001 Matt Pietrek.
    
    http://bytepointer.com/resources/pietrek_in_depth_look_into_pe_format_pt1.htm

    I've organized bits and pieces from the original PEDump code in this DLL as part
    of a university lab project (a task manager). Thanks to Matt for all his work in
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

// PEHLP32 header file - add it along with pehlp32.lib to your project

#ifndef _PEHLP32_H
#define _PEHLP32_H

#include <windows.h>

#define IMG_BASE ULONG_PTR
#define EN_LPARAM LPARAM

#define     T_PE        0x00000010
#define     T_OTHER     0x00000050


typedef struct
{
    HANDLE  hfile;
    HANDLE  hmap;
    LPVOID  filebase;
    LPVOID  ntheader;
    DWORD   type;
}   MOD_BASE;

typedef struct
{
    TCHAR   name[256];
    TCHAR   fnname[256];
    TCHAR   timedate[64];
    DWORD   characteristix;
    DWORD   forwarderchain;
    DWORD   firstthunkrva;
    DWORD   ordinal;
    DWORD   hint;
    DWORD   timestamp;
}   IMPORT_INFO;

typedef struct
{
    TCHAR   filename[256];
    TCHAR   timedate[64];
    TCHAR   fnname[256];
    DWORD   characteristix;
    DWORD   timestamp;
    DWORD   minorver;
    DWORD   majorver;
    DWORD   ordbase;
    DWORD   nooffun;
    DWORD   noofnames;
    DWORD   entryptrva;
    DWORD   ordinal;
    DWORD   forwarder;
}   EXPORT_INFO;

typedef struct
{
    TCHAR   name[64];
    DWORD   vsize;
    DWORD   vaddr;
    DWORD   rdatasize;
    DWORD   rdataoffs;
    DWORD   relocno;
    DWORD   relocoffs;
    DWORD   chars;
    TCHAR   szchars[14][30];
    DWORD   cchars;
}   SECTION_INFO;

#ifdef __cplusplus
extern "C" {
#endif

typedef BOOL ( CALLBACK * ENUMIMPORTMODPROC )   ( IMPORT_INFO *, EN_LPARAM );
typedef BOOL ( CALLBACK * ENUMIMPORTFNSPROC )   ( IMPORT_INFO *, EN_LPARAM );

typedef BOOL ( CALLBACK * GETEXPORTINFOPROC )   ( EXPORT_INFO *, EN_LPARAM );
typedef BOOL ( CALLBACK * ENUMEXPORTFNSPROC )   ( EXPORT_INFO *, EN_LPARAM );

typedef BOOL ( CALLBACK * ENUMSECTIONSPROC )    ( SECTION_INFO *, EN_LPARAM );
typedef BOOL ( CALLBACK * ENUMFHATTRIBPROC )    ( TCHAR *, EN_LPARAM );
typedef BOOL ( CALLBACK * HEXDUMPPROC )         ( TCHAR *, EN_LPARAM );

BOOL                    WINAPI PE_OpenModule            ( TCHAR * modname, MOD_BASE * mod, BOOL readonly );
BOOL                    WINAPI PE_CloseModule           ( MOD_BASE * mod );
LPVOID                  WINAPI PE_RVAToPtr              ( DWORD rva, PIMAGE_NT_HEADERS pNTHeader, IMG_BASE imageBase );
PIMAGE_SECTION_HEADER   WINAPI PE_GetSectionHeader      ( DWORD rva, PIMAGE_NT_HEADERS pNTHeader );
PIMAGE_SECTION_HEADER   WINAPI PE_FindSection           ( const TCHAR * name, PIMAGE_NT_HEADERS pNTHeader );
BOOL                    WINAPI PE_EnumImports           ( IMG_BASE base,ENUMIMPORTMODPROC enummod,ENUMIMPORTFNSPROC enumfns, EN_LPARAM lParam );
BOOL                    WINAPI PE_EnumExports           ( IMG_BASE base, GETEXPORTINFOPROC getinfo, ENUMEXPORTFNSPROC enumfns, EN_LPARAM lParam );
BOOL                    WINAPI PE_EnumSections          ( IMG_BASE base, ENUMSECTIONSPROC enumsections, EN_LPARAM lParam );
BOOL                    WINAPI PE_EnumCharacteristics   ( IMG_BASE base, ENUMFHATTRIBPROC enumattrib, EN_LPARAM lParam );
BOOL                    WINAPI PE_GetMachineType        ( DWORD machine, TCHAR * szoutbuf );
LPVOID                  WINAPI PE_GetFileHeader         ( IMG_BASE base );
LPVOID                  WINAPI PE_GetOptionalHeader     ( IMG_BASE base );
LPVOID                  WINAPI PE_GetNTHeader           ( IMG_BASE base );
BOOL                    WINAPI PE_IsConsole             ( IMG_BASE base );
BOOL                    WINAPI PE_IsGUI                 ( IMG_BASE base );
BOOL                    WINAPI PE_HexDump               ( void * src, DWORD dwsrclen, HEXDUMPPROC hexdumpproc, EN_LPARAM lParam );


#ifdef  __cplusplus
}
#endif
#endif // _PEHLP32_H

