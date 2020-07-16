/*
    PEHLP32, a PE (portable executable) helper library v. 1.1
    ----------------------------------------------------------
    Copyright (c) 2020 Adrian Petrila, YO3GFH
    Original code "imported" with small changes from PEDump utility,
	(c) 1994-2001 Matt Pietrek.
	
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

#include <windows.h>


#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))

#define GetImgDirEntryRVA( pNTHdr, IDE ) \
    (pNTHdr->OptionalHeader.DataDirectory[IDE].VirtualAddress)

#define GetImgDirEntrySize( pNTHdr, IDE ) \
    (pNTHdr->OptionalHeader.DataDirectory[IDE].Size)

//#define isprint(c)  ((c) >= 0x20 && (c) <= 0x7e)

#define     T_PE                0x00000010
#define     T_OTHER             0x00000050
#define     HEX_DUMP_WIDTH      16

typedef struct
{
    HANDLE  hfile;
    HANDLE  hmap;
    LPVOID  filebase;
    LPVOID  ntheader;
    DWORD   type;
}   MOD_BASE, * PMOD_BASE;

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
}   IMPORT_INFO, * PIMPORT_INFO;

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
}   EXPORT_INFO, * PEXPORT_INFO;

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
}   SECTION_INFO, * PSECTION_INFO;

typedef struct
{
    DWORD   flag;
    TCHAR   * name;
}   DWORD_FLAG_DESCRIPTIONS, * PDWORD_FLAG_DESCRIPTIONS;

typedef struct
{
    WORD    flag;
    TCHAR   * name;
}   WORD_FLAG_DESCRIPTIONS, * PWORD_FLAG_DESCRIPTIONS;

DWORD_FLAG_DESCRIPTIONS SectionCharacteristics[] = 
{
{ IMAGE_SCN_MEM_SHARED,             TEXT("SHARED") },
{ IMAGE_SCN_CNT_CODE,               TEXT("CODE") },
{ IMAGE_SCN_MEM_EXECUTE,            TEXT("EXECUTE") },
{ IMAGE_SCN_MEM_READ,               TEXT("READ") },
{ IMAGE_SCN_MEM_WRITE,              TEXT("WRITE") },
{ IMAGE_SCN_CNT_INITIALIZED_DATA,   TEXT("INITIALIZED_DATA") },
{ IMAGE_SCN_CNT_UNINITIALIZED_DATA, TEXT("UNINITIALIZED_DATA") },
{ IMAGE_SCN_LNK_OTHER,              TEXT("OTHER") },
{ IMAGE_SCN_LNK_INFO,               TEXT("INFO") },
{ IMAGE_SCN_LNK_COMDAT,             TEXT("COMDAT") },
{ IMAGE_SCN_MEM_LOCKED,             TEXT("LOCKED") },
{ IMAGE_SCN_MEM_PRELOAD,            TEXT("PRELOAD") },
{ IMAGE_SCN_MEM_DISCARDABLE,        TEXT("DISCARDABLE") }
};

#define NUMBER_SECTION_CHARACTERISTICS \
    (sizeof(SectionCharacteristics) / sizeof(DWORD_FLAG_DESCRIPTIONS))

WORD_FLAG_DESCRIPTIONS ImageFileHeaderCharacteristics[] = 
{
{ IMAGE_FILE_RELOCS_STRIPPED,           TEXT("RELOCS_STRIPPED") },
{ IMAGE_FILE_EXECUTABLE_IMAGE,          TEXT("EXECUTABLE_IMAGE") },
{ IMAGE_FILE_LINE_NUMS_STRIPPED,        TEXT("LINE_NUMS_STRIPPED") },
{ IMAGE_FILE_LOCAL_SYMS_STRIPPED,       TEXT("LOCAL_SYMS_STRIPPED") },
{ IMAGE_FILE_AGGRESIVE_WS_TRIM,         TEXT("AGGRESIVE_WS_TRIM") },
{ IMAGE_FILE_LARGE_ADDRESS_AWARE,       TEXT("IMAGE_FILE_LARGE_ADDRESS_AWARE") },
{ IMAGE_FILE_BYTES_REVERSED_LO,         TEXT("BYTES_REVERSED_LO") },
{ IMAGE_FILE_32BIT_MACHINE,             TEXT("32BIT_MACHINE") },
{ IMAGE_FILE_DEBUG_STRIPPED,            TEXT("DEBUG_STRIPPED") },
{ IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,   TEXT("REMOVABLE_RUN_FROM_SWAP") },
{ IMAGE_FILE_NET_RUN_FROM_SWAP,         TEXT("NET_RUN_FROM_SWAP") },
{ IMAGE_FILE_SYSTEM,                    TEXT("SYSTEM") },
{ IMAGE_FILE_DLL,                       TEXT("DLL") },
{ IMAGE_FILE_UP_SYSTEM_ONLY,            TEXT("UP_SYSTEM_ONLY") },
{ IMAGE_FILE_BYTES_REVERSED_HI,         TEXT("BYTES_REVERSED_HI") }
};

#define NUMBER_IMAGE_HEADER_FLAGS \
    (sizeof(ImageFileHeaderCharacteristics) / sizeof(WORD_FLAG_DESCRIPTIONS))

typedef BOOL ( CALLBACK * ENUMIMPORTMODPROC ) ( IMPORT_INFO *, DWORD );
typedef BOOL ( CALLBACK * ENUMIMPORTFNSPROC ) ( IMPORT_INFO *, DWORD );

typedef BOOL ( CALLBACK * GETEXPORTINFOPROC ) ( EXPORT_INFO *, DWORD );
typedef BOOL ( CALLBACK * ENUMEXPORTFNSPROC ) ( EXPORT_INFO *, DWORD );

typedef BOOL ( CALLBACK * ENUMSECTIONSPROC ) ( SECTION_INFO *, DWORD );
typedef BOOL ( CALLBACK * ENUMFHATTRIBPROC ) ( TCHAR *, DWORD );

typedef BOOL ( CALLBACK * HEXDUMPPROC ) ( TCHAR *, DWORD );
