/*******************************************************************************
 * Copyright (C) 2012..2016 norbert.klose@web.de
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILIint TY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library. If not, see <http://www.gnu.org/licenses/>.
 ******************************************************************************/
#ifndef MACHO_HPP
#define MACHO_HPP

#include <deque>
#include <fstream>
#include <iomanip>
#include <memory>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>
#include <cassert>
#include <cstdint>
#include <cstring>

/**
 * @brief This file implements the Mach-O (Mach object) file format, which is the standard used to store programs
 * and libraries on disk in the Mac app binary interface (ABI).
 */
namespace macho {

template<typename Int>
Int readInteger(const std::uint8_t * src, bool littleEndian)
{
    Int dest = 0;
    for (std::size_t i = 0; i < sizeof(Int); ++i)
        dest += static_cast<Int>(src[i]) << (littleEndian ? i * 8 : (sizeof(Int) - i - 1) * 8);
    return dest;
}

template<typename Int>
Int readInteger(std::istream & stream, bool isLittleEndian, const char * name)
{
    std::uint8_t buffer[sizeof(Int)];
    stream.read(reinterpret_cast<char*>(buffer), sizeof(Int));
    if (!stream || stream.gcount() != sizeof(Int))
        throw std::runtime_error(name);
    return readInteger<Int>(buffer, isLittleEndian);
}

template<typename Int>
Int readInteger(const std::uint8_t * & src, std::size_t & length, bool isLittleEndian, const char * name)
{
    if (length < sizeof(Int))
        throw std::runtime_error(name);
    Int result = readInteger<Int>(src, isLittleEndian);
    src += sizeof(Int);
    length -= sizeof(length);
    return result;
}

typedef std::uint32_t MachOCPUType;
typedef std::uint32_t MachOCPUSubType;

const std::uint32_t MH_MAGIC	   = 0xfeedface;
const std::uint32_t MH_CIGAM	   = 0xcefaedfe;
const std::uint32_t MH_MAGIC_64 = 0xfeedfacf;
const std::uint32_t MH_CIGAM_64 = 0xcffaedfe;

const MachOCPUType CPU_ARCH_MASK   = 0xff000000;
const MachOCPUType CPU_ARCH_ABI64  = 0x01000000;
const MachOCPUType CPU_TYPE_X86    = 0x00000007;
const MachOCPUType CPU_TYPE_X86_64 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
const MachOCPUType CPU_TYPE_ARM	   = 0x0000000C;
const MachOCPUType CPU_TYPE_ARM64  = CPU_TYPE_ARM | CPU_ARCH_ABI64;

const MachOCPUSubType CPU_SUBTYPE_MASK    = 0xff000000;
const MachOCPUSubType CPU_SUBTYPE_LIB64	  = 0x80000000;
const MachOCPUSubType CPU_SUBTYPE_X86_ALL = 0x00000003;

const std::uint32_t MH_OBJECT     = 0x1;
const std::uint32_t MH_EXECUTE    = 0x2;
const std::uint32_t MH_CORE       = 0x4;
const std::uint32_t MH_DYLIB      = 0x6;
const std::uint32_t MH_BUNDLE     = 0x8;
const std::uint32_t MH_DYLIB_STUB = 0x9;
const std::uint32_t MH_DSYM       = 0xa;
const std::uint32_t MH_TWOLEVEL   = 0x80;

/**
 * @brief A Mach-O file contains code and data for one architecture.
 * The header structure of a Mach-O file specifies e.g. the target architecture.
 */
struct MachOHeader
{
    std::uint32_t magic;
    MachOCPUType cputype;
    MachOCPUSubType cpusubtype;
    std::uint32_t filetype;
    std::uint32_t ncmds;
    std::uint32_t sizeofcmds;
    std::uint32_t flags;
    std::uint32_t reserved;

    MachOHeader() :
        magic(MH_MAGIC_64),
        cputype(0),
        cpusubtype(0),
        filetype(0),
        ncmds(0),
        sizeofcmds(0),
        flags(0),
        reserved(0) {}

    bool isLittleEndian() const
    {
        return magic == MH_MAGIC_64 || magic == MH_MAGIC;
    }

    bool is64Bit() const
    {
        return magic == MH_MAGIC_64 || magic == MH_CIGAM_64;
    }

    void deserialize(std::istream & stream);
};

const std::uint32_t LC_REQ_DYLD           = 0x80000000;
const std::uint32_t LC_SEGMENT            = 0x1;
const std::uint32_t LC_SYMTAB             = 0x2;
const std::uint32_t LC_UNIXTHREAD         = 0x5;
const std::uint32_t LC_DYSYMTAB           = 0xB;
const std::uint32_t LC_LOAD_DYLIB         = 0xC;
const std::uint32_t LC_ID_DYLIB           = 0xD;
const std::uint32_t LC_LOAD_DYLINKER      = 0xE;
const std::uint32_t LC_LOAD_WEAK_DYLIB    = 0x18|LC_REQ_DYLD;
const std::uint32_t LC_SEGMENT_64         = 0x19;
const std::uint32_t LC_UUID               = 0x1B;
const std::uint32_t LC_CODE_SIGNATURE     = 0x1D;
const std::uint32_t LC_REEXPORT_DYLIB     = 0x1F|LC_REQ_DYLD;
const std::uint32_t LC_DYLD_INFO          = 0x22;
const std::uint32_t LC_DYLD_INFO_ONLY     = LC_REQ_DYLD|LC_DYLD_INFO;
const std::uint32_t LC_VERSION_MIN_MACOSX = 0x24;
const std::uint32_t LC_FUNCTION_STARTS    = 0x26;
const std::uint32_t LC_MAIN               = LC_REQ_DYLD|0x28;
const std::uint32_t LC_DATA_IN_CODE       = 0x29;
const std::uint32_t LC_SOURCE_VERSION     = 0x2A;

// Forward Declaration
struct MachOFile;

/**
 * @brief The generic Mach-O load command structure.
 */
struct MachOLoadCommand
{
    MachOFile * machoFile;
    std::uint32_t cmd;
    std::uint32_t cmdsize;
    std::vector<std::uint8_t> buffer;

    MachOLoadCommand(MachOFile * machoFile = 0) :
        machoFile(machoFile),
        cmd(0),
        cmdsize(0) {}

    void deserialize(std::istream & stream);
};

/**
 * @brief A LC_UUID load command structure
 */
struct MachOUUID
{
    MachOFile * machoFile;
    std::uint8_t uuid[16];

    MachOUUID(MachOFile * machoFile) :
        machoFile(machoFile)
    {
        memset(uuid, 0, sizeof(uuid));
    }

    void deserialize(const MachOLoadCommand & loadCommand);
};

/**
 * @brief A mach-o string table referenced by a LC_SYMTAB load command.
 */
struct MachOStringTable : public std::vector<char>
{
    const char * operator[](std::size_t index) const
    {
        if (index < size())
            return data() + index;
        return 0;
    }
};

// MachOSymbol n_type

const std::uint8_t N_GSYM    = 0x20;
const std::uint8_t N_FNAME   = 0x22;
const std::uint8_t N_FUN     = 0x24;
const std::uint8_t N_STSYM   = 0x26;
const std::uint8_t N_LCSYM   = 0x28;
const std::uint8_t N_BNSYM   = 0x2E;
const std::uint8_t N_AST     = 0x32;
const std::uint8_t N_OPT     = 0x3C;
const std::uint8_t N_RSYM    = 0x40;
const std::uint8_t N_SLINE   = 0x44;
const std::uint8_t N_ENSYM   = 0x4E;
const std::uint8_t N_SSYM    = 0x60;
const std::uint8_t N_SO      = 0x64;
const std::uint8_t N_OSO     = 0x66;
const std::uint8_t N_LSYM    = 0x80;
const std::uint8_t N_BINCL   = 0x82;
const std::uint8_t N_SOL     = 0x84;
const std::uint8_t N_PARAMS  = 0x86;
const std::uint8_t N_VERSION = 0x88;
const std::uint8_t N_OLEVEL  = 0x8A;
const std::uint8_t N_PSYM    = 0xA0;
const std::uint8_t N_EINCL   = 0xA2;
const std::uint8_t N_ENTRY   = 0xA4;
const std::uint8_t N_LBRAC   = 0xC0;
const std::uint8_t N_EXCL    = 0xC2;
const std::uint8_t N_RBRAC   = 0xE0;
const std::uint8_t N_BCOMM   = 0xE2;
const std::uint8_t N_ECOMM   = 0xE4;
const std::uint8_t N_ECOML   = 0xE8;
const std::uint8_t N_LENG    = 0xFE;

const std::uint8_t N_TYPE_MASK = 0x0E;
const std::uint8_t N_TYPE_UNDF = 0x00;
const std::uint8_t N_TYPE_EXT  = 0x01;
const std::uint8_t N_TYPE_ABS  = 0x02;
const std::uint8_t N_TYPE_INDR = 0x0A;
const std::uint8_t N_TYPE_PBUD = 0x0C;
const std::uint8_t N_TYPE_SECT = 0x0E;
const std::uint8_t N_TYPE_PEXT = 0x10;
const std::uint8_t N_TYPE_STAB = 0xE0;

// MachOSymbol n_desc

const std::uint16_t REFERENCE_TYPE_MASK                       = 0x0F;
const std::uint16_t REFERENCE_FLAG_UNDEFINED_NON_LAZY         = 0x00;
const std::uint16_t REFERENCE_FLAG_UNDEFINED_LAZY             = 0x01;
const std::uint16_t REFERENCE_FLAG_DEFINED                    = 0x02;
const std::uint16_t REFERENCE_FLAG_PRIVATE_DEFINED            = 0x03;
const std::uint16_t REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY = 0x04;
const std::uint16_t REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY     = 0x05;
const std::uint16_t REFERENCED_DYNAMICALLY                    = 0x10;

const std::uint16_t N_DESC_DISCARDED     = 0x20;
const std::uint16_t N_NO_DEAD_STRIP      = 0x20;
const std::uint16_t N_WEAK_REF           = 0x40;
const std::uint16_t N_WEAK_DEF           = 0x80;
const std::uint16_t SELF_LIBRARY_ORDINAL = 0x00;
const std::uint16_t EXECUTABLE_ORDINAL   = 0xFF;

// Forward Declaration
struct MachOSymtab;

/**
 * @brief A nlist (nlist_64) symbol entry of a LC_SYMTAB load command structure.
 */
struct MachOSymbol
{
    MachOSymtab * symtab;
    std::string name;
    std::uint32_t n_strx;
    std::uint8_t n_type;
    std::uint8_t n_sect;
    std::uint16_t n_desc;
    std::uint64_t n_value;

    MachOSymbol(MachOSymtab * symtab = 0) :
        symtab(symtab),
        n_strx(0),
        n_type(0),
        n_sect(0),
        n_desc(0),
        n_value(0) {}

    void deserialize(std::istream & stream);
};

/**
 * @brief A LC_SYMTAB load command structure.
 */
struct MachOSymtab : public std::vector<MachOSymbol>
{
    MachOFile * machoFile;
    std::uint32_t symoff;
    std::uint32_t nsyms;
    std::uint32_t stroff;
    std::uint32_t strsize;
    MachOStringTable stringTable;

    MachOSymtab(MachOFile * machoFile = 0) :
        machoFile(machoFile),
        symoff(0),
        nsyms(0),
        stroff(0),
        strsize(0) {}

    MachOSymtab(const MachOSymtab & right) :
        std::vector<MachOSymbol>(right),
        machoFile(right.machoFile),
        symoff(right.symoff),
        nsyms(right.nsyms),
        stroff(right.stroff),
        strsize(right.strsize)
    {
        for (MachOSymbol & symbol : *this)
            symbol.symtab = this;
    }

    void deserialize(std::istream & stream, const MachOLoadCommand & loadCommand);

    MachOSymtab & operator=(const MachOSymtab & right)
    {
        std::vector<MachOSymbol>::operator=(right);
        for (MachOSymbol & symbol : *this)
            symbol.symtab = this;
        machoFile = right.machoFile;
        symoff = right.symoff;
        nsyms = right.nsyms;
        stroff = right.stroff;
        strsize = right.strsize;
        return *this;
    }
};


/** @brief section flags type mask. */
const std::uint32_t SECTION_TYPE = 0x000000ff;
/** @brief section flags attributes mask. */
const std::uint32_t SECTION_ATTRIBUTES = 0xffffff00;

// section types

const std::uint32_t S_REGULAR                             = 0x00;
const std::uint32_t S_ZEROFILL                            = 0x01;
const std::uint32_t S_CSTRING_LITERALS                    = 0x02;
const std::uint32_t S_4BYTE_LITERALS                      = 0x03;
const std::uint32_t S_8BYTE_LITERALS	                     = 0x04;
const std::uint32_t S_LITERAL_POINTERS                    = 0x05;
const std::uint32_t S_NON_LAZY_SYMBOL_POINTERS            = 0x06;
const std::uint32_t S_LAZY_SYMBOL_POINTERS                = 0x07;
const std::uint32_t S_SYMBOL_STUBS                        = 0x08;
const std::uint32_t S_MOD_INIT_FUNC_POINTERS              = 0x09;
const std::uint32_t S_MOD_TERM_FUNC_POINTERS              = 0x0A;
const std::uint32_t S_COALESCED                           = 0x0B;
const std::uint32_t S_GB_ZEROFILL                         = 0x0C;
const std::uint32_t S_INTERPOSING                         = 0x0D;
const std::uint32_t S_16BYTE_LITERALS                     = 0x0E;
const std::uint32_t S_DTRACE_DOF                          = 0x0F;
const std::uint32_t S_LAZY_DYLIB_SYMBOL_POINTERS	         = 0x10;
const std::uint32_t S_THREAD_LOCAL_REGULAR                = 0x11;
const std::uint32_t S_THREAD_LOCAL_ZEROFILL               = 0x12;
const std::uint32_t S_THREAD_LOCAL_VARIABLES              = 0x13;
const std::uint32_t S_THREAD_LOCAL_VARIABLE_POINTERS      = 0x14;
const std::uint32_t S_THREAD_LOCAL_INIT_FUNCTION_POINTERS = 0x15;

// section attributes

const std::uint32_t SECTION_ATTRIBUTES_USR     = 0xff000000;
const std::uint32_t S_ATTR_PURE_INSTRUCTIONS   = 0x80000000;
const std::uint32_t S_ATTR_NO_TOC              = 0x40000000;
const std::uint32_t S_ATTR_STRIP_STATIC_SYMS   = 0x20000000;
const std::uint32_t S_ATTR_NO_DEAD_STRIP       = 0x10000000;
const std::uint32_t S_ATTR_LIVE_SUPPORT        = 0x08000000;
const std::uint32_t S_ATTR_SELF_MODIFYING_CODE = 0x04000000;
const std::uint32_t S_ATTR_DEBUG               = 0x02000000;
const std::uint32_t SECTION_ATTRIBUTES_SYS     = 0x00ffff00;
const std::uint32_t S_ATTR_SOME_INSTRUCTIONS   = 0x00000400;
const std::uint32_t S_ATTR_EXT_RELOC           = 0x00000200;
const std::uint32_t S_ATTR_LOC_RELOC           = 0x00000100;

// Forward Declaration
struct MachOSegment;

/**
 * @brief A Mach-O section or section_64 structure.
 */
struct MachOSection : public std::vector<std::uint8_t>
{
    MachOSegment * segment;
    std::string sectionName;
    std::string segmentName;
    std::uint64_t addr;
    std::uint64_t filesize;
    std::uint32_t fileoff;
    std::uint32_t align;
    std::uint32_t reloff;
    std::uint32_t nreloc;
    std::uint32_t flags;
    std::uint32_t reserved1;
    std::uint32_t reserved2;
    std::uint32_t reserved3;

    MachOSection(MachOSegment * segment = 0) :
        segment(segment),
        addr(0),
        filesize(0),
        fileoff(0),
        align(0),
        reloff(0),
        nreloc(0),
        flags(0),
        reserved1(0),
        reserved2(0),
        reserved3(0) {}

    void deserialize(std::istream & stream, const std::uint8_t * & src, std::size_t & length);
};

// segment flags

const std::uint32_t SG_HIGHVM = 0x1;
const std::uint32_t SG_FVMLIB = 0x2;
const std::uint32_t SG_NORELOC = 0x4;
const std::uint32_t SG_PROTECTED_VERSION_1 = 0x8;

/**
 * @brief A LC_SEGMENT or LC_SEGMENT_64 load command structure
 */
struct MachOSegment : public std::vector<MachOSection>
{
    MachOFile * machoFile;
    std::uint32_t cmd;
    std::string segmentName;
    std::uint64_t vmaddr;
    std::uint64_t vmsize;
    std::uint64_t fileoff;
    std::uint64_t filesize;
    std::uint32_t maxprot;
    std::uint32_t initprot;
    std::uint32_t nsects;
    std::uint32_t flags;

    MachOSegment(MachOFile * machoFile = 0) :
        machoFile(machoFile),
        cmd(0),
        vmaddr(0),
        vmsize(0),
        fileoff(0),
        filesize(0),
        maxprot(0),
        initprot(0),
        nsects(0),
        flags(0) {}

    MachOSegment(const MachOSegment & right) :
        std::vector<MachOSection>(right),
        machoFile(right.machoFile),
        cmd(right.cmd),
        vmaddr(right.vmaddr),
        vmsize(right.vmsize),
        fileoff(right.fileoff),
        filesize(right.filesize),
        maxprot(right.maxprot),
        initprot(right.initprot),
        nsects(right.nsects),
        flags(right.flags)
    {
        for (MachOSection & section : *this)
            section.segment = this;
    }

    void deserialize(std::istream & stream, const MachOLoadCommand & loadCommand);

    MachOSegment & operator=(const MachOSegment & right)
    {
        std::vector<MachOSection>::operator=(right);
        for (MachOSection & section : *this)
            section.segment = this;
        machoFile = right.machoFile;
        cmd = right.cmd;
        segmentName = right.segmentName;
        vmaddr = right.vmaddr;
        vmsize = right.vmsize;
        fileoff = right.fileoff;
        filesize = right.filesize;
        maxprot = right.maxprot;
        initprot = right.initprot;
        nsects = right.nsects;
        flags = right.flags;
        return *this;
    }
};

/**
 * @brief A LC_LOAD_DYLIB, LC_ID_DYLIB, LC_LOAD_WEAK_DYLIB or LC_REEXPORT_DYLIB load command structure.
 */
struct MachODylib
{
    MachOFile * machoFile;
    std::uint32_t cmd;
    std::string libraryName;

    MachODylib(MachOFile * machoFile = 0) :
       machoFile(machoFile),
       cmd(0) {}

    void deserialize(std::istream & stream, const MachOLoadCommand & loadCommand);
};

/**
 * @brief The MachOFile class.
 */
struct MachOFile : public std::vector<MachOSegment>
{
    std::string filename;
    MachOHeader header;
    std::vector<MachOLoadCommand> loadCommands;
    MachOUUID uuid;
    MachOSymtab symtab;
    std::vector<MachODylib> dylibs;

    MachOFile() :
        uuid(this),
        symtab(this) {}

    MachOFile(const MachOFile & right) :
        std::vector<MachOSegment>(right),
        filename(right.filename),
        header(right.header),
        loadCommands(right.loadCommands),
        uuid(right.uuid),
        symtab(right.symtab),
        dylibs(right.dylibs)
    {
        for (MachOSegment & segment : *this)
            segment.machoFile = this;
        for (MachOLoadCommand & loadCommand : loadCommands)
            loadCommand.machoFile = this;
        uuid.machoFile = this;
        symtab.machoFile = this;
        for (MachODylib & dylib : dylibs)
            dylib.machoFile = this;
    }

    void deserialize(const std::string & filename, std::istream & stream);

    std::size_t findSections(const char * name, std::deque<const MachOSection*> & sections) const;

    const MachOSection * getSection(std::size_t index) const;

    const MachODylib * getDylib(std::size_t index) const;

    static bool isMachO(const std::string & filename);

    void open(const std::string & filename);

    MachOFile & operator=(const MachOFile & right)
    {
        std::vector<MachOSegment>::operator=(right);
        for (MachOSegment & segment : *this)
            segment.machoFile = this;
        filename = right.filename;
        header = right.header;
        loadCommands = right.loadCommands;
        for (MachOLoadCommand & loadCommand : loadCommands)
            loadCommand.machoFile = this;
        uuid = right.uuid;
        uuid.machoFile = this;
        symtab = right.symtab;
        symtab.machoFile = this;
        dylibs = right.dylibs;
        for (MachODylib & dylib : dylibs)
            dylib.machoFile = this;
        return *this;
    }

    /**
     * @brief similiar to otool -l
     */
    void printLoadCommands(std::ostream & stream) const;

    /**
     * @brief same as nm -map
     */
    void printSymtab(std::ostream & stream) const;
};

} // namespace macho

std::ostream & operator<<(std::ostream & stream, const macho::MachOHeader & right);
std::ostream & operator<<(std::ostream & stream, const macho::MachOSymbol & right);
std::ostream & operator<<(std::ostream & stream, const macho::MachOLoadCommand & right);
std::ostream & operator<<(std::ostream & stream, const macho::MachOUUID & right);
std::ostream & operator<<(std::ostream & stream, const macho::MachOSection & right);
std::ostream & operator<<(std::ostream & stream, const macho::MachOSegment & right);
std::ostream & operator<<(std::ostream & stream, const macho::MachOSymtab & right);
std::ostream & operator<<(std::ostream & stream, const macho::MachODylib & right);
std::ostream & operator<<(std::ostream & stream, const macho::MachOFile & right);

namespace macho {

inline void MachOHeader::deserialize(std::istream & stream)
{
    magic = readInteger<std::uint32_t>(stream, true, "mach-o: header: magic number");
    if (magic != MH_MAGIC && magic != MH_CIGAM && magic != MH_MAGIC_64 && magic != MH_CIGAM_64)
        throw std::runtime_error("mach-o: header magic number");

    cputype = readInteger<MachOCPUType>(stream, isLittleEndian(), "mach-o: header: cpu type");
    cpusubtype = readInteger<MachOCPUSubType>(stream, isLittleEndian(), "mach-o: header: cpu subtype");
    filetype = readInteger<std::uint32_t>(stream, isLittleEndian(), "mach-o: header: file type");
    ncmds = readInteger<std::uint32_t>(stream, isLittleEndian(), "mach-o: header: number of cmds");
    sizeofcmds = readInteger<std::uint32_t>(stream, isLittleEndian(), "mach-o: header: sizeof of cmds");
    flags = readInteger<std::uint32_t>(stream, isLittleEndian(), "mach-o: header: flags");
    reserved = readInteger<std::uint32_t>(stream, isLittleEndian(), "mach-o: header: reserved");
}

inline void MachOLoadCommand::deserialize(std::istream & stream)
{
    assert(machoFile);
    buffer.resize(sizeof(cmd) + sizeof(cmdsize));
    stream.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
    if (!stream || stream.gcount() < 0 || static_cast<std::size_t>(stream.gcount()) != buffer.size())
        throw std::runtime_error("mach-o: load command");

    cmd = readInteger<std::uint32_t>(buffer.data(), machoFile->header.isLittleEndian());
    cmdsize = readInteger<std::uint32_t>(buffer.data() + sizeof(std::uint32_t), machoFile->header.isLittleEndian());

    if (cmdsize < sizeof(cmd) + sizeof(cmdsize))
        throw std::runtime_error("mach-o: load command: wrong cmdsize");

    buffer.resize(cmdsize);

    stream.read(reinterpret_cast<char*>(buffer.data()) + sizeof(cmd) + sizeof(cmdsize),
                cmdsize - sizeof(cmd) - sizeof(cmdsize));
    if (!stream || stream.gcount() < 0 || static_cast<std::size_t>(stream.gcount()) != cmdsize - sizeof(cmd) - sizeof(cmdsize))
        throw std::runtime_error("mach-o: load command: wrong cmdsize");
}

inline void MachOUUID::deserialize(const MachOLoadCommand & loadCommand)
{
    if (loadCommand.buffer.size() < 24)
        throw std::runtime_error("mach-o: load command: uuid");
    memcpy(uuid, loadCommand.buffer.data() + 8, sizeof(uuid));
}

inline void MachOSymbol::deserialize(std::istream & stream)
{
    assert(symtab);
    assert(symtab->machoFile);

    bool littleEndian = symtab->machoFile->header.isLittleEndian();

    n_strx = readInteger<std::uint32_t>(stream, littleEndian, "mach-o: load command: symtab_command: nlist: n_strx");
    name = symtab->stringTable[n_strx];

    n_type = readInteger<std::uint8_t>(stream, littleEndian, "mach-o: load command: symtab_command: nlist: n_type");
    n_sect = readInteger<std::uint8_t>(stream, littleEndian, "mach-o: load command: symtab_command: nlist: n_sect");
    n_desc = readInteger<std::uint16_t>(stream, littleEndian, "mach-o: load command: symtab_command: nlist: n_desc");

    if (symtab->machoFile->header.is64Bit())
        n_value = readInteger<std::uint64_t>(stream, littleEndian, "mach-o: load command: symtab_command: nlist: 64-bit n_value");
    else
        n_value = readInteger<std::uint32_t>(stream, littleEndian, "mach-o: load command: symtab_command: nlist: 64-bit n_value");
}

inline void MachOSymtab::deserialize(std::istream & stream, const MachOLoadCommand & loadCommand)
{
    assert(machoFile);

    bool littleEndian = machoFile->header.isLittleEndian();
    const std::uint8_t * src = loadCommand.buffer.data() + 8;

    symoff = readInteger<std::uint32_t>(src, littleEndian);
    nsyms = readInteger<std::uint32_t>(src + 4, littleEndian);
    stroff = readInteger<std::uint32_t>(src + 8, littleEndian);
    strsize = readInteger<std::uint32_t>(src + 12, littleEndian);

    std::istream::pos_type currentPos = stream.tellg();

    if (!stringTable.empty())
        stringTable.clear();
    stringTable.resize(strsize);

    stream.seekg(stroff);
    if (!stream)
        throw std::runtime_error("mach-o: load command: symtab_command: stroff");

    stream.read(stringTable.data(), strsize);
    if (!stream || stream.gcount() != strsize)
        throw std::runtime_error("mach-o: load command: symtab_command: strsize");

    stream.seekg(symoff);
    if (!stream)
        throw std::runtime_error("mach-o: load command: symtab_command: symoff");

    if (!empty())
        clear();
    for (std::size_t i = 0; i < nsyms; ++i)
    {
        MachOSymbol symbol(this);
        symbol.deserialize(stream);
        push_back(symbol);
    }

    stream.seekg(currentPos);
}

inline void MachOSection::deserialize(std::istream & stream, const std::uint8_t * & src, std::size_t & length)
{
    assert(segment);
    assert(segment->machoFile);

    if (segment->cmd == LC_SEGMENT && length < 68)
        throw std::runtime_error("mach-o: load command: section");
    else if (length < 76)
        throw std::runtime_error("mach-o: load command: section_64");

    sectionName.assign(reinterpret_cast<const char*>(src), strnlen(reinterpret_cast<const char*>(src), 16));
    segmentName.assign(reinterpret_cast<const char*>(src + 16), strnlen(reinterpret_cast<const char*>(src + 16), 16));
    src += 32;
    length -= 32;

    bool littleEndian = segment->machoFile->header.isLittleEndian();

    if (segment->cmd == LC_SEGMENT)
    {
        std::uint32_t addr = readInteger<std::uint32_t>(src, littleEndian);
        std::uint32_t size = readInteger<std::uint32_t>(src + 4, littleEndian);
        this->addr = addr;
        this->filesize = size;
        src += 8;
        length -= 8;
    }
    else
    {
        addr = readInteger<std::uint64_t>(src, littleEndian);
        filesize = readInteger<std::uint64_t>(src + 8, littleEndian);
        src += 16;
        length -= 16;
    }
    fileoff = readInteger<std::uint32_t>(src, littleEndian);
    align = readInteger<std::uint32_t>(src + 4, littleEndian);
    reloff = readInteger<std::uint32_t>(src + 8, littleEndian);
    nreloc = readInteger<std::uint32_t>(src + 12, littleEndian);
    flags = readInteger<std::uint32_t>(src + 16, littleEndian);
    reserved1 = readInteger<std::uint32_t>(src + 20, littleEndian);
    reserved2 = readInteger<std::uint32_t>(src + 24, littleEndian);
    reserved3 = readInteger<std::uint32_t>(src + 28, littleEndian);
    src += 32;
    length -= 32;

    std::istream::pos_type currentPos = stream.tellg();

    stream.seekg(fileoff);
    if (!stream)
        throw std::runtime_error("mach-o: load command: section: offset");
    if (!empty())
        clear();
    resize(filesize);
    if (filesize)
    {
        stream.read(reinterpret_cast<char*>(data()), filesize);
        if (!stream || stream.gcount() < 0 || static_cast<std::size_t>(stream.gcount()) != filesize)
            throw std::runtime_error("mach-o: load command: section: size");
    }

    stream.seekg(currentPos);
}

inline void MachOSegment::deserialize(std::istream & stream, const MachOLoadCommand & loadCommand)
{
    assert(machoFile);

    cmd = loadCommand.cmd;

    if (cmd == LC_SEGMENT && loadCommand.buffer.size() < 56)
        throw std::runtime_error("mach-o: load command: segment_command");
    else if (loadCommand.buffer.size() < 72)
        throw std::runtime_error("mach-o: load command: segment_command_64");

    const std::uint8_t * src = loadCommand.buffer.data() + 8;

    segmentName.assign(reinterpret_cast<const char*>(src), strnlen(reinterpret_cast<const char*>(src), 16));
    src += 16;
    std::size_t length = loadCommand.buffer.size() - 24;

    bool littleEndian = machoFile->header.isLittleEndian();

    if (cmd == LC_SEGMENT)
    {
        std::uint32_t vmaddr = readInteger<std::uint32_t>(src, littleEndian);
        std::uint32_t vmsize = readInteger<std::uint32_t>(src + 4, littleEndian);
        std::uint32_t fileoff = readInteger<std::uint32_t>(src + 8, littleEndian);
        std::uint32_t filesize = readInteger<std::uint32_t>(src + 12, littleEndian);
        this->vmaddr = vmaddr;
        this->vmsize = vmsize;
        this->fileoff = fileoff;
        this->filesize = filesize;
        src += 16;
        length -= 16;
    }
    else
    {
        vmaddr = readInteger<std::uint64_t>(src, littleEndian);
        vmsize = readInteger<std::uint64_t>(src + 8, littleEndian);
        fileoff = readInteger<std::uint64_t>(src + 16, littleEndian);
        filesize = readInteger<std::uint64_t>(src + 24, littleEndian);
        src += 32;
        length -= 32;
    }
    maxprot = readInteger<std::uint32_t>(src , littleEndian);
    initprot = readInteger<std::uint32_t>(src + 4, littleEndian);
    nsects = readInteger<std::uint32_t>(src + 8, littleEndian);
    flags = readInteger<std::uint32_t>(src + 12, littleEndian);
    src += 16;
    length -= 16;

    if (!empty())
        clear();

    for (std::size_t i = 0; i < nsects; ++i)
    {
        MachOSection section(this);
        section.deserialize(stream, src, length);
        push_back(section);
    }
}

inline void MachODylib::deserialize(std::istream & stream, const MachOLoadCommand & loadCommand)
{
    assert(machoFile);

    cmd = loadCommand.cmd;

    const std::uint8_t * src = loadCommand.buffer.data() + 8;
    bool littleEndian = machoFile->header.isLittleEndian();

    std::uint32_t offset = readInteger<std::uint32_t>(src, littleEndian);
    if (offset >= loadCommand.cmdsize)
        throw std::runtime_error("mach-o load command: dylib_command: offset");
    libraryName = reinterpret_cast<const char*>(loadCommand.buffer.data()) + offset;
}

inline std::size_t MachOFile::findSections(const char * name, std::deque<const MachOSection*> & sections) const
{
    std::size_t found = 0;
    for (const MachOSegment & segment : *this)
        for (const MachOSection & section : segment)
            if (section.sectionName == name)
            {
                sections.push_back(&section);
                ++found;
            }
    return found;
}

inline const MachOSection * MachOFile::getSection(std::size_t index) const
{
    std::size_t i = 0;
    for (const MachOSegment & segment : *this)
        for (const MachOSection & section : segment)
            if (i == index)
                return &section;
            else
                ++i;
    return 0;
}

inline const MachODylib * MachOFile::getDylib(std::size_t index) const
{
    if (index <= dylibs.size())
        return &dylibs[index - 1];
    return 0;
}

inline bool MachOFile::isMachO(const std::string & filename)
{
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if (!file)
        return false;
    try
    {
        MachOHeader machoHeader;
        machoHeader.deserialize(file);
    }
    catch (...)
    {
        return false;
    }
    return true;
}

inline void MachOFile::open(const std::string & filename)
{
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if (!file)
        throw std::runtime_error(filename);
    deserialize(filename, file);
}

inline void MachOFile::printLoadCommands(std::ostream & stream) const
{
    std::size_t nSegment = 0, nDylib = 0;
    for (const MachOLoadCommand & loadCommand : loadCommands)
    {
        stream << loadCommand;
        switch (loadCommand.cmd)
        {
        case LC_SEGMENT:
        case LC_SEGMENT_64:
            stream << " " << (*this)[nSegment++];
            break;
        case LC_SYMTAB:
            stream << " " << symtab;
            break;
        case LC_UUID:
            stream << " " << uuid;
            break;
        case LC_LOAD_DYLIB:
        case LC_ID_DYLIB:
        case LC_LOAD_WEAK_DYLIB:
        case LC_REEXPORT_DYLIB:
            stream << " " << dylibs[nDylib++];
            break;
        }
        stream << std::endl;
    }
}

inline void MachOFile::printSymtab(std::ostream & stream) const
{
    for (const MachOSymbol & symbol : symtab)
        stream << symbol << std::endl;
}

inline void MachOFile::deserialize(const std::string & filename, std::istream & stream)
{
    this->filename = filename;

    header.deserialize(stream);

    if (!loadCommands.empty())
        loadCommands.clear();
    if (!dylibs.empty())
        dylibs.clear();
    if (!empty())
        clear();

    for (std::size_t i = 0; i < header.ncmds; ++i)
    {
        MachOLoadCommand loadCommand(this);
        loadCommand.deserialize(stream);
        loadCommands.push_back(loadCommand);

        switch (loadCommand.cmd)
        {
            case LC_SEGMENT:
            case LC_SEGMENT_64:
                {
                    MachOSegment segment(this);
                    segment.deserialize(stream, loadCommand);
                    push_back(segment);
                }
                break;
            case LC_SYMTAB:
                symtab.deserialize(stream, loadCommand);
                break;
            case LC_UUID:
                uuid.deserialize(loadCommand);
                break;
            case LC_LOAD_DYLIB:
            case LC_ID_DYLIB:
            case LC_LOAD_WEAK_DYLIB:
            case LC_REEXPORT_DYLIB:
                {
                    MachODylib dylib(this);
                    dylib.deserialize(stream, loadCommand);
                    dylibs.push_back(dylib);
                }
                break;
        }
    }
}

} // namespace macho

inline std::ostream & operator<<(std::ostream & stream, const macho::MachOHeader & right)
{
    switch (right.magic)
    {
        case macho::MH_CIGAM:
            stream << "CIGAM";
            break;
        case macho::MH_MAGIC:
            stream << "MAGIC";
            break;
        case macho::MH_CIGAM_64:
            stream << "CIGAM_64";
            break;
        case macho::MH_MAGIC_64:
            stream << "MAGIC_64";
            break;
        default:
            stream << "0x" << std::hex << std::setw(8) << std::setfill('0') << right.magic;
    }
    switch (right.cputype)
    {
        case macho::CPU_TYPE_X86:
            stream << " X86";
            break;
        case macho::CPU_TYPE_X86_64:
            stream << " X86_64";
            break;
        case macho::CPU_TYPE_ARM:
            stream << " ARM";
            break;
        case macho::CPU_TYPE_ARM64:
            stream << " ARM64";
            break;
        default:
            stream << " 0x" << std::hex << std::setw(8) << std::setfill('0') << right.cputype;
    }
    stream << " 0x" << std::hex << std::setw(8) << std::setfill('0') << right.cpusubtype;
    switch (right.filetype)
    {
        case macho::MH_OBJECT:
            stream << " OBJECT";
            break;
        case macho::MH_EXECUTE:
            stream << " EXECUTE";
            break;
        case macho::MH_CORE:
            stream << " CORE";
            break;
        case macho::MH_DYLIB:
            stream << " DYLIB";
            break;
        case macho::MH_BUNDLE:
            stream << " BUNDLE";
            break;
        case macho::MH_DYLIB_STUB:
            stream << " DYLIB_STUB";
            break;
        case macho::MH_DSYM:
            stream << " DSYM";
            break;
        default:
            stream << " " << std::dec << right.filetype;
    }
    stream << " ncmds=" << std::dec << right.ncmds << "/" << right.sizeofcmds
           << " flags=0x" << std::hex << std::setw(8) << std::setfill('0') << right.flags;
    return stream;
}

inline std::ostream & operator<<(std::ostream & stream, const macho::MachOSymbol & right)
{
    if (right.n_type & macho::N_TYPE_STAB) // debug symbol
    {
        stream << std::setfill('0') << std::setw(16) << std::hex << right.n_value
               << " - " << std::setfill('0') << std::hex << std::setw(2) << (unsigned) right.n_sect
               << " " << std::setfill('0') << std::hex << std::setw(4) << (unsigned) right.n_desc
               << " " << std::setfill(' ') << std::setw(5);
        switch (right.n_type)
        {
            case macho::N_GSYM:    // global symbol: name,,NO_SECT,type,0
                stream << "GSYM";
                break;
            case macho::N_FNAME:   // procedure name (f77 kludge): name,,NO_SECT,0,0
                stream << "FNAME";
                break;
            case macho::N_FUN:     // procedure: name,,n_sect,linenumber,address
                stream << "FUN";
                break;
            case macho::N_STSYM:   // static symbol: name,,n_sect,type,address
                stream << "STSYM";
                break;
            case macho::N_LCSYM:   // .lcomm symbol: name,,n_sect,type,address
                stream << "LCSYM";
                break;
            case macho::N_BNSYM:   // begin nsect sym: 0,,n_sect,0,address
                stream << "BNSYM";
                break;
            case macho::N_OPT:     // emitted with gcc2_compiled and in gcc source
                stream << "OPT";
                break;
            case macho::N_RSYM:    // register sym: name,,NO_SECT,type,register
                stream << "RSYM";
                break;
            case macho::N_SLINE:   // src line: 0,,n_sect,linenumber,address
                stream << "SLINE";
                break;
            case macho::N_ENSYM:   // end nsect sym: 0,,n_sect,0,address
                stream << "ENSYM";
                break;
            case macho::N_SSYM:    // structure elt: name,,NO_SECT,type,struct_offset
                stream << "SSYM";
                break;
            case macho::N_SO:      // source file name: name,,n_sect,0,address
                stream << "SO";
                break;
            case macho::N_OSO:     // object file name: name,,0,0,st_mtime
                stream << "OSO";
                break;
            case macho::N_LSYM:    // local sym: name,,NO_SECT,type,offset
                stream << "LSYM";
                break;
            case macho::N_BINCL:   // include file beginning: name,,NO_SECT,0,sum
                stream << "BINCL";
                break;
            case macho::N_SOL:     // #included file name: name,,n_sect,0,address
                stream << "SOL";
                break;
            case macho::N_PARAMS:  // compiler parameters: name,,NO_SECT,0,0
                stream << "PARAMS";
                break;
            case macho::N_VERSION: // compiler version: name,,NO_SECT,0,0
                stream << "VERSION";
                break;
            case macho::N_OLEVEL:  // compiler -O level: name,,NO_SECT,0,0
                stream << "OLEVEL";
                break;
            case macho::N_PSYM:    // parameter: name,,NO_SECT,type,offset
                stream << "PSYM";
                break;
            case macho::N_EINCL:   // include file end: name,,NO_SECT,0,0
                stream << "EINCL";
                break;
            case macho::N_ENTRY:   // alternate entry: name,,n_sect,linenumber,address
                stream << "ENTRY";
                break;
            case macho::N_LBRAC:   // left bracket: 0,,NO_SECT,nesting level,address
                stream << "LBRAC";
                break;
            case macho::N_EXCL:    // deleted include file: name,,NO_SECT,0,sum
                stream << "EXCL";
                break;
            case macho::N_RBRAC:   // right bracket: 0,,NO_SECT,nesting level,address
                stream << "RBRAC";
                break;
            case macho::N_BCOMM:   // begin common: name,,NO_SECT,0,0
                stream << "BCOMM";
                break;
            case macho::N_ECOMM:   // end common: name,,n_sect,0,0
                stream << "ECOMM";
                break;
            case macho::N_ECOML:   // end common (local name): 0,,n_sect,0,address
                stream << "ECOML";
                break;
            case macho::N_LENG:    // second stab entry with length information
                stream << "LENG";
                break;
        }
    }
    else
    {
        // address
        if (right.n_value || (right.n_type & macho::N_TYPE_MASK) != macho::N_TYPE_UNDF)
        {
            stream << std::setfill('0') << std::setw(16) << std::hex << right.n_value;
        }
        else
        {
            stream << "                ";
        }
        // type
        switch (right.n_type & macho::N_TYPE_MASK)
        {
            case macho::N_TYPE_UNDF:
                if (right.n_value != 0)
                {
                    stream << " (common)";
                    if (((right.n_desc >> 8) & 0xF) != 0)
                        stream << " (alignment 2^" << static_cast<int>((right.n_desc >> 8) & 0xF) << ") ";
                }
                else
                {
                    stream << " (undefined";
                    switch (right.n_desc & macho::REFERENCE_TYPE_MASK)
                    {
                        case macho::REFERENCE_FLAG_UNDEFINED_LAZY:
                            stream << " [lazy bound])";
                            break;
                        case macho::REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY:
                            stream << " [private lazy bound])";
                            break;
                        case macho::REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY:
                            stream << " [private])";
                            break;
                        default:
                            stream << ")";
                            break;
                    }
                }
                break;
            case macho::N_TYPE_PBUD:
                stream << " (prebound)";
                break;
            case macho::N_TYPE_ABS:
                stream << " (absolute)";
                break;
            case macho::N_TYPE_INDR:
                stream << " (indirection)";
                break;
            case macho::N_TYPE_SECT:
                // (segment,section)
                if (right.symtab && right.symtab->machoFile)
                {
                    const macho::MachOSection * section = right.symtab->machoFile->getSection(right.n_sect - 1);
                    if (section)
                        stream << " (" << section->segmentName << "," << section->sectionName << ")";
                }
                break;
        }
        if (right.n_type & macho::N_TYPE_EXT)
        {
            if (right.n_desc & macho::REFERENCED_DYNAMICALLY)
                stream << " [referenced dynamically]";
            if (right.n_type & macho::N_TYPE_PEXT)
            {
                if (right.n_desc & macho::N_WEAK_DEF)
                    stream << " weak private external";
                else
                    stream << " private external";
            }
            else if ((right.n_desc & macho::N_WEAK_REF) || (right.n_desc & macho::N_WEAK_DEF))
            {
                if ((right.n_desc & (macho::N_WEAK_REF | macho::N_WEAK_DEF)) == (macho::N_WEAK_REF | macho::N_WEAK_DEF))
                    stream << " weak external automatically hidden";
                else
                    stream << " weak external";
            }
            else
            {
                stream << " external";
            }
        }
        else
        {
            stream << " non-external";
            if (right.n_type & macho::N_TYPE_PEXT)
                stream << " (was a private external)";
        }
        if ( right.symtab
          && right.symtab->machoFile
          && right.symtab->machoFile->header.filetype == macho::MH_OBJECT
          && (right.n_desc & macho::N_NO_DEAD_STRIP) )
        {
            stream << " [no dead strip]";
        }
        if (right.n_desc & macho::N_DESC_DISCARDED)
        {
            stream << " [desc discarded]";
        }
    }
    stream << " " << right.name;
    if (!(right.n_type & macho::N_TYPE_STAB))
    {
        switch (right.n_desc & macho::REFERENCE_TYPE_MASK)
        {
        case macho::REFERENCE_FLAG_UNDEFINED_NON_LAZY:
        case macho::REFERENCE_FLAG_UNDEFINED_LAZY:
            if (right.symtab && right.symtab->machoFile && (right.symtab->machoFile->header.flags & macho::MH_TWOLEVEL) != 0)
            {
                unsigned char libraryOrdinal = (right.n_desc & 0xFF00) >> 8;
                if (libraryOrdinal > macho::SELF_LIBRARY_ORDINAL)
                {
                    const macho::MachODylib * dylib = right.symtab->machoFile->getDylib(libraryOrdinal);
                    if (dylib)
                        stream << " (from " << dylib->libraryName << ")";
                }
             }
             break;
        }
    }
    return stream;
}

inline std::ostream & operator<<(std::ostream & stream, const macho::MachOLoadCommand & right)
{
    switch (right.cmd)
    {
        case macho::LC_SEGMENT:
            stream << "LC_SEGMENT";
            break;
        case macho::LC_SYMTAB:
            stream << "LC_SYMTAB";
            break;
        case macho::LC_UNIXTHREAD:
            stream << "LC_UNIXTHREAD";
            break;
        case macho::LC_DYSYMTAB:
            stream << "LC_DYSYMTAB";
            break;
        case macho::LC_LOAD_DYLIB:
            stream << "LC_LOAD_DYLIB";
            break;
        case macho::LC_ID_DYLIB:
            stream << "LC_ID_DYLIB";
            break;
        case macho::LC_LOAD_DYLINKER:
            stream << "LC_LOAD_DYLINKER";
            break;
        case macho::LC_LOAD_WEAK_DYLIB:
            stream << "LC_LOAD_WEAK_DYLIB";
            break;
        case macho::LC_SEGMENT_64:
            stream << "LC_SEGMENT_64";
            break;
        case macho::LC_UUID:
            stream << "LC_UUID";
            break;
        case macho::LC_CODE_SIGNATURE:
            stream << "LC_CODE_SIGNATURE";
            break;
        case macho::LC_DYLD_INFO:
            stream << "LC_DYLD_INFO";
            break;
        case macho::LC_DYLD_INFO_ONLY:
            stream << "LC_DYLD_INFO_ONLY";
            break;
        case macho::LC_VERSION_MIN_MACOSX:
            stream << "LC_VERSION_MIN_MACOSX";
            break;
        case macho::LC_FUNCTION_STARTS:
            stream << "LC_FUNCTION_STARTS";
            break;
        case macho::LC_MAIN:
            stream << "LC_MAIN";
            break;
        case macho::LC_DATA_IN_CODE:
            stream << "LC_DATA_IN_CODE";
            break;
        case macho::LC_SOURCE_VERSION:
            stream << "LC_SOURCE_VERSION";
            break;
        default:
            stream << "0x" << std::hex << std::setw(sizeof(std::uint32_t) * 2) << std::setfill('0') << right.cmd;
    }
    stream << " cmdsize=" << std::dec << right.cmdsize;
    return stream;
}

inline std::ostream & operator<<(std::ostream & stream, const macho::MachOUUID & right)
{
    stream << "uuid=";
    for (std::size_t i = 0; i < sizeof(right.uuid); ++i)
        stream << std::hex << std::setw(2) << std::setfill('0') << (unsigned) right.uuid[i];
    return stream;
}

inline std::ostream & operator<<(std::ostream & stream, const macho::MachOSection & right)
{
    stream << "sectname=" << right.sectionName
           << " segname=" << right.segmentName
           << " addr=0x" << std::hex << std::setw(16) << std::setfill('0') << right.addr
           << " size=0x" << std::hex << right.filesize
           << " offset=" << std::dec << right.fileoff
           << " align=2^" << std::dec << right.align
           << " reloff=" << std::dec << right.reloff
           << " nreloc=" << std::dec << right.nreloc
           << " flags=0x" << std::hex << std::setw(8) << std::setfill('0') << right.flags
           << " reserved1=" << std::dec << right.reserved1
           << " reserved2=" << std::dec << right.reserved2;
    return stream;
}

inline std::ostream & operator<<(std::ostream & stream, const macho::MachOSegment & right)
{
    stream << "segname=" << right.segmentName
           << " vmaddr=0x" << std::hex << std::setw(16) << std::setfill('0') << right.vmaddr
           << " vmsize=0x" << std::hex << right.vmsize
           << " fileoff=" << std::dec << right.fileoff
           << " filesize=" << std::dec << right.filesize
           << " maxprot=0x" << std::hex << std::setw(8) << std::setfill('0') << right.maxprot
           << " initprot=0x" << std::hex << std::setw(8) << std::setfill('0') << right.initprot
           << " nsects=" << std::dec << right.nsects
           << " flags=0x" << std::hex << right.flags;
    for (const macho::MachOSection & section : right)
        stream << std::endl << section;
    return stream;
}

inline std::ostream & operator<<(std::ostream & stream, const macho::MachOSymtab & right)
{
    stream << "symoff=" << std::dec << right.symoff
           << " nsyms=" << std::dec << right.nsyms
           << " stroff=" << std::dec<< right.stroff
           << " strsize=" << std::dec << right.strsize;
    return stream;
}

inline std::ostream & operator<<(std::ostream & stream, const macho::MachODylib & right)
{
    stream << "library=" << right.libraryName;
    return stream;
}

inline std::ostream & operator<<(std::ostream & stream, const macho::MachOFile & right)
{
    stream << right.filename << ": " << right.header << std::endl;
    right.printLoadCommands(stream);
    right.printSymtab(stream);
    return stream;
}

#endif // MACHO_HPP
