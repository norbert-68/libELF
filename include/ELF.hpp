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
#ifndef ELF_HPP
#define ELF_HPP

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
#include <cstdint>
#include <cstring>

/**
 * @brief The namespace for the Executable and Linkable Format (ELF).
 * @see https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html
 */
namespace elf {

typedef uint16_t ELFHalf;
typedef uint32_t ELFWord;
typedef uint32_t ELF32Address;
typedef uint32_t ELF32Offset;
typedef uint64_t ELF64Address;
typedef uint64_t ELF64Offset;
typedef uint64_t ELFXWord;

template<typename Int>
struct ELFInteger
{
    Int value;

    ELFInteger(Int value = 0) : value(value) {}
    virtual ~ELFInteger() {}

    bool operator==(const ELFInteger<Int> & right) const { return value == right.value; }
    operator Int & () { return value; }
    operator Int () const { return value; }
};

struct ELFClass : public ELFInteger<uint8_t>
{
    ELFClass(uint8_t value = 0) : ELFInteger<uint8_t>(value) {}
};

const ELFClass ELF_CLASSNONE = 0;
const ELFClass ELF_CLASS32   = 1;
const ELFClass ELF_CLASS64   = 2;

struct ELFEndianness : public ELFInteger<uint8_t>
{
    ELFEndianness(uint8_t value = 0) : ELFInteger<uint8_t>(value) {}
};

const ELFEndianness ELF_DATANONE = 0;
const ELFEndianness ELF_DATA2LSB = 1;
const ELFEndianness ELF_DATA2MSB = 2;

struct ELFOsABI : public ELFInteger<uint8_t>
{
    ELFOsABI(uint8_t value = 0) : ELFInteger<uint8_t>(value) {}
};

const ELFOsABI ELF_OSABI_NONE    = 0;
const ELFOsABI ELF_OSABI_NETBSD  = 2;
const ELFOsABI ELF_OSABI_LINUX   = 3;
const ELFOsABI ELF_OSABI_FREEBSD = 9;
const ELFOsABI ELF_OSABI_OPENBSD = 12;

struct ELFType : public ELFInteger<ELFHalf>
{
    ELFType(ELFHalf value = 0) : ELFInteger<ELFHalf>(value) {}
};

const ELFType ET_NONE = 0;
const ELFType ET_REL  = 1;
const ELFType ET_EXEC = 2;
const ELFType ET_DYN  = 3;
const ELFType ET_CORE = 4;

struct ELFMachine : public ELFInteger<ELFHalf>
{
    ELFMachine(ELFHalf value = 0) : ELFInteger<ELFHalf>(value) {}
};

const ELFMachine EM_NO_MACHINE = 0;
const ELFMachine EM_X86        = 3;
const ELFMachine EM_ARM        = 40;
const ELFMachine EM_X86_64     = 62;

template<typename Int>
Int readInteger(const uint8_t * src, ELFEndianness endianness)
{
    Int result = 0;
    for (std::size_t i = 0; i < sizeof(Int); ++i)
        result += static_cast<Int>(src[i]) << (endianness == ELF_DATA2LSB ? i * 8 : (sizeof(Int) - i - 1) * 8);
    return result;
}

template<typename Int>
Int readInteger(const uint8_t * & src, std::size_t & length, ELFEndianness endianness, const char * name)
{
    if (length < sizeof(Int))
        throw std::runtime_error(name);
    Int result = readInteger<Int>(src, endianness);
    src += sizeof(Int);
    length -= sizeof(Int);
    return result;
}

/**
 * @brief The Executable and Linkable Format (ELF) Header
 *
 * The header starts with the ELF Identification. The first four bytes start with
 * 0x7F 'E' 'L' 'F'.
 */
struct ELFHeader
{
    const std::size_t ELF_HEADER_SIZE_32IT  = 52;
    const std::size_t ELF_HEADER_SIZE_64BIT = 64;

    /**
     * @brief File class
     */
    ELFClass elfClass;

    /**
     * @brief Data encoding
     */
    ELFEndianness elfEndianness;

    /**
     * @brief ELF header version number
     */
    uint8_t headerVersion;

    /**
     * @brief The OS- or ABI-specific ELF extensions used
     */
    ELFOsABI elfOsABI;

    /**
     * @brief The object file type
     */
    ELFType elfType;

    /**
     * @brief The required architecture
     */
    ELFMachine elfMachine;

    /**
     * @brief The object file version
     */
    ELFWord elfVersion;

    /**
     * @brief The program header table's file offset in bytes, or zero, if the file has no program header table.
     * ELF32Offset for 32bit ELFHeader.
     */
    ELF64Offset programHeaderOffset;

    /**
     * @brief The section header table's file offset in bytes, or  zero, if the file has no section header table.
     * ELF32Offset for 32bit ELFHeader.
     */
    ELF64Offset sectionHeaderOffset;

    /**
     * @brief The ELF header's size in bytes.
     */
    ELFHalf headerSize;

    /**
     * @brief The size in bytes of one entry in the file's program header table; all entries are the same size.
     */
    ELFHalf programHeaderEntrySize;

    /**
     * @brief The number of entries in the program header table, or  zero, if a file has no program header table.
     */
    ELFHalf programHeaderEntryNums;

    /**
     * @brief The size in bytes of one entry in the file's section header table; all entries are the same size.
     */
    ELFHalf sectionHeaderEntrySize;

    /**
     * @brief The number of entries in the section header table.
     * If the number of sections is greater than or equal to SHN_LORESERVE (0xff00), this member has the value zero
     * and the actual number of section header table entries is contained in the @e size field of the section header
     * at index 0. (Otherwise, the sh_size member of the initial entry contains 0.)
     */
    ELFWord sectionHeaderEntryNums;

    /**
     * @brief The section header table index of the entry associated with the section name string table, or zero,
     * if the file has no section name string table.
     * If the section name string table section index is greater than or equal to SHN_LORESERVE (0xff00), this
     * member has the value SHN_XINDEX (0xffff) and the actual index of the section name string table section is
     * contained in the @e link field of the section header at index 0. (Otherwise, the @e link member of the
     * initial entry contains 0.)
     */
    ELFWord sectionHeaderIndexOfSectionNames;

    ELFHeader() :
        headerVersion(1),
        elfVersion(1),
        programHeaderOffset(0),
        sectionHeaderOffset(0),
        headerSize(0),
        programHeaderEntrySize(0),
        programHeaderEntryNums(0),
        sectionHeaderEntrySize(0),
        sectionHeaderEntryNums(0),
        sectionHeaderIndexOfSectionNames(0)
    {}

    std::string getFileType() const;

    void deserialize(std::istream & stream);
};

/**
 * @brief This value marks an undefined, missing, irrelevant, or otherwise meaningless section reference.
 * For example, a symbol ``defined'' relative to section number SHN_UNDEF is an undefined symbol.
 */
const ELFHalf SHN_UNDEF = 0;
/** @brief This value specifies the lower bound of the range of reserved indexes. */
const ELFHalf SHN_LORESERVE = 0xff00;
/**
 * @brief This value is an escape value. It indicates that the actual section header index is too large
 * to fit in the containing field and is to be found in another location (specific to the structure where
 * it appears).
 */
const ELFHalf SHN_XINDEX = 0xffff;
/**
 * @brief This value specifies the upper bound of the range of reserved indexes. The system reserves
 * indexes between SHN_LORESERVE and SHN_HIRESERVE, inclusive; the values do not reference the section
 * header table. The section header table does not contain entries for the reserved indexes.
 */
const ELFHalf SHN_HIRESERVE = 0xffff;

struct ELFSectionType : ELFInteger<ELFWord>
{
    ELFSectionType(ELFWord value = 0) : ELFInteger<ELFWord>(value) {}
};

/**
 * @brief This value marks the section header as inactive; it does not have an associated section.
 * Other members of the section header have undefined values.
 */
const ELFSectionType SHT_NULL = 0;
/**
 * @brief The section holds information defined by the program, whose format and meaning are
 * determined solely by the program.
 */
const ELFSectionType SHT_PROGBITS = 1;
/**
 * @brief This section hold a symbol table. Typically, SHT_SYMTAB provides symbols for link editing,
 * though it may also be used for dynamic linking. As a complete symbol table, it may contain many
 * symbols unnecessary for dynamic linking. Consequently, an object file may also contain a
 * @e SHT_DYNSYM section, which holds a minimal set of dynamic linking symbols, to save space.
 */
const ELFSectionType SHT_SYMTAB = 2;
/** @brief The section holds a string table. */
const ELFSectionType SHT_STRTAB = 3;
/**
 * @brief The section holds relocation entries with explicit addends, such as type Elf32_Rela for
 * the 32-bit class of object files or type Elf64_Rela for the 64-bit class of object files.
 */
const ELFSectionType SHT_RELA = 4;
/** @brief The section holds a symbol hash table. */
const ELFSectionType SHT_HASH = 5;
/** @brief The section holds information for dynamic linking. */
const ELFSectionType SHT_DYNAMIC = 6;
/** @brief The section holds information that marks the file in some way. */
const ELFSectionType SHT_NOTE = 7;
/**
 * @brief A section of this type occupies no space in the file but otherwise resembles SHT_PROGBITS.
 * Although this section contains no bytes, the sh_offset member contains the conceptual file offset.
 */
const ELFSectionType SHT_NOBITS = 8;
/**
 * @brief The section holds relocation entries without explicit addends, such as type Elf32_Rel for
 * the 32-bit class of object files or type Elf64_Rel for the 64-bit class of object files.
 */
const ELFSectionType SHT_REL = 9;
/** @brief This section type is reserved but has unspecified semantics. */
const ELFSectionType SHT_SHLIB = 10;
/** @brief This section hold a minimal of dynamic linking symbols to save space. */
const ELFSectionType SHT_DYNSYM = 11;
/** @brief This section contains an array of pointers to initialization functions. */
const ELFSectionType SHT_INIT_ARRAY = 14;
/** @brief This section contains an array of pointers to termination functions. */
const ELFSectionType SHT_FINI_ARRAY = 15;
/**
 * @brief This section contains an array of pointers to functions that are invoked before all other
 * initialization functions.
 */
const ELFSectionType SHT_PREINIT_ARRAY = 16;
/**
 * @brief This section defines a section group. A section group is a set of sections that are related
 * and that must be treated specially by the linker. The section header table entry for a group section
 * must appear in the section header table before the entries for any of the sections that are members
 * of the group.
 */
const ELFSectionType SHT_GROUP = 17;
/**
 * @brief This section is associated with a section of type SHT_SYMTAB and is required if any of the
 * section header indexes referenced by that symbol table contain the escape value SHN_XINDEX. The
 * section is an array of Elf32_Word values. Each value corresponds one to one with a symbol table
 * entry and appear in the same order as those entries. The values represent the section header indexes
 * against which the symbol table entries are defined. Only if corresponding symbol table entry's st_shndx field contains the escape value SHN_XINDEX will the matching Elf32_Word hold the actual section header index; otherwise, the entry must be SHN_UNDEF (0).  */
const ELFSectionType SHT_SYMTAB_SHNDX = 18;

/**
 * @brief The Executable and Linkable Format (ELF) Section Header
 */
struct ELFSectionHeader
{
    /**
     * @brief This member specifies the name of the section. Its value is an index into the
     * section header string table section, giving the location of a null-terminated string.
     */
    ELFWord nameIndex;

    /**
     * @brief The actual name pointing into the section name string table.
     */
    const char * name;

    /**
     * @brief This member categorizes the section's contents and semantics.
     */
    ELFSectionType type;

    /**
     * @brief Sections support 1-bit flags that describe miscellaneous attributes.
     */
    ELFXWord flags;

    /**
     * @brief If the section will appear in the memory image of a process, this member
     * gives the address at which the section's first byte should reside. Otherwise, the
     * member contains 0.
     */
    ELF64Address addr;

    /**
     * @brief This member's value gives the byte offset from the beginning of the file to
     * the first byte in the section. One section type, SHT_NOBITS, occupies no space in
     * the file, and its sh_offset member locates the conceptual placement in the file.
     */
    ELF64Offset offset;

    /**
     * @brief This member gives the section's size in bytes. Unless the section type is SHT_NOBITS,
     * the section occupies sh_size bytes in the file. A section of type SHT_NOBITS may have a
     * non-zero size, but it occupies no space in the file.
     */
    ELFXWord size;

    /**
     * @brief This member holds a section header table index link, whose interpretation depends on
     * the section type.
     */
    ELFWord link;

    /**
     * @brief This member holds extra information, whose interpretation depends on the section type.
     *  If the sh_flags field for this section header includes the attribute SHF_INFO_LINK, then this
     *  member represents a section header table index.
     */
    ELFWord info;

    /**
     * @brief Some sections have address alignment constraints. For example, if a section holds a
     * doubleword, the system must ensure doubleword alignment for the entire section. The value of
     * @e addr must be congruent to 0, modulo the value of @e addressAlignment. Currently, only 0
     * and positive integral powers of two are allowed. Values 0 and 1 mean the section has no
     * alignment constraints.
     */
    ELFXWord addressAlignment;

    /**
     * @brief Some sections hold a table of fixed-size entries, such as a symbol table. For such a
     * section, this member gives the size in bytes of each entry. The member contains 0 if the section
     * does not hold a table of fixed-size entries.
     */
    ELFXWord entrySize;

    ELFSectionHeader() :
        nameIndex(0),
        name(0),
        flags(0),
        addr(0),
        offset(0),
        size(0),
        link(0),
        info(0),
        addressAlignment(0),
        entrySize(0) {}

    void deserialize(const uint8_t * & src, std::size_t & length, ELFEndianness endianness, ELFClass elfClass);
};

/**
 * @brief The Executable and Linkable Format (ELF) Section Header
 */
struct ELFSection
{
    /** @brief The actual name pointing into the section name string table. */
    const char * name;
    /** @brief This member categorizes the section's contents and semantics. */
    ELFSectionType type;
    /** @brief Sections support 1-bit flags that describe miscellaneous attributes. */
    ELFXWord flags;
    /** @brief This member holds extra information, whose interpretation depends on the section type. */
    ELFWord info;
    /** @brief Some sections have address alignment constraints. */
    ELFXWord addressAlignment;
    /** @brief The pointer to the section's first data byte, or 0. */
    const uint8_t * binaryContent;
    /** @brief The length of the section's @e binaryContent. */
    std::size_t binaryLength;

    ELFSection() :
        name(0),
        flags(0),
        info(0),
        addressAlignment(0),
        binaryContent(0),
        binaryLength(0) {}

};

/**
 * @brief The Executable and Linkable Format (ELF) file.
 */
class ELFFile
{
public:

    typedef std::vector<ELFSectionHeader> SectionHeaderTable;

    ELFHeader header;
    std::string filename;
    SectionHeaderTable sectionHeaderTable;

    std::size_t findSections(const char * name, std::deque<ELFSection> & sections) const;

    static bool isELF(const std::string & filename);

    void open(const std::string & filename);

    void deserialize(std::istream & stream);

protected:

    /** @brief The binary content without the ELF header. */
    std::unique_ptr<uint8_t[]> binaryContent;
    /** @brief The length in number of bytes of @e binaryContent without the ELF header size. */
    std::size_t binaryLength;

};

} // namespace elf

template<typename Int> std::ostream & operator<<(std::ostream & stream, const elf::ELFInteger<Int> & integer);
std::ostream & operator<<(std::ostream & stream, const elf::ELFClass & right);
std::ostream & operator<<(std::ostream & stream, const elf::ELFMachine & right);
std::ostream & operator<<(std::ostream & stream, const elf::ELFSectionType & right);
std::ostream & operator<<(std::ostream & stream, const elf::ELFSectionHeader & right);
std::ostream & operator<<(std::ostream & stream, const elf::ELFFile & right);

namespace elf {

inline std::string ELFHeader::getFileType() const
{
    std::ostringstream strstr;
    strstr << elfClass << "-" << elfMachine;
    return strstr.str();
}

inline void ELFHeader::deserialize(std::istream & stream)
{
    uint8_t buffer[ELF_HEADER_SIZE_64BIT];
    stream.read(reinterpret_cast<char*>(buffer), 8);
    if (!stream || stream.gcount() != 8)
        throw std::runtime_error("elf: header: magic");

    if (buffer[0x00] != 0x7F || buffer[0x01] != 'E' || buffer[0x02] != 'L' || buffer[0x03] != 'F')
        throw std::runtime_error("elf: header: wrong magic (0x7F'ELF')");

    elfClass = buffer[0x04];
    if (elfClass != ELF_CLASS32 && elfClass != ELF_CLASS64)
        throw std::runtime_error("elf: header: wrong class");

    elfEndianness = buffer[0x05];
    if (elfEndianness != ELF_DATA2LSB && elfEndianness != ELF_DATA2MSB)
        throw std::runtime_error("elf: header: wrong endianness");

    headerVersion = buffer[0x06];
    if (headerVersion != 1)
        throw std::runtime_error("elf: header: version");
    elfOsABI = buffer[0x07];

    std::streamsize remainingHeaderSize = (elfClass == ELF_CLASS32 ? ELF_HEADER_SIZE_32IT : ELF_HEADER_SIZE_64BIT) - 8;
    stream.read(reinterpret_cast<char*>(buffer) + 8, remainingHeaderSize);
    if (!stream || stream.gcount() != remainingHeaderSize)
        throw std::runtime_error("elf: header: elf type");

    elfType = readInteger<ELFHalf>(buffer + 0x10, elfEndianness);
    if (elfType != ET_REL && elfType != ET_EXEC && elfType != ET_DYN && elfType != ET_CORE)
        throw std::runtime_error("elf: header: wrong elf type");

    elfMachine = readInteger<uint16_t>(buffer + 0x12, elfEndianness);
    if (elfMachine != EM_X86 && elfMachine != EM_ARM && elfMachine != EM_X86_64)
        throw std::runtime_error("elf: header: elf machine");

    elfVersion = readInteger<ELFWord>(buffer + 0x14, elfEndianness);
    if (elfVersion != 1)
        throw std::runtime_error("elf: header: elf version");

    if (elfClass == ELF_CLASS32)
    {
        programHeaderOffset = readInteger<ELF32Offset>(buffer + 0x1C, elfEndianness);
        sectionHeaderOffset = readInteger<ELF32Offset>(buffer + 0x20, elfEndianness);
        headerSize = readInteger<ELFHalf>(buffer + 0x28, elfEndianness);
        programHeaderEntrySize = readInteger<ELFHalf>(buffer + 0x2A, elfEndianness);
        programHeaderEntryNums = readInteger<ELFHalf>(buffer + 0x2C, elfEndianness);
        sectionHeaderEntrySize = readInteger<ELFHalf>(buffer + 0x2E, elfEndianness);
        sectionHeaderEntryNums = readInteger<ELFHalf>(buffer + 0x30, elfEndianness);
        sectionHeaderIndexOfSectionNames = readInteger<ELFHalf>(buffer + 0x32, elfEndianness);
    }
    else
    {
        programHeaderOffset = readInteger<ELF64Offset>(buffer + 0x20, elfEndianness);
        sectionHeaderOffset = readInteger<ELF64Offset>(buffer + 0x28, elfEndianness);
        headerSize = readInteger<ELFHalf>(buffer + 0x34, elfEndianness);
        programHeaderEntrySize = readInteger<ELFHalf>(buffer + 0x36, elfEndianness);
        programHeaderEntryNums = readInteger<ELFHalf>(buffer + 0x38, elfEndianness);
        sectionHeaderEntrySize = readInteger<ELFHalf>(buffer + 0x3A, elfEndianness);
        sectionHeaderEntryNums = readInteger<ELFHalf>(buffer + 0x3C, elfEndianness);
        sectionHeaderIndexOfSectionNames = readInteger<ELFHalf>(buffer + 0x3E, elfEndianness);
    }
    if (headerSize != remainingHeaderSize + 8)
        throw std::runtime_error("elf: header: wrong header size");
}

inline void ELFSectionHeader::deserialize(const uint8_t * & src, std::size_t & length, ELFEndianness endianness, ELFClass elfClass)
{
    nameIndex = readInteger<ELFWord>(src, length, endianness, "elf: section header: name index");
    type.value = readInteger<ELFWord>(src, length, endianness, "elf: section header: type");

    if (elfClass == ELF_CLASS32)
    {
        flags = readInteger<ELFWord>(src, length, endianness, "elf: section header: flags");
        addr = readInteger<ELF32Address>(src, length, endianness, "elf: section header: addr");
        offset = readInteger<ELF32Offset>(src, length, endianness, "elf: section header: offset");
        size = readInteger<ELFWord>(src, length, endianness, "elf: section header: size");
    }
    else
    {
        flags = readInteger<ELFXWord>(src, length, endianness, "elf: section header: 64-bit flags");
        addr = readInteger<ELF64Address>(src, length, endianness, "elf: section header: 64-bit addr");
        offset = readInteger<ELF64Offset>(src, length, endianness, "elf: section header: 64-bit offset");
        size = readInteger<ELFXWord>(src, length, endianness, "elf: section header: 64-bit size");
    }

    link = readInteger<ELFWord>(src, length, endianness, "elf: section header: link");
    info = readInteger<ELFWord>(src, length, endianness, "elf: section header: info");

    if (elfClass == ELF_CLASS32)
    {
        addressAlignment = readInteger<ELFWord>(src, length, endianness, "elf: section header: address alignment");
        entrySize = readInteger<ELFWord>(src, length, endianness, "elf: section header: entry size");
    }
    else
    {
        addressAlignment = readInteger<ELFXWord>(src, length, endianness, "elf: section header: 64-bit address alignment");
        entrySize = readInteger<ELFXWord>(src, length, endianness, "elf: section header: 64-bit entry size");
    }
}

inline std::size_t ELFFile::findSections(const char * name, std::deque<ELFSection> & sections) const
{
    std::size_t result = 0;
    for (const ELFSectionHeader & sectionHeader : sectionHeaderTable)
    {
        if (strcmp(sectionHeader.name, name) == 0)
        {
            ELFSection section;
            section.name = sectionHeader.name;
            section.type = sectionHeader.type;
            section.info = sectionHeader.info;
            section.flags = sectionHeader.flags;
            section.addressAlignment = sectionHeader.addressAlignment;
            section.binaryContent = binaryContent.get() + sectionHeader.offset - header.headerSize;
            section.binaryLength = sectionHeader.size;
            sections.push_back(section);
            ++result;
        }
    }
    return result;
}

inline bool ELFFile::isELF(const std::string & filename)
{
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if (!file)
        return false;
    try
    {
        ELFHeader elfHeader;
        elfHeader.deserialize(file);
    }
    catch (...)
    {
        return false;
    }
    return true;
}

inline void ELFFile::open(const std::string & filename)
{
    this->filename = filename;
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if (!file)
        throw std::runtime_error(filename);
    deserialize(file);
}

inline void ELFFile::deserialize(std::istream & stream)
{
    binaryContent.reset();
    binaryLength = 0;

    header.deserialize(stream);

    std::size_t sectionHeaderEntryNums = header.sectionHeaderEntryNums;
    if (sectionHeaderEntryNums == 0)
        sectionHeaderEntryNums = 1;
    binaryLength = header.sectionHeaderOffset
                 + header.sectionHeaderEntrySize * sectionHeaderEntryNums
                 - header.headerSize;
    binaryContent.reset(new uint8_t[binaryLength]);
    char * readPtr = reinterpret_cast<char*>(binaryContent.get());
    for (std::size_t readLength = binaryLength; readLength; readLength -= stream.gcount(), readPtr += stream.gcount())
    {
        stream.read(readPtr, readLength);
        if (!stream)
            throw std::runtime_error("elf: header: wrong section header offset, section header entry size or section header entry nums");
    }

    // parse section header table...
    if (!sectionHeaderTable.empty())
        sectionHeaderTable.clear();
    const uint8_t * src = binaryContent.get() + (header.sectionHeaderOffset - header.headerSize);
    for (std::size_t i = 0; i < sectionHeaderEntryNums; ++i)
    {
        ELFSectionHeader sectionHeader;

        std::size_t length = header.sectionHeaderEntrySize;
        sectionHeader.deserialize(src, length, header.elfEndianness, header.elfClass);
        sectionHeaderTable.push_back(sectionHeader);

        if (i == 0 && header.sectionHeaderEntryNums == 0)
        {
            sectionHeaderEntryNums = sectionHeader.size;
            if (sectionHeaderEntryNums > 1)
            {
                std::size_t newLength = header.sectionHeaderOffset
                                      + header.sectionHeaderEntrySize * sectionHeaderEntryNums
                                      - header.headerSize;
                std::unique_ptr<uint8_t[]> newContent(new uint8_t[newLength]);
                memcpy(newContent.get(), binaryContent.get(), binaryLength);
                char * readPtr = reinterpret_cast<char*>(newContent.get()) + binaryLength;
                for (std::size_t readLength = newLength - binaryLength; readLength; readLength -= stream.gcount(), readPtr += stream.gcount())
                {
                    stream.read(readPtr, readLength);
                    if (!stream)
                        throw std::runtime_error("elf: wrong section header size");
                }
                binaryContent.swap(newContent);
                binaryLength = newLength;
            }
        }

        src += length;
    }

    std::size_t sectionHeaderIndexOfSectionNames = header.sectionHeaderIndexOfSectionNames;
    if (sectionHeaderIndexOfSectionNames == SHN_XINDEX)
        sectionHeaderIndexOfSectionNames = sectionHeaderTable[0].link;
    ELFSectionHeader & sectionNamesHeader = sectionHeaderTable[sectionHeaderIndexOfSectionNames];
    const char * stringTable = reinterpret_cast<const char*>(binaryContent.get() + sectionNamesHeader.offset - header.headerSize);
    for (std::size_t i = 0; i < sectionHeaderTable.size(); ++i)
    {
        ELFSectionHeader & sectionHeader = sectionHeaderTable[i];
        sectionHeader.name = stringTable + sectionHeader.nameIndex;
    }
}

} // namespace elf

template<typename Int>
std::ostream & operator<<(std::ostream & stream, const elf::ELFInteger<Int> & integer)
{
    return stream << static_cast<Int>(integer);
}

inline std::ostream & operator<<(std::ostream & stream, const elf::ELFClass & right)
{
    if (right == elf::ELF_CLASS32)
        return stream << "ELF32";
    if (right == elf::ELF_CLASS64)
        return stream << "ELF64";
    return stream << "ELF";
}

inline std::ostream & operator<<(std::ostream & stream, const elf::ELFMachine & right)
{
    if (right == elf::EM_X86)
        return stream << "x86";
    if (right == elf::EM_ARM)
        return stream << "ARM";
    if (right == elf::EM_X86_64)
        return stream << "x86-64";
    return stream << "Unknown";
}

inline std::ostream & operator<<(std::ostream & stream, const elf::ELFSectionType & right)
{
    if (right == elf::SHT_NULL)
        return stream << "SHT_NULL";
    if (right == elf::SHT_PROGBITS)
        return stream << "SHT_PROGBITS";
    if (right == elf::SHT_SYMTAB)
        return stream << "SHT_SYMTAB";
    if (right == elf::SHT_STRTAB)
        return stream << "SHT_STRTAB";
    if (right == elf::SHT_RELA)
        return stream << "SHT_RELA";
    if (right == elf::SHT_HASH)
        return stream << "SHT_HASH";
    if (right == elf::SHT_DYNAMIC)
        return stream << "SHT_DYNAMIC";
    if (right == elf::SHT_NOTE)
        return stream << "SHT_NOTE";
    if (right == elf::SHT_NOBITS)
        return stream << "SHT_NOBITS";
    if (right == elf::SHT_REL)
        return stream << "SHT_REL";
    if (right == elf::SHT_SHLIB)
        return stream << "SHT_SHLIB";
    if (right == elf::SHT_DYNSYM)
        return stream << "SHT_DYNSYM";
    if (right == elf::SHT_INIT_ARRAY)
        return stream << "SHT_INIT_ARRAY";
    if (right == elf::SHT_FINI_ARRAY)
        return stream << "SHT_FINI_ARRAY";
    if (right == elf::SHT_PREINIT_ARRAY)
         return stream << "SHT_PREINIT_ARRAY";
     if (right == elf::SHT_GROUP)
         return stream << "SHT_GROUP";
     if (right == elf::SHT_SYMTAB_SHNDX)
         return stream << "SHT_SYMTAB_SHNDX";
     return stream << "Unknown";
}

inline std::ostream & operator<<(std::ostream & stream, const elf::ELFSectionHeader & right)
{
    stream << " " << std::setw(20) << right.name
           << " " << std::hex << std::setfill('0') << std::setw(8) << right.size
           << " " << std::hex << std::setfill('0') << std::setw(16) << right.addr
           << " " << std::setfill(' ') << std::setw(17) << right.type
           << " name=" << std::dec << right.nameIndex
           << " flags=" << right.flags
           << " offset=" << right.offset
           << " link=" << right.link
           << " info=" << right.info
           << " addrAlign=" << right.addressAlignment
           << " entSize=" << right.entrySize;
    return stream;
}

inline std::ostream & operator<<(std::ostream & stream, const elf::ELFFile & right)
{
    stream << right.filename << ": file format " << right.header.getFileType() << std::endl
           << std::setfill(' ')
           << std::setw(3)  << "Idx"
           << std::setw(21) << "Name"
           << std::setw(9)  << "Size"
           << std::setw(17) << "Address"
           << std::setw(18) << "Type";
    for (std::size_t i = 0; i < right.sectionHeaderTable.size(); ++i)
        stream << std::endl << std::setw(3) << i << right.sectionHeaderTable[i];
    return stream;
}

#endif // ELF_HPP
