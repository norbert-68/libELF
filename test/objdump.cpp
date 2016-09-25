/*******************************************************************************
 * Copyright (C) 2012..2016 norbert.klose@web.de
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library. If not, see <http://www.gnu.org/licenses/>.
 ******************************************************************************/

#include <MachO.hpp>
#include <exception>
#include <set>
#include <string>
#include <vector>
#include <iostream>
#include <getopt.h>
#include <stdlib.h>

struct Options
{
    typedef std::vector<std::string> Filenames;
    typedef std::set<std::string> SegmentNames;
    typedef std::set<std::string> SectionNames;

    bool printMachHeader;
    bool printLoadCommands;
    bool printSymbols;
    bool printFile;
    bool printUUID;
    SegmentNames segmentNames;
    SectionNames sectionNames;
    Filenames filenames;
    
    Options() :
        printMachHeader(false),
        printLoadCommands(false),
        printSymbols(false),
        printFile(false),
        printUUID(false)
    {}
    
};

void usage(const char * programName)
{
    std::cout << "usage: " << programName << " [option]*" << std::endl
              << std::endl
              << "where option may" << std::endl
              << std::endl
              << " FILENAME                filename of an input file to be processed"          << std::endl
              << " -h,--mach-header        print the mach header"                              << std::endl
              << " -l,--load-commands      print the load commands"                            << std::endl
              << " -s,--symbols            print the symbol table (similiar to nm -ap)"        << std::endl
              << " -f,--file               print file information (similiar to -hls)"          << std::endl
              << " -u,--uuid               print UUID and corresponding dSYM bundle locations" << std::endl
              << "    --segment <segment>  print contents of segment"                          << std::endl
              << "    --section <section>  print contents of section"                          << std::endl;
}

/**
 * @returns Either EXIT_SUCCESS on success, or EXIT_FAILURE on failure.
 */
int getOptions(int argc, char * args[], Options & options)
{
    int result = EXIT_SUCCESS;
    
    static struct option longOptions[] =
    {
        { "mach-header"  , no_argument      , 0, 'h' },
        { "load-commands", no_argument      , 0, 'l' },
        { "symbols"      , no_argument      , 0, 's' },
        { "file"         , no_argument      , 0, 'f' },
        { "uuid"         , no_argument      , 0, 'u' },
        { "segment"      , required_argument, 0, 256 },
        { "section"      , required_argument, 0, 257 },
        { 0              , 0                , 0, 0   }
    };
    
    int nextOption;
    while ((nextOption = getopt_long(argc, args, "fhlsu", longOptions, 0)) != -1 && result == EXIT_SUCCESS)
    {
        switch (nextOption)
        {
            case 'f':
                options.printFile = true;
                break;
            case 'h':
                options.printMachHeader = true;
                break;
            case 'l':
                options.printLoadCommands = true;
                break;
            case 's':
                options.printSymbols = true;
                break;
            case 'u':
                options.printUUID = true;
                break;
            case 256: // --segment
                options.segmentNames.insert(optarg);
                break;
            case 257: // --section
                options.sectionNames.insert(optarg);
                break;
            case '?':
            default:
                usage(args[0]);
                result = EXIT_FAILURE;
                break;
        }
    }

    // take all unprocessed commandline arguments as FILENAME
    while (optind < argc)
        options.filenames.push_back(args[optind++]);
    
    return result;
}

int main(int argc, char * args[])
{
    int result = EXIT_SUCCESS;
    try
    {
        Options options;
        result = getOptions(argc, args, options);
        
        if (result == EXIT_SUCCESS)
        {
            for (const std::string & filename : options.filenames)
            {
                macho::MachOFile machoFile;
                std::cout << filename << std::endl;
                machoFile.open(filename);
                
                if (options.printMachHeader)
                {
                    std::cout << machoFile.header << std::endl;
                }
                
                if (options.printLoadCommands)
                    machoFile.printLoadCommands(std::cout);

                if (options.printSymbols)
                    machoFile.printSymtab(std::cout);

                if (options.printUUID)
                    std::cout << machoFile.uuid << std::endl;

                if (options.printFile)
                    std::cout << machoFile;

                if (!options.segmentNames.empty() || ! options.sectionNames.empty())
                {
                //                    std::vector<const macho::MachOSegment*> segments;
                //                    machoFile->getSegments(options.segmentNames, segments);
                //                    if (!options.sectionNames.empty())
                //                    {
                //                        std::vector<const macho::MachOSection*> sections;
                //                        for (std::vector<const macho::MachOSegment*>::const_iterator jtr = segments.begin(); jtr != segments.end(); ++jtr)
                //                            (*jtr)->getSections(options.sectionNames, sections);
                //                        for (std::vector<const macho::MachOSection*>::const_iterator jtr = sections.begin(); jtr != sections.end(); ++jtr)
                //                            std::cout << (*jtr)->toString() << std::endl
                //                                      << common::hexdump((*jtr)->getBytes(), (*jtr)->getSize()) << std::endl;
                //                        
                //                    }
                //                    else
                //                    {
                //                        for (std::vector<const macho::MachOSegment*>::const_iterator jtr = segments.begin(); jtr != segments.end(); ++jtr)
                //                            std::cout << (*jtr)->toString() << std::endl;
                //                    }
                }
            }
        }
    }
    catch (const std::exception & exception)
    {
        std::cerr << exception.what() << std::endl;
        result = EXIT_FAILURE;
    }
    catch (...)
    {
        std::cerr << "unknown exception" << std::endl;
        result = EXIT_FAILURE;
    }

    return result;
}
