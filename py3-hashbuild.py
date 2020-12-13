# Copyright (c) 2013 Andrew White <awhite.au@gmail.com>
# Copyright (c) 2020 Patrick Reichenberger

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#


#   Hashbuild
#   Create hashes from PE files by implementing a custom PE loader
#   and normalising parts that change on a page basis


import sys
import struct
import hashlib
import itertools
import os
import os.path

import pefile
import hexdump

# --------------
# Abstract Class
# --------------
class Disk(object):
    """Disk driver for reading the contents of the disk"""
    def __init__(self, disk):
        self.disk = disk

    def read(self):
        """Read all executable files on the disk"""
        pass

    def find(self):
        """Find all PE files on disk"""
        pass


# ----------------------
# Module Implementations
# ----------------------
class Filesystem(Disk):
    """Read files from a mounted disk image"""
    def __init__(self, disk):
        super(Filesystem, self).__init__(disk)

    def read(self, path):
        """Read all PE files on disk"""
        f = open(path, mode='rb')
        data = f.read()
        f.close()
        return data

    def find(self):
        """Find all PE files on disk"""
        extensions = [".dll", ".exe", ".drv", ".cpl", ".ocx", ".mui"]
        for path, dirs, files in os.walk(self.disk):
            for filename in files:
                name = filename.lower()
                if name[-4:] in extensions:
                    yield name, os.path.join(path, filename)


# ----------
# Main Logic
# ----------
class HashBuild:
    "Build a hash for each PE file on the disk"
    def __init__(self, args):
        if len(args) != 3:
            print("Usage - py3-hashbuild.py <mounted disk> <output file>")
            quit()
        diskfile = args[1]
        hashfile = args[2]
        count = 0

        # build a list of files to read
        files = {}
        count = 0
        disk = Filesystem(diskfile)
        for name, path in disk.find():
            files.setdefault(name, [])
            files[name].append(path)
            count += 1

        # sort files (based on filename, not path)
        names = files.keys()
        names = sorted(names)
        
        # output summary
        print("Found {0} files to hash".format(count))

        # parse PEs and build hashes
        for name in names:
            paths = files[name]
            output = []
            for path in paths:
                try:
                    #if name != "win32u.dll":
                    #    break
                    print(path)

                    pe_file = pefile.PE(path, fast_load=True)
                    memory_lay = pe_file.get_memory_mapped_image()

                    if pe_file.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE:
                        addr_len = 4
                    elif pe_file.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
                        addr_len = 8
                    else:
                        print("Error: No PE or PE+ file.")
                        break
            
                    iat_directory = pe_file.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IAT']]
                    iat_zeroes = self.iat(iat_directory, addr_len)
                    
                    ################ BEGIN PARSING RELOCATIONS
                    ### ORIGINAL
                    reloc_zeroes = self.orig_relocation_parsing(pe_file, memory_lay)
                    ################
                    ### PEFILE (is slower and consumes more memory)
                    #base_relocations_locations = self.pefile_relocation_parsing(pe_file)
                    #reloc_zeroes = self.build_to_zero_dict(base_relocations_locations)      
                    ################ END PARSING RELOCATIONS

                    #all_zeroes = reloc_zeroes | iat_zeroes # Requires Python 3.9 which is not supported on <= Win7
                    all_zeroes = reloc_zeroes
                    intersec = set(iat_zeroes.keys()).intersection(set(reloc_zeroes.keys()))
                    for page in intersec:
                        all_zeroes[page] = sorted(reloc_zeroes[page] + iat_zeroes[page])    
                    for page in set(iat_zeroes.keys())-intersec:
                        all_zeroes[page] = iat_zeroes[page]

                    pages, zeroes = self.zero(memory_lay, all_zeroes, addr_len)             
                    # hash
                    hashes = self.hash(pages)

                except pefile.PEFormatError as error:
                    print("PEFormatError in file \"{path}\": {error}".format(path=path, error=error))
                    break
                except FileNotFoundError as error:
                    break


                perms_list = []
                header_num_pages = 0
                perms_list.extend([0]*(pe_file.OPTIONAL_HEADER.SizeOfHeaders // 4096))
                header_num_pages += pe_file.OPTIONAL_HEADER.SizeOfHeaders // 4096

                # Add page permission for partly used header page
                if pe_file.OPTIONAL_HEADER.SizeOfHeaders % 4096 != 0:
                    perms_list.append(0)
                    header_num_pages += 1

                # Adjust alignment for header
                if pe_file.OPTIONAL_HEADER.SectionAlignment // 4096:
                    header_align_pages = header_num_pages % (pe_file.OPTIONAL_HEADER.SectionAlignment // 4096)
                else:
                    header_alig_pages = 0
                if header_align_pages != 0:
                    perms_list.extend([0]*((pe_file.OPTIONAL_HEADER.SectionAlignment // 4096)-header_align_pages))
                    header_num_pages += (pe_file.OPTIONAL_HEADER.SectionAlignment // 4096)-header_align_pages

                for section in pe_file.sections:
                    if (section.Characteristics & 0x20000000) == 0x20000000:
                        perm_bit = 1
                    else:
                        perm_bit = 0
                    num_pages = 0
                    perms_list.extend([perm_bit]*(section.Misc_VirtualSize // 4096))
                    num_pages += (section.Misc_VirtualSize // 4096)
                    # Check if section aligns at page boundary or not. If not -> append additional page
                    if section.Misc_VirtualSize % 4096 != 0:
                        perms_list.append(perm_bit)
                        num_pages += 1
                    # check alignment
                    if pe_file.OPTIONAL_HEADER.SectionAlignment // 4096:
                        align_pages = num_pages % (pe_file.OPTIONAL_HEADER.SectionAlignment // 4096)
                    else:
                        align_pages = 0
                    if align_pages != 0:
                        perms_list.extend([perm_bit]*((pe_file.OPTIONAL_HEADER.SectionAlignment // 4096)-align_pages))
                        num_pages += ((pe_file.OPTIONAL_HEADER.SectionAlignment // 4096)-align_pages)

                # generate output for file
                output.append(self.output(hashes, zeroes, perms_list, path, name))

            if len(output) > 1:
                # join into single list of unique hashes
                output = self.filter(output)
            elif len(output) > 0:
                output = output[0]
            else:
                #no output
                continue
            #output hashes for file
            self.write(hashfile, output)

    def iat(self, iat_directory, addr_len):
        """Determine where to normalise the import address table"""
        iat_zeroes = {}
        
        offset = 0
        
        offset = iat_directory.VirtualAddress % 0x1000
        addr = iat_directory.VirtualAddress - (offset)
        iat_zeroes[addr] = []
        while addr + offset < iat_directory.VirtualAddress + iat_directory.Size:
            if offset == 0x1000:
                # move to the next page
                addr += offset
                iat_zeroes[addr] = []
                offset = 0
            iat_zeroes[addr].append(offset)
            offset += addr_len

        return(iat_zeroes)

    def dump_relocations(self, pe_file):
        '''
        Dump base relocations (from pefile package)
        '''
        base_relocations = list()
        if pe_file.has_relocs():
            for base_reloc in pe_file.DIRECTORY_ENTRY_BASERELOC:
                base_reloc_list = list()
                base_relocations.append(base_reloc_list)
                base_reloc_list.append(base_reloc.struct.dump_dict())
                for reloc in base_reloc.entries:
                    reloc_dict = dict()
                    base_reloc_list.append(reloc_dict)
                    reloc_dict['RVA'] = reloc.rva
                    try:
                        reloc_dict['Type'] = pefile.RELOCATION_TYPE[reloc.type][16:]
                    except KeyError:
                        reloc_dict['Type'] = reloc.type
        return base_relocations

    def get_base_relocation_locations(self, base_relocs):
        base_relocations_locations = list()
        for i in range(0,len(base_relocs)):
            for relo in base_relocs[i]:
                if 'Type' in relo and relo['Type'] == "HIGHLOW":
                    base_relocations_locations.append(relo['RVA'])
                if 'Type' in relo and relo['Type'] == "DIR64":
                    base_relocations_locations.append(relo['RVA'])
        return base_relocations_locations

    def orig_relocation_parsing(self, pe_file, memory_lay):
        
        def parse_relocations(relocs):
            """Parse the relocations for the given page"""
            zeroes = []
            offset = 0
            last = -1
            while offset < len(relocs):
                # Load relocation entry content
                entry = int.from_bytes(relocs[offset:offset+2], "little")
                # Extract relocation entry type
                reloc_type = (entry & 0xF000) >> 12
                # Extract relocation entry address (offset into page)
                reloc_addr = entry & 0x0FFF
                if reloc_type == 3:
                    # IMAGE_REL_BASED_HIGHLOW
                    if reloc_addr > last:
                        #prevent padding 0's from being added
                        zeroes.append(reloc_addr)
                        last = reloc_addr
                elif reloc_type == 0:
                    # IMAGE_REL_BASED_ABSOLUTE - used as padding
                    pass
                else:
                    # TODO - any other types (not yet encountered)
                    pass
                offset += 0x2
            return zeroes

        """Get all the relocations for the pe, broken into chunks based on pages"""
        virt_addr_reloc_section = pe_file.OPTIONAL_HEADER.DATA_DIRECTORY[5].dump_dict()['VirtualAddress']['Value']
        reloc_section_size = pe_file.OPTIONAL_HEADER.DATA_DIRECTORY[5].dump_dict()['Size']['Value']
        reloc_section_content = memory_lay[virt_addr_reloc_section:virt_addr_reloc_section + reloc_section_size]
        # IMAGE_BASE_RELOCATION
        offset = 0
        relocations = {}
        while offset < reloc_section_size:
            # Determine VirtualAddress of relocation table block
            vaddr = int.from_bytes(reloc_section_content[offset:offset+4], "little")
            # Determine Size of relocation table block
            size = int.from_bytes(reloc_section_content[offset+0x4:offset+0x8], "little")
            if size == 0:
                break
            # Load relocation table block content (only relocation entries; obviously separated by pages)
            page_relocs = reloc_section_content[offset + 0x8:offset + 0x8 + size]
            # Store relocation offsets within page in dictionary where page offset is key and the list of offsets into page are the value
            relocations[vaddr] = parse_relocations(page_relocs)
            # Add size to go to the next relocation table block
            offset += size
        
        return relocations
        #### End orig relocation parsing

    def pefile_relocation_parsing(self, pe_file):
        pe_file.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']])
        pe_file_dict = {}
        # Dump base relocations
        pe_file_dict['Base relocations'] = self.dump_relocations(pe_file)
        # Extract addresses where relocations to apply
        base_relocations_locations = self.get_base_relocation_locations(pe_file_dict['Base relocations'])
        return base_relocations_locations

    def build_to_zero_dict(self, addresses_list):
        to_zero_dict = {}
        for i in addresses_list:
            addr_page_bound = i // 4096
            to_zero_dict.setdefault(addr_page_bound * 4096, [])
            to_zero_dict[addr_page_bound*4096].append(i % 4096)
        return to_zero_dict

    def zero(self, virtual, alterations, addr_len):
        """Normalise the alterations and split into page size chunks"""
        vaddr = 0
        pages = {}
        unapplied = 0

        while vaddr < len(virtual):
            if vaddr in alterations:
                zeroes = alterations[vaddr]
                offset = 0
                # check for any unapplied zeroes from page overlaps
                if unapplied > 0:
                    data = b"\x00" * unapplied
                    offset = unapplied
                    # add position of where alteration would start
                    #alterations[vaddr].insert(0, -(4 - unapplied))
                    alterations[vaddr].insert(0, -(addr_len - unapplied))
                    unapplied = 0
                else:
                    data = b""
                for zero in zeroes:
                    if zero < 0 or zero < offset:
                        # already been applied or padding
                        continue
                    # add previous
                    data += virtual[vaddr + offset:vaddr + zero]
                    # add zeroes
                    if zero <= 0x1000 - addr_len:
                        # does not cross page boundary
                        data += b"\x00"*addr_len
                        offset = zero + addr_len
                    else:
                        # crosses page boundary
                        diff = 0x1000 - zero
                        data += b"\x00" * diff
                        unapplied = addr_len - diff
                        offset = 0x1000
                # add remaining
                if offset < 0x1000:
                    data += virtual[vaddr + offset:vaddr + 0x1000]
                pages[vaddr] = data
            else:
                pages[vaddr] = virtual[vaddr:vaddr + 0x1000]
            vaddr += 0x1000
        return pages, alterations

    def hash(self, pages):
        """Hash the normalised pages"""
        hashes = {}
        for addr, page in pages.items():
            hash = hashlib.sha1(page).hexdigest()
            hashes[addr] = hash
        return hashes

    def output(self, hashes, zeroes, perms, path, name):
        """Output the hash information to a file"""
        output = []
        offset = 0
        while offset / 0x1000 < len(hashes):
            hash = hashes[offset]
            line = "{0},{1:x},{2},{3},{4}\n"
            if offset in zeroes:
                # convert offsets to hex
                offsets = ["{0:x}".format(x) for x in zeroes[offset]]
                offsets = " ".join(offsets)
            else:
                offsets = ""

            output.append(line.format(name, int(offset / 0x1000), hash, perms[int(offset / 0x1000)], offsets))
            offset += 0x1000
        print("Hashed ", path)
        return output

    def filter(self, output):
        """Remove duplicate entries"""
        #combine hashes from all files into a single list
        #zip different length lists - http://docs.python.org/2/library/itertools.html#itertools.izip_longest
        #zip lists into single list - http://stackoverflow.com/questions/3471999/how-do-i-merge-two-lists-into-a-single-list
        #zip unknown number of lists - http://stackoverflow.com/questions/5938786/how-would-you-zip-an-unknown-number-of-lists-in-python
        output = itertools.zip_longest(*output)
        output = list(itertools.chain.from_iterable(output))

        #remove duplicates
        #from http://stackoverflow.com/questions/480214/how-do-you-remove-duplicates-from-a-list-in-python-whilst-preserving-order
        seen = set()
        seen_add = seen.add
        output = [ x for x in output if x not in seen and not seen_add(x)]

        #remove None added by using izip_longest with different length lists
        if None in output:
            output.remove(None)
        return output


    def write(self, hashfile, output):
        """Write new hashes to the file"""
        f = open(hashfile, "a")
        f.write("".join(output))
        f.close()

if __name__ == "__main__":
    hashes = HashBuild(sys.argv)
