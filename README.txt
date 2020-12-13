Hashtest
========

Validate integrity of in memory code using hashes

Made up of two components, Hashbuild and Hashtest.
For more details see paper @ http://dfrws.org/2013/proceedings/DFRWS2013-12.pdf

Hashbuild
---------
  Parses a mounted filesystem and creates a hash set for all Portable Executable (PE) files on the disk.
  Supports PE files (32-bit) and PE+ (64-bit) files.  

  Tested on:
    - Windows 10 32-bit (1903)
    - Windows 10 64-bit (1809)
    - Windows 7 SP1 32-bit
   
  Usage:

```
python3 py3-hashbuild.py <mount point> <output file>
```
    
    
Hashtest
--------
  Takes a hash set and validates the code in user space memory for a given memory image
  Requires Volatility, tested on version 2.6.1
  Dumps pages that are not validated to a specified directory
  
  Usage
    python vol.py -f <memory image> --profile <memory image OS> hashtest 
                  -s <hash set> -D <dump directory>
  
  Output categories
    Verified      - code hash matched stored hash
    Failed        - code hash did not match stored hash
    Unknown       - code hash information did not exist for page
    Unverifiable  - Windows behaviour that cannot be verified (see paper)
  
  
Note: The results for Win10 64-bit are not perfect and as good as for 32-bit. This needs to be further investigated.

Note2: code is still a little messy, a cleaned up version is coming soon
