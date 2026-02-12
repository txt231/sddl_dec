# sddl_dec
Tool for decrypting Panasonic TV SDDL.SEC files.   
This tool will decrypt and unpack the files from an SDDL.SEC firmware update package used on Panasonic TVs.  
**Notice:** The tool will not directly extract the contents of the firmware by itself! It only unpacks and decrypts the SDDL.SEC file. To inspect the output of the program, use a tool like [binwalk](github.com/ReFirmLabs/binwalk). To see what you can expect, read more below.
## Support
The tool can extract SDDL.SEC files from TVs released in and after 2011. Older files seem to use a different format.
## Installation
Build from source, by downloading the code and running `cargo build --release`. The binary will be saved in `target/release`.  
  
If you prefer to use the old python version, you can find it in the `python` branch (Please note that it is now very outdated, and no support will be provided).
## Usage
`sddl_dec [OPTIONS] <INPUT_FILE> [OUTPUT_FOLDER]`  
`<INPUT_FILE>` - The SDDL.SEC file to extract.  
`<OUTPUT_FOLDER>` - Folder to save extracted files to. If not provided, will use `_<filename>`  
`[OPTIONS]` - Can be:  
`-v` - Verbose mode - Print more detailed information about the file    
`-s` - Save .TXT and TDI files (read more below)  
`-h` - Show help message.  
## About SDDL.SEC and the output of the program
An SDDL.SEC file is an encrypted, ciphered and partially compressed archive that contains the firmware data for the TV.
The main contents of the file can consist of:
- SDIT.FDI - Probably stands for some combination of "Software Download Information Table" - it contains information about the modules contained within the file, their versions and respective models. It is not saved by default, but you can keep it with the `-s` option.
- A bunch of XXX.TXT files, each one respective to one group in the SDIT. They usually contain information about the target of the update. By default, they are not saved and will be only printed to output, but with the `-s` option they will be saved.
- `PEAKS` module - this is the main firmware data split into chunks, usually of 2/4MB of size - it is saved into a PEAKS.bin file, or in case of 2014-2018 files, the files embedded inside will be saved into a PEAKS folder.
The content of the `PEAKS` module varies depending on the TV's platform, from my findings the structure is:
    - For FreeBSD-based 2011-2013 models, and some later lower-end models: Read about the format and further instructions [here](https://gist.github.com/theubusu/fdec541b90459a86aedf4e5c174a565d)
    - For FreeBSD-based 2014-~2018? models - the output are 2 files in a PEAKS folder: "root.tgz" containing the rootfs filesystem, and a "DLDATA_LIST.TXT" file which specifies the partition it should be installed to.
    - For Linux-based 2019+ models - the output blob contains a bootloader, DTB and rootfs squashfs filesystem (binwalk)
- There can also be additional modules, such as `BOOT`, `PEAKSBT`, `STM`, `DTB` - these are either the TV's bootloader or some other firmware.
# License
Licensed under GNU GPL v3.  