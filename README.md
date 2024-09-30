# YaraScan.py

**YaraScan.py** is a simple script that performs YARA rule scanning across multiple modes: scanning directories, all running processess and whats on the memory (dlls, threat, handles), or specific processes. It is designed for forensic analysts, malware researchers or DFIR teams who need to apply YARA rules efficiently to identify malicious files, memory regions, or active processes.

## Features

- **Directory Scanning**: Scan all files in a specified directory for matches against YARA rules.
- **Memory Scanning**: Scan the entire system memory for patterns or signatures defined in YARA rules.
- **Process Memory Scanning**: Target a specific process and scan its memory for YARA rule matches.

# instalation 
```
git clone https://github.com/abr4xc/YaraScan.git
cd YaraScan
pip install -r requirements 

 ```
 
## Usage

The script supports three modes of operation: directory scanning, memory scanning, and process-specific scanning. Each mode can be triggered by the corresponding command-line flag.

## Command-Line Arguments

python yarascan.py [OPTIONS]

-d, --directory: Scans all files in the given directory.
-m, --memory: Scans the entire system memory.
-PM, --process-memory: Scans the memory of a specific process by PID.
-r, --rules: Specifies the YARA rule file(s) to be used.

## Example Commands
 1. Directory Scanning
```
python yarascan.py -d /path/to/directory -r rules.yar
```

2. Memory Scanning
```   
python yarascan.py -m -r rules.yar
```

3. Process Memory Scanning
```
python yarascan.py -PM 1234 -r rules.yar
```

# Contributing

Contributions, bug reports, and feature requests are welcome! Please feel free to submit a pull request or open an issue in the GitHub repository.
