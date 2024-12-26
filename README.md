# Advanced PE Crypter

A sophisticated PE file crypter and protector written in C++ that provides advanced features for executable protection.

## Features

- Strong encryption using AES-256 in CBC mode with secure key generation
- Multiple injection methods:
  - Process Hollowing
  - APC Injection
  - Module Stomping
  - Early Bird Injection
- Advanced anti-analysis techniques:
  - Anti-debugging protection
  - Anti-VM detection
  - Sandbox detection
  - Timing checks
- Metamorphic engine:
  - Code morphing
  - Instruction substitution
  - Dead code insertion
  - Control flow obfuscation
- PE file manipulation:
  - Section manipulation
  - Import table obfuscation
  - Header modification
  - Resource encryption
- Modern GUI with progress tracking and detailed options

## Requirements

- Windows 10 or later
- Visual Studio 2022
- CMake 3.15 or later
- Administrator privileges (for certain features)

## Building

1. Clone the repository:
```bash
git clone https://github.com/yourusername/improved_crypter.git
cd improved_crypter
```

2. Build the project:
```bash
# On Windows
.\build.bat

# On Unix-like systems with Windows cross-compilation
./build.sh
```

The compiled executable will be in `build/bin/Release/improved_crypter.exe`

## Usage

1. Launch the application with administrator privileges
2. Select the input PE file to protect
3. Configure protection options:
   - Enable/disable metamorphic engine
   - Choose injection method
   - Configure anti-analysis features
   - Set additional protection options
4. Select output location
5. Click "Build" to create the protected executable

## Security Features

### Encryption
- AES-256 encryption in CBC mode
- Secure random key generation using BCrypt
- Unique IV for each encryption
- Key storage protection

### Anti-Analysis
- Debug detection (user-mode and kernel-mode)
- Virtual machine detection
- Sandbox environment detection
- Analysis tools detection
- Timing-based checks

### Code Protection
- Metamorphic engine for code transformation
- Control flow obfuscation
- Dead code insertion
- Instruction substitution
- Import table obfuscation

### Injection Methods
- Process Hollowing: Creates a suspended process and replaces its memory with encrypted payload
- APC Injection: Queues an APC to execute the payload in target process
- Module Stomping: Overwrites an existing module with the payload
- Early Bird: Injects payload during process initialization

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational purposes only. Users are responsible for complying with all applicable laws and regulations regarding the use of this software.

## Acknowledgments

- Windows API documentation
- PE format specifications
- Various anti-analysis techniques research papers
- Open source cryptography implementations
