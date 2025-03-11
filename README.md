# Personal Firewall

A cross-platform GUI-based personal firewall that allows users to block applications from accessing the internet on Windows and Linux.

## Features

- User-friendly GUI for managing application internet access
- Block/unblock applications with a simple toggle
- View active connections
- Persistent rules (saved between application restarts)
- Administrator privilege handling
- Cross-platform support (Windows and Linux)

## Screenshots

(Screenshots will be added here after the first release)

## Installation

### Prerequisites

- Python 3.8 or higher
- Administrative privileges (required for firewall operations)

### Windows

1. Download the latest release from the [Releases](https://github.com/Latex999/personal-firewall/releases) page
2. Extract the ZIP file to a location of your choice
3. Run the installer (`setup.exe`) or run directly with Python:

```bash
pip install -r requirements.txt
python personal_firewall.py
```

### Linux

1. Download the latest release from the [Releases](https://github.com/Latex999/personal-firewall/releases) page
2. Extract the archive to a location of your choice
3. Install dependencies and run:

```bash
pip install -r requirements.txt
sudo python personal_firewall.py  # Sudo is required for firewall operations
```

## Building from Source

```bash
git clone https://github.com/Latex999/personal-firewall.git
cd personal-firewall
pip install -r requirements.txt
python personal_firewall.py  # Add 'sudo' on Linux
```

## Usage

1. Launch the application (with administrative privileges)
2. The main window will display a list of applications with internet access
3. Toggle the switch next to an application to block/allow internet access
4. Use the search bar to find specific applications
5. Click "Refresh" to update the list of applications and their statuses

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.