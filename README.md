# SLE4442 Manager

A comprehensive tool for reading, writing, and managing SLE4442 smart cards with both GUI and CLI support.

![SLE4442 Manager GUI](img)

## Acknowledgments

Thanks to [@luu176](https://github.com/luu176/SLE4442-Card-Manager) and [@hvfrancesco](https://github.com/hvfrancesco/SLE4442-card-manager) for their previous work.

## Features
- **Read and Write card memory**
- **Import/Export** raw HEX format files
- **Read security memory** (error counter and protection bits)
- **Unlock and Change PSC** (PIN)
- **Send raw APDU commands** for advanced operations
- **Multiple reader support** with automatic detection
- **APDU logging** for debugging
- **Full CLI support** for automation and scripting

## Screenshots

### Read Operations
![Read card memory](img)

### Export and Import
![Export and Import functionality](img)

### Write Operations
![Write to card](img)

### PIN Management and Exception Handling
![PIN unlock and error handling](img)

### Raw APDU and Logs
![Raw APDU commands and logging](img)

## Quick Start

```bash
pip install pyscard
pip install PyQt5  # Optional, for GUI mode


python sle4442_manager.py

python sle4442_manager.py --nogui # for CLI mode
```
