
# PyQt5  Chat Application

[![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)](https://python.org)
[![PyQt5](https://img.shields.io/badge/PyQt5-latest-green.svg)](https://pypi.org/project/PyQt5/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A secure chat application using PyQt5 with an intuitive graphical user interface, leveraging modern cryptographic practices to securely connect a client and a server.

## Overview

This application provides a simple and secure way to chat between systems. It employs X25519 key exchange for secure key negotiation, and AES-GCM for data encryption, ensuring confidentiality and integrity in message exchange.

## Features

- **Dual Mode Operation**: Choose between Client or Server modes for communication.
- **Secure Key Exchange**: Utilizes X25519 for efficient and secure key exchange.
- **AES-GCM Encryption**: Ensures high security for messages with AES-GCM encryption.
- **Resilient Connections**: Automatically attempts reconnection upon network disruption.
- **User-Friendly GUI**: Built with PyQt5, offering a clean and responsive interface.
- **Message Alignment**: Chat messages are visually distinct, aligning client messages left and server messages right.

## Getting Started

Follow these instructions to set up and run the project on your local machine.

### Prerequisites

Ensure you have Python 3.x installed on your system. Required Python packages:

- [PyQt5](https://pypi.org/project/PyQt5/)
- [cryptography](https://pypi.org/project/cryptography/)

Use pip to install the dependencies:

```bash
pip install PyQt5 cryptography
```

### Installation

Clone the repository:

```bash
git clone https://github.com/wangyifan349/QTsocket5_chat.git
cd QTsocket5_chat
```

### Running the Application

Launch the application with Python:

```bash
python chat_app.py
```

### Usage

1. **Configuration**:
   - **Mode Selection**: Choose Client or Server mode.
   - **Enter Connection Details**: Input the IP address and port number.

2. **Initiate Chat**:
   - Click "Start" to initialize the connection.
   - Use the text input field to send messages.

## Contributing

We welcome contributions! Please fork the repository and submit a pull request for any enhancements or bug fixes.

## License

This project is licensed under the terms of the MIT License. You are free to use, modify, and distribute this software under the terms of this license. See the [LICENSE](LICENSE) file for more details.

## Acknowledgements

- [PyQt5](https://riverbankcomputing.com/software/pyqt/intro) for the GUI framework.
- [Cryptography Library](https://cryptography.io/) for secure encryption functions.

## Contact

Feel free to reach out for any inquiries or issues through the repository's issue tracker.

---

Thank you for checking out this project! We hope you find it useful and informative.

