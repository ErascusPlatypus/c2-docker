# Command & Control (C2) Framework

A secure, modular, and cross-platform Command and Control framework designed for security professionals, pentesters, and red teams. This framework provides a robust infrastructure for managing remote agents across Windows and Linux systems.

## Features

- **Secure Communication**: TLS/SSL encrypted communications with mutual authentication
- **Challenge-Response Authentication**: Secure agent verification using cryptographic challenge-response
- **Cross-platform Support**: Full compatibility with both Windows and Linux systems
- **Modular Command Structure**: Commands organized by tactical categories (recon, persistence, exfiltration, etc.)
- **Stealth Capabilities**: Sleep jitter, fileless execution, and anti-forensic techniques
- **Admin Dashboard**: Web-based interface for agent management and command execution
- **Docker Support**: Ready for containerized deployment in any environment
- **Configurable**: Easily customizable via environment variables or configuration files

## Architecture

The framework consists of two main components:

1. **C2 Server**: Flask-based server that manages agent registration, command distribution, and result collection
2. **Agent Client**: Cross-platform client that executes commands and reports results back to the server

## Installation

### Using Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/yourusername/c2-framework.git
cd c2-framework

# Build and run with Docker Compose
docker-compose up -d
```

### Manual Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/c2-framework.git
cd c2-framework

# Install dependencies
pip install -r requirements.txt

# Generate SSL certificates (if needed)
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365

# Run the server
python run_server.py
```

## Configuration

The framework can be configured using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `C2_SERVER_HOST` | Host to bind the server to | `0.0.0.0` |
| `C2_SERVER_PORT` | Port to bind the server to | `443` |
| `C2_SSL_CERT` | Path to SSL certificate | cert.pem |
| `C2_SSL_KEY` | Path to SSL key | key.pem |
| `C2_SHARED_SECRET` | Secret for challenge-response auth | `changeme` |
| `C2_ADMIN_USER` | Username for admin dashboard | `admin` |
| `C2_ADMIN_PASS` | Password for admin dashboard | `changeme` |
| `C2_LOG_LEVEL` | Logging verbosity | `INFO` |

## Usage

### Server

After starting the server, the following endpoints will be available:

- `/overview`: Agent check-in and registration
- `/verify`: Challenge-response verification
- `/cmd`: Command distribution
- `/report`: Result collection
- `/admin/agents`: List all registered agents
- `/admin/agent/<id>/history`: View agent command history
- `/admin/agent/<id>/queue`: Queue commands for specific agents

### Agent

Agents automatically register with the server, retrieve commands, execute them, and report results back to the server.

```bash
# Run an agent
python -m client.agent
```

## Command Categories

The framework includes pre-defined commands for various tactics:

- **Initial Access**: Establish foothold on target systems
- **Reconnaissance**: Gather information about the environment
- **Privilege Escalation**: Gain higher-level permissions
- **Persistence**: Maintain access across reboots
- **Defense Evasion**: Avoid detection and cover tracks
- **Lateral Movement**: Move through the network
- **Data Exfiltration**: Extract valuable information
- **Cleanup**: Remove artifacts and evidence

## Security Considerations

This framework is designed for authorized security testing only. Misuse may violate computer crime laws and regulations. Always ensure you have proper authorization before using this tool.

## Extending the Framework

The modular design makes it easy to add new functionality:

- Add new commands to commands.py
- Implement new endpoints in routes.py
- Enhance client capabilities in agent.py

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and professional security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Acknowledgements

- This project was inspired by various open-source C2 frameworks
- Special thanks to all contributors and the security research community

---

*Note: This is a functional Command and Control framework designed for educational purposes and authorized penetration testing. Always use responsibly and legally.*
