# QRadar MCP Server

A QRadar SIEM integration service based on the MCP (Model Connector Protocol) that provides access and management capabilities for QRadar security events.

## Features

- Get specific offense details by ID
- Integration with QRadar SIEM system
- Based on MCP protocol for integration with various AI applications

## Requirements

- Python 3.10+
- Access to QRadar SIEM instance
- API credentials

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd MCP_Server_for_Qradar
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure environment variables:
   Create a `.env` file with the following content:
   ```env
   QRADAR_HOST=https://your-qradar-host
   QRADAR_USERNAME=your-username
   QRADAR_PASSWORD=your-password
   ```

## Usage

Run the service:
```bash
python main.py
```

## Tools

### get_offenses_id
Retrieves detailed information about a specific offense by its ID.

## License

MIT

## requirements.txt

```txt
httpx>=0.23.0
python-dotenv>=0.19.0
mcp>=0.1.0
fastapi>=0.68.0
uvicorn>=0.15.0
```

## Project Structure

Based on your provided code, the recommended project structure is:

```
MCP_Server_for_Qradar/
├── main.py              # Main application file
├── README.md            # Project documentation
├── requirements.txt     # Python dependencies
├── .env.example         # Environment variables example
└── .gitignore           # Git ignore configuration
```

## .env.example

```env
# QRadar Configuration Example
QRADAR_HOST=https://your-qradar-host:443
QRADAR_USERNAME=your-api-username
QRADAR_PASSWORD=your-api-password
```
