# QRadar MCP Server

A production-ready Model Context Protocol (MCP) server that serves as an intelligent security event analysis assistant for IBM QRadar. This server provides both data querying capabilities and advanced automated root cause analysis for security incidents.

## Overview

The QRadar MCP Server bridges the gap between QRadar SIEM and AI-powered security analysis. It offers:

1. **Data Querying Module**: Direct integration with QRadar REST API for retrieving security events, logs, and executing custom queries
2. **Intelligent Analysis Module**: Automated root cause analysis, indicator extraction, timeline reconstruction, and actionable investigation recommendations

## Features

### Data Querying Tools

- **`search_offenses`**: Search security offenses by time range, severity, status, and type
- **`get_offense_details`**: Retrieve comprehensive details about a specific offense
- **`get_offense_logs`**: Fetch all log entries associated with an offense
- **`execute_aql_query`**: Execute custom AQL (Ariel Query Language) queries for maximum flexibility

### Intelligent Analysis Tools

- **`analyze_offense`**: Performs comprehensive root cause analysis including:
  - Automatic indicator extraction (IPs, domains, usernames, hashes)
  - Attack timeline reconstruction
  - Attack pattern identification
  - Structured investigation report generation

- **`recommend_investigation_actions`**: Generates prioritized, actionable recommendations such as:
  - EDR endpoint queries
  - Network isolation steps
  - User account investigations
  - Threat intelligence checks
  - IAM permission reviews

## Installation

### Prerequisites

- Python 3.11 or higher
- Access to a QRadar instance with API credentials
- QRadar username and password for authentication

### Setup

1. **Clone or download this repository**

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   
   这将安装所有必需的依赖，包括 `python-dotenv`（用于加载 `.env` 文件）。

3. **Configure environment variables**:
   
   **重要：必须创建 `.env` 文件来配置环境变量！**
   
   a. 复制示例配置文件：
   
   **Windows (PowerShell)**:
   ```powershell
   Copy-Item env.example .env
   ```
   
   **Windows (CMD)**:
   ```cmd
   copy env.example .env
   ```
   
   **Linux/Mac**:
   ```bash
   cp env.example .env
   ```
   
   b. 编辑 `.env` 文件，填入你的 QRadar 配置信息：
   
   **Windows**: 使用记事本或其他文本编辑器打开 `.env` 文件
   ```powershell
   notepad .env
   ```
   
   **Linux/Mac**: 使用你喜欢的文本编辑器
   ```bash
   nano .env
   # 或
   vim .env
   ```
   
   c. 在 `.env` 文件中设置以下必需的环境变量：
   ```env
   QRADAR_HOST=https://your-qradar-instance.com
   QRADAR_USERNAME=your-username
   QRADAR_PASSWORD=your-password
   ```
   
   d. 可选的环境变量（如不设置将使用默认值）：
   ```env
   QRADAR_TIMEOUT=30          # 请求超时时间（秒），默认：30
   QRADAR_VERIFY_SSL=true     # SSL 证书验证，默认：true
   ```
   
   **注意**：
   - `.env` 文件包含敏感信息，请确保不要将其提交到版本控制系统
   - `.env` 文件已在 `.gitignore` 中被忽略
   - 不要使用 `export` 命令设置环境变量，请使用 `.env` 文件

4. **验证安装**：
   
   确保 `.env` 文件已正确配置后，可以运行服务器进行测试：
   ```bash
   python main.py
   ```
   
   如果配置正确，服务器将启动并显示初始化成功的日志信息。

## Running the Server

### Development Mode

Run the MCP server in development mode:

```bash
mcp dev main.py
```

Or using Python directly:

```bash
python main.py
```

The server uses stdio transport for communication with MCP clients.

### Production Deployment

For production deployment, you may want to:

1. Use a process manager like `systemd` or `supervisord`
2. Configure proper logging
3. Set up monitoring and health checks
4. Ensure `.env` file is properly secured with appropriate file permissions (e.g., `chmod 600 .env`)

## Usage Examples

### Example 1: Search for Recent High-Severity Offenses

```python
# Using the search_offenses tool
{
  "tool": "search_offenses",
  "arguments": {
    "start_time": "2024-01-01T00:00:00Z",
    "end_time": "2024-01-31T23:59:59Z",
    "severity": 8,
    "status": "OPEN",
    "limit": 50
  }
}
```

### Example 2: Get Offense Details

```python
{
  "tool": "get_offense_details",
  "arguments": {
    "offense_id": 12345
  }
}
```

### Example 3: Analyze an Offense

```python
{
  "tool": "analyze_offense",
  "arguments": {
    "offense_id": 12345
  }
}
```

**Response includes**:
- Offense summary and statistics
- Extracted security indicators (IPs, domains, usernames)
- Reconstructed attack timeline
- Identified attack patterns
- Key findings and recommendations

### Example 4: Get Investigation Recommendations

```python
{
  "tool": "recommend_investigation_actions",
  "arguments": {
    "offense_id": 12345
  }
}
```

Or with specific indicators:

```python
{
  "tool": "recommend_investigation_actions",
  "arguments": {
    "indicators": [
      "192.168.1.100",
      "malicious-domain.com",
      "suspicious_user"
    ]
  }
}
```

### Example 5: Execute Custom AQL Query

```python
{
  "tool": "execute_aql_query",
  "arguments": {
    "query": "SELECT sourceip, destinationip, COUNT(*) as event_count FROM events WHERE category=5001 GROUP BY sourceip, destinationip ORDER BY event_count DESC LAST 24 HOURS",
    "timeout": 120
  }
}
```

## Tool Reference

### search_offenses

Search for QRadar offenses with various filters.

**Parameters**:
- `start_time` (optional): ISO 8601 datetime string
- `end_time` (optional): ISO 8601 datetime string
- `severity` (optional): Integer 1-10
- `status` (optional): "OPEN", "CLOSED", or "HIDDEN"
- `offense_type` (optional): Integer offense type ID
- `limit` (optional): Max results (default: 50, max: 1000)
- `offset` (optional): Pagination offset (default: 0)

**Returns**: List of offense objects

### get_offense_details

Get detailed information about a specific offense.

**Parameters**:
- `offense_id` (required): Integer offense ID

**Returns**: Offense object with full details

### get_offense_logs

Get all log entries for an offense.

**Parameters**:
- `offense_id` (required): Integer offense ID
- `limit` (optional): Max logs (default: 1000, max: 10000)
- `offset` (optional): Pagination offset (default: 0)

**Returns**: List of log entry objects

### execute_aql_query

Execute a custom AQL query.

**Parameters**:
- `query` (required): AQL query string
- `timeout` (optional): Timeout in seconds (default: 60, max: 300)

**Returns**: Query results as list of dictionaries

### analyze_offense

Perform comprehensive root cause analysis.

**Parameters**:
- `offense_id` (required): Integer offense ID

**Returns**: Comprehensive analysis report including:
- Offense details
- Summary and statistics
- Extracted indicators
- Attack timeline
- Identified patterns

### recommend_investigation_actions

Generate investigation recommendations.

**Parameters**:
- `offense_id` (optional): Integer offense ID
- `indicators` (optional): List of indicator strings (IPs, usernames, domains)

**Returns**: List of prioritized recommendations with:
- Priority level
- Action type
- Title and description
- Associated indicators
- Rationale

## Architecture

The codebase is organized into three main modules:

1. **`main.py`**: MCP server entry point, tool registration, and request handling
2. **`qradar_client.py`**: Async QRadar API client with comprehensive error handling
3. **`analysis_engine.py`**: Intelligent analysis logic for root cause analysis and recommendations

### Key Design Principles

- **Fully Async**: All I/O operations use `async/await` for optimal performance
- **Type Safety**: Comprehensive type hints using Pydantic models
- **Error Handling**: Robust error handling for network issues, API limits, and data validation
- **Modularity**: Clear separation of concerns between data access and analysis logic
- **Extensibility**: Easy to add new analysis patterns and recommendation types

## Error Handling

The server handles various error scenarios:

- **Authentication failures**: Clear error messages for invalid username/password
- **Network errors**: Timeout handling and connection error recovery
- **API rate limits**: Proper error reporting for rate limit exceeded
- **Invalid data**: Validation and sanitization of API responses
- **Missing data**: Graceful handling of empty results

## Security Considerations

1. **Credentials**: Never hardcode QRadar credentials. Always use the `.env` file for configuration.
2. **`.env` File Security**: 
   - The `.env` file contains sensitive credentials
   - Set appropriate file permissions: `chmod 600 .env` (Linux/Mac)
   - Never commit `.env` to version control (already in `.gitignore`)
   - Use `env.example` as a template for documentation
3. **SSL Verification**: By default, SSL certificates are verified. Only disable in development.
4. **Password Security**: Passwords should be stored securely and rotated regularly.
5. **Network Security**: Ensure the server runs in a secure network environment.

## Troubleshooting

### Connection Issues

If you encounter connection errors:

1. Verify `QRADAR_HOST` is correct and accessible
2. Check network connectivity and firewall rules
3. Verify SSL certificate if using HTTPS
4. Test with `curl` or `httpx` directly

### Authentication Errors

If authentication fails:

1. Verify `QRADAR_USERNAME` and `QRADAR_PASSWORD` are correct
2. Check if the account is locked or expired
3. Verify user permissions in QRadar
4. Test credentials with direct API call using curl or httpx

### Performance Issues

For large datasets:

1. Use pagination (limit/offset) appropriately
2. Set reasonable timeouts
3. Consider using AQL queries for complex filtering
4. Monitor QRadar API rate limits

## Contributing

This is a production-ready implementation. To extend functionality:

1. Add new analysis patterns in `analysis_engine.py`
2. Extend QRadar API methods in `qradar_client.py`
3. Register new tools in `main.py`

## License

This project is provided as-is for security analysis purposes.

## Support

For issues related to:
- **QRadar API**: Consult IBM QRadar API documentation
- **MCP Protocol**: Refer to Model Context Protocol specification
- **This Server**: Review code documentation and error messages

## Version History

- **v1.0.0**: Initial production release with full feature set

