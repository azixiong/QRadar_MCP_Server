"""
QRadar MCP Server

This is the main entry point for the QRadar Model Context Protocol (MCP) server.
It provides tools for querying QRadar data and performing intelligent security analysis.
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime
from dotenv import load_dotenv

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from qradar_client import QRadarClient, QRadarConfig
from analysis_engine import AnalysisEngine, InvestigationRecommendation

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize server
server = Server("qradar-mcp-server")

# Initialize QRadar client and analysis engine (lazy initialization)
qradar_client: Optional[QRadarClient] = None
analysis_engine: Optional[AnalysisEngine] = None


def get_qradar_client() -> QRadarClient:
    """Get or create QRadar client instance."""
    global qradar_client
    if qradar_client is None:
        qradar_client = QRadarClient()
    return qradar_client


def get_analysis_engine() -> AnalysisEngine:
    """Get or create analysis engine instance."""
    global analysis_engine
    if analysis_engine is None:
        analysis_engine = AnalysisEngine(get_qradar_client())
    return analysis_engine


@server.list_tools()
async def list_tools() -> List[Tool]:
    """
    List all available tools in the MCP server.
    
    Returns:
        List of Tool definitions
    """
    return [
        Tool(
            name="search_offenses",
            description=(
                "Search for QRadar security offenses (events) based on various criteria. "
                "Returns a list of offenses matching the specified filters such as time range, "
                "severity level, status, and offense type."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "start_time": {
                        "type": "string",
                        "format": "date-time",
                        "description": "ISO 8601 datetime string for filtering offenses that started after this time"
                    },
                    "end_time": {
                        "type": "string",
                        "format": "date-time",
                        "description": "ISO 8601 datetime string for filtering offenses that started before this time"
                    },
                    "severity": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 10,
                        "description": "Filter by severity level (1-10)"
                    },
                    "status": {
                        "type": "string",
                        "enum": ["OPEN", "CLOSED", "HIDDEN"],
                        "description": "Filter by offense status"
                    },
                    "offense_type": {
                        "type": "integer",
                        "description": "Filter by offense type ID"
                    },
                    "limit": {
                        "type": "integer",
                        "default": 50,
                        "minimum": 1,
                        "maximum": 1000,
                        "description": "Maximum number of results to return (default: 50)"
                    },
                    "offset": {
                        "type": "integer",
                        "default": 0,
                        "minimum": 0,
                        "description": "Offset for pagination (default: 0)"
                    }
                }
            }
        ),
        Tool(
            name="get_offense_details",
            description=(
                "Get detailed information about a specific QRadar offense by its ID. "
                "Returns comprehensive offense metadata including severity, status, "
                "source/destination addresses, timestamps, and more."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "offense_id": {
                        "type": "integer",
                        "description": "The ID of the offense to retrieve"
                    }
                },
                "required": ["offense_id"]
            }
        ),
        Tool(
            name="get_offense_logs",
            description=(
                "Get all log entries associated with a specific QRadar offense. "
                "Returns raw log data including source/destination IPs, ports, usernames, "
                "protocols, and payloads. Useful for detailed investigation."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "offense_id": {
                        "type": "integer",
                        "description": "The ID of the offense"
                    },
                    "limit": {
                        "type": "integer",
                        "default": 1000,
                        "minimum": 1,
                        "maximum": 10000,
                        "description": "Maximum number of logs to return (default: 1000)"
                    },
                    "offset": {
                        "type": "integer",
                        "default": 0,
                        "minimum": 0,
                        "description": "Offset for pagination (default: 0)"
                    }
                },
                "required": ["offense_id"]
            }
        ),
        Tool(
            name="execute_aql_query",
            description=(
                "Execute a custom AQL (Ariel Query Language) query against QRadar. "
                "Provides maximum flexibility for complex data retrieval. "
                "Returns query results as a list of dictionaries."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The AQL query string to execute"
                    },
                    "timeout": {
                        "type": "integer",
                        "default": 60,
                        "minimum": 10,
                        "maximum": 300,
                        "description": "Query timeout in seconds (default: 60)"
                    }
                },
                "required": ["query"]
            }
        ),
        Tool(
            name="analyze_offense",
            description=(
                "Perform comprehensive root cause analysis on a QRadar offense. "
                "This intelligent tool automatically: "
                "1. Retrieves offense details and all associated logs, "
                "2. Extracts security indicators (IPs, domains, usernames, hashes), "
                "3. Reconstructs the attack timeline, "
                "4. Identifies attack patterns and relationships, "
                "5. Generates a structured investigation report with actionable insights."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "offense_id": {
                        "type": "integer",
                        "description": "The ID of the offense to analyze"
                    }
                },
                "required": ["offense_id"]
            }
        ),
        Tool(
            name="recommend_investigation_actions",
            description=(
                "Generate actionable investigation recommendations based on an offense ID or "
                "a list of security indicators (IPs, usernames, domains). "
                "Returns prioritized recommendations such as EDR queries, network isolation, "
                "user investigations, and threat intelligence checks."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "offense_id": {
                        "type": "integer",
                        "description": "Optional offense ID to analyze for recommendations"
                    },
                    "indicators": {
                        "type": "array",
                        "items": {
                            "type": "string"
                        },
                        "description": "Optional list of security indicators (IPs, usernames, domains, etc.)"
                    }
                }
            }
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """
    Handle tool execution requests.
    
    Args:
        name: The name of the tool to execute
        arguments: The arguments for the tool
        
    Returns:
        List of TextContent objects containing the tool results
    """
    try:
        if name == "search_offenses":
            result = await handle_search_offenses(arguments)
        
        elif name == "get_offense_details":
            result = await handle_get_offense_details(arguments)
        
        elif name == "get_offense_logs":
            result = await handle_get_offense_logs(arguments)
        
        elif name == "execute_aql_query":
            result = await handle_execute_aql_query(arguments)
        
        elif name == "analyze_offense":
            result = await handle_analyze_offense(arguments)
        
        elif name == "recommend_investigation_actions":
            result = await handle_recommend_investigation_actions(arguments)
        
        else:
            raise ValueError(f"Unknown tool: {name}")
        
        # Format result as JSON string
        if isinstance(result, (dict, list)):
            result_text = json.dumps(result, indent=2, default=str)
        else:
            result_text = str(result)
        
        return [TextContent(type="text", text=result_text)]
    
    except Exception as e:
        logger.error(f"Error executing tool {name}: {str(e)}", exc_info=True)
        error_result = {
            "error": str(e),
            "tool": name,
            "arguments": arguments
        }
        return [TextContent(type="text", text=json.dumps(error_result, indent=2))]


async def handle_search_offenses(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Handle search_offenses tool execution."""
    client = get_qradar_client()
    
    # Parse datetime strings if provided
    start_time = None
    if "start_time" in arguments:
        start_time = datetime.fromisoformat(arguments["start_time"].replace("Z", "+00:00"))
    
    end_time = None
    if "end_time" in arguments:
        end_time = datetime.fromisoformat(arguments["end_time"].replace("Z", "+00:00"))
    
    offenses = await client.search_offenses(
        start_time=start_time,
        end_time=end_time,
        severity=arguments.get("severity"),
        status=arguments.get("status"),
        offense_type=arguments.get("offense_type"),
        limit=arguments.get("limit", 50),
        offset=arguments.get("offset", 0)
    )
    
    return {
        "count": len(offenses),
        "offenses": [offense.dict(exclude_none=True) for offense in offenses]
    }


async def handle_get_offense_details(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Handle get_offense_details tool execution."""
    client = get_qradar_client()
    offense_id = arguments["offense_id"]
    
    offense = await client.get_offense_details(offense_id)
    return offense.dict(exclude_none=True)


async def handle_get_offense_logs(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Handle get_offense_logs tool execution."""
    client = get_qradar_client()
    offense_id = arguments["offense_id"]
    
    logs = await client.get_offense_logs(
        offense_id,
        limit=arguments.get("limit", 1000),
        offset=arguments.get("offset", 0)
    )
    
    return {
        "count": len(logs),
        "logs": [log.dict(exclude_none=True) for log in logs]
    }


async def handle_execute_aql_query(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Handle execute_aql_query tool execution."""
    client = get_qradar_client()
    query = arguments["query"]
    timeout = arguments.get("timeout", 60)
    
    results = await client.execute_aql_query(query, timeout=timeout)
    
    return {
        "count": len(results),
        "results": results
    }


async def handle_analyze_offense(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Handle analyze_offense tool execution."""
    engine = get_analysis_engine()
    offense_id = arguments["offense_id"]
    
    analysis = await engine.analyze_offense(offense_id)
    return analysis


async def handle_recommend_investigation_actions(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Handle recommend_investigation_actions tool execution."""
    engine = get_analysis_engine()
    
    offense_id = arguments.get("offense_id")
    indicators = arguments.get("indicators")
    
    recommendations = await engine.recommend_investigation_actions(
        offense_id=offense_id,
        indicators=indicators
    )
    
    return {
        "count": len(recommendations),
        "recommendations": [
            {
                "priority": rec.priority,
                "action_type": rec.action_type,
                "title": rec.title,
                "description": rec.description,
                "indicators": rec.indicators,
                "rationale": rec.rationale
            }
            for rec in recommendations
        ]
    }


async def main():
    """Main entry point for the MCP server."""
    logger.info("Starting QRadar MCP Server...")
    
    # Validate configuration
    try:
        client = get_qradar_client()
        logger.info("QRadar client initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize QRadar client: {str(e)}")
        logger.error("Please ensure QRADAR_HOST, QRADAR_USERNAME, and QRADAR_PASSWORD environment variables are set")
        raise
    
    # Run the server using stdio transport
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())

