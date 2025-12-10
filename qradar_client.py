"""
QRadar API Client Module

This module provides an asynchronous client for interacting with the QRadar REST API.
It handles authentication, request/response processing, and error handling.
"""

import os
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import httpx
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

logger = logging.getLogger(__name__)


class QRadarConfig(BaseModel):
    """Configuration model for QRadar connection."""
    host: str = Field(..., description="QRadar host address (e.g., https://qradar.example.com)")
    username: str = Field(..., description="QRadar username for authentication")
    password: str = Field(..., description="QRadar password for authentication")
    timeout: int = Field(default=30, description="Request timeout in seconds")
    verify_ssl: bool = Field(default=True, description="Whether to verify SSL certificates")


class Offense(BaseModel):
    """Model representing a QRadar Offense."""
    id: int
    description: Optional[str] = None
    severity: Optional[int] = None
    status: Optional[str] = None
    start_time: Optional[int] = None
    last_updated_time: Optional[int] = None
    source_address_ids: Optional[List[int]] = None
    destination_address_ids: Optional[List[int]] = None
    domain_id: Optional[int] = None
    offense_type: Optional[int] = None
    offense_source: Optional[str] = None
    magnitude: Optional[int] = None
    credibility: Optional[int] = None
    relevance: Optional[int] = None
    assigned_to: Optional[str] = None
    follow_up: Optional[bool] = None
    protected: Optional[bool] = None


class LogEntry(BaseModel):
    """Model representing a QRadar log entry."""
    id: Optional[int] = None
    qid: Optional[int] = None
    start_time: Optional[int] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    username: Optional[str] = None
    category: Optional[int] = None
    protocol: Optional[str] = None
    payload: Optional[str] = None
    raw_log: Optional[str] = None
    log_source_id: Optional[int] = None
    event_count: Optional[int] = None


class QRadarClient:
    """
    Asynchronous client for QRadar REST API.
    
    This client handles all interactions with QRadar, including authentication,
    request formatting, error handling, and response parsing.
    """
    
    def __init__(self, config: Optional[QRadarConfig] = None):
        """
        Initialize QRadar client.
        
        Args:
            config: Optional QRadarConfig. If not provided, loads from environment variables.
        """
        if config is None:
            host = os.getenv("QRADAR_HOST")
            username = os.getenv("QRADAR_USERNAME")
            password = os.getenv("QRADAR_PASSWORD")
            
            if not host or not username or not password:
                raise ValueError(
                    "QRadar configuration missing. Please set QRADAR_HOST, QRADAR_USERNAME, "
                    "and QRADAR_PASSWORD environment variables."
                )
            
            config = QRadarConfig(
                host=host.rstrip('/'),
                username=username,
                password=password,
                timeout=int(os.getenv("QRADAR_TIMEOUT", "30")),
                verify_ssl=os.getenv("QRADAR_VERIFY_SSL", "true").lower() == "true"
            )
        
        self.config = config
        self.base_url = f"{config.host}/api"
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        # Store credentials for Basic Auth
        self.auth = (config.username, config.password)
        self.timeout = httpx.Timeout(config.timeout, connect=10.0)
    
    async def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute an HTTP request to QRadar API.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path (without base URL)
            params: Optional query parameters
            json_data: Optional JSON body data
            
        Returns:
            Parsed JSON response as dictionary
            
        Raises:
            httpx.HTTPError: For network or HTTP errors
            ValueError: For invalid responses
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                verify=self.config.verify_ssl
            ) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=self.headers,
                    params=params,
                    json=json_data,
                    auth=self.auth  # Use Basic Authentication
                )
                response.raise_for_status()
                
                # QRadar may return empty responses for some endpoints
                if response.status_code == 204 or not response.content:
                    return {}
                
                return response.json()
        
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise ValueError("QRadar authentication failed. Please check your username and password.")
            elif e.response.status_code == 403:
                raise ValueError("QRadar access forbidden. Please check your permissions.")
            elif e.response.status_code == 404:
                raise ValueError(f"QRadar resource not found: {endpoint}")
            elif e.response.status_code == 429:
                raise ValueError("QRadar API rate limit exceeded. Please retry later.")
            else:
                logger.error(f"QRadar API error: {e.response.status_code} - {e.response.text}")
                raise ValueError(f"QRadar API error: {e.response.status_code}")
        
        except httpx.TimeoutException:
            raise ValueError(f"QRadar API request timed out after {self.config.timeout} seconds")
        
        except httpx.RequestError as e:
            logger.error(f"QRadar connection error: {str(e)}")
            raise ValueError(f"Failed to connect to QRadar: {str(e)}")
    
    async def search_offenses(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        severity: Optional[int] = None,
        status: Optional[str] = None,
        offense_type: Optional[int] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Offense]:
        """
        Search for QRadar offenses based on various criteria.
        
        Args:
            start_time: Filter offenses that started after this time
            end_time: Filter offenses that started before this time
            severity: Filter by severity level (1-10)
            status: Filter by status (e.g., "OPEN", "CLOSED", "HIDDEN")
            offense_type: Filter by offense type ID
            limit: Maximum number of results to return (default: 50)
            offset: Offset for pagination (default: 0)
            
        Returns:
            List of Offense objects matching the criteria
        """
        params: Dict[str, Any] = {
            "limit": limit,
            "offset": offset
        }
        
        if start_time:
            params["start_time"] = int(start_time.timestamp() * 1000)
        if end_time:
            params["end_time"] = int(end_time.timestamp() * 1000)
        if severity is not None:
            params["severity"] = severity
        if status:
            params["status"] = status
        if offense_type is not None:
            params["offense_type"] = offense_type
        
        try:
            response = await self._request("GET", "/siem/offenses", params=params)
            offenses_data = response if isinstance(response, list) else response.get("data", [])
            
            return [Offense(**offense) for offense in offenses_data]
        
        except Exception as e:
            logger.error(f"Error searching offenses: {str(e)}")
            raise
    
    async def get_offense_details(self, offense_id: int) -> Offense:
        """
        Get detailed information about a specific offense.
        
        Args:
            offense_id: The ID of the offense to retrieve
            
        Returns:
            Offense object with full details
        """
        try:
            response = await self._request("GET", f"/siem/offenses/{offense_id}")
            return Offense(**response)
        
        except Exception as e:
            logger.error(f"Error getting offense details for ID {offense_id}: {str(e)}")
            raise
    
    async def get_offense_logs(
        self,
        offense_id: int,
        limit: int = 1000,
        offset: int = 0
    ) -> List[LogEntry]:
        """
        Get all log entries associated with a specific offense.
        
        Args:
            offense_id: The ID of the offense
            limit: Maximum number of logs to return (default: 1000)
            offset: Offset for pagination (default: 0)
            
        Returns:
            List of LogEntry objects
        """
        params = {
            "limit": limit,
            "offset": offset
        }
        
        try:
            response = await self._request(
                "GET",
                f"/siem/offenses/{offense_id}/events",
                params=params
            )
            
            # QRadar returns events in a nested structure
            events_data = response if isinstance(response, list) else response.get("events", [])
            
            logs = []
            for event in events_data:
                # Extract log data from event structure
                log_data = {
                    "id": event.get("id"),
                    "qid": event.get("qid"),
                    "start_time": event.get("start_time"),
                    "source_ip": event.get("sourceip"),
                    "destination_ip": event.get("destinationip"),
                    "source_port": event.get("sourceport"),
                    "destination_port": event.get("destinationport"),
                    "username": event.get("username"),
                    "category": event.get("category"),
                    "protocol": event.get("protocolid"),
                    "payload": event.get("payload"),
                    "raw_log": event.get("payload"),
                    "log_source_id": event.get("logsourceid"),
                    "event_count": event.get("event_count")
                }
                logs.append(LogEntry(**log_data))
            
            return logs
        
        except Exception as e:
            logger.error(f"Error getting offense logs for ID {offense_id}: {str(e)}")
            raise
    
    async def execute_aql_query(
        self,
        query: str,
        timeout: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute an AQL (Ariel Query Language) query.
        
        Args:
            query: The AQL query string
            timeout: Optional timeout in seconds (defaults to client timeout)
            
        Returns:
            List of dictionaries representing query results
        """
        # First, create the search
        search_data = {
            "query_expression": query
        }
        
        try:
            # Create the search
            search_response = await self._request(
                "POST",
                "/ariel/searches",
                json_data=search_data
            )
            search_id = search_response.get("search_id")
            
            if not search_id:
                raise ValueError("Failed to create AQL search. No search_id returned.")
            
            # Wait for search to complete
            status = "WAIT"
            max_wait_time = timeout or self.config.timeout
            start_time = datetime.now()
            
            while status in ["WAIT", "EXECUTE"]:
                if (datetime.now() - start_time).total_seconds() > max_wait_time:
                    raise ValueError(f"AQL query timed out after {max_wait_time} seconds")
                
                status_response = await self._request(
                    "GET",
                    f"/ariel/searches/{search_id}"
                )
                status = status_response.get("status", "UNKNOWN")
                
                if status == "COMPLETED":
                    break
                elif status == "ERROR":
                    error_msg = status_response.get("error_message", "Unknown error")
                    raise ValueError(f"AQL query failed: {error_msg}")
                
                # Wait a bit before checking again
                import asyncio
                await asyncio.sleep(1)
            
            # Get the results
            results_response = await self._request(
                "GET",
                f"/ariel/searches/{search_id}/results"
            )
            
            # AQL results are typically in a list format
            if isinstance(results_response, list):
                return results_response
            elif isinstance(results_response, dict) and "events" in results_response:
                return results_response["events"]
            else:
                return [results_response]
        
        except Exception as e:
            logger.error(f"Error executing AQL query: {str(e)}")
            raise
    
    async def get_address_info(self, address_id: int) -> Dict[str, Any]:
        """
        Get information about a network address (IP) by ID.
        
        Args:
            address_id: The address ID
            
        Returns:
            Dictionary with address information
        """
        try:
            response = await self._request("GET", f"/siem/local_destination_addresses/{address_id}")
            return response
        except Exception as e:
            logger.warning(f"Could not get address info for ID {address_id}: {str(e)}")
            return {}
    
    async def get_source_address_info(self, address_id: int) -> Dict[str, Any]:
        """
        Get information about a source network address (IP) by ID.
        
        Args:
            address_id: The source address ID
            
        Returns:
            Dictionary with address information
        """
        try:
            response = await self._request("GET", f"/siem/source_addresses/{address_id}")
            return response
        except Exception as e:
            logger.warning(f"Could not get source address info for ID {address_id}: {str(e)}")
            return {}

