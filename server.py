#!/usr/bin/env python3
"""Kali Linux Penetration Testing MCP Server"""

import subprocess
import shlex
import re
import logging
import sys
import json
from fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)

logger = logging.getLogger(__name__)

# Initialize FastMCP
mcp = FastMCP("Kali Pentest MCP")

def sanitize_target(target):
    """Sanitize target input to prevent command injection"""
    # Allow only alphanumeric, dots, hyphens, underscores, and forward slashes
    if not re.match(r'^[a-zA-Z0-9\.\-_/]+$', target):
        raise ValueError("Invalid target format")
    return target

def sanitize_port(port):
    """Sanitize port input"""
    if port:
        try:
            port_num = int(port)
            if not (1 <= port_num <= 65535):
                raise ValueError("Port must be between 1 and 65535")
            return str(port_num)
        except ValueError:
            raise ValueError("Invalid port format")
    return ""

def run_command(command, timeout=300):
    """Execute command safely with timeout and return structured output"""
    try:
        logger.info(f"Executing command: {' '.join(command)}")
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        
        # Return structured output
        output = {
            "command": " ".join(command),
            "return_code": result.returncode,
            "stdout": result.stdout.strip() if result.stdout else "",
            "stderr": result.stderr.strip() if result.stderr else "",
            "success": result.returncode == 0
        }
        
        # Create a formatted output string for display
        display_output = []
        if output["stdout"]:
            display_output.append(f"STDOUT:\n{output['stdout']}")
        if output["stderr"]:
            display_output.append(f"STDERR:\n{output['stderr']}")
        if output["return_code"] != 0:
            display_output.append(f"Return code: {output['return_code']}")
            
        return "\n\n".join(display_output) if display_output else "Command completed with no output"
        
    except subprocess.TimeoutExpired:
        return f"Command timed out after {timeout} seconds"
    except Exception as e:
        return f"Error executing command: {str(e)}"

@mcp.tool()
def nmap_scan(target: str = "", scan_type: str = "basic", ports: str = ""):
    """Perform network scanning with nmap"""
    try:
        if not target:
            return "Error: Target is required"
            
        target = sanitize_target(target)
        
        # Build nmap command based on scan type
        cmd = ["nmap"]
        
        if scan_type == "basic":
            cmd.extend(["-sT", "-O", "-sV"])
        elif scan_type == "stealth":
            cmd.extend(["-sS", "-O", "-sV"])
        elif scan_type == "udp":
            cmd.extend(["-sU"])
        elif scan_type == "comprehensive":
            cmd.extend(["-sS", "-sU", "-O", "-sV", "-sC"])
        else:
            cmd.extend(["-sT"])
            
        if ports:
            # Handle port ranges and individual ports
            port_pattern = r'^[0-9,-]+$'
            if not re.match(port_pattern, ports):
                return "Error: Invalid port format. Use numbers, commas, and dashes only."
            cmd.extend(["-p", ports])
            
        cmd.append(target)
        
        return run_command(cmd)
        
    except ValueError as e:
        return f"Error: {str(e)}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"

@mcp.tool()
def nikto_scan(target: str = "", port: str = "80", ssl: str = "false"):
    """Perform web vulnerability scanning with nikto"""
    try:
        if not target:
            return "Error: Target is required"
            
        target = sanitize_target(target)
        
        cmd = ["nikto", "-h", target]
        
        if port:
            port = sanitize_port(port)
            cmd.extend(["-p", port])
            
        if ssl.lower() == "true":
            cmd.append("-ssl")
            
        return run_command(cmd, timeout=600)
        
    except ValueError as e:
        return f"Error: {str(e)}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"

@mcp.tool()
def sqlmap_scan(target: str = "", parameter: str = "", database: str = ""):
    """Perform SQL injection testing with sqlmap"""
    try:
        if not target:
            return "Error: Target URL is required"
            
        # Basic URL validation
        if not (target.startswith("http://") or target.startswith("https://")):
            return "Error: Target must be a valid HTTP/HTTPS URL"
            
        cmd = ["sqlmap", "-u", target, "--batch", "--level=1", "--risk=1"]
        
        if parameter:
            # Sanitize parameter name
            if not re.match(r'^[a-zA-Z0-9_]+$', parameter):
                return "Error: Invalid parameter name"
            cmd.extend(["-p", parameter])
            
        if database:
            if not re.match(r'^[a-zA-Z0-9_]+$', database):
                return "Error: Invalid database name"
            cmd.extend(["-D", database, "--tables"])
            
        return run_command(cmd, timeout=900)
        
    except Exception as e:
        return f"Unexpected error: {str(e)}"

@mcp.tool()
def wpscan_scan(target: str = "", enumerate: str = "vp"):
    """Perform WordPress scanning with wpscan"""
    try:
        if not target:
            return "Error: Target URL is required"
            
        if not (target.startswith("http://") or target.startswith("https://")):
            return "Error: Target must be a valid HTTP/HTTPS URL"
            
        cmd = ["wpscan", "--url", target, "--no-update"]
        
        # Enumerate options: u=users, p=plugins, t=themes, vp=vulnerable plugins
        valid_enums = ["u", "p", "t", "vp", "vt", "tt", "cb", "dbe"]
        if enumerate and enumerate in valid_enums:
            cmd.extend(["--enumerate", enumerate])
            
        return run_command(cmd, timeout=600)
        
    except Exception as e:
        return f"Unexpected error: {str(e)}"

@mcp.tool()
def dirb_scan(target: str = "", wordlist: str = "", extensions: str = ""):
    """Perform directory bruteforcing with dirb"""
    try:
        if not target:
            return "Error: Target URL is required"
            
        if not (target.startswith("http://") or target.startswith("https://")):
            return "Error: Target must be a valid HTTP/HTTPS URL"
            
        cmd = ["dirb", target]
        
        # Use default wordlist if none specified
        if wordlist:
            # Sanitize wordlist path
            if not re.match(r'^[a-zA-Z0-9\.\-_/]+$', wordlist):
                return "Error: Invalid wordlist path"
            cmd.append(wordlist)
        else:
            cmd.append("/usr/share/dirb/wordlists/common.txt")
            
        if extensions:
            # Sanitize extensions
            if not re.match(r'^[a-zA-Z0-9,\.]+$', extensions):
                return "Error: Invalid extensions format"
            cmd.extend(["-X", extensions])
            
        return run_command(cmd, timeout=900)
        
    except Exception as e:
        return f"Unexpected error: {str(e)}"

@mcp.tool()
def searchsploit_search(query: str = "", exact: str = "false"):
    """Search for exploits using searchsploit"""
    try:
        if not query:
            return "Error: Search query is required"
            
        # Sanitize search query - allow more characters for search
        if not re.match(r'^[a-zA-Z0-9\s\.\-_\(\)\[\]]+$', query):
            return "Error: Invalid search query format"
            
        cmd = ["searchsploit"]
        
        if exact.lower() == "true":
            cmd.append("--exact")
            
        cmd.append(query)
        
        return run_command(cmd)
        
    except Exception as e:
        return f"Unexpected error: {str(e)}"

@mcp.tool()
def system_info():
    """Get system information and available tools"""
    try:
        info = []
        
        # Check OS
        result = subprocess.run(["uname", "-a"], capture_output=True, text=True)
        info.append(f"System: {result.stdout.strip()}")
        
        # Check available tools
        tools = ["nmap", "nikto", "sqlmap", "wpscan", "dirb", "searchsploit"]
        available_tools = []
        
        for tool in tools:
            result = subprocess.run(["which", tool], capture_output=True)
            if result.returncode == 0:
                available_tools.append(tool)
                
        info.append(f"Available tools: {', '.join(available_tools)}")
        
        return "\n".join(info)
        
    except Exception as e:
        return f"Error getting system info: {str(e)}"

if __name__ == "__main__":
    mcp.run()
