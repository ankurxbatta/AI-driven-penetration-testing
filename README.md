# AI-driven penetration testing

An **MCP server** that gives an AI assistant safe, structured access to real
Kali Linux security tools. Ask the assistant in plain language to scan a target,
and it runs the right tool, parses the output, and reasons about what it found —
while the server keeps it inside strict guardrails.

Demo: `Example/MCP.mp4`.

## The idea

Penetration testing means driving a lot of separate command-line tools and
reading their raw output. This project wraps those tools as **Model Context
Protocol (MCP)** tools, so a language model can call them directly. The model
decides *what* to run; the server controls *how* it runs and what it is allowed
to touch.

## Tools exposed

Each is a callable MCP tool backed by the real Kali binary:

| Tool | What it does |
| --- | --- |
| `nmap_scan` | Port and service discovery |
| `nikto_scan` | Web server vulnerability scan |
| `sqlmap_scan` | SQL injection testing |
| `wpscan_scan` | WordPress vulnerability scan |
| `dirb_scan` | Directory and content brute-forcing |
| `searchsploit_search` | Look up known exploits |
| `system_info` | Report the environment the server runs in |

## Safety

Because a model is choosing the arguments, every input is validated before it
reaches a shell:

- **Target sanitisation** — only alphanumerics, dots, hyphens, underscores and
  slashes are allowed, so a target string cannot smuggle in extra commands.
- **Port sanitisation** — port arguments are checked before use.
- Commands are run through a controlled wrapper rather than a raw shell string.

This is built for **authorised testing only** — your own machines, deliberately
vulnerable practice targets, or systems you have written permission to assess.

## Repository layout

```
server.py                    the MCP server and all tool definitions
requirements.txt             fastmcp, uvicorn
Dockerfile                   Kali-based image with the tools installed
docker-compose.yml
entrypoint.sh
claude_desktop_config.json   example: wiring the server into an MCP client
Example/MCP.mp4              demo recording
```

## Running it

The tools it drives (nmap, nikto, sqlmap, …) live in the Docker image, so the
container is the intended way to run it:

```bash
docker compose up --build
```

Then point an MCP client at the server — `claude_desktop_config.json` shows the
shape of that configuration.

## Built with

Python, FastMCP, Docker, and the Kali Linux security toolset.
