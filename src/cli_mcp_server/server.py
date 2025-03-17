import os
import re
import shlex
import subprocess
import getpass
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple

import mcp.server.stdio
import mcp.types as types
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions

server = Server("cli-mcp-server")


class CommandError(Exception):
    """Base exception for command-related errors"""

    pass


class CommandSecurityError(CommandError):
    """Security violation errors"""

    pass


class CommandExecutionError(CommandError):
    """Command execution errors"""

    pass


class CommandTimeoutError(CommandError):
    """Command timeout errors"""

    pass


@dataclass
class SecurityConfig:
    """
    Security configuration for command execution
    """

    allowed_commands: set[str]
    allowed_flags: set[str]
    max_command_length: int
    command_timeout: int
    allow_all_commands: bool = False
    allow_all_flags: bool = False
    allowed_sudo_commands: set[str] = None
    allow_all_sudo_commands: bool = False


class CommandExecutor:
    def __init__(self, allowed_dir: str, security_config: SecurityConfig):
        if not allowed_dir or not os.path.exists(allowed_dir):
            raise ValueError("Valid ALLOWED_DIR is required")
        self.allowed_dir = os.path.abspath(os.path.realpath(allowed_dir))
        self.security_config = security_config

    def _normalize_path(self, path: str) -> str:
        """
        Normalizes a path and ensures it's within allowed directory.
        """
        try:
            if os.path.isabs(path):
                # If absolute path, check directly
                real_path = os.path.abspath(os.path.realpath(path))
            else:
                # If relative path, combine with allowed_dir first
                real_path = os.path.abspath(os.path.realpath(os.path.join(self.allowed_dir, path)))

            if not self._is_path_safe(real_path):
                raise CommandSecurityError(f"Path '{path}' is outside of allowed directory: {self.allowed_dir}")

            return real_path
        except CommandSecurityError:
            raise
        except Exception as e:
            raise CommandSecurityError(f"Invalid path '{path}': {str(e)}")

    def validate_command(self, command_string: str) -> tuple[str, List[str]]:
        """
        Validates and parses a command string for security and formatting.

        Splits the command string into command and arguments.

        Args:
            command_string (str): The command string to validate and parse.

        Returns:
            tuple[str, List[str]]: A tuple containing:
                - The command name (str)
                - List of command arguments (List[str])
        """

        try:
            parts = shlex.split(command_string)
            if not parts:
                raise CommandSecurityError("Empty command")

            command, args = parts[0], parts[1:]

            # Validate command if not in allow-all mode
            if not self.security_config.allow_all_commands and command not in self.security_config.allowed_commands:
                raise CommandSecurityError(f"Command '{command}' is not allowed")

            # Process and validate arguments
            validated_args = []
            for arg in args:
                if arg.startswith("-"):
                    if not self.security_config.allow_all_flags and arg not in self.security_config.allowed_flags:
                        raise CommandSecurityError(f"Flag '{arg}' is not allowed")
                    validated_args.append(arg)
                    continue

                # For any path-like argument, validate it
                if "/" in arg or "\\" in arg or os.path.isabs(arg) or arg == ".":
                    normalized_path = self._normalize_path(arg)
                    validated_args.append(normalized_path)
                else:
                    # For non-path arguments, add them as-is
                    validated_args.append(arg)

            return command, validated_args

        except ValueError as e:
            raise CommandSecurityError(f"Invalid command format: {str(e)}")

    def _is_path_safe(self, path: str) -> bool:
        """
        Checks if a given path is safe to access within allowed directory boundaries.

        Validates that the absolute resolved path is within the allowed directory
        to prevent directory traversal attacks.

        Args:
            path (str): The path to validate.

        Returns:
            bool: True if path is within allowed directory, False otherwise.
                Returns False if path resolution fails for any reason.

        Private method intended for internal use only.
        """
        try:
            # Resolve any symlinks and get absolute path
            real_path = os.path.abspath(os.path.realpath(path))
            allowed_dir_real = os.path.abspath(os.path.realpath(self.allowed_dir))

            # Check if the path starts with allowed_dir
            return real_path.startswith(allowed_dir_real)
        except Exception:
            return False

    def execute(self, command_string: str) -> subprocess.CompletedProcess:
        """
        Executes a command string in a controlled environment.

        Runs the command after validating it against security constraints including length limits.
        Supports shell operators (&&, |, >, >>) for complex command execution.

        Args:
            command_string (str): The command string to execute.

        Returns:
            subprocess.CompletedProcess: The result of the command execution containing
                stdout, stderr, and return code.

        Raises:
            CommandSecurityError: If the command:
                - Exceeds maximum length
                - Fails security validation
                - Fails during execution

        Notes:
            - Executes with shell=True to support operators
            - Uses timeout and working directory constraints
            - Captures both stdout and stderr
        """
        if len(command_string) > self.security_config.max_command_length:
            raise CommandSecurityError(f"Command exceeds maximum length of {self.security_config.max_command_length}")

        try:
            # For shell operators support, we use shell=True
            return subprocess.run(
                command_string,
                shell=True,
                text=True,
                capture_output=True,
                timeout=self.security_config.command_timeout,
                cwd=self.allowed_dir,
            )
        except subprocess.TimeoutExpired:
            raise CommandTimeoutError(f"Command timed out after {self.security_config.command_timeout} seconds")
        except CommandError:
            raise
        except Exception as e:
            raise CommandExecutionError(f"Command execution failed: {str(e)}")
            
    def execute_sudo(self, command_string: str, password: str = None) -> subprocess.CompletedProcess:
        """
        Executes a command with sudo privileges in a secure, controlled environment.
        
        Args:
            command_string (str): The command string to execute with sudo.
            password (str, optional): The sudo password. If None, will attempt to run without password.
            
        Returns:
            subprocess.CompletedProcess: The result of the command execution.
            
        Raises:
            CommandSecurityError: If the command violates security constraints.
            CommandTimeoutError: If the command execution times out.
            CommandExecutionError: If the command execution fails.
        """
        if len(command_string) > self.security_config.max_command_length:
            raise CommandSecurityError(f"Command exceeds maximum length of {self.security_config.max_command_length}")
            
        try:
            # Parse the command to validate it
            parts = shlex.split(command_string)
            if not parts:
                raise CommandSecurityError("Empty command")
                
            command, args = parts[0], parts[1:]
            
            # Check if command is allowed for sudo execution
            if not self.security_config.allow_all_sudo_commands and command not in self.security_config.allowed_sudo_commands:
                raise CommandSecurityError(f"Command '{command}' is not allowed for sudo execution")
                
            # Validate arguments and paths
            validated_args = []
            for arg in args:
                if arg.startswith("-"):
                    if not self.security_config.allow_all_flags and arg not in self.security_config.allowed_flags:
                        raise CommandSecurityError(f"Flag '{arg}' is not allowed")
                    validated_args.append(arg)
                    continue

                # For any path-like argument, validate it
                if "/" in arg or "\\" in arg or os.path.isabs(arg) or arg == ".":
                    normalized_path = self._normalize_path(arg)
                    validated_args.append(normalized_path)
                else:
                    # For non-path arguments, add them as-is
                    validated_args.append(arg)
            
            # Prepare sudo command
            sudo_cmd = ["sudo"]
            
            # Add password if provided
            if password:
                sudo_cmd = ["echo", password, "|", "sudo", "-S"]
                return subprocess.run(
                    f"echo {shlex.quote(password)} | sudo -S {command} {' '.join(shlex.quote(arg) for arg in validated_args)}",
                    shell=True,  # Need shell=True for piping the password
                    text=True,
                    capture_output=True,
                    timeout=self.security_config.command_timeout,
                    cwd=self.allowed_dir,
                )
            else:
                # Run without password
                return subprocess.run(
                    ["sudo", command] + validated_args,
                    shell=False,
                    text=True,
                    capture_output=True,
                    timeout=self.security_config.command_timeout,
                    cwd=self.allowed_dir,
                )
                
        except subprocess.TimeoutExpired:
            raise CommandTimeoutError(f"Command timed out after {self.security_config.command_timeout} seconds")
        except CommandError:
            raise
        except Exception as e:
            raise CommandExecutionError(f"Sudo command execution failed: {str(e)}")


# Load security configuration from environment
def load_security_config() -> SecurityConfig:
    """
    Loads security configuration from environment variables with default fallbacks.

    Creates a SecurityConfig instance using environment variables to configure allowed
    commands, flags, patterns, and execution constraints. Uses predefined defaults if
    environment variables are not set.

    Returns:
        SecurityConfig: Configuration object containing:
            - allowed_commands: Set of permitted command names
            - allowed_flags: Set of permitted command flags/options
            - max_command_length: Maximum length of command string
            - command_timeout: Maximum execution time in seconds
            - allow_all_commands: Whether all commands are allowed
            - allow_all_flags: Whether all flags are allowed
            - allowed_sudo_commands: Set of permitted sudo commands
            - allow_all_sudo_commands: Whether all sudo commands are allowed

    Environment Variables:
        ALLOWED_COMMANDS: Comma-separated list of allowed commands or 'all' (default: "ls,cat,pwd")
        ALLOWED_FLAGS: Comma-separated list of allowed flags or 'all' (default: "-l,-a,--help")
        ALLOWED_SUDO_COMMANDS: Comma-separated list of allowed sudo commands or 'all' (default: "")
        MAX_COMMAND_LENGTH: Maximum command string length (default: 1024)
        COMMAND_TIMEOUT: Command timeout in seconds (default: 30)
    """
    allowed_commands = os.getenv("ALLOWED_COMMANDS", "ls,cat,pwd")
    allowed_flags = os.getenv("ALLOWED_FLAGS", "-l,-a,--help")
    allowed_sudo_commands = os.getenv("ALLOWED_SUDO_COMMANDS", "")
    
    allow_all_commands = allowed_commands.lower() == 'all'
    allow_all_flags = allowed_flags.lower() == 'all'
    allow_all_sudo_commands = allowed_sudo_commands.lower() == 'all'
    
    return SecurityConfig(
        allowed_commands=set() if allow_all_commands else set(allowed_commands.split(",")),
        allowed_flags=set() if allow_all_flags else set(allowed_flags.split(",")),
        max_command_length=int(os.getenv("MAX_COMMAND_LENGTH", "1024")),
        command_timeout=int(os.getenv("COMMAND_TIMEOUT", "30")),
        allow_all_commands=allow_all_commands,
        allow_all_flags=allow_all_flags,
        allowed_sudo_commands=set() if allow_all_sudo_commands else set(allowed_sudo_commands.split(",")) if allowed_sudo_commands else set(),
        allow_all_sudo_commands=allow_all_sudo_commands,
    )


executor = CommandExecutor(allowed_dir=os.getenv("ALLOWED_DIR", ""), security_config=load_security_config())


@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    commands_desc = "all commands" if executor.security_config.allow_all_commands else ", ".join(executor.security_config.allowed_commands)
    flags_desc = "all flags" if executor.security_config.allow_all_flags else ", ".join(executor.security_config.allowed_flags)
    sudo_commands_desc = "all commands" if executor.security_config.allow_all_sudo_commands else ", ".join(executor.security_config.allowed_sudo_commands) if executor.security_config.allowed_sudo_commands else "none"
    
    tools = [
        types.Tool(
            name="run_command",
            description=(
                f"Allows command (CLI) execution in the directory: {executor.allowed_dir}\n\n"
                f"Available commands: {commands_desc}\n"
                f"Available flags: {flags_desc}\n\n"
                "Shell operators (&&, |, >, >>) are now supported for complex commands."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Single command to execute (example: 'ls -l' or 'cat file.txt')",
                    }
                },
                "required": ["command"],
            },
        ),
        types.Tool(
            name="show_security_rules",
            description=("Show what commands and operations are allowed in this environment.\n"),
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
    ]
    
    # Only add sudo tool if there are allowed sudo commands
    if executor.security_config.allow_all_sudo_commands or (executor.security_config.allowed_sudo_commands and len(executor.security_config.allowed_sudo_commands) > 0):
        tools.append(
            types.Tool(
                name="run_sudo_command",
                description=(
                    f"Allows execution of commands with sudo privileges in the directory: {executor.allowed_dir}\n\n"
                    f"Available sudo commands: {sudo_commands_desc}\n"
                    f"Available flags: {flags_desc}\n\n"
                    "Note: Shell operators (&&, |, >, >>) are not supported."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "Single command to execute with sudo (example: 'apt update' or 'systemctl restart service')",
                        },
                        "password": {
                            "type": "string",
                            "description": "Sudo password (optional, will attempt passwordless sudo if not provided)",
                        }
                    },
                    "required": ["command"],
                },
            )
        )
    
    return tools


@server.call_tool()
async def handle_call_tool(name: str, arguments: Optional[Dict[str, Any]]) -> List[types.TextContent]:
    if name == "run_command":
        if not arguments or "command" not in arguments:
            return [types.TextContent(type="text", text="No command provided", error=True)]

        try:
            result = executor.execute(arguments["command"])

            response = []
            if result.stdout:
                response.append(types.TextContent(type="text", text=result.stdout))
            if result.stderr:
                response.append(types.TextContent(type="text", text=result.stderr, error=True))

            response.append(
                types.TextContent(
                    type="text",
                    text=f"\nCommand completed with return code: {result.returncode}",
                )
            )

            return response

        except CommandSecurityError as e:
            return [types.TextContent(type="text", text=f"Security violation: {str(e)}", error=True)]
        except subprocess.TimeoutExpired:
            return [
                types.TextContent(
                    type="text",
                    text=f"Command timed out after {executor.security_config.command_timeout} seconds",
                    error=True,
                )
            ]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error: {str(e)}", error=True)]
            
    elif name == "run_sudo_command":
        if not arguments or "command" not in arguments:
            return [types.TextContent(type="text", text="No command provided", error=True)]
            
        # Check if sudo commands are allowed
        if not executor.security_config.allow_all_sudo_commands and (
            not executor.security_config.allowed_sudo_commands or 
            len(executor.security_config.allowed_sudo_commands) == 0
        ):
            return [types.TextContent(
                type="text", 
                text="Sudo commands are not allowed in this environment", 
                error=True
            )]
            
        password = arguments.get("password", None)
        
        try:
            result = executor.execute_sudo(arguments["command"], password)
            
            response = []
            if result.stdout:
                response.append(types.TextContent(type="text", text=result.stdout))
            if result.stderr:
                response.append(types.TextContent(type="text", text=result.stderr, error=True))
                
            response.append(
                types.TextContent(
                    type="text",
                    text=f"\nSudo command completed with return code: {result.returncode}",
                )
            )
            
            return response
            
        except CommandSecurityError as e:
            return [types.TextContent(type="text", text=f"Security violation: {str(e)}", error=True)]
        except CommandTimeoutError:
            return [
                types.TextContent(
                    type="text",
                    text=f"Command timed out after {executor.security_config.command_timeout} seconds",
                    error=True,
                )
            ]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error: {str(e)}", error=True)]

    elif name == "show_security_rules":
        commands_desc = "All commands allowed" if executor.security_config.allow_all_commands else ", ".join(sorted(executor.security_config.allowed_commands))
        flags_desc = "All flags allowed" if executor.security_config.allow_all_flags else ", ".join(sorted(executor.security_config.allowed_flags))
        sudo_commands_desc = "All sudo commands allowed" if executor.security_config.allow_all_sudo_commands else ", ".join(sorted(executor.security_config.allowed_sudo_commands)) if executor.security_config.allowed_sudo_commands else "None"
        
        security_info = (
            "Security Configuration:\n"
            f"==================\n"
            f"Working Directory: {executor.allowed_dir}\n"
            f"\nAllowed Commands:\n"
            f"----------------\n"
            f"{commands_desc}\n"
            f"\nAllowed Flags:\n"
            f"-------------\n"
            f"{flags_desc}\n"
            f"\nAllowed Sudo Commands:\n"
            f"--------------------\n"
            f"{sudo_commands_desc}\n"
            f"\nSecurity Limits:\n"
            f"---------------\n"
            f"Max Command Length: {executor.security_config.max_command_length} characters\n"
            f"Command Timeout: {executor.security_config.command_timeout} seconds\n"
        )
        return [types.TextContent(type="text", text=security_info)]

    raise ValueError(f"Unknown tool: {name}")


async def main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="cli-mcp-server",
                server_version="0.2.1",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )
