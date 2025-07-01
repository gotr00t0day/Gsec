import subprocess
import logging
import shlex
from typing import Optional, Tuple
from modules import format_info

# Set up logging for errors only
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

def subpro_scan(command: str) -> Optional[str]:
    """
    Execute subprocess commands safely and return output.
    
    Args:
        command: Command string to execute
        
    Returns:
        Decoded command output or None if command fails
        
    Raises:
        ValueError: If command is empty or None
        subprocess.CalledProcessError: If command execution fails
    """
    if not command or not command.strip():
        raise ValueError("Command cannot be empty")
    
    try:
        # Split command safely to avoid shell injection
        cmd_list = shlex.split(command)
        
        # Execute without shell=True for security
        process = subprocess.run(
            cmd_list,
            capture_output=True,
            timeout=60,  # Prevent hanging processes
            text=False   # Get bytes to handle encoding properly
        )
        
        # Handle output decoding with fallback
        try:
            output = process.stdout.decode('utf-8')
        except UnicodeDecodeError:
            # Fallback to latin-1 for non-UTF8 content
            try:
                output = process.stdout.decode('latin-1')
            except UnicodeDecodeError:
                # Last resort - ignore errors
                output = process.stdout.decode('utf-8', errors='ignore')
        
        # Handle errors
        if process.stderr:
            try:
                error_output = process.stderr.decode('utf-8')
                logger.warning(f"Command stderr: {error_output}")
            except UnicodeDecodeError:
                logger.warning("Command produced non-UTF8 error output")
        
        if process.returncode != 0:
            logger.warning(f"Command exited with code {process.returncode}: {command}")
        
        # Remove INFO log for cleaner output
        return output
        
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after 60 seconds: {command}")
        return None
        
    except FileNotFoundError:
        logger.error(f"Command not found: {command}")
        raise
        
    except Exception as e:
        logger.error(f"Unexpected error executing command '{command}': {str(e)}")
        raise