import subprocess
import logging
import shlex
from typing import Optional
from modules import format_info

# Set up logging for errors only
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

def commands(cmd: str) -> Optional[subprocess.CompletedProcess]:
    """
    Execute system commands safely with proper error handling and logging.
    
    Args:
        cmd: Command string to execute
        
    Returns:
        CompletedProcess object or None if command fails
        
    Raises:
        ValueError: If command is empty or None
        subprocess.CalledProcessError: If command execution fails
    """
    if not cmd or not cmd.strip():
        raise ValueError("Command cannot be empty")
    
    try:
        # Split command safely to avoid shell injection
        cmd_list = shlex.split(cmd)
        
        # Execute without shell=True for security
        result = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=30,  # Prevent hanging
            check=True
        )
        
        # Remove INFO logs for cleaner output
        if result.stdout:
            # Print command output directly without INFO prefix
            print(result.stdout.strip())
            
        return result
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {cmd}")
        logger.error(f"Error code: {e.returncode}")
        logger.error(f"Error output: {e.stderr}")
        raise
        
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {cmd}")
        raise
        
    except FileNotFoundError:
        logger.error(f"Command not found: {cmd}")
        raise
        
    except Exception as e:
        logger.error(f"Unexpected error executing command '{cmd}': {str(e)}")
        raise