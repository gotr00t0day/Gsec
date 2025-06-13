from colorama import Fore

def format_output(message: str, status: str = "info", prefix_color: str = Fore.MAGENTA, separator_color: str = Fore.CYAN, text_color: str = Fore.WHITE) -> None:
    """
    Format output messages consistently with the existing style.
    
    Args:
        message: The message to display
        status: Type of message ('info', 'success', 'warning', 'error')
        prefix_color: Color for the [+]/[-] prefix
        separator_color: Color for the separator
        text_color: Color for the main text
    """
    if status == "info" or status == "success":
        prefix = "[+]"
    elif status == "warning" or status == "error":
        prefix = "[-]"
    else:
        prefix = "[+]"
    
    print(f"{prefix_color}{prefix} {separator_color}-{text_color} {message}")

def format_info(message: str) -> None:
    """Format an info message."""
    format_output(message, "info")

def format_success(message: str) -> None:
    """Format a success message."""
    format_output(message, "success")

def format_warning(message: str) -> None:
    """Format a warning message."""
    format_output(message, "warning")

def format_error(message: str) -> None:
    """Format an error message."""
    format_output(message, "error")
