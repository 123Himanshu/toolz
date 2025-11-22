"""Utility functions for security scanners"""
import logging
from pathlib import Path
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def ensure_directory(path: Path) -> None:
    """Create directory if it doesn't exist"""
    path.mkdir(parents=True, exist_ok=True)
    logger.debug(f"Ensured directory exists: {path}")


def get_output_path(scan_type: str, target: str, extension: str) -> Path:
    """
    Generate output path for scan results
    
    Args:
        scan_type: Type of scan (e.g., 'trivy_image', 'openvas_report')
        target: Target being scanned
        extension: File extension
    
    Returns:
        Path object for output file
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Sanitize target name for filename
    safe_target = target.replace('/', '_').replace(':', '_').replace('.', '_')
    
    # Create filename
    filename = f"{scan_type}_{safe_target}_{timestamp}.{extension}"
    
    # Determine output directory based on scan type
    if 'trivy' in scan_type:
        output_dir = Path("/app/scans/trivy")
    elif 'openvas' in scan_type:
        output_dir = Path("/app/scans/openvas")
    else:
        output_dir = Path("/app/scans")
    
    ensure_directory(output_dir)
    
    return output_dir / filename


def format_timestamp() -> str:
    """Get formatted timestamp"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitize_filename(filename: str) -> str:
    """Sanitize filename by removing invalid characters"""
    invalid_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|']
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename
