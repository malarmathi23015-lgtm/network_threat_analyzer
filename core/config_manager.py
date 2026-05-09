"""
============================================================
core/config_manager.py
AI-Powered Linux Network Threat Analyzer

PURPOSE:
    Loads and provides access to settings from config/config.ini
    and .env files. All modules use this instead of hardcoding values.

BEGINNER NOTE:
    A config manager is like a settings menu for your program.
    Instead of changing values scattered across many files,
    you change them in one place (config.ini) and everything updates.
============================================================
"""

import configparser
import os
from pathlib import Path

from dotenv import load_dotenv

from core.logger import setup_logger

logger = setup_logger("ConfigManager")


class ConfigManager:
    """
    Loads configuration from config/config.ini and .env files.

    This class follows the Singleton-like pattern — load it once,
    use it everywhere in your project.

    Usage:
        config = ConfigManager()
        interface = config.get("NETWORK", "interface")
        threshold = config.get_int("THRESHOLDS", "port_scan_threshold")
    """

    def __init__(self, config_path: str = "config/config.ini"):
        """
        Initialize and load configuration files.

        Args:
            config_path (str): Path to the .ini config file
        """
        # Load .env file first (secrets like API keys)
        load_dotenv()

        self.config = configparser.ConfigParser()
        self.config_path = config_path

        self._load_config()

    def _load_config(self):
        """Read the config.ini file into memory."""
        if not Path(self.config_path).exists():
            logger.error(f"Config file not found: {self.config_path}")
            logger.info("Using default settings. Create config/config.ini to customize.")
            return

        self.config.read(self.config_path)
        logger.info(f"Configuration loaded from: {self.config_path}")

    def get(self, section: str, key: str, fallback: str = "") -> str:
        """
        Get a string value from config.

        Args:
            section (str): Section name in config.ini e.g. 'NETWORK'
            key (str): Key name e.g. 'interface'
            fallback (str): Default value if key not found

        Returns:
            str: The config value, or fallback if not found
        """
        # Check environment variables first (they override config file)
        env_key = f"{section}_{key}".upper()
        env_value = os.getenv(env_key)
        if env_value:
            return env_value

        return self.config.get(section, key, fallback=fallback)

    def get_int(self, section: str, key: str, fallback: int = 0) -> int:
        """
        Get an integer value from config.

        Args:
            section (str): Section name
            key (str): Key name
            fallback (int): Default value if not found

        Returns:
            int: The config value as integer
        """
        try:
            return self.config.getint(section, key, fallback=fallback)
        except (ValueError, configparser.NoSectionError, configparser.NoOptionError):
            return fallback

    def get_bool(self, section: str, key: str, fallback: bool = False) -> bool:
        """
        Get a boolean value from config (true/false/yes/no/1/0).

        Args:
            section (str): Section name
            key (str): Key name
            fallback (bool): Default value if not found

        Returns:
            bool: The config value as boolean
        """
        try:
            return self.config.getboolean(section, key, fallback=fallback)
        except (ValueError, configparser.NoSectionError, configparser.NoOptionError):
            return fallback

    def get_float(self, section: str, key: str, fallback: float = 0.0) -> float:
        """
        Get a float value from config.

        Args:
            section (str): Section name
            key (str): Key name
            fallback (float): Default value if not found

        Returns:
            float: The config value as float
        """
        try:
            return self.config.getfloat(section, key, fallback=fallback)
        except (ValueError, configparser.NoSectionError, configparser.NoOptionError):
            return fallback

    def get_env(self, key: str, fallback: str = "") -> str:
        """
        Get a value directly from environment variables.

        Args:
            key (str): Environment variable name e.g. 'SECRET_KEY'
            fallback (str): Default if not set

        Returns:
            str: Environment variable value or fallback
        """
        return os.getenv(key, fallback)

    def display_config_summary(self):
        """Print a summary of loaded config sections (hides sensitive values)."""
        logger.info("=" * 50)
        logger.info("CURRENT CONFIGURATION SUMMARY")
        logger.info("=" * 50)
        for section in self.config.sections():
            for key, value in self.config[section].items():
                # Mask sensitive values like API keys and secrets
                if any(word in key.lower() for word in ["key", "secret", "password", "token"]):
                    display_value = "*" * 8 + " (hidden)"
                else:
                    display_value = value
                logger.info(f"  [{section}] {key} = {display_value}")
        logger.info("=" * 50)


# --------------------------------------------------------
# Create a global config instance that can be imported
# by any module in the project.
#
# Usage in other modules:
#   from core.config_manager import config
#   interface = config.get("NETWORK", "interface")
# --------------------------------------------------------
config = ConfigManager()
