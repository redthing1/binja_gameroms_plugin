"""
Base ROM loader class with shared functionality for all game console ROM loaders.
"""

import traceback
from abc import ABC, abstractmethod
from typing import Optional, Dict

from binaryninja import (
    BinaryView,
    SegmentFlag,
    SymbolType,
    Symbol,
    TagType,
    Platform,
    Architecture,
    log_error,
)
from binaryninja.log import Logger


class BaseROMLoader(BinaryView, ABC):
    """
    Abstract base class for game ROM loaders.
    Provides common functionality shared across all ROM loader implementations.
    """

    # Common segment permission flags used across all loaders
    PERM_RWX: SegmentFlag = (
        SegmentFlag.SegmentReadable
        | SegmentFlag.SegmentWritable
        | SegmentFlag.SegmentExecutable
    )
    PERM_RW: SegmentFlag = SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable
    PERM_RX: SegmentFlag = SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable
    PERM_R: SegmentFlag = SegmentFlag.SegmentReadable

    def __init__(self, data: BinaryView):
        super().__init__(file_metadata=data.file, parent_view=data)
        
        # Store reference to raw data and create logger
        self.raw_data: BinaryView = data
        self.logger: Logger = self.create_logger(self.get_loader_name())
        
        # Cache for created tag types to avoid redundant API calls
        self._created_tag_types: Dict[str, TagType] = {}
        
        # Set up architecture and platform - subclasses will override this
        self._setup_architecture_and_platform()

    @abstractmethod
    def get_loader_name(self) -> str:
        """Return the name for this loader (used for logging)."""
        pass

    @abstractmethod
    def get_tag_type_definitions(self) -> Dict[str, str]:
        """Return dictionary mapping tag type names to icons."""
        pass

    @abstractmethod
    def _setup_architecture_and_platform(self) -> None:
        """Set up self.arch and self.platform for this ROM type."""
        pass

    def _get_or_create_tag_type(self, name: str, icon: str) -> Optional[TagType]:
        """
        Retrieves an existing tag type by its name or creates a new one if it doesn't exist.
        Results are cached to avoid redundant API calls and improve performance.
        
        Args:
            name: The name of the tag type (e.g., "Memory Region")
            icon: The icon (emoji or short string) for the tag type (e.g., "🗺️")
            
        Returns:
            The TagType object if successfully found or created, or None if both attempts fail
        """
        name_lower = name.lower()
        if name_lower in self._created_tag_types:
            self.logger.log_debug(f"Retrieved cached tag type: '{name}'")
            return self._created_tag_types[name_lower]

        # Try to get existing tag type first
        existing_tag_type = self.get_tag_type(name)
        if existing_tag_type:
            self.logger.log_debug(f"Found existing tag type: '{name}'. Caching it.")
            self._created_tag_types[name_lower] = existing_tag_type
            return existing_tag_type

        # Create new tag type if it doesn't exist
        try:
            self.logger.log_info(f"Creating new tag type: '{name}' with icon '{icon}'")
            new_tag_type = self.create_tag_type(name, icon)
            self._created_tag_types[name_lower] = new_tag_type
            return new_tag_type
        except Exception as e:
            self.logger.log_error(f"Failed to create tag type '{name}': {e}")
            return None

    def _initialize_tag_types(self) -> None:
        """
        Defines and caches all necessary tag types used by this loader.
        Uses get_tag_type_definitions() to get the platform-specific definitions.
        """
        tag_definitions = self.get_tag_type_definitions()
        self.logger.log_info(f"Initializing {len(tag_definitions)} tag types...")
        
        initialized_count = 0
        for name, icon in tag_definitions.items():
            if self._get_or_create_tag_type(name, icon):
                initialized_count += 1
            else:
                self.logger.log_warn(f"Could not initialize tag type: '{name}' with icon '{icon}'")
        
        self.logger.log_info(f"{initialized_count}/{len(tag_definitions)} tag types ready for use")

    def _define_hardware_register(
        self,
        address: int,
        name: str,
        tag_category_name: str,
        description: str = "",
    ) -> None:
        """
        Helper method to define a symbol for a hardware register at a given address
        and apply a descriptive tag to it for better organization in the UI.
        
        Args:
            address: The memory-mapped I/O address of the hardware register
            name: The conventional name for the register symbol
            tag_category_name: The category name of the tag type
            description: An optional comment to add for the register at its address
        """
        try:
            # Define the symbol for the register
            self.define_auto_symbol(Symbol(SymbolType.DataSymbol, address, name))

            # Add description as comment if provided
            if description:
                self.set_comment_at(address, description)

            # Get the appropriate tag type and apply it
            tag_definitions = self.get_tag_type_definitions()
            tag_icon = tag_definitions.get(tag_category_name, "🔩")  # Generic fallback
            tag_type = self._get_or_create_tag_type(tag_category_name, tag_icon)
            
            if tag_type:
                self.add_tag(address, tag_type.name, data=name)
            else:
                self.logger.log_warn(
                    f"Could not obtain tag type '{tag_category_name}' for register '{name}' at 0x{address:08x}"
                )
        except Exception as e:
            self.logger.log_error(
                f"Error processing hardware register '{name}' at 0x{address:08x}: {e}\n{traceback.format_exc()}"
            )

    def _add_memory_segment_with_tag(
        self,
        address: int,
        size: int,
        permissions: SegmentFlag,
        name: str,
        tag_name: str = "Memory Region",
        file_offset: int = 0,
        file_length: int = 0,
    ) -> None:
        """
        Helper to add a memory segment with consistent tagging and commenting.
        
        Args:
            address: Starting virtual address of the segment
            size: Size of the segment in bytes
            permissions: R/W/X permissions for the segment
            name: Descriptive name for the segment
            tag_name: Category for the tag (from tag type definitions)
            file_offset: Offset in file for file-backed segments
            file_length: Length of data from file to map
        """
        self.logger.log_debug(
            f"Mapping '{name}': addr=0x{address:08x}, size=0x{size:x} ({size // 1024}KB), perms={permissions}"
        )
        
        try:
            # Add the segment
            self.add_auto_segment(address, size, file_offset, file_length, permissions)
            
            # Get tag type and apply tag
            tag_definitions = self.get_tag_type_definitions()
            tag_icon = tag_definitions.get(tag_name, "🗺️")  # Default map icon
            tag_type = self._get_or_create_tag_type(tag_name, tag_icon)
            if tag_type:
                self.add_tag(address, tag_type.name, data=f"{name} Start")
            
            # Add comment at start of region
            self.set_comment_at(address, f"{name} ({size // 1024}KB)")
            self.logger.log_info(f"Successfully mapped '{name}'")
            
        except Exception as e:
            self.logger.log_error(
                f"Failed to map memory region '{name}' at 0x{address:08x}: {e}\n{traceback.format_exc()}"
            )

    # Required BinaryView method overrides
    def perform_is_executable(self) -> bool:
        """Indicates that ROM files contain executable code."""
        return True

    def perform_get_address_size(self) -> int:
        """Returns the address size for the platform (typically 4 bytes for 32-bit)."""
        return 4