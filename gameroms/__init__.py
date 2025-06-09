"""
Game ROM loaders for Binary Ninja.

This package contains ROM loaders for various gaming platforms:
- GBA (Game Boy Advance)
- NDS (Nintendo DS) 
- PSP (PlayStation Portable)
"""

# Re-export the main loader classes for convenience
from .gba import GBAView
from .nds import NDSView
from .psp import PSPView

__all__ = ['GBAView', 'NDSView', 'PSPView']