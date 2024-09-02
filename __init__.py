from binaryninja import *
from .gbarom import GBAView
from .ndsrom import NDSView

GBAView.register()
NDSView.register()
