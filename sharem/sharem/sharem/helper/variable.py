from ..DLLs.emu_helpers.sharem_artifacts import Artifacts_emulation
from .emu import EMU, emulationOptions
from ..singleton.helpers import Singleton
import sharem.sharem.constants as constants
from sharem.sharem.helper.foundbooleans import foundBooleans

class Variables(metaclass=Singleton):
    def __init__(self):
        # Startup Modules
        self.moduleBooleans: dict[str, foundBooleans] = {
            constants.ShellcodeLabel.SHELLCODE_LABEL: foundBooleans(),
            constants.ShellcodeLabel.SHELLCODE_DECODED_STUB_LABEL: foundBooleans(),
            constants.ShellcodeLabel.SHELLCODE_DECODED_BODY_LABEL: foundBooleans(),
            constants.ShellcodeLabel.SHELLCODE_DECODED_FULL_LABEL: foundBooleans()
        }  # start modules dicitonary
        self.m = {}
        self.dictName_mBool = (
            "shellcode"  # this is for the mBool object, was previous named 'o'
        )

        self.bit32_argparse = False
        self.shellBit = 32
        self.rawHex = False
        self.filename = ""
        self.logged_syscalls = []
        self.emulation_multiline = True
        self.shellSizeLimit = ""
        self.bShellcodeAll = False

        ###initilize our classes for sharem
        self.emu = EMU()
        self.art = Artifacts_emulation()
        self.emuObj = emulationOptions()

        # call the class inits
        # self.CreateClasses
        self.filename = ""
        self.text = "1"

    def cleanColors(self, out):
        """Find and replace all term sequences giving color to output."""
        out = out.replace(constants.RED, "")
        out = out.replace(constants.GREEN, "")
        out = out.replace(constants.YELLOW, "")
        out = out.replace(constants.BLUE, "")
        out = out.replace(constants.MAGENTA, "")
        out = out.replace(constants.CYAN, "")
        out = out.replace(constants.WHITE, "")
        out = out.replace(constants.RESET, "")
        return out
