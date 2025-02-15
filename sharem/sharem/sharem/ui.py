import colorama
import itertools
from typing import Literal
from abc import abstractmethod

from .parseconf import Configuration
import sharem.sharem.constants as constants
from sharem.sharem.helper.listhelpers import get_max_length
from sharem.sharem.helper.variable import Variables

colorama.init()


def banner() -> str:
    """
    #   ("`-''-/").___..--''"`-._
    #    `6_ 6  )   `-.  (     ).`-.__.`)
    #    (_Y_.)'  ._   )  `._ `. ``-..-'
    #  _..`--'_..-_/  /--'_.' ,'
    # (il),-''  (li),'  ((!.-'

    # Felix Lee <flee@cse.psu.edu>
    """
    text = """

  ____  _   _    _    ____  _____ __  __       ("`-''-/").___..--''"`-._          
 / ___|| | | |  / \  |  _ \| ____|  \/  |       `6_ 6  )   `-.  (     ).`-.__.`)  
 \___ \| |_| | / _ \ | |_) |  _| | |\/| |       (_Y_.)'  ._   )  `._ `. ``-..-'   
  ___) |  _  |/ ___ \|  _ <| |___| |  | |     _..`--'_..-_/  /--'_.' ,'           
 |____/|_| |_/_/   \_\_| \_\_____|_|  |_|    (il),-''  (li),'  ((!.-'             
 

"""
    return text


class Screen:
    """Base class of print the UI to the screen."""

    def __init__(self):
        """Initialize Screen Class."""
        pass

    @abstractmethod
    def __repr__(self):
        """Display content to screen."""


class ImportScreen(Screen):
    """Parent class of the import menu screen."""

    OPTIONS_LABEL = (
        constants.YELLOW
        + """
  .............
     Options
  .............
"""
        + constants.RESET
    )

    def __init__(self, shellBit: Literal[32, 64], name: str, hMd5: str) -> None:
        """Initialize common values for Screen."""
        self.shellBit: Literal[32, 64] = shellBit
        self.name = name
        self.hMd5 = hMd5
        self.showType: str = ""
        self.output: str = ""
        self._init_output()

    def _format_showType(self) -> str:
        """Format showType for screen. If None, does nothing."""
        if self.showType:
            return f"\n\t{self.showType}: "
        return ""

    def _init_output(self) -> None:
        """Initialize output with constant values."""
        self.output += constants.GREEN + banner() + constants.RESET
        self.output += (
            constants.WHITE
            + "  Shellcode Analysis & Emulation Framework, v. 1.024"
            + constants.RESET
        )
        self.output += (
            constants.GREEN
            + self._format_showType()
            + constants.CYAN
            + self.name
            + constants.GREEN
            + "\tMd5: "
            + constants.CYAN
            + self.hMd5
            + constants.RESET
        )

    @abstractmethod
    def _set_options_content(self) -> None:
        """Set options content for Screen."""

    def _append_output(self, content: str) -> None:
        """Append content to the screen output."""
        self.output += content


class RawHexScreen(ImportScreen):
    """Class to handle displaying screens for Raw Hex inputs."""

    def __init__(self, shellBit: Literal[32, 64], name: str, hMd5: str) -> None:
        super().__init__(shellBit, name, hMd5)
        self.showType = "Shellcode"

    def _set_options_content(self) -> None:
        """Create options menu for Raw Hex input."""
        self._append_output(
            constants.CYAN
            + f"""
   h		{constants.RESET + "Display options." + constants.CYAN}
   l		{constants.RESET + "Shellcode Emulator" + constants.CYAN}
   z		{constants.RESET + "Do everything with current selections." + constants.CYAN}
   s		{constants.RESET + "Find Assembly instructions associated with shellcode." + constants.CYAN}
   D		{constants.RESET + "Disassemble shellcode" + constants.CYAN}
   d		{constants.RESET + "Disassembly of shellcode submenu" + constants.CYAN}
   p		{constants.RESET + "Print Menu - print outputs to file" + constants.CYAN}
   b		{constants.RESET + "Brute-force deobfuscation of shellcode." + constants.CYAN}
   U		{constants.RESET + "Toggle between actions on obfuscated/deobfuscated shellcode." + constants.CYAN}
   k		{constants.RESET + "Find strings." + constants.CYAN}
   o		{constants.RESET + "Output bins and ASCII text." + constants.CYAN}
   i		{constants.RESET + "Show basic " + self.showType + " info." + constants.CYAN}
   a		{constants.RESET + "Change architecture, 32-bit or 64-bit." + constants.YELLOW + " [ " + constants.CYAN + str(self.shellBit) + "-bit" + constants.YELLOW + " ]" + constants.CYAN}
   c		{constants.RESET + "Save current configuration." + constants.CYAN}
   q		{constants.RESET + "Quick find all." + constants.CYAN}
   x		{constants.RESET + "Exit." + constants.CYAN}
    """
        )

    def __repr__(self):
        """String representation of Raw Hex Screen."""
        self._set_options_content()
        return ImportScreen.OPTIONS_LABEL + self.output


class PEFileScreen(ImportScreen):
    """Class to handle displaying options screen for PE File inputs."""

    def __init__(self, shellBit: Literal[32, 64], name: str, hMd5: str) -> None:
        """Initialize PEFileScreen."""
        super().__init__(shellBit, name, hMd5)
        self.showType = "PE File"

    def _set_options_content(self) -> None:
        """Create options menu for PE File input."""
        self._append_output(
            constants.CYAN
            + f"""
   h		{constants.RESET + "Display options." + constants.CYAN}
   s		{constants.RESET + "Find Assembly instructions associated with shellcode." + constants.CYAN}
   z		{constants.RESET + "Do everything with current selections." + constants.CYAN}
   p		{constants.RESET + "Print Menu - print outputs to file" + constants.CYAN}
   k		{constants.RESET + "Find strings." + constants.CYAN}
   m		{constants.RESET + "Find modules in the IAT and beyond." + constants.CYAN}
   e		{constants.RESET + "Find imports." + constants.CYAN}
   i		{constants.RESET + "Show basic " + self.showType + " info." + constants.CYAN}
   a		{constants.RESET + "Change architecture, 32-bit or 64-bit." + constants.YELLOW + " [ " + constants.CYAN + str(self.shellBit) + "-bit" + constants.YELLOW + " ]" + constants.CYAN}
   c		{constants.RESET + "Save current configuration." + constants.CYAN}
   q		{constants.RESET + "Quick find all." + constants.CYAN}
   x		{constants.RESET + "Exit." + constants.CYAN}
    """
        )

    def __repr__(self):
        """String representation of PE File Screen."""
        self._set_options_content()
        return ImportScreen.OPTIONS_LABEL + self.output


class BitMenuScreen(Screen):
    """Bit Menu Screen."""

    def __init__(self):
        """Initialize BitMenu Screen."""
        super().__init__()

    def __repr__(self):
        """Content to print to the BitMenu Screen."""
        return (
            "\nChange bit mode, "
            + constants.YELLOW
            + "32-bit "
            + constants.RESET
            + "or"
            + constants.RED
            + " 64-bit\n"
            + constants.RESET
            + "Enter 32 or 64: "
        )


def showOptions(shellBit: Literal[32, 64], rawHex, name, hMd5):
    if rawHex:
        print(RawHexScreen(shellBit, name, hMd5))
    else:
        print(PEFileScreen(shellBit, name, hMd5))


def printBitMenu():
    print(BitMenuScreen())


def displayCurrentInstructions(variables: Variables, shellcode_label):  # Display current shellcode instruction selections
    iMenu = "\n"
    iMenu += " Shellcode instructions to find:\n"
    iMenu += (
        constants.CYAN
        + "\tpr"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " Push ret\t\t\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if variables.moduleBooleans[shellcode_label].bPushRet else " "
    iMenu += "]\n"
    iMenu += (
        constants.CYAN
        + "\tcp"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " Call pop / GetPC\t\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if variables.moduleBooleans[shellcode_label].bCallPop else " "
    iMenu += "]\n"
    iMenu += (
        constants.CYAN
        + "\tfe"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " Fstenv / GetPC\t\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if variables.moduleBooleans[shellcode_label].bFstenv else " "
    iMenu += "]\n"
    iMenu += (
        constants.CYAN
        + "\tsy"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " Windows syscall\t\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if variables.moduleBooleans[shellcode_label].bEgg else " "
    iMenu += "]\n"
    iMenu += (
        constants.CYAN
        + "\thg"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " Heaven's gate\t\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if variables.moduleBooleans[shellcode_label].bHeaven else " "
    iMenu += "]\n"
    iMenu += (
        constants.CYAN
        + "\tpb"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " Walking the PEB\t\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if variables.moduleBooleans[shellcode_label].bPEB else " "
    iMenu += "]\n"
    iMenu += (
        constants.CYAN
        + "\tfd"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " Find disassembly\t\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if variables.moduleBooleans[shellcode_label].bDisassembly else " "
    iMenu += "]\n"
    iMenu += (
        constants.CYAN
        + "\tall"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " All selections\t\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if variables.moduleBooleans[shellcode_label].bAll else " "
    iMenu += "]\n\t\t*Default\n\n"
    # print(iMenu)
    return iMenu


# goodone
def displayCurrentSelections(
    bpPushRet,
    bpCallPop,
    bpFstenv,
    bpSyscall,
    bpHeaven,
    bpPEB,
    bpStrings,
    bpEvilImports,
    bpModules,
    bpPushStrings,
    bDisass,
    bPrintEmulation,
    bpAll,
):  # Displays current print selections
    iMenu = " Selections to print:\n"
    iMenu += (
        constants.CYAN
        + "\tpr"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " Push rets\t\t\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if bpPushRet else " "
    iMenu += constants.RESET + "]\n"
    iMenu += (
        constants.CYAN
        + "\tcp"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " Call pop / GetPC\t\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if bpCallPop else " "
    iMenu += constants.RESET + "]\n"
    iMenu += (
        constants.CYAN
        + "\tfe"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " Fstenv / GetPC\t\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if bpFstenv else " "
    iMenu += constants.RESET + "]\n"

    iMenu += (
        constants.CYAN
        + "\tsy"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " Windows syscall\t\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if bpSyscall else " "
    iMenu += constants.RESET + "]\n"
    iMenu += (
        constants.CYAN
        + "\thg"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " Heaven's gate\t\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if bpHeaven else " "
    iMenu += constants.RESET + "]\n"
    iMenu += (
        constants.CYAN
        + "\tpb"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " Walking the PEB\t\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if bpPEB else " "
    iMenu += constants.RESET + "]\n"
    iMenu += (
        constants.CYAN
        + "\tim"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " Imports\t\t\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if bpEvilImports else " "
    iMenu += constants.RESET + "]\n"
    iMenu += (
        constants.CYAN
        + "\tlm"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " Loaded modules\t\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if bpModules else " "
    iMenu += constants.RESET + "]\n"
    iMenu += (
        constants.CYAN
        + "\tst"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " Strings \t\t\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if bpStrings else " "
    iMenu += constants.RESET + "]\n"
    iMenu += (
        constants.CYAN
        + "\tps"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " Push Stack Strings \t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if bpPushStrings else " "
    iMenu += constants.RESET + "]\n"
    iMenu += (
        constants.CYAN
        + "\tfd"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " Find disassembly\t\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if bDisass else " "
    iMenu += constants.RESET + "]\n"
    iMenu += (
        constants.CYAN
        + "\tem"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " print emulation\t\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if bPrintEmulation else " "
    iMenu += constants.RESET + "]\n"
    iMenu += (
        constants.CYAN
        + "\tall"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " All selections\t\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if bpAll else " "

    iMenu += "]\n\t\t" + constants.RED + "*Default\n\n" + constants.RESET
    # print(iMenu)
    return iMenu


# ui Discover Menu text
def instructionsMenu(variables: Variables, shellcode_label):
    iMenu = displayCurrentInstructions(variables, shellcode_label)
    iMenu += (
        constants.GREEN
        + "\n h"
        + constants.RESET
        + constants.WHITE
        + " - Show options.\n"
    )
    iMenu += (
        constants.GREEN
        + " g"
        + constants.RESET
        + constants.WHITE
        + " - Toggle selections.\n"
    )
    iMenu += (
        constants.GREEN
        + " c"
        + constants.RESET
        + constants.WHITE
        + " - Clear all selections.\n"
    )
    iMenu += (
        constants.GREEN
        + " t"
        + constants.RESET
        + constants.WHITE
        + " - Change technical setttings for finding shellcode instructions.\n"
    )
    iMenu += (
        constants.GREEN
        + " z"
        + constants.RESET
        + constants.WHITE
        + " - Find instructions.\n"
    )
    iMenu += (
        constants.GREEN
        + " r"
        + constants.RESET
        + constants.WHITE
        + " - reset found instructions.\n"
    )
    iMenu += (
        constants.GREEN
        + " x"
        + constants.RESET
        + constants.WHITE
        + " - Exit.\n"
        + constants.RESET
    )
    print(iMenu)


class InstructionSelectScreen(Screen):
    """Class for the Instruction Select Menu."""

    def __init__(self):
        """Initialize Instruction Select Menu Screen."""
        super().__init__()

    def __repr__(self):
        """String representation of screen."""
        return (
            "\n\n ...................\n"
            " Toggle Instructions"
            "\n ...................\n"
            " Enter each instruction set code to toggle, delimitied by a space.\n"
            "\t e.g. cp, fe, peb, all, none\n\n"
            " x to exit.\n\n"
        )


def instructionSelectMenu():
    print(InstructionSelectScreen())


def techSettingsMenu(bytesForward, bytesBack, linesForward, linesBack, rawHex):
    tMenu = "\n"
    if not rawHex:
        tMenu += " Global PE settings:\n"
        tMenu += (
            constants.CYAN
            + "\t Max bytes to dissassemble forward:  "
            + constants.YELLOW
            + str(bytesForward)
            + constants.RESET
        )
        tMenu += "\n"
        tMenu += (
            constants.CYAN
            + "\t Max bytes to dissassemble backward: "
            + constants.YELLOW
            + str(bytesBack)
            + constants.RESET
        )
    else:
        tMenu += " Global Shellcode settings:\n"

        tMenu += (
            constants.CYAN
            + "\t Max instructions to check forward:  "
            + constants.YELLOW
            + str(linesForward)
            + constants.RESET
        )
        tMenu += "\n"
        tMenu += (
            constants.CYAN
            + "\t Max instructions to check backward: "
            + constants.YELLOW
            + str(linesBack)
            + constants.RESET
        )
    tMenu += "\n\n\n"
    tMenu += "  " + constants.GREEN + "h" + constants.RESET + " - Display options.\n"
    tMenu += "  " + constants.GREEN + "g" + constants.RESET + " - Global settings.\n"
    tMenu += "  " + constants.GREEN + "c" + constants.RESET + " - Call pop / GetPC.\n"
    tMenu += "  " + constants.GREEN + "p" + constants.RESET + " - Walking the PEB.\n"
    tMenu += (
        "  "
        + constants.GREEN
        + "k"
        + constants.RESET
        + " - Change minimum length of strings.\n"
    )
    tMenu += "  " + constants.GREEN + "x" + constants.RESET + " - Exit.\n"
    print(tMenu)


def globalTechMenu(bytesForward, bytesBack, linesForward, linesBack, rawHex):
    if not rawHex:
        gtMenu = "\nModify global PE file settings:\n"
        gtMenu += (
            constants.GREEN
            + "\tfb "
            + constants.RESET
            + "- Max bytes to dissassemble forward:  "
            + constants.YELLOW
            + str(bytesForward)
            + constants.RESET
        )
        gtMenu += "\n"
        gtMenu += (
            constants.GREEN
            + "\tbb "
            + constants.RESET
            + "- Max bytes to dissassemble backward: "
            + constants.YELLOW
            + str(bytesBack)
            + constants.RESET
        )
        gtMenu += "\n\n" + constants.RESET

    else:
        gtMenu = "\nModify global Shellcode settings:\n"

        gtMenu += (
            constants.GREEN
            + "\tfi "
            + constants.RESET
            + "- Max lines to check forward:  "
            + constants.YELLOW
            + str(linesForward)
            + constants.RESET
        )
        gtMenu += "\n"
        gtMenu += (
            constants.GREEN
            + "\tbi "
            + constants.RESET
            + "- Max lines to check backward: "
            + constants.YELLOW
            + str(linesBack)
            + constants.RESET
        )
        gtMenu += "\n\n"
        gtMenu += (
            constants.GREEN + "x" + constants.RESET + "  - Exit.\n" + constants.RESET
        )

    print(gtMenu)


def cpTechMenu(maxDistance):
    cpTMenu = (
        "\nMax call distance: "
        + constants.YELLOW
        + str(maxDistance)
        + constants.RESET
        + "\n"
    )
    cpTMenu += "\tHow far forward can you go for GetPC.\n\n"
    cpTMenu += "Enter max call distance below.\n"
    print(cpTMenu)


# def displayCurrentSelections(bpPushRet, bpCallPop, bpFstenv, bpSyscall, bpHeaven, bpPEB, bpStrings, bpEvilImports, bpModules, bpPushStrings, bDisass, bpAll): #Displays current print selections


def printMenu(
    bpPushRet,
    bpCallPop,
    bpFstenv,
    bpSyscall,
    bpHeaven,
    bpPEB,
    bExportAll,
    bpStrings,
    bpEvilImports,
    bpModules,
    bpPushStrings,
    bDisass,
    bpAll,
    outDir,
    emulation_verbose,
    emulation_multiline,
    bPrintEmulation,
    p2screen=None,
):
    if p2screen:
        p2screen = "x"
    else:
        p2screen = " "

    iMenu = displayCurrentSelections(
        bpPushRet,
        bpCallPop,
        bpFstenv,
        bpSyscall,
        bpHeaven,
        bpPEB,
        bpStrings,
        bpEvilImports,
        bpModules,
        bpPushStrings,
        bDisass,
        bPrintEmulation,
        bpAll,
    )

    iMenu += " {} {} \t\t[".format(
        constants.GREEN + "j" + constants.RESET,
        constants.WHITE + "- Export all to JSON." + constants.RESET,
    )
    iMenu += constants.CYAN + "x" + constants.RESET if bExportAll else " "
    iMenu += "]\n"
    iMenu += " {} {} \t\t[".format(
        constants.GREEN + "e" + constants.RESET,
        constants.WHITE + "- Emulation verbose print style." + constants.RESET,
    )
    iMenu += constants.CYAN + "x" + constants.RESET if emulation_verbose else " "
    iMenu += "]\n"
    iMenu += " {} {} \t[".format(
        constants.GREEN + "m" + constants.RESET,
        constants.WHITE + "- Multiline print style of artifacts." + constants.RESET,
    )
    iMenu += constants.CYAN + "x" + constants.RESET if emulation_multiline else " "
    iMenu += "]\n"
    iMenu += " {} {} \t\t\t[{}]\n".format(
        constants.GREEN + "p" + constants.RESET,
        constants.WHITE + "- Print to screen" + constants.RESET,
        constants.CYAN + p2screen + constants.RESET,
    )
    # iMenu += " {} {} \t\t{}\n".format(constants.GREEN + "d" + constants.RESET, whi + "- Change output directory" + constants.RESET, constants.CYAN + outDir + constants.RESET)
    iMenu += " {} {}\n".format(
        constants.GREEN + "h" + constants.RESET,
        constants.WHITE + "- Show options." + constants.RESET,
    )
    iMenu += " {} {}\n".format(
        constants.GREEN + "c" + constants.RESET,
        constants.WHITE + "- Clear all print selections." + constants.RESET,
    )
    iMenu += " {} {}\n".format(
        constants.GREEN + "s" + constants.RESET,
        constants.WHITE + "- Windows syscall submenu." + constants.RESET,
    )
    iMenu += " {} {}\n".format(
        constants.GREEN + "g" + constants.RESET,
        constants.WHITE + "- Toggle selections." + constants.RESET,
    )
    iMenu += " {} {}\n".format(
        constants.GREEN + "z" + constants.RESET,
        constants.WHITE + "- Print selections." + constants.RESET,
    )
    iMenu += " {} {}\n".format(
        constants.GREEN + "x" + constants.RESET,
        constants.WHITE + "- Exit." + constants.RESET,
    )
    print(iMenu)


def osFindSelection(osVersion):
    # Returns [ ] if false else [x]
    menuString = ""
    g = ""
    if osVersion.toggle:
        menuString += "[x]"
        g = "[x]"
    else:
        menuString += "[ ]"
        g = "[ ]"
    return g


def newSysCallPrint(syscallSelection):
    codes = ["xp", "v", "w7", "w8", "w10", "s3", "s8", "s12", "all"]

    all_selections = []
    list_of_strings1 = []
    list_of_strings2 = []

    for ver in syscallSelection:
        all_selections.append(ver)

    column1 = []
    column2 = []

    for i in all_selections:
        if i.code == "w10":
            index = all_selections.index(i)

    column1 = all_selections[:index]
    column2 = all_selections[index:]

    for i in column1:
        list_of_strings1.append(i.code + "  " + i.name)

    for i in column2:
        list_of_strings2.append(i.code + "  " + i.name)
    for both in itertools.zip_longest(column1, column2):
        col1 = both[0]
        col2 = both[1]
        if col1 != None:
            code1 = col1.code
            toggle1 = col1.toggle
            if toggle1:
                toggle1 = "x"
            else:
                toggle1 = " "
            cat1 = col1.category
            name1 = col1.name
        if col2 != None:
            code2 = col2.code
            toggle2 = col2.toggle
            if toggle2:
                toggle2 = "x"
            else:
                toggle2 = " "
            cat2 = col2.category
            name2 = col2.name
        maxLen1 = get_max_length(list_of_strings1)
        maxLen2 = get_max_length(list_of_strings2)
        L1Len = len(code1 + " " + name1)
        L2Len = len(code2 + "  " + name2)
        if col1 != None and col2 != None:
            # print(code1, code2, codes)
            if code1 in codes and code2 in codes:
                print(
                    " {}  {}{:>{x}}[{}]\t{}  {}{:>{y}}[{}]".format(
                        constants.GREEN + code1 + constants.RESET,
                        constants.CYAN + name1 + constants.RESET,
                        "",
                        constants.RED + toggle1 + constants.RESET,
                        constants.GREEN + code2 + constants.RESET,
                        constants.CYAN + name2 + constants.RESET,
                        "",
                        constants.RED + toggle2 + constants.RESET,
                        x=(maxLen1 - L1Len + 8),
                        y=(maxLen2 - L2Len + 10),
                    )
                )
            elif code1 in codes and code2 not in codes:
                print(
                    " {}  {}{:>{x}}[{}]\t\t{}  {}{:>{y}}[{}]".format(
                        constants.GREEN + code1 + constants.RESET,
                        constants.CYAN + name1 + constants.RESET,
                        "",
                        constants.RED + toggle1 + constants.RESET,
                        constants.YELLOW + code2 + constants.RESET,
                        constants.WHITE + name2 + constants.RESET,
                        "",
                        constants.RED + toggle2 + constants.RESET,
                        x=(maxLen1 - L1Len + 8),
                        y=(maxLen2 - L2Len + 2),
                    )
                )
            else:
                print(
                    "\t{}  {} {:>{x}}[{}]\t\t{}  {}{:>{y}}[{}]".format(
                        constants.YELLOW + code1 + constants.RESET,
                        name1,
                        "",
                        constants.RED + toggle1 + constants.RESET,
                        constants.YELLOW + code2 + constants.RESET,
                        name2,
                        "",
                        constants.RED + toggle2 + constants.RESET,
                        x=(maxLen1 - L1Len),
                        y=(maxLen2 - L2Len + 2),
                    )
                )
        elif col2 is None:
            if code1 in codes:
                print(
                    " {}  {}{:>{x}}[{}]".format(
                        constants.GREEN + code1 + constants.RESET,
                        constants.CYAN + name1 + constants.RESET,
                        "",
                        constants.RED + toggle1 + constants.RESET,
                        x=(maxLen1 - L1Len + 8),
                    )
                )
            else:
                print(
                    "\t{}  {} {:>{x}}[{}]".format(
                        constants.YELLOW + code1 + constants.RESET,
                        name1,
                        "",
                        constants.RED + toggle1 + constants.RESET,
                        x=(maxLen1 - L1Len),
                    )
                )
        elif col1 is None:
            if code2 in codes:
                print(" {}  {}{:>{x}}[ ]".format(code2, name2))
            else:
                print("\t{}  {} {:>{x}}[ ]".format(code2, name2))


def syscallSelectionMenu():
    print("#### WINDOWS XP ####")
    print("Windows XP (SP1)")
    # code = "xp1"
    print("Windows XP (SP2)\n")
    # code = "xp2"

    print("#### WINDOWS VISTA ####")
    print("Windows Vista (SP0)")
    # code = "v0"
    print("Windows Vista (SP1)")
    # code = "v1"
    print("Windows Vista (SP2)\n")
    # code = "v2"

    print("#### WINDOWS 7 ####")
    print("Windows 7 (SP0)")
    # code = "w70"
    print("Windows 7 (SP1)\n")
    # code = "w71"

    print("#### WINDOWS 8 ####")
    print("Windows 8 (8.0)")
    # code = "w80"
    print("Windows 8 (8.1)\n")
    # code = "w81"

    print("#### WINDOWS 10 ####")
    print("Windows 10 (1507)")
    # code = "r0"
    print("Windows 10 (1511)")
    # code = "r1"
    print("Windows 10 (1607)")
    # code = "r2"
    print("Windows 10 (1703)")
    # code = "r3"
    print("Windows 10 (1709)")
    # code = "r4"
    print("Windows 10 (1803)")
    # code = "r5"
    print("Windows 10 (1809)")
    # code = "r6"
    print("Windows 10 (1903)")
    # code = "r7"
    print("Windows 10 (1909)")
    # code = "r8"
    print("Windows 10 (2004)")
    # code = "r9"
    print("Windows 10 (20H2)\n")
    # code = "r10"

    print("#### WINDOWS SERVER 2003 ####")
    print("Windows Server 2003 (SP0)")
    # code = "s30"
    print("Windows Server 2003 (SP2)")
    # code = "s32"
    print("Windows Server 2003 (R2)")
    # code = "s3r"
    print("Windows Server 2003 (R2 SP2)\n")
    # code = "s3r2"

    print("#### WINDOWS SERVER 2008 ####")
    print("Windows Server 2008 (SP0)")
    # code = "s80"
    print("Windows Server 2008 (SP2)")
    # code = "s82"
    print("Windows Server 2008 (R2)")
    # code = "s8r"
    print("Windows Server 2008 (R2 SP1)\n")
    # code = "s8r1"

    print("#### WINDOWS SERVER 2012 ####")
    print("Windows Server 2012 (SP0)")
    # code = "s120"
    print("Windows Server 2012 (R2)\n")
    # code = "s12r"

    print("#### WINDOWS 2000 ####")
    print("Windows 2000 (SP0)")
    # code = "w200"
    print("Windows 2000 (SP1)")
    # code = "w201"
    print("Windows 2000 (SP2)")
    # code = "w202"
    print("Windows 2000 (SP3)")
    # code = "w203"
    print("Windows 2000 (SP4)\n")
    # code = "w204"

    print("#### WINDOWS NT ####")
    print("Windows NT (SP3 TS)")
    # code = "nt3t"
    print("Windows NT (SP3)")
    # code = "nt3"
    print("Windows NT (SP4)")
    # code = "nt4"
    print("Windows NT (SP5)")
    # code = "nt5"
    print("Windows NT (SP6)")
    # code = "nt6"


class EmulationSyscallSubScreen(Screen):
    """Displays the Emulation Syscalls Print Sub-Menu."""

    def __init__(self, emuSyscallSelection):
        """Initialize Emulation Syscalls Print Sub-Menu."""
        self.output: str = ""
        self.emuSyscallSelection = emuSyscallSelection

    def emuNewSysCallPrint(self):
        """Print all OS Build versions as part of syscall selection."""
        for line in constants.SYSCALL_NAME_STRINGS:
            line = line.split(maxsplit=1)
            code = line[0]
            description = line[1]

            tog = "x" if code != "NA" and self.emuSyscallSelection[code][0] else " "
            if description.split()[0] == "Windows" or description.split()[0] == "All":
                self.output += "\n{}\n".format(
                    constants.CYAN + description + constants.RESET
                )
            else:
                self.output += "{}\t{}  {}\n".format(
                    "[" + constants.RED + tog + constants.RESET + "]",
                    constants.YELLOW + code + constants.RESET,
                    description,
                )

    def __repr__(self) -> str:
        """String representation of Emulation Syscalls Sub-Menu."""
        self.output += constants.RED
        self.output += "Note: "
        self.output += constants.RESET
        self.output += "  Only one OSBuild may be selected for emulation."
        self.output += constants.MAGENTA
        self.output += " \n OSBuild Selection:\n"
        self.output += constants.RESET
        self.emuNewSysCallPrint()
        self.output += constants.MAGENTA
        self.output += " \n\n Functional Commands:\n\n"
        self.output += constants.RESET
        self.output += " {} - Options.\n".format(constants.CYAN + "h" + constants.RESET)
        self.output += " {} - Clear syscall selection.\n".format(
            constants.CYAN + "c" + constants.RESET
        )
        self.output += " {} - Enter syscall selection.\n".format(
            constants.CYAN + "g" + constants.RESET
        )
        self.output += " {} - Exit.\n".format(constants.CYAN + "x" + constants.RESET)
        return self.output


def emuSyscallPrintSubMenu(emuSyscallSelection):
    print(EmulationSyscallSubScreen(emuSyscallSelection))


def syscallPrintSubMenu(
    syscallSelection, showDisassembly, syscallPrintBit, showOptions
):
    print(
        constants.RED
        + "Note:"
        + constants.RESET
        + "   This is a pseudo-emulation performed statically, on shellcode or PE files. \n\tFor more accurate results, select the desired OSBuild in emulation submenu. \n\tAdditional new OSBuild releases supported there."
    )
    vMenu = ""

    if showOptions:
        print(constants.MAGENTA + " \n OSBuild Selections:\n" + constants.RESET)
        newSysCallPrint(syscallSelection)

        vMenu = ""
    if showOptions:
        vMenu += constants.MAGENTA + " \n\n Functional Commands:\n\n" + constants.RESET
        vMenu += " {} - Options.\n".format(constants.CYAN + "h" + constants.RESET)
        vMenu += " {} - Clear syscall selections.\n".format(
            constants.CYAN + "c" + constants.RESET
        )
        vMenu += " {} - Enter syscall selections.\n".format(
            constants.CYAN + "g" + constants.RESET
        )
        vMenu += " {} - Change architecture for syscall.\t[".format(
            constants.CYAN + "b" + constants.RESET
        )
        vMenu += constants.RED + str(syscallPrintBit) + "-bit" + constants.RESET
        vMenu += "]\n"
        vMenu += (
            "    -    "
            + constants.YELLOW
            + "Note:"
            + constants.RESET
            + " This should generally remain 64-bit.\n"
        )
        vMenu += " {} - Display disassembly.\t[".format(
            constants.CYAN + "d" + constants.RESET
        )
        vMenu += constants.RED + "x" + constants.RESET if showDisassembly else " "
        vMenu += "]\n"
        vMenu += " {} - Print syscalls.\n".format(
            constants.CYAN + "z" + constants.RESET
        )
        # vMenu += "b - Change bits 64]\n"
        vMenu += " {} - Exit.\n".format(constants.CYAN + "x" + constants.RESET)

    print(vMenu)


class ModulesMenuScreen(Screen):
    """Menu Screen for loaded Modules."""

    def __init__(self, modulesMode: Literal[1, 2, 3]):
        """Initialize screen for loaded Modules."""
        super().__init__()
        self.modulesMode: Literal[1, 2, 3] = modulesMode
        self.output: str = ""

    def __repr__(self):
        """String representation of Modules Menu Screen."""
        self.output += (
            constants.GREEN
            + "\tNote: This feature is experimental and not always accurate.\n\n"
            + constants.RESET
        )
        self.output += "Select one of the following options:\n"
        self.output += (
            "\t" + constants.CYAN + "1" + constants.RESET + " - Find only DLLs in IAT"
        )
        if self.modulesMode == 1:
            self.output += "\t\t[" + constants.RED + "x" + constants.RESET + "]\n"
        else:
            self.output += "\t\t[ ]\n"
        self.output += (
            "\t"
            + constants.CYAN
            + "2"
            + constants.RESET
            + " - Find DLLs in IAT and beyond"
        )
        if self.modulesMode == 2:
            self.output += "\t\t[" + constants.RED + "x" + constants.RESET + "]\n"
        else:
            self.output += "\t\t[ ]\n"
        self.output += (
            "\t"
            + constants.CYAN
            + "3"
            + constants.RESET
            + " - Find DLLs in IAT, beyond, and more"
        )
        if self.modulesMode == 3:
            self.output += "\t[" + constants.RED + "x" + constants.RESET + "]\n"
        else:
            self.output += "\t[ ]\n"
        self.output += constants.GREEN + "\t\tDefault\n" + constants.RESET
        self.output += (
            "\t " + constants.CYAN + "h" + constants.RESET + " - Show options.\n"
        )
        self.output += "\t " + constants.CYAN + "p" + constants.RESET + " - Print.\n"
        self.output += "\t " + constants.CYAN + "z" + constants.RESET + " - Execute.\n"
        self.output += "\t " + constants.CYAN + "r" + constants.RESET + " - reset .\n"
        self.output += "\t " + constants.CYAN + "x" + constants.RESET + " - Exit.\n"
        return self.output


def printModulesMenu(modulesMode):
    print(ModulesMenuScreen(modulesMode))


def stringMenu(
    bAsciiStrings,
    bWideCharStrings,
    bPushStackStrings,
    bAllStrings,
    s,
    useStringsFile,
    stringsEmu,
):
    if useStringsFile:
        strFile = "Yes"
    else:
        strFile = "No"

    if stringsEmu:
        emu = "Yes"
    else:
        emu = "No"
    iMenu = ""
    iMenu += constants.GREEN + " Strings to find:\n\n" + constants.RESET
    iMenu += (
        constants.CYAN
        + "\tas"
        + constants.YELLOW
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " ASCII strings\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if bAsciiStrings else " "
    iMenu += constants.RESET + "]\n"
    iMenu += (
        constants.CYAN
        + "\twc"
        + constants.YELLOW
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " Wide char strings\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if bWideCharStrings else " "
    iMenu += constants.RESET + "]\n"
    iMenu += (
        constants.CYAN
        + "\tps"
        + constants.YELLOW
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " Push stack strings\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if bPushStackStrings else " "
    iMenu += constants.RESET + "]\n"
    iMenu += (
        constants.CYAN
        + "\tall"
        + constants.YELLOW
        + constants.RESET
        + " -"
        + constants.YELLOW
        + " All strings\t"
        + constants.RESET
        + "["
    )
    iMenu += constants.CYAN + "x" + constants.RESET if bAllStrings else " "
    iMenu += constants.RESET + "]\n\n"
    # iMenu += "Sections:\n"
    # for sec in s:
    # 	iMenu += "\t" + sec.sectionName.decode() + "\n"
    # iMenu += "\n"
    iMenu += constants.MAGENTA + " h" + constants.RESET + " - Show options.\n"
    iMenu += constants.MAGENTA + " g" + constants.RESET + " - Toggle selections.\n\n"
    iMenu += constants.GREEN + " Strings emulation:\n\n" + constants.RESET
    iMenu += (
        constants.GREEN
        + "\tm"
        + constants.RESET
        + " - Manually set register values for emulation.\n"
        + constants.RESET
    )

    iMenu += (
        constants.YELLOW + "\t\tNote: This is only a sanity check.\n" + constants.RESET
    )
    iMenu += (
        constants.GREEN
        + "\tn"
        + constants.RESET
        + " - Change name of registers text file for emulation "
        + constants.YELLOW
        + "["
        + constants.RESET
        + "{}".format(constants.CYAN + strFile + constants.RESET)
        + constants.YELLOW
        + "]\n"
        + constants.RESET
    )
    iMenu += (
        constants.GREEN
        + "\t\tDefault: "
        + constants.RESET
        + constants.CYAN
        + "regs.txt\n"
        + constants.RESET
    )
    iMenu += (
        constants.GREEN
        + "\te"
        + constants.RESET
        + " - Enable emulation of stack strings with use of registers "
        + constants.YELLOW
        + "["
        + constants.RESET
        + "{}".format(constants.CYAN + emu + constants.RESET)
        + constants.YELLOW
        + "]\n"
        + constants.RESET
    )
    iMenu += (
        constants.YELLOW
        + "\t\tNote: This should not be used ordinarily.\n"
        + constants.RESET
    )
    iMenu += (
        constants.GREEN
        + "\ts"
        + constants.RESET
        + " - Check accuracy of found stack strings.\n"
        + constants.RESET
    )
    iMenu += (
        constants.GREEN
        + "\tk"
        + constants.RESET
        + " - Change minimum length of strings.\n\n"
        + constants.RESET
    )

    iMenu += constants.MAGENTA + " c" + constants.RESET + " - Clear selections.\n"
    iMenu += constants.MAGENTA + " p" + constants.RESET + " - Print found strings.\n"
    iMenu += constants.MAGENTA + " z" + constants.RESET + " - Find strings.\n"
    iMenu += constants.MAGENTA + " r" + constants.RESET + " - reset found strings.\n"
    iMenu += constants.MAGENTA + " x" + constants.RESET + " - Exit.\n"
    print(iMenu)


def emulatorUI(emuObj, emulation_multiline, emulation_verbose):
    # print(mag+"\tPlease note the setup.py MUST be run first before emulation will work!"+constants.RESET)

    # text = """
    #   ....................
    #    Shellcode Emulator
    #   ....................\n\n
    #  """
    text = ""
    text += (
        constants.GREEN
        + """
     _____       SHAREM   _       _             
    |  ___|              | |     | |            
    | |__ _ __ ___  _   _| | __ _| |_ ___  _ __ 
    |  __| '_ ` _ \| | | | |/ _` | __/ _ \| '__|
    | |__| | | | | | |_| | | (_| | || (_) | |   
    \____/_| |_| |_|\__,_|_|\__,_|\__\___/|_|   
                                                
    \n"""
        + constants.RESET
    )

    # text+=constants.CYAN+	"\tPlease note the"+constants.GREEN+" em_setup.py"+constants.CYAN+" MUST be run first before emulation will work!\n\n"+constants.RESET

    vmode = emuObj.verbose
    maxinst = emuObj.maxEmuInstr
    var = Variables()
    em = var.emu
    arch = em.arch
    bloop = em.maxLoop  # emuObj.breakLoop  old
    # iternum = emuObj.numOfIter
    ent = em.entryOffset
    stackTD = em.timeless_debugging_stack

    osBuild = em.winVersion + " " + em.winSP
    if em.breakOutOfLoops:
        bloopTog = "x"
    else:
        bloopTog = " "

    if vmode:
        vmodeTog = "x"
    else:
        vmodeTog = " "

    if stackTD:
        stackTDTog = "x"
    else:
        stackTDTog = " "

    if emulation_verbose:
        emuVerbose = "x"
    else:
        emuVerbose = " "

    if emulation_multiline:
        emuMultiLine = "x"
    else:
        emuMultiLine = " "

    if em.codeCoverage:
        emuCoCo = "x"
    else:
        emuCoCo = " "
    # iMenu += " {} {} \t\t[".format(constants.GREEN + "e"+ constants.RESET, whi + "- Emulation verbose print style." + constants.RESET)
    # iMenu += constants.CYAN + "x" + constants.RESET if emulation_verbose else " "
    # iMenu += "]\n"
    # iMenu += " {} {} \t[".format(constants.GREEN + "m"+ constants.RESET, whi + "- Emulation multiline print style." + constants.RESET)
    # iMenu += constants.CYAN + "x" + constants.RESET if emulation_multiline else " "
    # iMenu += "]\n"

    text += "  {}        \n".format(
        constants.CYAN
        + "z"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Initiate emulation."
        + constants.RESET
    )
    text += "  {}{:>5}[{}]\n".format(
        constants.CYAN
        + "s"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Select Windows syscall OSBuild."
        + constants.RESET,
        "",
        constants.CYAN + osBuild + constants.RESET,
    )

    text += "  {}        \n".format(
        constants.CYAN
        + "d"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Edit Simulated Values."
        + constants.RESET
    )
    text += "  {}{:>3} [{}]\n".format(
        constants.CYAN
        + "m"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Maximum instructions to emulate."
        + constants.RESET,
        "",
        constants.CYAN + str(maxinst) + constants.RESET,
    )

    text += "  {}{:>1} [{}]\n".format(
        constants.CYAN
        + "v"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Verbose mode (Timeless Debugging)."
        + constants.RESET,
        "",
        constants.CYAN + vmodeTog + constants.RESET,
    )
    text += "\t{}\n".format(
        constants.GREEN
        + "Log all Assembly executed to "
        + constants.CYAN
        + "emulationLog.txt"
        + constants.RESET
    )

    text += "  {}{:>1}[{}]\n".format(
        constants.CYAN
        + "t"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Save stack with Timeless Debugging."
        + constants.RESET,
        "",
        constants.CYAN + stackTDTog + constants.RESET,
    )
    text += "\t{}\n".format(
        constants.GREEN
        + "Log stack values +/- 0xA0 to "
        + constants.CYAN
        + "stackLog.txt"
        + constants.RED
        + "\n\tWarning:"
        + constants.WHITE
        + " Slow"
        + constants.RESET
    )

    text += "  {}{:>13}[{}]\n".format(
        constants.CYAN
        + "c"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Complete code coverage."
        + constants.RESET,
        "",
        constants.CYAN + emuCoCo + constants.RESET,
    )

    text += "  {}{:>13}{}\n".format(
        constants.CYAN
        + "o"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Access Complete Code Coverage Submenu"
        + constants.RESET,
        "",
        constants.CYAN + "" + constants.RESET,
    )

    text += "  {}{:>13}       [{}]\n".format(
        constants.CYAN
        + "a"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  CPU Architecture"
        + constants.RESET,
        "",
        constants.CYAN + str(arch) + constants.RESET,
    )
    text += "  {}{:>7} [{}]\n".format(
        constants.CYAN
        + "b"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Break out of infinite loops."
        + constants.RESET,
        "",
        constants.CYAN + bloopTog + constants.RESET,
    )

    text += "  {}{:>1} [{}]\n".format(
        constants.CYAN
        + "n"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Number of iterations before break."
        + constants.RESET,
        "",
        constants.CYAN + str(bloop) + constants.RESET,
    )

    text += "  {}{:>1} [{}]\n".format(
        constants.CYAN
        + "p"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Emulation verbose print style.    "
        + constants.RESET,
        "",
        constants.CYAN + str(emuVerbose) + constants.RESET,
    )

    text += "  {}{:>1} [{}]\n".format(
        constants.CYAN
        + "e"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Change entry point offset.        "
        + constants.RESET,
        "",
        constants.CYAN + hex(ent) + constants.RESET,
    )

    text += "  {}{:>1}[{}]\n".format(
        constants.CYAN
        + "w"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Multiline print style of artifacts."
        + constants.RESET,
        "",
        constants.CYAN + str(emuMultiLine) + constants.RESET,
    )

    text += "  {}        \n".format(
        constants.CYAN
        + "h"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Show this menu."
        + constants.RESET
    )

    text += "  {}        \n".format(
        constants.CYAN
        + "x"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Exit."
        + constants.RESET
    )

    text += "\n"
    print(text)


def emuCodeCoverageUI():
    # print(mag+"\tPlease note the setup.py MUST be run first before emulation will work!"+constants.RESET)
    text = (
        constants.GREEN + "\n\t\tComplete Code Coverage Submenu\n\n" + constants.RESET
    )
    var = Variables()
    em = var.emu
    text += (
        constants.RED
        + "\tNote:"
        + constants.RESET
        + " It is recommended to stick with the defaults for the first group of options.\n\n"
    )
    sizeStack = str(em.codeCoverageStackAmt) + " bytes"

    if em.showCCDebugInfo:
        debugTog = "x"
    else:
        debugTog = " "

    if em.writeToTempFile:
        tempTog = "x"
    else:
        tempTog = " "

    if em.StopExecutingAfterTraversed:
        traversedTog = "x"
    else:
        traversedTog = " "

    if em.displayNonTraversedCC:
        colorCodeTog = "x"
    else:
        colorCodeTog = " "

    if em.includeCallInCC:
        callTog = "x"
    else:
        callTog = " "

    if em.includeJmpInCC:
        jmpTog = "x"
    else:
        jmpTog = " "

    if em.excludeJmpCallCoverage:
        excludeTog = "x"
    else:
        excludeTog = " "

    text += "  {}{:>2}[{}]\n".format(
        constants.CYAN
        + "s"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Size of "
        + constants.MAGENTA
        + "ESP"
        + constants.YELLOW
        + " and "
        + constants.MAGENTA
        + "EBP"
        + constants.YELLOW
        + " to save with each coverage object."
        + constants.RESET,
        "",
        constants.CYAN + sizeStack + constants.RESET,
    )

    text += "  {}{:>1}[{}]\n".format(
        constants.CYAN
        + "t"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Stop emulation after revisiting already traversed code."
        + constants.RESET,
        "",
        constants.CYAN + traversedTog + constants.RESET,
    )

    text += "\t{}\n".format(
        constants.WHITE
        + "Emulation restarts with next coverage object."
        + constants.RESET
    )

    text += "  {}{:>12} [{}]\n".format(
        constants.CYAN
        + "c"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Include "
        + constants.MAGENTA
        + "CALL"
        + constants.YELLOW
        + " instructions in code coverage."
        + constants.RESET,
        "",
        constants.CYAN + callTog + constants.RESET,
    )
    text += "  {}{:>13} [{}]\n".format(
        constants.CYAN
        + "j"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Include "
        + constants.MAGENTA
        + "JMP"
        + constants.YELLOW
        + " instructions in code coverage."
        + constants.RESET,
        "",
        constants.CYAN + jmpTog + constants.RESET,
    )
    text += "\t{}\n".format(
        constants.WHITE
        + "Not recommended unless excluding addresses from coverage via JSON."
        + constants.RESET
    )
    text += "  {}{} [{}]\n".format(
        constants.CYAN
        + "e"
        + constants.RESET
        + " -"
        + constants.MAGENTA
        + "  Exclude addresses"
        + constants.YELLOW
        + " after JMP or CALL from code coverage."
        + constants.RESET,
        "",
        constants.CYAN + excludeTog + constants.RESET,
    )
    text += "\t{}\n".format(
        constants.WHITE
        + "Addresses to exclude must be specified via JSON."
        + constants.RESET
    )

    text += "  {}{:>24}[{}]\n".format(
        constants.CYAN
        + "w"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Write "
        + constants.MAGENTA
        + "temporary file "
        + constants.YELLOW
        + "to hardisk."
        + constants.RESET,
        "",
        constants.CYAN + tempTog + constants.RESET,
    )
    text += "\t{}\n".format(
        constants.WHITE + "Likely only needed if memory problems." + constants.RESET
    )

    text += "\n\n  {}{:>8} [{}]\n".format(
        constants.CYAN
        + "d"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Display code coverage "
        + constants.MAGENTA
        + "debugging info "
        + constants.YELLOW
        + "to screen."
        + constants.RESET,
        "",
        constants.CYAN + debugTog + constants.RESET,
    )
    text += "  {}{:>7}[{}]\n".format(
        constants.CYAN
        + "o"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Show offsets for non-traversed code/data in "
        + constants.CYAN
        + "cyan"
        + constants.YELLOW
        + "."
        + constants.RESET,
        "",
        constants.CYAN + colorCodeTog + constants.RESET,
    )

    text += "  {}        \n".format(
        constants.CYAN
        + "r"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  reset to defaults."
        + constants.RESET
    )

    text += "  {}        \n".format(
        constants.CYAN
        + "h"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Show this menu."
        + constants.RESET
    )

    text += "  {}        \n".format(
        constants.CYAN
        + "x"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Exit - return to Emulator submenu."
        + constants.RESET
    )

    text += "\n"
    print(text)


def emuSimValuesMenu():
    conr = Configuration()
    print("\n")
    print(f"{constants.YELLOW} ...................................")
    print(f"{constants.YELLOW} Emulation Simulation Values")
    print(f"{constants.YELLOW} ...................................")

    print(
        constants.RED
        + " Note:"
        + constants.RESET
        + "  These may also be set in the config."
    )

    def emuSimValHelpList():
        global SimFileSystem

        print(f"\n{constants.MAGENTA} Computer Settings:")
        print(
            f"{constants.CYAN}    c {constants.WHITE}- {constants.YELLOW}Current User {constants.WHITE}[{constants.CYAN}{conr.simulatedValues_current_user}{constants.WHITE}]"
        )
        print(
            f"{constants.CYAN}    u {constants.WHITE}- {constants.YELLOW}Users {constants.WHITE}[{constants.CYAN}{str(conr.simulatedValues_users)[1:-1]}{constants.WHITE}]"
        )
        print(
            f"{constants.CYAN}    n {constants.WHITE}- {constants.YELLOW}Computer Name {constants.WHITE}[{constants.CYAN}{conr.simulatedValues_computer_name}{constants.WHITE}]"
        )
        print(
            f"{constants.CYAN}    a {constants.WHITE}- {constants.YELLOW}Computer IP Address {constants.WHITE}[{constants.CYAN}{conr.simulatedValues_computer_ip_address}{constants.WHITE}]"
        )

        print(f"\n{constants.MAGENTA} File System:")
        print(
            f"{constants.CYAN}    p {constants.WHITE}- {constants.YELLOW}Temp File Prefix {constants.WHITE}[{constants.CYAN}{conr.simulatedValues_temp_file_prefix}{constants.WHITE}]"
        )
        print(
            f"{constants.CYAN}    l {constants.WHITE}- {constants.YELLOW}Drive Letter {constants.WHITE}[{constants.CYAN}{conr.simulatedValues_drive_letter}{constants.WHITE}]"
        )
        print(
            f"{constants.CYAN}    s {constants.WHITE}- {constants.YELLOW}Start Directory {constants.WHITE}[{constants.CYAN}{conr.simulatedValues_start_directory}{constants.WHITE}]"
        )
        print(
            f"{constants.CYAN}    d {constants.WHITE}- {constants.YELLOW}File Download {constants.WHITE}[{constants.CYAN}{conr.simulatedValues_download_files}{constants.WHITE}]"
        )

        print(f"\n{constants.MAGENTA} System Time:")
        print(
            f"{constants.CYAN}    z {constants.WHITE}- {constants.YELLOW}Timezone {constants.WHITE}[{constants.CYAN}{conr.simulatedValues_timezone}{constants.WHITE}]"
        )
        print(
            f"{constants.CYAN}    e {constants.WHITE}- {constants.YELLOW}Time since Epoch {constants.WHITE}[{constants.CYAN}{conr.simulatedValues_system_time_since_epoch}{constants.WHITE}]"
        )
        print(
            f"{constants.CYAN}    t {constants.WHITE}- {constants.YELLOW}Uptime in Minutes {constants.WHITE}[{constants.CYAN}{conr.simulatedValues_system_uptime_minutes}{constants.WHITE}]"
        )

        print(f"\n{constants.MAGENTA} Other:")
        print(
            f"{constants.CYAN}    r {constants.WHITE}- {constants.YELLOW}Default Registry Value {constants.WHITE}[{constants.CYAN}{conr.simulatedValues_default_registry_value}{constants.WHITE}]"
        )
        print(
            f"{constants.CYAN}    b {constants.WHITE}- {constants.YELLOW}Clipboard Data {constants.WHITE}[{constants.CYAN}{conr.simulatedValues_clipboard_data}{constants.WHITE}]"
        )

        print(
            f"\n{constants.CYAN}  h {constants.WHITE}- {constants.YELLOW}Show this menu"
        )

    emuSimValHelpList()
    print(
        "\n"
        + constants.YELLOW
        + " Sharem>"
        + constants.CYAN
        + "Emulator>"
        + constants.GREEN
        + "SimValues> "
        + constants.RESET,
        end="",
    )
    simValueIn = input().lower()[0]
    while simValueIn != "x":
        if simValueIn == "c":
            conr.simulatedValues_current_user = input("   Enter Current User: ")
        elif simValueIn == "u":
            print("   Enter List of Users Seperated by Comas")
            conr.simulatedValues_users = list(
                set(input("   Users: ").replace(" ", "").split(","))
            )
            SimFileSystem.InitializeFileSystem()
        elif simValueIn == "n":
            conr.simulatedValues_computer_name = input("   Enter Computer Name: ")
        elif simValueIn == "a":
            conr.simulatedValues_computer_ip_address = input(
                "   Enter Computer IP Address: "
            )
        elif simValueIn == "p":
            conr.simulatedValues_temp_file_prefix = input("   Enter Temp File Prefix: ")
        elif simValueIn == "l":
            conr.simulatedValues_drive_letter = input("   Enter Drive Letter: ")
            SimFileSystem.InitializeFileSystem()
        elif simValueIn == "s":
            conr.simulatedValues_start_directory = input("   Enter Start Directory: ")
            SimFileSystem.InitializeFileSystem()
        elif simValueIn == "d":
            if conr.simulatedValues_download_files:
                conr.simulatedValues_download_files = False
            else:
                conr.simulatedValues_download_files = True
        elif simValueIn == "z":
            conr.simulatedValues_timezone = input(
                "   Enter Timezone: "
            )  # possible add list of timezones
        elif simValueIn == "e":
            conr.simulatedValues_system_time_since_epoch = int(
                input("   Enter Time Since Epoch: ")
            )
        elif simValueIn == "t":
            conr.simulatedValues_system_uptime_minutes = int(
                input("   Enter Uptime in Minutes: ")
            )
        elif simValueIn == "r":
            conr.simulatedValues_default_registry_value = input(
                "   Enter Defualt Registry Value: "
            )
        elif simValueIn == "b":
            conr.simulatedValues_clipboard_data = input("   Enter Clipboard data: ")
        elif simValueIn == "h":
            emuSimValHelpList()

        print(
            "\n"
            + constants.CYAN
            + " Sharem>"
            + constants.GREEN
            + "Print>"
            + constants.YELLOW
            + "SimValues> "
            + constants.RESET,
            end="",
        )
        simValueIn = input().lower()[0]


def disPrintStyle(disassemblyFound, toggList):
    comments = toggList["comments"]
    show_ascii = toggList["show_ascii"]
    bShowLabels = toggList["labels"]
    bDoShowOffsets = toggList["offsets"]
    bDoshowOpcodes = toggList["opcodes"]
    maxOpDisplay = toggList["max_opcodes"]
    btsV = toggList["binary_to_string"]

    if comments:
        commentsTogg = "x"
    else:
        commentsTogg = " "

    if show_ascii:
        asciiTogg = "x"
    else:
        asciiTogg = " "

    if bDoShowOffsets:
        offsetTogg = "x"
    else:
        offsetTogg = " "

    if bShowLabels:
        labelTogg = "x"
    else:
        labelTogg = " "

    if bDoshowOpcodes:
        opcodeTogg = "x"
    else:
        opcodeTogg = " "

    if disassemblyFound:
        generated = "FOUND"
    else:
        generated = "NOT DISASSEMBLED"

    maxOpval = (
        constants.WHITE
        + "["
        + constants.CYAN
        + str(maxOpDisplay)
        + constants.WHITE
        + "]"
        + constants.RESET
    )
    printStyleVal = (
        constants.WHITE
        + "["
        + constants.CYAN
        + str(btsV)
        + constants.WHITE
        + "]"
        + constants.RESET
    )
    text = ""
    text += (
        "\n\n" + constants.GREEN + "  Disassembly Print Style\n\n\n" + constants.RESET
    )
    text += """
   ....................
      Style Toggles
   ....................\n
  """
    text += (
        "   Use"
        + constants.GREEN
        + " toggle"
        + constants.RESET
        + " to make your selections.\n\n"
    )
    text += "\t{}       [{}]\n".format(
        constants.CYAN
        + "c"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Display comments in disassembly"
        + constants.RESET,
        constants.CYAN + commentsTogg + constants.RESET,
    )
    text += "\t{}           [{}]\n".format(
        constants.CYAN
        + "a"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Display ASCII alongside Hex"
        + constants.RESET,
        constants.CYAN + asciiTogg + constants.RESET,
    )
    text += "\t{}                       [{}]\n".format(
        constants.CYAN
        + "o"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Display opcodes"
        + constants.RESET,
        constants.CYAN + opcodeTogg + constants.RESET,
    )
    text += "\t{}         [{}]\n".format(
        constants.CYAN
        + "l"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Display labels in disassembly"
        + constants.RESET,
        constants.CYAN + labelTogg + constants.RESET,
    )
    text += "\t{}        [{}]\n".format(
        constants.CYAN
        + "f"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Display offsets in disassembly"
        + constants.RESET,
        constants.CYAN + offsetTogg + constants.RESET,
    )
    text += "\n"

    text += """
   ....................
      Style Options
   ....................\n\n
  """
    text += "  {} {}              \n".format(
        constants.GREEN + "g" + constants.WHITE + ":" + constants.RESET,
        constants.WHITE + "  Toggle selections." + constants.RESET,
    )
    text += "    {} {}         {}\n".format(
        constants.GREEN + "m" + constants.WHITE + ":" + constants.RESET,
        constants.WHITE + "  Maximum opcodes to display as hex" + constants.RESET,
        maxOpval,
    )
    text += "    {} {}                  {}\n".format(
        constants.GREEN + "p" + constants.WHITE + ":" + constants.RESET,
        constants.WHITE + "  Opcode print style (1-3)" + constants.RESET,
        printStyleVal,
    )
    text += "    {} {}  [{}]              \n".format(
        constants.GREEN + "r" + constants.WHITE + ":" + constants.RESET,
        constants.WHITE
        + "  Regenerate disassembly with new settings"
        + constants.RESET,
        constants.CYAN + generated + constants.RESET,
    )
    text += "    {} {}              \n".format(
        constants.GREEN + "h" + constants.WHITE + ":" + constants.RESET,
        constants.WHITE + "  Print this menu." + constants.RESET,
    )
    text += "\n\n"

    print(text)


def disToggleMenu(shellEntry, shellSizeLimit, disassemblyFound, toggList):
    deobfuscatedSuccessfully = False  # NEED TO GET THIS FROM AUSTIN

    deobfcode = toggList["deobfCode"]
    findshell = toggList["findShell"]
    hidden_calls = toggList["hidden_calls"]
    ignoreDisDiscovery = toggList["ignore_dis_discovery"]
    findString = toggList["findString"]

    maxOpDisplay = toggList["max_opcodes"]
    btsV = toggList["binary_to_string"]

    if findString:
        strTogg = "x"
    else:
        strTogg = " "

    if deobfcode:
        deobfTogg = "x"
    else:
        deobfTogg = " "

    if findshell:
        findshellTogg = "x"
    else:
        findshellTogg = " "

    if hidden_calls:
        hiddenTogg = "x"
    else:
        hiddenTogg = " "

    if deobfuscatedSuccessfully:
        deobSucTogg = constants.CYAN + "DEOBFUSCATED" + constants.RESET
    else:
        deobSucTogg = constants.CYAN + "NOT DEOBFUSCATED" + constants.RESET

    text = (
        constants.GREEN
        + """
  Disassembly Creation:

  """
        + constants.RESET
    )
    text += "\t{}       [{}]\n".format(
        constants.CYAN
        + "  s"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Use found strings in shellcode"
        + constants.RESET,
        constants.CYAN + strTogg + constants.RESET,
    )
    text += "\t{}       [{}]\n".format(
        constants.CYAN
        + "  d"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Utilize deobfuscated shellcode"
        + constants.RESET,
        constants.CYAN + deobfTogg + constants.RESET,
    )
    text += "\t\t\t[" + deobSucTogg + "]\n"
    text += "\t{}          [{}]\n".format(
        constants.CYAN
        + "  c"
        + constants.RESET
        + " -"
        + constants.YELLOW
        + "  Find lost/hidden calls/jmps"
        + constants.RESET,
        constants.CYAN + hiddenTogg + constants.RESET,
    )
    print(text)
    disassembleUiMenu(
        shellEntry,
        shellSizeLimit,
        disassemblyFound,
        maxOpDisplay,
        btsV,
        ignoreDisDiscovery,
    )


def disassembleUiMenu(
    shellEntry, shellSizeLimit, disassemblyFound, maxOpDisplay, btsV, ignoreDisDiscovery
):
    dfOut = ""
    if ignoreDisDiscovery:
        ignDiscTogg = (
            constants.WHITE
            + "["
            + constants.CYAN
            + "x"
            + constants.WHITE
            + "]"
            + constants.RESET
        )
    else:
        ignDiscTogg = constants.WHITE + "[ ]" + constants.RESET

    if disassemblyFound:
        dfOut = (
            constants.WHITE
            + "["
            + constants.CYAN
            + "FOUND"
            + constants.WHITE
            + "]"
            + constants.RESET
        )
    shellsize = constants.CYAN + str(shellSizeLimit) + " kb" + constants.RESET

    if disassemblyFound:
        printDis = (
            constants.WHITE
            + "["
            + constants.CYAN
            + "FOUND"
            + constants.WHITE
            + "]"
            + constants.RESET
        )
    else:
        printDis = (
            constants.WHITE
            + "["
            + constants.CYAN
            + " NOT DISASSEMBLED"
            + constants.WHITE
            + "]"
            + constants.RESET
        )

    menu = """
  ......................
   Disassembly Options
  ......................

   {}:		Display options.
   {}:		Toggle selections.
   {}:		Output raw shellcode to Json format.
   {}:		Change entry point [{}].
   {}:		Use md5 hash as shellcode filename.

   {}:		Generate disassembly.{}
   {}:		Print disassembly to screen. {}
   {}:		Maximum size of shellcode to disassemble [{}].
                   More than 150 kb is not recommended.
   {}:		Do not use generated disassembly to find shellcode instructions {}
                   Should be unchecked except with very large shellcodes.
   {}:		Disassembly print style submenu
   {}:		Return to main menu.
            
 
    """.format(
        constants.GREEN + "h" + constants.RESET,
        constants.GREEN + "g" + constants.RESET,
        constants.GREEN + "j" + constants.RESET,
        constants.GREEN + "e" + constants.RESET,
        constants.CYAN + hex(shellEntry) + constants.RESET,
        constants.GREEN + "u" + constants.RESET,
        constants.GREEN + "D" + constants.RESET,
        dfOut,
        constants.GREEN + "p" + constants.RESET,
        printDis,
        constants.GREEN + "m" + constants.RESET,
        shellsize,
        constants.GREEN + "i" + constants.RESET,
        ignDiscTogg,
        constants.GREEN + "r" + constants.RESET,
        constants.GREEN + "x" + constants.RESET,
    )

    print(menu)


def shellcodeStringMenu(
    bAsciiStrings, bWideCharStrings, bPushStackStrings, bAllStrings, s
):
    iMenu = ""
    iMenu += "Strings to find:\n"
    iMenu += "\tas - ASCII strings\t["
    iMenu += "x" if bAsciiStrings else " "
    iMenu += "]\n"
    iMenu += "\twc - Wide char strings\t["
    iMenu += "x" if bWideCharStrings else " "
    iMenu += "]\n"
    iMenu += "\tps - Push stack strings\t["
    iMenu += "x" if bPushStackStrings else " "
    iMenu += "]\n"
    iMenu += "\tall - All strings\t["
    iMenu += "x" if bAllStrings else " "
    iMenu += "]\n\n"
    iMenu += "h - Show options.\n"
    iMenu += "g - Toggle selections.\n"
    iMenu += "c - Clear selections.\n"
    iMenu += "p - Print found strings.\n"
    iMenu += "m - Change minimum shellcode length.\n"
    iMenu += "z - Find strings.\n"
    iMenu += "r - reset found strings.\n"
    iMenu += "x - Exit.\n"
    print(iMenu)


def showStringSelections(
    bAsciiStrings, bWideCharStrings, bPushStackStrings, bAllStrings, s
):
    iMenu = "\nSelections changed.\n\n"
    iMenu += "Strings to find:\n"
    iMenu += "\tas - ASCII strings\t["
    iMenu += "x" if bAsciiStrings else " "
    iMenu += "]\n"
    iMenu += "\twc - Wide char strings\t["
    iMenu += "x" if bWideCharStrings else " "
    iMenu += "]\n"
    iMenu += "\tps - Push stack strings\t["
    iMenu += "x" if bPushStackStrings else " "
    iMenu += "]\n"
    iMenu += "\tall - All strings\t["
    iMenu += "x" if bAllStrings else " "
    iMenu += "]\n\n"
    print(iMenu)


def importsMenu():
    iMenu = ""
    iMenu += "h - Show options.\n"
    iMenu += "p - Print imports.\n"
    iMenu += "z - Execute.\n"
    iMenu += "r - reset found imports.\n"
    iMenu += "x - Exit.\n"
    print(iMenu)
