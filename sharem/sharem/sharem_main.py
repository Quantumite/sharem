from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import re
import pefile
import sys
import binascii
import os
import ctypes
from ctypes import *
import typing
from typing import Literal, Optional
from dataclasses import dataclass
import copy

import time
import timeit
import string
import csv
import json
import datetime
import colorama
import ast
from argparse import Namespace
import hashlib
import platform
import textwrap3
import traceback

from sharem.sharem.helper.variable import Variables
from sharem.sharem.assemblyx86 import retR32
from sharem.sharem.helper.jsonPrinting import jsonPrint
from sharem.sharem.helper.shellcodeClass import shellcode
from sharem.sharem.helper.sharemuDeob import sharDeobf
from sharem.sharem.helper.listhelpers import get_max_length
from sharem.sharem.helper.printingOutput import PrintingOutput
from sharem.sharem.helper.emuHelpers import ord2
from sharem.sharem.parseconf import Configuration
from sharem.sharem.modules import em
from sharem.sharem.lists import (
    SYSCALL_BOOL_DICT,
    FFInstructions,
    PEB_WALK,
    FSTENV_GET_BASE,
    PEB_WALK_MOV_64,
    CALLPOP_START,
    EGGHUNT,
    PUSH_RET,
    HEAVEN,
)
from sharem.sharem.DLLs.emu_helpers.sharem_filesystem import Directory_system
from sharem.sharem.DLLs.hookAPIs import art
from sharem.sharem.ui import (
    showOptions,
    emulatorUI,
    emuSyscallPrintSubMenu,
    emuSimValuesMenu,
    emuCodeCoverageUI,
    instructionsMenu,
    displayCurrentInstructions,
    displayCurrentSelections,
    disPrintStyle,
    disToggleMenu,
    techSettingsMenu,
    cpTechMenu,
    globalTechMenu,
    printBitMenu,
    printMenu,
    printModulesMenu,
    syscallPrintSubMenu,
    stringMenu,
    showStringSelections,
    shellcodeStringMenu,
)
from sharem.sharem.sharemu import (
    startEmu,
    loggedList,
    logged_syscalls,
    logged_dlls,
    findArtifacts,
    bAddReadThriceTuple,
    bAddReadTuple,
    bAddReadTwiceTuple,
    bAddWriteThriceTuple,
    bAddWriteTuple,
    bAddWriteTwiceTuple,
    CODE_ADDR,
    traversedAdds,
)
import sharem.sharem.constants as constants
from sharem.sharem.selfModify import austinDecode


platformType = platform.uname()[0]

slash = ""
if platformType == "Windows":
    slash = "\\"
else:
    slash = "/"
try:
    import ssdeep
except:
    print(
        "Ssdeep needs to be installed. A Windows Python wrapper is available:\nhttps://github.com/Bw3ll/ssdeep-windows-32_64 \nThe Linux version of SSDeep is here:\nhttps://github.com/DinoTools/python-ssdeep"
    )

try:
    if platformType == "Windows":
        import win32api
        import win32con
        import win32file
        import _win32sysloader
except:
    print(
        "Pywin32 needs to be installed.\nhttps://pypi.org/project/pywin32/\n\tThe setup.py is not always effective at installing Pywin32, so it may need to be manually done.\n"
    )

colorama.init()


class IATS:
    def __init__(self):  # , name):
        """Initializes the data."""
        self.name = ""
        self.entries = []
        self.SearchedFully = False
        self.path = []


class FoundIATs:
    def __init__(self):  # , name):
        """Initializes the data."""
        self.found = []
        self.foundDll = []
        self.path = []
        self.originate = []


class patterns:
    def __init__(self):
        self.path_pattern = 0
        self.lang_pattern = 0
        self.dotted_w_pattern = 0
        self.variable_pattern = 0

    def getPatterns(self):
        return (
            self.path_pattern,
            self.lang_pattern,
            self.dotted_w_pattern,
            self.variable_pattern,
        )


class shellHash:
    def __init__(self, shell=None, mode=None):
        if shell:
            self.ssdeep = ssdeep.hash(shell)  # @TODO data must be binary or text
            self.md5sum = hashlib.md5(shell).hexdigest()
            self.sha256 = hashlib.sha256(shell).hexdigest()
        self.mode = mode

    def show(self):
        if self.mode is None:
            out = constants.MAGENTA + "Shellcode hashes\n" + constants.RESET
        elif self.mode == unencryptedBodyShell:
            out = (
                constants.MAGENTA + "Decoded shellcode body hashes\n" + constants.RESET
            )
        elif self.mode == decoderShell:
            out = (
                constants.MAGENTA + "Shellcode decoder stub hashes\n" + constants.RESET
            )
        elif self.mode == unencryptedShell:
            out = (
                constants.MAGENTA + "Decoded shellcode (all) hashes\n" + constants.RESET
            )

        out += constants.YELLOW + "\tmd5: " + constants.RESET + self.md5 + "\n"
        out += constants.YELLOW + "\tsha256: " + constants.RESET + self.sha256 + "\n"
        out += constants.YELLOW + "\tssdeep: " + constants.RESET + self.ssdeep + "\n"
        return out


s = []  # start sections
list_of_files = []
list_of_files32 = []
list_of_files64 = []
list_of_pe32 = []
list_of_pe64 = []

SimFileSystem = Directory_system()

list_of_unk_files = []
sharem_out_dir = "current_dir"
emulation_verbose = True

labels = set()
offsets = set()
off_Label = set()
off_PossibleBad = set()

elapsed_time = 0
doneAlready1 = []
syscallString = ""
chMode = False
sections = []
numArgs = len(sys.argv)
peName = ""
PEsList = []
PE_path = ""
PEsList_Index = 0
skipZero = False
numPE = 1
skipPath = False
FoundApisAddress = []
FoundApisName = []

shellEntry = 0x00
decodedBytes = b""
maxZeroes = 0
shellEntry = 0x0
useDirectory = False

GPA = ""
pe = ""
GPAl = []
MAl = []
Remove = []
fname = ""
entryPoint = 0
VirtualAdd = 0
ImageBase = 0
vSize = 0
startAddress = 0
endAddy = 0
gName = ""
o: str = (
    constants.ShellcodeLabel.SHELLCODE_LABEL
)  # seems to be the label access information in the `m` object
sectionName = ""
cs = Cs(CS_ARCH_X86, CS_MODE_32)
cs64 = Cs(CS_ARCH_X86, CS_MODE_64)
directory = ""
newpath = ""
PEtemp = ""
PE_DLL = []
PE_DLLS = []
PE_DLLS2 = []
paths = []
bit32 = True
PE_Protect = ""
index = 0
CheckallModules = False
present = []
new = []
new2 = []
deeperLevel = []
asciiMode = "ascii"
stringsTemp = []
stringsTempWide = []
pushStringsTemp = []
filename = ""
filename2 = ""
filenameRaw = ""
skipExtraction = False
rawHex = False
rawData2 = b""
useHash = False
known_arch = False
numArgs = len(sys.argv)
rawBin = False  # only if .bin, not .txt
isPe = False
pointsLimit = 3
maxDistance = 15
useStringsFile = False
minStrLen = 6
mEAX = ""
mEBX = ""
mEDX = ""
mECX = ""
mEBP = ""
mESP = ""


gDisassemblyText = ""
gDisassemblyTextNoC = ""
emulation_multiline = False
# Moved from viewBool's work area
linesForward = 40
bPushRet = True
bFstenv = True
bSyscall = True
bHeaven = True
bCallPop = True
bPrintEmulation = True
bDisassembly = True
bAnaHiddenCallsDone = False
bAnaConvertBytesDone = False
bAnaFindStrDone = False
deobfShell = True
fastMode = False
pebPoints = 3
p2screen = True
configOptions = {}
print_style = "left"
stubFile = "stub.txt"
sameFile = True
stubEntry = 0
stubEnd = 0
shellSizeLimit = 120
conFile = str("config.cfg")
workDir = False
bit32_argparse = False
save_bin_file = True
linesForward = 7
linesBack = 10
bytesForward = 15
bytesBack = 15
unencryptedShell = 0x0
decoderShell = 0x1
unencryptedBodyShell = 0x3
sample = 0x4
allObject = 0x5
gDirectory = ""  # #used to hold original directory --immutable
debugging = False

emuObj = None
patt = patterns()
sBy = None
IATs: FoundIATs = None

syscallRawHexOverride = False
heavRawHexOverride = False
fstenvRawHexOverride = False

emuSyscallSelection = copy.deepcopy(SYSCALL_BOOL_DICT)
emuSyscallCode = ""
fRaw = sharDeobf()
printOut = PrintingOutput()


GoodStrings = {
    "cmd",
    "net",
    "add",
    "win",
    "http",
    "dll",
    "sub",
    "calc",
    "https",
    "recv",
}
toggList = {
    "findString": True,
    "deobfCode": False,
    "findShell": False,
    "comments": True,
    "hidden_calls": True,
    "show_ascii": True,
    "ignore_dis_discovery": False,
    "opcodes": True,
    "labels": True,
    "offsets": True,
    "max_opcodes": 8,
    "binary_to_string": 3,
}

brawHex = ""
bstrLit = ""
bfindString = True
bdeobfCode = False
bdeobfCodeFound = False

bfindShell = True
bfindShellFound = False
##add in the current directory later, as right now this will only output to the logs folder

jsonP = jsonPrint(filename=filename, rawHex=rawHex)


def isPE(file_path: str) -> bool:
    """Check for MZ bytes in file given by file_path."""
    mz = b"\x4d\x5a"
    with open(file_path, "rb") as hnd:
        mzFile = hnd.read(2)
    return mzFile == mz


@dataclass
class SharemContext:
    """Class holding context values for running SHAREM."""

    fullFileName: str
    baseFileName: str
    shellcodeArch: Optional[Literal[32, 64]]
    peArch: Optional[Literal[32, 64]]
    fileExtension: str  # if txt extension, treat as rawHex
    rawData: bytes
    platformType: str
    confFile: str


def CliParser(args: Namespace) -> SharemContext:
    """Parse command-line arguments into SharemContext."""

    platformType = platform.uname()[0]

    if args.r or args.r64 or args.r32:
        if args.r:
            fullFileName = args.r
            shellcodeArch = 32

        if args.r32:
            fullFileName = args.r32
            shellcodeArch = 32

        elif args.r64:
            fullFileName = args.r64
            shellcodeArch = 64

        if os.path.isfile(fullFileName):
            baseFileName = os.path.basename(fullFileName)
            if len(fullFileName) > 3:
                fileExtension = baseFileName[-3:]

        else:
            raise FileNotFoundError(f"{fullFileName} file doesn't exist")

    peArch = None
    if args.pe:
        if os.path.isfile(args.pe):
            fullFileName = args.pe
            baseFileName = os.path.basename(args.pe)
            if platformType == "Windows":
                if win32file.GetBinaryType(args.pe) == 6:
                    peArch = 64
                else:
                    peArch = 32
            else:
                peArch = 32
        else:
            raise FileNotFoundError(f"{args.pe} file does not exist.")

    confFile = "config.cfg"
    if args.c:
        if os.path.isfile(args.c):
            confFile = args.c
            print(f"Config path is: {confFile}")
        else:
            raise FileNotFoundError(f"{args.c} file does not exist.")

    # @TODO re-enable analysis in directory later
    # if args.d:
    # useDirectory = True
    # if os.path.isdir(args.d):
    # workingDir = args.d
    # workDir = True
    # for path in os.listdir(workingDir):
    # full_path = os.path.join(workingDir, path)
    # if os.path.isfile(full_path):
    # if isPE(full_path):
    # if platformType == "Windows":
    # if win32file.GetBinaryType(full_path) == 6:
    # bit32 = False
    # list_of_pe64.append(full_path)

    # else:
    # bit32 = True
    # list_of_pe32.append(full_path)

    # peName = full_path
    # gName = path

    # else:
    # bit32 = True
    # list_of_pe32.append(full_path)
    # peName = full_path
    # gName = path

    # else:
    # if not known_arch:
    # rawHex = True
    # gName = path
    # filename = full_path
    # list_of_unk_files.append(full_path)

    # elif pathlib.Path(full_path).is_dir():
    # dirName = os.path.basename(full_path)
    # if "32" in dirName:
    # for f in os.listdir(full_path):
    # ext = f[-3:]
    # if ext == "txt":
    # rawHex = True
    # rawBin = False

    # bit32 = True
    # full_file_path = os.path.join(full_path, f)
    # filename = full_file_path
    # gName = f
    # list_of_files32.append(full_file_path)
    # else:
    # rawHex = True
    # rawBin = True
    # bit32 = True
    # fp = open(f, "rb")
    # rawData2 = fp.read()
    # fp.close()
    # full_file_path = os.path.join(full_path, f)
    # filename = full_file_path
    # gName = f
    # list_of_files32.append(full_file_path)

    # elif "64" in dirName:
    # for f in os.listdir(full_path):
    # ext = f[-3:]
    # if ext == "txt":
    # rawHex = True
    # rawBin = False
    # filename = f
    # bit32 = False
    # full_file_path = os.path.join(full_path, f)
    # list_of_files64.append(full_file_path)
    # else:
    # rawHex = True
    # rawBin = True
    # filename = f
    # bit32 = False
    # fp = open(f, "rb")
    # rawData2 = fp.read()
    # fp.close()
    # full_file_path = os.path.join(full_path, f)
    # list_of_files64.append(full_file_path)

    # else:
    # print("Directory ", full_path, "isn't 32 or 64 bit")
    # continue
    # else:
    # print(args.d, "directory doesn't exist")
    # sys.exit()
    return SharemContext(
        fullFileName,
        baseFileName,
        shellcodeArch,
        peArch,
        fileExtension,
        None,
        platformType,
        confFile,
    )


def clearConsole():
    """Run `cls` in windows and `clear` in *nix."""
    os.system(f"{'cls' if os.name in ('nt', 'dos') else 'clear'}")


class OSVersion:
    # Used for list of OSVersions to print for syscall
    def _init_(self, name, category, toggle, code):
        self.name = name  # Version, e.g. SP1
        self.category = category  # OS, e.g. Windows 10
        self.toggle = toggle  # To print or not
        self.code = code  # The opcode, e.g. xp1
        # ^Used for selection


class MyBytes:
    def __init__(self, nameOfType, rawD, name):  # , name):
        """Initializes the data."""
        self.peName = "peName"
        self.shellcode_label = nameOfType
        self.name = name
        self.modName = "modName"
        self.pe = pe  # pefile.PE(self.peName)
        self.data2 = 0
        self.rawData2 = rawD
        self.VirtualAdd = 0
        self.ImageBase = 0
        self.vSize = 0
        self.SizeOfRawData = 0
        self.startLoc = 0
        self.endAddy = 0
        self.entryPoint = 0
        self.sectionName = "sectionName"
        self.protect = ""
        self.depStatus = ""
        self.aslrStatus = ""
        self.sehSTATUS = ""
        self.CFGstatus = ""
        self.md5 = 0
        self.sha256 = 0
        self.ssdeep = 0
        self.Imports = []
        self.Hash_sha256_section = ""
        self.Hash_md5_section = ""
        self.Strings = []  # tuple - strings, starting offset
        self.pushStrings = []
        self.wideStrings = []  # tuple - strings, starting offset
        self.save_PEB_info = []
        self.save_PushRet_info = []
        # self.sectionStart =0 ### image base + virtual address
        self.save_FSTENV_info = []  # tuple - addr, NumOps, modSecName, secNum
        self.save_Egg_info = []  # tuple - addr, NumOps, modSecName, secNum
        self.save_Callpop_info = []  # tuple - addr, NumOps, modSecName, secNum, pop_offset
        self.save_Heaven_info = []

    def setShellName(self, n):
        self.shellName = n

    def setName(self, n):
        self.name = n

    def setHashes(self):
        ssdeepHash = ssdeep.hash(self.rawData2)
        md5sum = hashlib.md5(self.rawData2).hexdigest()
        sha256 = hashlib.sha256(self.rawData2).hexdigest()
        self.md5 = md5sum
        self.sha256 = sha256
        self.ssdeep = ssdeepHash

    def setHashesPE(self):
        global peName
        print(peName)
        ssdeepHash = ssdeep.hash(open(peName, "rb").read())
        md5sum = hashlib.md5(open(peName, "rb").read()).hexdigest()
        sha256 = hashlib.sha256(open(peName, "rb").read()).hexdigest()
        self.md5 = md5sum
        self.sha256 = sha256
        self.ssdeep = ssdeepHash

    def getHashes(self):
        # out=constants.MAGENTA +"Shellcode hashes\n"+constants.RESET
        out += constants.YELLOW + "\tmd5: " + constants.RESET + self.md5 + "\n"
        out += constants.YELLOW + "\tsha256: " + constants.RESET + self.sha256 + "\n"
        out += constants.YELLOW + "\tssdeep: " + constants.RESET + self.ssdeep + "\n"
        return out

    def getMd5(self):
        return self.md5

    def getSsdeep(self):
        return self.ssdeep

    def getSha256(self):
        return self.sha256


def findDecoderStubEnd(test1, test2):
    for t, each in enumerate(test1):
        if each != test2[t]:
            return t


def emuDeobfuSuccess(
    shell_code: shellcode, emBytes, mode: constants.ModeEnum
) -> tuple[Optional[shellHash], Optional[shellHash], Optional[shellHash]]:
    print("  This may be self-modifying code. Switching to decoded shellcode.")
    decoderstub_hash = None
    decodedfullbody_hash = None
    unencrypted_shell_hash = None

    shell_code.setDecoded(emBytes)
    shell_code.decryptSuccess = True
    if mode == "stub":
        decoderstub_hash = shellHash(
            shell_code.decoderStub, constants.ModeEnum.DECODERSHELL
        )
        decodedfullbody_hash = shellHash(
            shell_code.decodedFullBody, constants.ModeEnum.UNENCRYPTEDBODYSHELL
        )
    else:
        unencrypted_shell_hash = shellHash(emBytes, constants.ModeEnum.UNENCRYPTEDSHELL)

    module[constants.ShellcodeLabel.SHELLCODE_DECODED_FULL_LABEL] = newModule(
        constants.ShellcodeLabel.SHELLCODE_DECODED_FULL_LABEL, emBytes
    )  # This feels like it should be stub and full but it's not in the code so optimizing as-is
    return (decoderstub_hash, decodedfullbody_hash, unencrypted_shell_hash)


class DisassemblyBytes:
    def __init__(self):  #
        """Initializes the data."""
        self.offsets = []  # starting offsets of bytes - may not always be 0 or 1
        self.values = []  # the hex value
        self.ranges = []  # does it identify ranges?
        self.bytesType = []
        self.strings = []  # TRUE if strings, false if not
        self.stringsStart = []  # offset the strings starts @
        self.stringsValue = []
        self.pushStringEnd = []
        self.pushStringValue = []
        self.boolPushString = []
        self.specialVal = []  # align, FF
        self.boolspecial = []
        self.specialStart = []
        self.specialEnd = []
        self.comments = []
        self.shDisassemblyLine = []
        self.shAddresses = []
        self.shMnemonic = []
        self.shOp_str = []
        self.shCodes = []
        self.gDisassemblyText = ""
        self.gDisassemblyTextNoC = ""
        self.ApiTable = []
        self.ApiStart = []
        self.ApiEnd = []
        self.ApiValue = []
        self.dataAccessed = []
        self.dataAccessedSize = []

    def dataAccessedFunc(self, values):
        accessStart = values[0]
        accessStart = accessStart - CODE_ADDR
        size = values[1]

        i = accessStart
        for x in range(size):
            self.dataAccessed[i] = True
            self.dataAccessedSize[i] = (accessStart, size)
            i = i + 1


def clearDisassemblyBytesClass():
    global sBy
    sBy.offsets.clear()
    sBy.values.clear()
    sBy.ranges.clear()
    sBy.bytesType.clear()
    sBy.strings.clear()
    sBy.stringsStart.clear()
    sBy.stringsValue.clear()
    sBy.pushStringEnd.clear()
    sBy.pushStringValue.clear()
    sBy.boolPushString.clear()
    sBy.specialVal.clear()
    sBy.boolspecial.clear()
    sBy.specialStart.clear()
    sBy.specialEnd.clear()
    sBy.comments.clear()
    sBy.ApiTable.clear()
    sBy.ApiStart.clear()
    sBy.ApiEnd.clear()
    sBy.ApiValue.clear()
    sBy.dataAccessed.clear()
    sBy.dataAccessedSize.clear()


def newModule(
    nameOfType: Optional[constants.ShellcodeLabel],
    sharemContext: SharemContext,
    variables: Variables,
) -> MyBytes:
    show = False
    if show:
        out = (
            constants.MAGENTA
            + "new module "
            + sharemContext.fullFileName
            + constants.RESET
        )
        if rawHex:
            out += " - shellcode -  len rawdata2: " + (str(len(sharemContext.rawData)))
        else:
            out += " -pe file"

    obj = MyBytes(nameOfType, sharemContext.rawData, sharemContext.fullFileName)
    obj.setShellName(nameOfType)
    obj.setName(sharemContext.fullFileName)

    if variables.rawHex:
        obj.setHashes()
        variables.moduleBooleans[nameOfType].name = sharemContext.fullFileName
    else:  # pe file
        obj.setHashesPE()
        obj.setShellName("pe")
        variables.moduleBooleans[
            sharemContext.fullFileName
        ].name = sharemContext.fullFileName  # name of pe file is the key

    if show:
        print(out)
        print(constants.GREEN + "# mods" + constants.RESET, len(m))

    return obj


def newSection(filename: str, my_bytes_list: list):
    obj = MyBytes("pe", 0, filename)
    my_bytes_list.append(obj)


def stripWhite(str1):
    """Strip null-byte and \r\n from string."""
    if isinstance(str1, str):
        str1 = str1.strip(b"\x00\x0a\x0d")
        return str1
    return str1


def stripSpec(str1):
    print("stripSpec")
    str1 = str1.strip("\x17")
    return str1


def getLast(absoluteAddress):
    try:
        absoluteAddress = absoluteAddress.decode()
    except:
        pass

    absoluteAddress = str(absoluteAddress)
    array = absoluteAddress.split(slash)
    new = ""
    for word in array:
        new = word
    last = len(array) - 1
    return array[last].lower()


def addIAT(dll, org):
    global IATs
    global peName
    global paths
    tempPaths = []
    truePath = " "
    try:
        dll = dll.decode()
    except:
        pass
    try:
        org = org.decode()
    except:
        pass
    for y in paths:
        tempPaths.append(getLast(y))

    properName = ""
    for x in iatList:
        try:
            x.name = x.name.decode()
        except:
            pass
        if x.name.lower() == dll.lower():
            properName = x.name
            t = 0
            for w in tempPaths:
                if w == x.name.lower():
                    truePath = paths[t]
                t += 1

    if (dll.lower() == getLast(peName).lower()) or (dll.lower() == peName.lower()):
        truePath = " "

    dllLower = dll.lower()
    if dll not in IATs.found:
        if properName == "":
            properName = dll

        IATs.found.append(dllLower)
        IATs.foundDll.append(properName)
        IATs.originate.append(org)
        if (dll.lower() == getLast(peName).lower()) or (dll.lower() == peName.lower()):
            pass
        else:
            IATs.path.append(truePath)
        if dllLower == "msvcrt.dll":
            IATs.found.append(
                "sechost.dll"
            )  ### not sure how/why sechost gets on? hardcoding
            IATs.foundDll.append("sechost.dll")
            if bit32:
                IATs.path.append("C:\Windows\SysWOW64\sechost.dll")
            else:
                IATs.path.append("C:\Windows\System32\sechost.dll")
            IATs.originate.append("advapi32.dll")


def dep(pe: pefile.PE) -> bool:
    return bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100)


def aslr(pe: pefile.PE) -> bool:
    return bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040)


def seh(pe: pefile.PE) -> bool:
    return bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400)


def CFG(pe: pefile.PE) -> bool:
    return bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000)


def Extraction():
    # print("Extraction")
    global entryPoint
    global VirtualAdd
    global ImageBase
    global vSize
    global startAddress
    global endAddy
    global o
    global peName
    global index
    global pe

    try:
        head, tail = os.path.split(peName)
    except Exception as e:
        print(e)
        pass
    PEtemp = PE_path + "/" + peName
    if not skipPath:
        pe = pefile.PE(peName)
    if skipPath:
        pe = pefile.PE(PEtemp)

    old = o
    m[o].modName = peName
    m[o].entryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    m[o].VirtualAdd = pe.sections[0].VirtualAddress
    m[o].ImageBase = pe.OPTIONAL_HEADER.ImageBase
    m[o].vSize = pe.sections[0].Misc_VirtualSize
    m[o].startLoc = m[o].VirtualAdd + m[o].ImageBase
    m[o].endAddy = m[o].startLoc + m[o].vSize
    m[o].endAddy2 = m[o].startLoc + m[o].vSize
    m[o].sectionName = pe.sections[0].Name
    m[o].SizeOfRawData = pe.sections[0].SizeOfRawData
    m[o].Hash_sha256_section = pe.sections[0].get_hash_md5()
    m[o].Hash_md5_section = pe.sections[0].get_hash_sha256()

    o = old
    tem = 0

    m[o].data2 = pe.sections[0].get_data()[0:]

    m[o].protect = str(peName) + "\t"
    m[o].depStatus = dep(pe)
    m[o].aslrStatus = aslr(pe)
    m[o].sehSTATUS = seh(pe)
    m[o].CFGstatus = CFG(pe)
    m[o].protect = (
        m[o].protect
        + str(m[o].depStatus)
        + str(m[o].aslrStatus)
        + str(m[o].sehSTATUS)
        + str(m[o].CFGstatus)
    )


def findEvilImports():
    global FoundApisAddress
    for item in pe.DIRECTORY_ENTRY_IMPORT:
        for i in item.imports:
            FoundApisName.append(tuple((item.dll, i.name, hex(i.address))))
    moduleBooleans[shellcode_label].bEvilImportsFound = True


def showImports(out2File=None):
    apis = []
    for dll, api, offset in FoundApisName:
        apis.append(api.decode())
    maxLen = get_max_length(apis)
    # print(maxLen)

    cat = ""
    cat += "\n***************\n"
    cat += "   Imports\n"
    cat += "***************\n\n"

    catNoClr = cat
    # print("{:>{x}}[{}]".format("", constants.GREEN + "Found" + res, x=15+(maxLen-curLen)))
    for dll, api, offset in FoundApisName:
        try:
            curLen = len(api.decode())
            # cat += constants.YELLOW +api.decode()  + "\t" + constants.CYAN + dll.decode() + "\t"+ constants.RED + str(offset)+ constants.RESET + "\n"
            cat += "{}{:>{x}} {}  {}\n".format(
                constants.YELLOW + api.decode(),
                "",
                constants.CYAN + dll.decode(),
                constants.RED + str(offset) + constants.RESET,
                x=5 + (maxLen - curLen),
            )
            catNoClr += "{}{:>{x}} {}  {}\n".format(
                api.decode(), "", dll.decode(), str(offset), x=5 + (maxLen - curLen)
            )

        except:
            pass
    if out2File:
        return catNoClr
    return cat


def curIAT():
    ans = len(iatList)
    return ans - 1


def searchIATName(term):
    # input("in searchname")
    # print "searchIatname " + term
    z = 0
    try:
        term = term.decode()
    except:
        pass

    for x in iatList:
        try:
            x.name = x.name.decode()
        except:
            pass
        if term.lower() == x.name.lower():
            # input("name match")
            return True
    return False


def addDeeper(dll):
    global deeperLevel
    dll = dll.lower()
    # print "add " + dll
    if dll not in deeperLevel:
        deeperLevel.append(dll)


def InMem2():
    global IATs
    global peName
    dprint2(len(IATs.foundDll))
    IATs.found.append(peName.lower())
    IATs.foundDll.append(peName)
    IATs.path.append("")
    IATs.originate.append("")
    addIAT(b"NTDLL.dll", b"IAT")  # 2
    addIAT(b"KERNEL32.dll", b"IAT")  # 3
    addIAT(b"KERNELBASE.dll", b"IAT")  # 4
    for t, dll in enumerate(iatList[0].entries):
        try:
            dll = dll.decode()
        except:
            pass
        if dll.lower() not in IATs.found:
            try:
                addDeeper(iatList[t].name)
                addIAT(dll, iatList[t].name)
            except:
                pass
            old = dll
            truth = searchOld(old)
            if not truth:
                truth = searchOld(old)


def giveLoadedModules(mode=None):
    global IATs
    global filename
    t = 0
    out = constants.YELLOW + "\nLoaded Modules\n\n" + constants.RESET
    for x in IATs.foundDll:
        try:
            x = x.decode()
        except:
            pass
        try:
            IATs.path[t] = IATs.path[t].decode()
        except:
            pass
        try:
            IATs.originate[t] = IATs.originate[t].decode()
        except:
            pass
        fromStr = ""

        if IATs.originate[t] != "":
            fromStr = constants.YELLOW + " from " + constants.CYAN + IATs.originate[t]
        out += (
            constants.GREEN + x + constants.RESET + "\t" + IATs.path[t] + fromStr
        ) + "\n"
        t += 1
    out += (
        constants.RED + "\nTotal: " + constants.RESET + str(len(IATs.originate))
    ) + "\n"

    if filename == "":
        outfile = peName.split(".")[0]
        outfile = peName.split("\\")[-1]
        outfileName = peName
    else:
        outfile = filename.split(".")[0]
        outfile = filename.split("\\")[-1]
        outfileName = filename

    if mode == "text" or mode == "save":
        # out = cleanColors(out)
        if mode == "save":
            out2 = Variables.cleanColors(self=Variables, out=out)
            outfileNoExt = outfile.split(".", 1)[0]
            outfileName = outfileName.split("\\")[-1]
            # txtFileName =  os.getcwd() + slash + outfileNoExt + slash + outfileName + "_" + "loaded_Modules" + ".txt"
            txtFileName = (
                outfileNoExt + slash + outfileName + "_" + "loaded_Modules" + ".txt"
            )
            saveFile = os.path.join(
                os.path.dirname(__file__), "sharem", "logs", txtFileName
            )

            os.makedirs(os.path.dirname(saveFile), exist_ok=True)
            text = open(saveFile, "w")
            text.write(out2)
    return out


def findOldIAT(dll):
    try:
        dll = dll.decode()
    except:
        pass
    dll = dll.lower()
    # print "findoldIAT --->  "  + dll
    if dll not in IATs.found:
        return True, dll
    else:
        return False, ""


def searchOld(old):
    try:
        old = old.decode()
    except:
        pass
    old = old.lower()
    GotOne = False
    for t, x in enumerate(iatList):
        try:
            x.name = x.name.decode()
        except:
            pass
        if x.name.lower() == old:
            for dll in iatList[t].entries:
                try:
                    dll = dll.decode()
                except:
                    pass
                # if dll.lower() not in IATs.found:
                truth, foundDll = findOldIAT(dll)
                if truth:
                    GotOne = True
                    addIAT(foundDll, x.name)
                    addDeeper(x.name)
                    while truth:
                        truth = searchOld(foundDll)
                        if not truth:
                            GotOne = False
                    if not truth:
                        t2 = goInsidePreviouslySearched(x.name.lower())
                        if not t2:
                            return False
    return GotOne


def goInsidePreviouslySearched(old) -> bool:
    GotOne = False
    for x in iatList:
        if x.name.lower() == old.lower():
            for dll in x.entries:
                truth, foundDll = findOldIAT(dll)
                if truth:
                    GotOne = True
                    addIAT(foundDll, x.name)
                    addDeeper(x.name)
                    while truth:
                        truth = searchOld(foundDll)
                        if not truth:
                            GotOne = False

                    if not truth:
                        t2 = searchOld(old)
                        if not t2:
                            if not checkSearchedFully2(dll):
                                t3 = lookInsideDeeper(dll)
                            return False

                if not truth:
                    if not checkSearchedFully2(dll):
                        t3 = lookInsideDeeper(dll)
                    else:
                        return True  # FALSE???


def checkSearchedFully():
    global IATs
    for x in iatList:
        notIn = 0
        for dll in x.entries:
            if dll.lower() not in IATs.found:
                notIn += 1
        if notIn == 0:
            x.SearchedFully = True


def checkSearchedFully2(dll):
    checkSearchedFully()
    for x in iatList:
        if dll == x.name:
            return x.SearchedFully


def lookInsideDeeper(currentDll):
    for x in iatList:
        if x.name == currentDll:
            for dll in x.entries:
                truth, foundDll = findOldIAT(dll)
                if truth:
                    GotOne = True
                    addIAT(foundDll, x.name)
                    addDeeper(x.name)
                    t = searchOld(foundDll)
                    if t == False:
                        if checkSearchedFully2(currentDll) == False:
                            truth = lookInsideDeeper(currentDll)


def getDLLs(pe: pefile.PE, iatList: list, PE_DLLS: list):
    name = ""
    iatList.append(IATs())
    iatList[0].name = "IAT"

    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            iatList[0].entries.append(entry.dll)
            name = entry.dll
            name = name.decode()
            PE_DLLS.append(name)
    except:
        pass


def digDeeper(PE_DLL):
    # print("One deep call")
    global PE_DLLS
    global paths
    global deeper
    doneAlready0 = []
    c = 0
    cont = False

    for dll in PE_DLL:
        # print("PEDLL IS")
        # print(PE_DLL)
        try:
            dll = dll.decode()
        except:
            pass

        # if(dll == "CRYPTBASE.dll"):
        # input("on crypt")
        newpath = ""
        # print("############### DLL #################")
        # print("DLL = " + dll)
        if dll not in doneAlready0:
            # print("done already conditional")
            # print("#########################################")
            # print("APPENDING SOMETHING NEW: " + dll)
            # input("enter...")
            peFound = True
            if platformType == "Windows":
                newpath = extractDLLNew(dll)
                doneAlready0.append(dll)
                paths.append(newpath)
                try:
                    pe = pefile.PE(newpath)
                except:
                    peFound = False
                    name = "Invalid path for " + dll + " "
                    iatList[c].entries.append(name)
                    PE_DLLS.append(name)
        name = ""
        name = ""
        try:
            if peFound:
                cont = False
                if not searchIATName(dll):
                    iatList.append(IATs())
                    c = curIAT()
                    iatList[c].name = dll
                    cont = True

                # print(dll)
                # print(type(pe))
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    name = entry.dll
                    try:
                        name = name.decode()
                    except:
                        # input("enter...")
                        pass

                    # print(name)
                    if cont:
                        apiMSWIN = re.match(r"\bAPI-MS-WIN\b", name, re.M | re.I)
                        if not apiMSWIN:
                            iatList[c].entries.append(name)
                    apiMSWIN = re.match(r"\bAPI-MS-WIN\b", name, re.M | re.I)
                    if not apiMSWIN:
                        if name not in PE_DLLS:
                            PE_DLLS.append(name)  # + " " + dll)
        except Exception:
            # # pass
            # print(e)
            # print(traceback.format_exc())
            # input("EXCPETED")
            pass


def digDeeper2():
    global PE_DLLS
    global paths
    doneAlready = []
    for dll in PE_DLLS:
        try:
            dll = dll.decode()
        except:
            pass
        newpath = ""
        if dll not in doneAlready:
            newpath = extractDLLNew(dll)
            doneAlready.append(dll)
            paths.append(newpath)
            pe = pefile.PE(newpath)
        name = ""
        try:
            cont = False
            if not searchIATName(dll):
                iatList.append(IATs())
                c = curIAT()
                iatList[c].name = dll
                cont = True
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                name = entry.dll
                try:
                    name = name.decode()
                except:
                    pass
                if cont:
                    apiMSWIN = re.match(r"\bAPI-MS-WIN\b", name, re.M | re.I)
                    if not apiMSWIN:
                        iatList[c].entries.append(name)
                apiMSWIN = re.match(r"\bAPI-MS-WIN\b", name, re.M | re.I)
                if not apiMSWIN:
                    doneAlready.append(dll)
                    if name not in PE_DLLS:
                        PE_DLLS.append(name)  # + " " + dll)
        except Exception:
            # print(e)
            # input("deeper2")
            pass


def ObtainAndExtractSections(
    filename: str, iat_list: list, pe_dlls: list, sections: list, my_bytes_list: list
):
    global o
    global t

    pe = pefile.PE(filename)

    getDLLs(pe, iatList, pe_dlls)

    for sec in pe.sections:
        sections.append(sec.Name)

    for t, x in enumerate(pe.sections):
        newSection(peName, my_bytes_list)
        s[t].modName = peName
        s[t].entryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        s[t].VirtualAdd = pe.sections[t].VirtualAddress
        s[t].ImageBase = pe.OPTIONAL_HEADER.ImageBase
        s[t].vSize = pe.sections[t].Misc_VirtualSize
        s[t].startLoc = s[t].VirtualAdd + s[t].ImageBase
        s[t].endAddy = s[t].startLoc + s[t].vSize
        s[t].endAddy2 = s[t].startLoc + s[t].vSize
        s[t].sectionName = stripWhite(pe.sections[t].Name)
        s[t].SizeOfRawData = pe.sections[t].SizeOfRawData

        s[t].Hash_sha256_section = pe.sections[t].get_hash_md5()
        s[t].Hash_md5_section = pe.sections[t].get_hash_sha256()
        tem = 0
        s[t].data2 = pe.sections[t].get_data()[0:]
        s[t].protect = str(peName) + "\t"
        s[t].depStatus = str(dep())
        s[t].aslrStatus = str(aslr())
        s[t].sehSTATUS = str(seh())
        s[t].CFGstatus = str(CFG())
        s[t].protect = (
            s[t].protect
            + s[t].depStatus
            + s[t].aslrStatus
            + s[t].sehSTATUS
            + s[t].CFGstatus
        )

    display = ""
    for r in sections:
        r = stripWhite(r)
        display = display + str(r) + ", "


def extractDLLNew(dllName):
    # print ("extractDLLNew", dllName)
    global o
    global index
    global newpath
    global ans
    global PE_Protect
    global PE_path

    # A very small portin of this loadlibrary comes from: https://www.programcreek.com/python/example/53932/ctypes.wintypes.HANDLE
    # All of the elaborate loading through alternate means is entirely original
    # index = 0
    # print dllName
    # remove if could not be found
    # print("INDEX = " + str(index))
    try:
        dllName = dllName.decode()
    except:
        pass

    # print ("try1")
    newpath = _win32sysloader.GetModuleFilename(dllName) or _win32sysloader.LoadModule(
        dllName
    )
    ans = newpath
    # print ("Success", ans)

    if ans == None:
        try:
            dllHandle = win32api.LoadLibraryEx(
                dllName, 0, win32con.LOAD_LIBRARY_AS_DATAFILE
            )
            windll.kernel32.GetModuleHandleW.restype = wintypes.HMODULE
            windll.kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
            windll.kernel32.GetModuleFileNameW.restype = wintypes.DWORD
            windll.kernel32.GetModuleFileNameW.argtypes = [
                wintypes.HANDLE,
                wintypes.LPWSTR,
                wintypes.DWORD,
            ]
            h_module_base = windll.kernel32.GetModuleHandleW(dllName)
            module_path = ctypes.create_unicode_buffer(255)
            windll.kernel32.GetModuleFileNameW(h_module_base, module_path, 255)
            pe = pefile.PE(module_path.value)
            win32api.FreeLibrary(dllHandle)

            if h_module_base is None:
                directory = PE_path
                # print ("directory", directory)
                newpath = os.path.abspath(os.path.join(directory, dllName))
                if os.path.exists(newpath):
                    module_path.value = newpath
                    ans = newpath
                else:
                    if bit32:
                        directory = r"C:\Windows\SysWOW64"
                        newpath = os.path.abspath(os.path.join(directory, dllName))
                        if os.path.exists(newpath):
                            module_path.value = newpath
                            ans = newpath
                        else:
                            print(
                                "\t\tNote: "
                                + dllName
                                + " will be excluded. Please scan this manually if needed."
                            )
                            Remove.append(dllName)
                    if not bit32:
                        directory = r"C:\Windows\System32"
                        newpath = os.path.abspath(os.path.join(directory, dllName))
                        if os.path.exists(newpath):
                            module_path.value = newpath
                            ans = newpath
                        else:
                            # print "\t\tNote: " + dllName + " will be excluded. Please scan this manually if needed."
                            Remove.append(dllName)
            head, tail = os.path.split(module_path.value)

            if tail != dllName:
                PE_DLLS[index] = tail
                Remove.append(dllName)
            ans = module_path.value

            m[o].protect = str(dllName) + "\t"
            m[o].depStatus = str(dep())
            m[o].aslrStatus = str(aslr())
            m[o].sehSTATUS = str(seh())
            m[o].CFGstatus = str(CFG())
            m[o].protect = (
                m[o].protect
                + m[o].depStatus
                + m[o].aslrStatus
                + m[o].sehSTATUS
                + m[o].CFGstatus
            )
            PE_Protect = PE_Protect + str(m[o].protect)
            # print m[o].protect

            index += 1
        except Exception:
            # print (e)
            # print(traceback.format_exc())

            # print ("a1")

            directory = PE_path
            # print ("directory", directory)
            newpath = os.path.abspath(os.path.join(directory, dllName))
            if os.path.exists(newpath):
                ans = os.path.abspath(os.path.join(directory, dllName))

            else:
                if bit32:
                    directory = r"C:\Windows\SysWOW64"
                    newpath = os.path.abspath(os.path.join(directory, dllName))
                    if os.path.exists(newpath):
                        ans = os.path.abspath(os.path.join(directory, dllName))
                    else:
                        # print "\t\tNote: " + dllName + " will be excluded. Please scan this manually if needed."
                        Remove.append(dllName)
                if not bit32:
                    directory = r"C:\Windows\System32"
                    newpath = os.path.abspath(os.path.join(directory, dllName))
                    if os.path.exists(newpath):
                        ans = os.path.abspath(os.path.join(directory, dllName))
                    else:
                        # print "\t\tNote: " + dllName + " will be excluded. Please scan this manually if needed."
                        Remove.append(dllName)

            m[o].protect = dllName + "\t"
            m[o].depStatus = str(dep())
            m[o].aslrStatus = str(aslr())
            m[o].sehSTATUS = str(seh())
            m[o].CFGstatus = str(CFG())
            m[o].protect = (
                m[o].protect
                + m[o].depStatus
                + m[o].aslrStatus
                + m[o].sehSTATUS
                + m[o].CFGstatus
            )
            PE_Protect = PE_Protect + str(m[o].protect)
            # print m[o].protect

            index += 1
            # print(e)
            # input("EXCEPTED NEWDLL")
            # pass

            # print  "\t* " + str(ans)
            # print(type(dllName))
            # print("CALLED")
    try:
        ans = ans.decode()
    except:
        pass
    try:
        # print ("[*] Found ", dllName, " at ",  newpath)
        # print ("ans", ans,"\n")
        return ans
    except:
        print("Error:", dllName, "was not found. ")
        return ""


def hashesText():
    global o
    global sh

    o = constants.ShellcodeLabel.SHELLCODE_LABEL
    txt = ""
    txt += "md5: " + m[o].getMd5() + "\n"
    txt += "sha256: " + m[o].getSha256() + "\n"
    txt += "ssdeep: " + m[o].getSsdeep() + "\n\n"

    if sh:
        if sh.decryptSuccess:
            previousO = o
            o = constants.ShellcodeLabel.SHELLCODE_DECODED_FULL_LABEL

            txt += "Deobfuscated Shellcode:\n"
            txt += "\tmd5: " + m[o].getMd5() + "\n"
            txt += "\tsha256: " + m[o].getSha256() + "\n"
            txt += "\tssdeep: " + m[o].getSsdeep() + "\n\n"
            txt += "Note: data below is from  deobfuscated shellcode.\n"
            o = previousO
    return txt


def showBasicInfo():
    global shellEntry
    global o
    cat = ""
    # o=0
    dprint2("# m: " + str(len(m)))
    previousO = o
    if rawHex:
        try:
            cat += (
                constants.GREEN
                + "Shellcode Entry point: "
                + constants.RESET
                + str(hex(shellEntry))
                + "\n"
            )
            cat += hashesText()
        except TypeError:
            cat += (
                constants.GREEN
                + "Shellcode Entry point: "
                + constants.RESET
                + str(shellEntry)
                + "\n"
            )
            cat += hashesText()
        o = previousO
    else:
        for o in m:
            cat += m[o].modName.decode() + "\n"
            (
                cat
                + constants.GREEN
                + "Section: "
                + constants.RESET
                + str(m[0].sectionName)
                + "\n"
            )
            cat += (
                constants.GREEN
                + "Entry point: "
                + constants.RESET
                + str(hex(m[o].entryPoint))
                + "\n"
            )
            cat += (
                constants.GREEN
                + "Virtual Address: "
                + constants.RESET
                + str(hex(m[o].VirtualAdd))
                + "\n"
            )
            cat += (
                constants.GREEN
                + "ImageBase: "
                + constants.RESET
                + str(hex(m[o].ImageBase))
                + "\n"
            )
            cat += (
                constants.GREEN
                + "VirtualSize: "
                + constants.RESET
                + str(hex(m[o].vSize))
                + "\n"
            )
            cat += (
                constants.GREEN
                + "Size of section: "
                + constants.RESET
                + str(hex(m[o].data2))
                + "\n"
            )
            cat += (
                constants.GREEN + "DEP: " + constants.RESET + str(m[o].depStatus) + "\n"
            )
            cat += (
                constants.GREEN
                + "ASLR: "
                + constants.RESET
                + str(m[o].aslrStatus)
                + "\n"
            )
            cat += (
                constants.GREEN + "SEH: " + constants.RESET + str(m[o].sehSTATUS) + "\n"
            )
            cat += (
                constants.GREEN + "CFG: " + constants.RESET + str(m[o].CFGstatus) + "\n"
            )
            cat += "\n"
            cat += ""
    # 	o+=1
    # o=0
    return cat


def showBasicInfoSections():
    global gName
    dprint2("showBasicInfoSections")
    cat = ""
    t = 0
    # dprint2 ("# s: " + str(len(s)))
    cat += constants.MAGENTA + (gName) + "\n"
    cat += constants.GREEN + "Md5: " + constants.RESET + str(m[o].getMd5()) + "\n"
    cat += constants.GREEN + "Sha256: " + constants.RESET + str(m[o].getSha256()) + "\n"
    cat += (
        constants.GREEN + "Ssdeep: " + constants.RESET + str(m[o].getSsdeep()) + "\n\n"
    )

    cat += "\nSection info\n\n"
    for each in s:
        cat += (
            "Section:"
            + constants.YELLOW
            + s[t].sectionName.decode()
            + constants.RESET
            + "\n"
        )
        # cat +="Section: " + str(m[0].sectionName) +"\n"
        cat += (
            constants.GREEN
            + "Entry point: "
            + constants.RESET
            + str(hex(s[t].entryPoint))
            + "\n"
        )
        cat += (
            constants.GREEN
            + "Virtual Address: "
            + constants.RESET
            + str(hex(s[t].VirtualAdd))
            + "\n"
        )
        cat += (
            constants.GREEN
            + "ImageBase: "
            + constants.RESET
            + str(hex(s[t].ImageBase))
            + "\n"
        )
        cat += (
            constants.GREEN
            + "VirtualSize: "
            + constants.RESET
            + str(hex(s[t].vSize))
            + "\n"
        )
        cat += (
            constants.GREEN
            + "SizeOfRawData: "
            + constants.RESET
            + str(hex(s[t].SizeOfRawData))
            + "\n"
        )
        cat += (
            constants.GREEN
            + "VirtualAddress: "
            + constants.RESET
            + str(hex(s[t].VirtualAdd))
            + "\n"
        )
        cat += (
            constants.GREEN
            + "ImageBase + sec. virtual address: "
            + constants.RESET
            + str(hex(s[t].startLoc))
            + "\n"
        )
        cat += (
            constants.GREEN
            + "Actual size of section: "
            + constants.RESET
            + str(hex(len(s[t].data2)))
            + "\n"
        )
        cat += constants.GREEN + "DEP: " + constants.RESET + str(s[t].depStatus) + "\n"
        cat += (
            constants.GREEN + "ASLR: " + constants.RESET + str(s[t].aslrStatus) + "\n"
        )
        cat += constants.GREEN + "SEH: " + constants.RESET + str(s[t].sehSTATUS) + "\n"
        cat += constants.GREEN + "CFG: " + constants.RESET + str(s[t].CFGstatus) + "\n"

        cat += (
            constants.GREEN
            + "Sha256: "
            + constants.RESET
            + s[t].Hash_sha256_section
            + "\n"
        )
        cat += (
            constants.GREEN + "md5: " + constants.RESET + s[t].Hash_md5_section + "\n"
        )
        cat += "\n"
        cat += ""
        t += 1
    t = 0
    return cat


def show1(int):
    show = "{0:02x}".format(int)  #
    return show


def me(mode=None):
    print(sys._getframe().f_lineno)
    if mode == 1:
        input()


def toString(input1):
    result = ""
    zz = ""
    extra = ""
    for y in input1:
        zz = "{0:02x}".format(y)  #
        if (y > 31) & (y < 127):
            try:
                zz = int(zz, 16)
                zz = chr(zz)
            except:
                zz = "."
        else:
            zz = "."
        result += zz
    return result


def binaryToStr(binary, mode=None):
    newop = ""

    try:
        if mode == None or mode == 1:
            for v in binary:
                newop += "\\x" + "{0:02x}".format(v)  #   e.g \\xab\\xac\\xad\\xae
            return newop
        elif mode == 2:
            for v in binary:
                newop += "{0:02x}".format(v)  #   e.g abacadae
                # print ("newop",newop)
            return newop
        elif mode == 3:
            for v in binary:
                newop += "{0:02x} ".format(v)  #   e.g ab ac ad ae
            return newop
    except Exception as e:
        print("*Not valid format")
        print(e)


def Text2Json(shell, jsonOut=None):
    global filename

    time = datetime.datetime.now()
    filetime = time.strftime("%Y%m%d_%H%M%S")

    raw_shellcode = shell
    raw_hex = raw_shellcode[0]
    raw_hex = raw_hex.replace("\n", "")  # remove new lines
    raw_hex = raw_hex.replace('"', "")  # remove double quotes
    raw_hex = raw_hex.split(":")[1]  # read only shellcode and ignore "Raw Hex:"

    str_lit = raw_shellcode[1]
    str_lit = str_lit.replace("\n", "").replace(
        '"', ""
    )  # remove new lines and double quotes
    str_lit = str_lit.split(":")[1]
    shellcode_dict = {"rawhex": raw_hex, "strlit": str_lit}

    # print(shellcode_dict)
    if jsonOut is not None:
        return shellcode_dict
    fileName = (
        "rawhex" + "_" + filename + "_" + filetime + ".json"
    )  # @TODO this needs more processing, does not strip off folder information from input args

    outDir = os.getcwd() + slash + "outputs" + slash
    fullPath = outDir + fileName
    os.makedirs(os.path.dirname(outDir), exist_ok=True)

    try:
        with open(fullPath, "w") as outfile:
            json.dump(shellcode_dict, outfile, indent=4)

        print("\n" + fileName + "\n")
    except Exception as e:
        print(e)


def binaryToText(binary, json=None):
    global brawHex
    global bstrLit
    strLit = ""
    rawH = ""
    arrayLit = ""
    returnVal = ""
    try:
        for v in binary:
            i = ord2(v)
            strLit += "\\x" + show1(i)
            rawH += show1(i)
            arrayLit += "0x" + show1(i) + ", "
        brawHex = rawH
        bstrLit = strLit

        rawHwColor = (
            constants.YELLOW
            + "\nRaw Hex:\n"
            + constants.RESET
            + '"'
            + constants.GREEN
            + rawH
            + constants.RESET
            + '"\n'
        )
        rawH = "\nRaw Hex:\n" + '"' + rawH + '"\n'

        strLitwColor = (
            constants.YELLOW
            + "\nString Literal:\n"
            + constants.RESET
            + '"'
            + constants.GREEN
            + strLit
            + constants.RESET
            + '"\n'
        )
        strLit = "\nString Literal:\n" + '"' + strLit + '"\n'

        arrayLit = arrayLit[:-2]

        arrayLitwColor = (
            constants.YELLOW
            + "\nArray Literal:\n"
            + constants.RESET
            + "{"
            + constants.GREEN
            + arrayLit
            + constants.RESET
            + "}\n"
        )
        arrayLit = "\nArray Literal:\n" + "{" + arrayLit + "}\n"

        if json == None:
            # print (strLitwColor)
            # print (rawHwColor)
            # print (arrayLitwColor)
            pass
        returnVal = rawH + strLit + arrayLit
    except Exception as e:
        print("*Not valid format")
        print(e)
    if json == None:
        return returnVal
    elif json == "json":
        return rawH, strLit


def get_PEB_walk_start(mode, NumOpsDis, bytesToMatch, secNum, data2):
    # change to work off of data2 - add param - get rid of secNum

    global o
    foundCount = 0
    numOps = NumOpsDis
    t = 0
    len_data2 = len(data2)
    len_bytesToMatch = len(bytesToMatch)
    found = False
    for v in data2:
        found = True  # reset flag
        # replace with bytesToMatch list if desired
        # for i in range(len(bytesToMatch)): #can break out on no match for efficiency, left as is for simplicity
        i = 0
        for x in bytesToMatch:
            if found == False:
                break
            # elif ((i+t) >= len_data2 or i >= len_bytesToMatch):
            # 	found = False # out of range
            try:
                # print(data2[t+i])
                # input("enter..")
                if (data2[t + i]) != (bytesToMatch[i]):
                    found = False  # no match
            except Exception:
                pass
            i += 1

        if found:
            # print("hit a found")
            # input("enter..")
            ans = disHerePEB(mode, t, numOps, secNum, data2)
            if mode == "decrypt" and ans is not None:
                print("got disherepeb", ans)
                return ans

        t = t + 1


def get_PEB_walk_start_64(
    NumOpsDis, bytesToMatch, secNum, data2
):  ############### AUSTIN ######################
    # change to work off of data2 - add param - get rid of secNum
    # bytesToMatch 'RAX_OFFSET_NONE': b"\x65\x48\x8B\x04\x25\x60\x00\x00\x00",
    global o
    foundCount = 0
    numOps = NumOpsDis

    t = 0
    len_data2 = len(data2)
    len_bytesToMatch = len(bytesToMatch)

    # print("Data2 type: ", type(data2), "bytes to match type", type(bytesToMatch),"Data2 Length: ", len(data2), "bytes to match len", len(bytesToMatch))
    # input()

    t = 0
    found = False

    # print("Type of lists dict", type(bytesToMatch))
    # print("Type", type(data2))

    # for i in bytesToMatch:
    # 	i = str(i)
    # 	for k in data2:
    # 		k = str(k)
    # 		print("Type ", type(i), type(k), i, k)
    # 		input()

    for v in data2:
        found = True  # reset flag
        # replace with bytesToMatch list if desired
        # for i in range(len(bytesToMatch)): #can break out on no match for efficiency, left as is for simplicity
        i = 0
        for x in bytesToMatch:
            if found == False:
                break
            # elif ((i+t) >= len_data2 or i >= len_bytesToMatch):
            # 	found = False # out of range
            try:
                # input("enter..")
                if (data2[t + i]) != (bytesToMatch[i]):
                    found = False  # no match
            except Exception as e:
                print(e)
                # input(e)
                pass
            i += 1

        if found:
            # print("offset", t, "Section", secNum)
            # print("dis Here ", t, numOps, secNum)
            # print (found)
            # print (binaryToStr(data2[t:t+10]))

            disHerePEB_64(t, numOps, secNum, data2)

        t = t + 1


total1 = 0
total2 = 0


def disHerePEB(
    mode, address, NumOpsDis, secNum, data
):  ############ AUSTIN ##############
    dprint2("disHerePEB", mode)
    # print("disherepeb HERE")
    global o
    global pebPoints
    w = 0

    start = timeit.default_timer()
    foundAdv = False
    foundPEB = False
    foundLDR = False
    listEntryText = ""
    ## Capstone does not seem to allow me to start disassemblying at a given point, so I copy out a chunk to  disassemble. I append a 0x00 because it does not always disassemble correctly (or at all) if just two bytes. I cause it not to be displayed through other means. It simply take the starting address of the jmp [reg], disassembles backwards, and copies it to a variable that I examine more closely.
    # lGoBack = linesGoBackFindOP

    # print("disHere")
    # print(hex(address))
    # print(secNum)
    # input("addy")

    CODED2 = ""
    x = NumOpsDis
    # start = timeit.default_timer()
    if secNum != "noSec":
        section = s[secNum]

    CODED3 = data[address : (address + NumOpsDis)]
    # print("########################")
    # print(type(CODED2))
    # print("########################")
    #
    # stop = timeit.default_timer()
    # total1 += (stop - start)
    # print("Time 1 PEB: " + str(stop - start))

    # I create the individual lines of code that will appear>
    # print(len(CODED2))
    val = ""
    val2 = []
    val3 = []
    # address2 = address + section.ImageBase + section.VirtualAdd
    val5 = []

    loadTIB_offset = -1
    loadLDR_offset = -1
    loadModList_offset = -1
    advanceDLL_Offset = [-1]
    points = 0
    # start = timeit.default_timer()
    # CODED3 = CODED2.encode()
    # print("BINARY2STR")
    # print(binaryToStr(CODED3))
    for i in cs.disasm(CODED3, address):
        # print('address in for = ' + str(address))
        if secNum == "noSec":
            # print("i = " + str(i) + " i.mnemonic = " + str(i.mnemonic))
            # add = hex(int(i.address))
            add4 = hex(int(i.address))
            addb = hex(int(i.address))
        else:
            add = hex(int(i.address))
            addb = hex(int(i.address + section.VirtualAdd))
            add2 = str(add)
            add3 = hex(int(i.address + section.startLoc))
            add4 = str(add3)
        val = (
            i.mnemonic + " " + i.op_str + "\t\t\t\t" + add4 + " (offset " + addb + ")\n"
        )
        # val2.append(val)
        # val3.append(add2)

        loadPEB = re.match(
            "^((mov)|(add)|(xor)|(or)|(adc)|(xchg)) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?d?word ptr fs:\[((((e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?)?0x30)|(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))))\]",
            val,
            re.IGNORECASE,
        )

        # if(movLoadPEB or addLoadPEB or adcLoadPEB or xorLoadPEB or orLoadPEB or xchgLoadPEB or pushLoadPEB and foundPEB):
        if loadPEB:
            loadTIB_offset = addb
            points += 1
            foundPEB = True
        elif not foundPEB:
            return

        loadLDR = re.match(
            "^((mov)|(add)|(xor)|(or)|(adc)|(xchg)) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?(0x0?c)\])",
            val,
            re.IGNORECASE,
        )

        # if(movLoadLDR or addLoadLDR or adcLoadLDR or xorLoadLDR or orLoadLDR or xchgLoadLDR):

        if foundLDR:
            loadInLoadOrder = re.match(
                "^((mov)|(add)|(xor)|(or)|(adc)|(xchg)) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?(0x0?c)\])",
                val,
                re.IGNORECASE,
            )

            # if(movLoadLDR or addLoadLDR or adcLoadLDR or xorLoadLDR or orLoadLDR or xchgLoadLDR):
            if loadInLoadOrder:
                loadModList_offset = addb
                points += 1
                listEntryText = "LIST_ENTRY InLoadOrderModuleList"

        if loadLDR:
            loadLDR_offset = addb
            points += 1
            foundLDR = True

        loadInMemOrder = re.match(
            "^((mov)|(add)|(adc)|(xor)|(or)|(xchg)) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?((0x14))\])",
            val,
            re.IGNORECASE,
        )

        # if(movLoadInMemOrder or addLoadInMemOrder or adcLoadInMemOrder or xorLoadInMemOrder or orLoadInMemOrder or xchgLoadInMemOrder):
        if loadInMemOrder:
            loadModList_offset = addb
            points += 1
            listEntryText = "LIST_ENTRY InMemoryOrderModuleList"

        loadInInitOrder = re.match(
            "^((mov)|(add)|(adc)|(xor)|(or)|(xchg)) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?((0x1c))\])",
            val,
            re.IGNORECASE,
        )

        if loadInInitOrder:
            # if(movLoadInInitOrder or addLoadInInitOrder or adcLoadInInitOrder or xorLoadInInitOrder or orLoadInInitOrder or xchgLoadInInitOrder):
            loadModList_offset = addb
            points += 1
            listEntryText = "LIST_ENTRY InInitializationOrderModuleList"

        dereference = re.match(
            "^((mov)|(add)|(adc)|(xor)|(or)|(xchg)) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l)))\])",
            val,
            re.IGNORECASE,
        )

        # if(movDereference or addDereference or adcDereference or orDereference or xorDereference or xchgDereference):
        if dereference:
            advanceDLL_Offset_temp = addb
            if not foundAdv:
                advanceDLL_Offset[0] = advanceDLL_Offset_temp
                foundAdv = True
                points += 1
            else:
                advanceDLL_Offset.append(advanceDLL_Offset_temp)

        lodsd = re.match("^(lodsd)", val, re.IGNORECASE)

        if lodsd:
            advanceDLL_Offset_temp = addb
            if not foundAdv:
                advanceDLL_Offset[0] = advanceDLL_Offset_temp
                foundAdv = True
                points += 1
            else:
                advanceDLL_Offset.append(advanceDLL_Offset_temp)

        val5.append(val)
        # print (val)
    # return val5
    # stop = timeit.default_timer()
    # total2 += (stop - start)
    # print("Time 2 PEB: " + str(stop - start))

    disString = val5

    stop = timeit.default_timer()
    dprint2("Time PEB: " + str(stop - start))

    if points >= pebPoints:
        if rawHex:
            modSecName = peName
        else:
            modSecName = section.sectionName

        if mode == "decrypt":
            dprint2("decrypt returning")
            dprint2(
                address,
                NumOpsDis,
                modSecName,
                secNum,
                points,
                loadTIB_offset,
                loadLDR_offset,
                (loadModList_offset, listEntryText),
                advanceDLL_Offset,
            )
            return (
                address,
                NumOpsDis,
                modSecName,
                secNum,
                points,
                loadTIB_offset,
                loadLDR_offset,
                (loadModList_offset, listEntryText),
                advanceDLL_Offset,
            )
        # print("SAVING PEB SEQUENCE: PEBPOINTS = ", pebPoints, "FOUND ", points, " POINTS")
        # print(disString)
        # print("saveBasePEBWalk", address, NumOpsDis, modSecName, secNum, points, loadTIB_offset, loadLDR_offset, (loadModList_offset, listEntryText	), advanceDLL_Offset)
        saveBasePEBWalk_64(
            address,
            NumOpsDis,
            modSecName,
            secNum,
            points,
            loadTIB_offset,
            loadLDR_offset,
            (loadModList_offset, listEntryText),
            advanceDLL_Offset,
        )


def disHerePEB_64(
    address, NumOpsDis, secNum, data
):  ############## AUSTIN ####################
    global o
    global pebPoints

    w = 0

    foundAdv = False
    foundPEB = False
    foundLDR = False
    listEntryText = ""
    ## Capstone does not seem to allow me to start disassemblying at a given point, so I copy out a chunk to  disassemble. I append a 0x00 because it does not always disassemble correctly (or at all) if just two bytes. I cause it not to be displayed through other means. It simply take the starting address of the jmp [reg], disassembles backwards, and copies it to a variable that I examine more closely.
    # lGoBack = linesGoBackFindOP

    CODED2 = ""
    x = NumOpsDis
    # start = timeit.default_timer()
    if secNum != "noSec":
        section = s[secNum]

    CODED2 = data[address : (address + NumOpsDis)]
    # print("########################")
    # print(type(CODED2))
    # print("########################")
    #
    # stop = timeit.default_timer()
    # total1 += (stop - start)
    # print("Time 1 PEB: " + str(stop - start))

    # I create the individual lines of code that will appear>
    # print(len(CODED2))
    val = ""
    val2 = []
    val3 = []
    # address2 = address + section.ImageBase + section.VirtualAdd
    val5 = []

    # start = timeit.default_timer()
    # CODED3 = CODED2.encode()
    CODED3 = CODED2

    for i in cs64.disasm(CODED3, address):
        if secNum == "noSec":
            dprint2("i = " + str(i) + " i.mnemonic = " + str(i.mnemonic))
            # add = hex(int(i.address))
            add4 = hex(int(i.address))
            addb = hex(int(i.address))
        else:
            add = hex(int(i.address))
            addb = hex(int(i.address + section.VirtualAdd))
            add2 = str(add)
            add3 = hex(int(i.address + section.startLoc))
            add4 = str(add3)
        val = (
            i.mnemonic + " " + i.op_str + "\t\t\t\t" + add4 + " (offset " + addb + ")\n"
        )
        val5.append(val)

    loadTIB_offset = -1
    loadLDR_offset = -1
    loadModList_offset = -1
    advanceDLL_Offset = [-1]
    points = 0
    disString = val5
    for line in disString:
        ##############################################

        loadPEB = re.match(
            "^((mov)|(add)|(xor)|(or)|(adc)|(xchg)) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)?word ptr gs:\[(((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?)?0x60)\]",
            line,
            re.IGNORECASE,
        )

        if loadPEB:
            loadTIB_offset = addb
            foundPEB = True
            points += 1
        elif not foundPEB:
            return

        ##############################################

        loadLDR = re.match(
            "^((mov)|(add)|(xor)|(or)|(adc)|(xchg)) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x18)\])",
            line,
            re.IGNORECASE,
        )

        if loadLDR:
            loadLDR_offset = addb
            points += 1
            foundLDR = True

        loadInLoadOrder = re.match(
            "^((mov)|(add)|(xor)|(or)|(adc)|(xchg)) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x10)\])",
            line,
            re.IGNORECASE,
        )

        if loadInLoadOrder:
            loadModList_offset = addb
            points += 1
            listEntryText = "LIST_ENTRY InLoadOrderModuleList"

        loadInMemOrder = re.match(
            "^((mov)|(add)|(xor)|(or)|(adc)|(xchg)) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x20)\])",
            line,
            re.IGNORECASE,
        )

        if loadInMemOrder:
            loadModList_offset = addb
            points += 1
            listEntryText = "LIST_ENTRY InMemoryOrderModuleList"

        loadInInitOrder = re.match(
            "^((mov)|(add)|(xor)|(or)|(adc)|(xchg)) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x30)\])",
            line,
            re.IGNORECASE,
        )

        if loadInInitOrder:
            loadModList_offset = addb
            points += 1
            listEntryText = "LIST_ENTRY InInitializationOrderModuleList"

        ###############################################

        dereference = re.match(
            "^((mov)|(add)|(xor)|(or)|(adc)|(xchg))  ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((d|q)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15))))\])",
            line,
            re.IGNORECASE,
        )

        if dereference:
            advanceDLL_Offset_temp = addb
            if not foundAdv:
                advanceDLL_Offset[0] = advanceDLL_Offset_temp
                foundAdv = True
                points += 1
            else:
                advanceDLL_Offset.append(advanceDLL_Offset_temp)

        ###############################################

        lod = re.match("^(lodsq)|(lodsd)", line, re.IGNORECASE)

        if lod:
            advanceDLL_Offset_temp = addb
            if not foundAdv:
                advanceDLL_Offset[0] = advanceDLL_Offset_temp
                foundAdv = True
                points += 1
            else:
                advanceDLL_Offset.append(advanceDLL_Offset_temp)

    if points >= pebPoints:
        if rawHex:
            modSecName = peName
        else:
            modSecName = section.sectionName
        saveBasePEBWalk(
            address,
            NumOpsDis,
            modSecName,
            secNum,
            points,
            loadTIB_offset,
            loadLDR_offset,
            (loadModList_offset, listEntryText),
            advanceDLL_Offset,
        )


def saveBasePEBWalk_64(
    address,
    NumOpsDis,
    modSecName,
    secNum,
    points,
    loadTIB_offset,
    loadLDR_offset,
    loadModList_offset,
    advanceDLL_Offset,
):  ############## AUSTIN ####################
    peb_data = tuple(
        (
            address,
            NumOpsDis,
            modSecName,
            secNum,
            points,
            loadTIB_offset,
            loadLDR_offset,
            loadModList_offset,
            advanceDLL_Offset,
        )
    )

    if secNum != "noSec":
        if peb_data not in s[secNum].save_PEB_info:
            s[secNum].save_PEB_info.append(
                tuple(
                    (
                        address,
                        NumOpsDis,
                        modSecName,
                        secNum,
                        points,
                        loadTIB_offset,
                        loadLDR_offset,
                        loadModList_offset,
                        advanceDLL_Offset,
                    )
                )
            )
    else:
        secNum = -1
        modSecName = "rawHex"
        m[o].save_PEB_info.append(
            tuple(
                (
                    address,
                    NumOpsDis,
                    modSecName,
                    secNum,
                    points,
                    loadTIB_offset,
                    loadLDR_offset,
                    loadModList_offset,
                    advanceDLL_Offset,
                )
            )
        )


def printSavedPEB():  ######################## AUSTIN ###############################3
    # formatting
    # global m[o].rawData2

    dprint2("printSavedPEB", len(m[o].rawData2))
    dprint2("m[o].save_PEB_info", len(m[o].save_PEB_info))
    dprint2("rawhex", rawHex)
    j = 0

    if rawHex:
        for item in m[o].save_PEB_info:
            # print("-----------------> ",item)

            mods = item[7]
            if -1 in mods:
                mods = "N/A"
            else:
                if len(mods) > 1:
                    mods = ", ".join(item[7])
            adv = item[8]
            # input()
            if -1 in adv:
                adv = "N/A"
            else:
                if len(adv) > 1:
                    adv = ", ".join(str(adv))
                else:
                    adv = str(adv[0])
            print("OFFSETS: ")

            print("PEB WALKING START = " + constants.MAGENTA + str(hex(item[0])) + res)
            print("TIB = " + constants.MAGENTA + str(item[5]) + constants.RESET)
            print("LDR = " + constants.MAGENTA + str(item[6]) + constants.RESET)
            print("MODS = " + constants.MAGENTA + str(mods) + constants.RESET)
            print("Adv = " + constants.MAGENTA + str(adv) + constants.RESET)

            CODED2 = b""

            address = item[0]
            NumOpsDis = item[1]
            modSecName = item[2]
            secNum = item[3]
            points = item[4]

            CODED2 = m[o].rawData2[address : (address + NumOpsDis)]

            outString = "\n\nItem: " + str(j) + " | Points: " + str(points)
            if secNum != -1:
                outString += (
                    " | Section: " + str(secNum) + " | Section name: " + str(modSecName)
                )
                # if(secNum != 0):
                # 	trash = raw_input("enter...")

            else:
                outString += " | Module: " + modSecName

            print(
                "\n******************************************************************************"
            )
            print(constants.YELLOW + outString + res)
            print("\n")
            val = ""
            val2 = []
            val3 = []
            # address2 = address + section.ImageBase + section.VirtualAdd
            val5 = []
            for i in cs.disasm(CODED2, address):
                if rawHex:
                    add4 = hex(int(i.address))
                    addb = hex(int(i.address))
                else:
                    add = hex(int(i.address))
                    addb = hex(int(i.address + section.VirtualAdd))
                    add2 = str(add)
                    add3 = hex(int(i.address + section.startLoc))
                    add4 = str(add3)
                val = formatPrint(i, add4, addb)

                # val =  constants.GREEN + i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + constants.CYAN + " (offset " + addb + ")\n" + res
                print(val)
            # return val5
            print("\n")
            j += 1
    else:
        h = 0
        for section in s:
            h += 1
            # print("PRINTING SECTION " + str(h))
            for item in section.save_PEB_info:
                # print("------------->",item)
                try:
                    mods = item[7]
                    if -1 in mods:
                        mods = "N/A"
                    else:
                        if len(mods) > 1:
                            mods = ", ".join(item[7])
                except Exception:
                    # print(e)
                    mods = "N/A"
                    pass
                # input()

                CODED2 = ""

                print("OFFSETS: ")
                print("PEBWALKSTART = " + constants.MAGENTA + str(hex(item[0])) + res)
                if len(item) > 5:
                    try:
                        print(
                            "TIB = "
                            + constants.MAGENTA
                            + str(item[5])
                            + constants.RESET
                        )
                    except:
                        pass
                    try:
                        print(
                            "LDR = "
                            + constants.MAGENTA
                            + str(item[6])
                            + constants.RESET
                        )
                    except:
                        pass
                    try:
                        print(
                            "MODS = " + constants.MAGENTA + str(mods) + constants.RESET
                        )
                    except:
                        pass
                    try:
                        for adv in item[8]:
                            if adv == -1:
                                adv = "N/A"
                            print(
                                "Adv = "
                                + constants.MAGENTA
                                + str(adv)
                                + constants.RESET
                            )
                    except:
                        pass

                address = item[0]
                NumOpsDis = item[1]
                modSecName = item[2]
                secNum = item[3]
                points = item[4]

                section = s[secNum]

                outString = "\n\nItem: " + str(j) + " | Points: " + str(points)
                if secNum != -1:
                    outString += (
                        " | Section: "
                        + str(secNum)
                        + " | Section name: "
                        + modSecName.decode()
                    )
                    # if(secNum != 0):
                    # 	trash = raw_input("enter...")

                else:
                    outString += " | Module: " + modSecName

                print(
                    "\n******************************************************************************"
                )
                print(constants.YELLOW + outString + res)
                print("\n")
                val = ""
                val2 = []
                val3 = []
                address2 = address + section.ImageBase + section.VirtualAdd
                val5 = []

                CODED2 = section.data2[address : (address + NumOpsDis)]

                CODED3 = CODED2
                for i in cs.disasm(CODED3, address):
                    add = hex(int(i.address))
                    addb = hex(int(i.address + section.VirtualAdd))
                    add2 = str(add)
                    add3 = hex(int(i.address + section.startLoc))
                    add4 = str(add3)
                    val = formatPrint(i, add4, addb, pe=True)

                    # val =  constants.GREEN + i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + constants.CYAN + " (offset " + addb + ")" + res
                    val2.append(val)
                    val3.append(add2)
                    val5.append(val)
                    print(constants.GREEN + val + res)
                print("\n")
                j += 1
                # print str(type(m[o].data2))
                # trash = raw_input("enter...")


def printSavedPEB_64():  ############## AUSTIN ####################
    # formatting
    # global m[o].rawData2

    dprint2("printSavedPEB", len(m[o].rawData2))
    dprint2("m[o].save_PEB_info", len(m[o].save_PEB_info))
    dprint2("rawhex", rawHex)
    j = 0

    if rawHex:
        for item in m[o].save_PEB_info:
            # print("-----------------> ",item)

            mods = item[7]
            if -1 in mods:
                mods = "N/A"
            else:
                if len(mods) > 1:
                    mods = ", ".join(item[7])
            adv = item[8]
            # input()
            if -1 in adv:
                adv = "N/A"
            else:
                if len(adv) > 1:
                    adv = ", ".join(str(adv))
                else:
                    adv = str(adv[0])
            print("OFFSETS: ")

            print("PEB WALKING START = " + constants.MAGENTA + str(hex(item[0])) + res)
            print("TIB = " + constants.MAGENTA + str(item[5]) + constants.RESET)
            print("LDR = " + constants.MAGENTA + str(item[6]) + constants.RESET)
            print("MODS = " + constants.MAGENTA + str(mods) + constants.RESET)
            print("Adv = " + constants.MAGENTA + str(adv) + constants.RESET)

            CODED2 = b""

            address = item[0]
            NumOpsDis = item[1]
            modSecName = item[2]
            secNum = item[3]
            points = item[4]

            CODED2 = m[o].rawData2[address : (address + NumOpsDis)]

            outString = "\n\nItem: " + str(j) + " | Points: " + str(points)
            if secNum != -1:
                outString += (
                    " | Section: " + str(secNum) + " | Section name: " + str(modSecName)
                )
                # if(secNum != 0):
                # 	trash = raw_input("enter...")

            else:
                outString += " | Module: " + modSecName

            print(
                "\n******************************************************************************"
            )
            print(constants.YELLOW + outString + res)
            print("\n")
            val = ""
            val2 = []
            val3 = []
            # address2 = address + section.ImageBase + section.VirtualAdd
            val5 = []
            for i in cs.disasm(CODED2, address):
                if rawHex:
                    add4 = hex(int(i.address))
                    addb = hex(int(i.address))
                else:
                    add = hex(int(i.address))
                    addb = hex(int(i.address + section.VirtualAdd))
                    add2 = str(add)
                    add3 = hex(int(i.address + section.startLoc))
                    add4 = str(add3)
                val = formatPrint(i, add4, addb)

                # val =  constants.GREEN + i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + constants.CYAN + " (offset " + addb + ")\n" + res
                print(val)
            # return val5
            print("\n")
            j += 1
    else:
        h = 0
        for section in s:
            h += 1
            # print("PRINTING SECTION " + str(h))
            for item in section.save_PEB_info:
                print("------------->", item)
                try:
                    mods = item[7]
                    if -1 in mods:
                        mods = "N/A"
                    else:
                        if len(mods) > 1:
                            mods = ", ".join(item[7])
                except Exception:
                    # print(e)
                    mods = "N/A"
                    pass
                # input()

                CODED2 = ""

                print("OFFSETS: ")
                print("PEBWALKSTART = " + constants.MAGENTA + str(hex(item[0])) + res)
                if len(item) > 5:
                    try:
                        print(
                            "TIB = "
                            + constants.MAGENTA
                            + str(item[5])
                            + constants.RESET
                        )
                    except:
                        pass
                    try:
                        print(
                            "LDR = "
                            + constants.MAGENTA
                            + str(item[6])
                            + constants.RESET
                        )
                    except:
                        pass
                    try:
                        print(
                            "MODS = " + constants.MAGENTA + str(mods) + constants.RESET
                        )
                    except:
                        pass
                    try:
                        for adv in item[8]:
                            if adv == -1:
                                adv = "N/A"
                            print(
                                "Adv = "
                                + constants.MAGENTA
                                + str(adv)
                                + constants.RESET
                            )
                    except:
                        pass

                address = item[0]
                NumOpsDis = item[1]
                modSecName = item[2]
                secNum = item[3]
                points = item[4]

                section = s[secNum]

                outString = "\n\nItem: " + str(j) + " | Points: " + str(points)
                if secNum != -1:
                    outString += (
                        " | Section: "
                        + str(secNum)
                        + " | Section name: "
                        + modSecName.decode()
                    )
                    # if(secNum != 0):
                    # 	trash = raw_input("enter...")

                else:
                    outString += " | Module: " + modSecName

                print(
                    "\n******************************************************************************"
                )
                print(constants.YELLOW + outString + res)
                print("\n")
                val = ""
                val2 = []
                val3 = []
                address2 = address + section.ImageBase + section.VirtualAdd
                val5 = []

                CODED2 = section.data2[address : (address + NumOpsDis)]

                CODED3 = CODED2
                for i in cs.disasm(CODED3, address):
                    add = hex(int(i.address))
                    addb = hex(int(i.address + section.VirtualAdd))
                    add2 = str(add)
                    add3 = hex(int(i.address + section.startLoc))
                    add4 = str(add3)
                    val = formatPrint(i, add4, addb, pe=True)

                    # val =  constants.GREEN + i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + constants.CYAN + " (offset " + addb + ")" + res
                    val2.append(val)
                    val3.append(add2)
                    val5.append(val)
                    print(constants.GREEN + val + res)
                print("\n")
                j += 1
                # print str(type(m[o].data2))
                # trash = raw_input("enter...")


def get_PushRet_start(
    NumOpsDis, bytesToMatch, secNum, data2
):  ######################### AUSTIN #############################
    # print ("get_PushRet_start", (NumOpsDis ,bytesToMatch, secNum))
    # print (binaryToStr(data2))
    global o
    foundCount = 0
    numOps = NumOpsDis

    t = 0
    len_data2 = len(data2)
    len_bytesToMatch = len(bytesToMatch)

    for v in data2:
        found = True  # reset flag
        # replace with bytesToMatch list if desired
        # for i in range(len(bytesToMatch)): #can break out on no match for efficiency, left as is for simplicity
        i = 0
        for x in bytesToMatch:
            if found == False:
                break
            # elif ((i+t) >= len_data2 or i >= len_bytesToMatch):
            # 	found = False # out of range
            try:
                # print(data2[t+i])
                # input("enter..")
                if (data2[t + i]) != (bytesToMatch[i]):
                    found = False  # no match
            except Exception as e:
                # input(e)
                # print ("ERROR")
                print(e)
                pass
            i += 1

        if found:
            # print("Matched: ", hex(v))
            # input()
            disHerePushRet(t, numOps, secNum, data2)

        t = t + 1


def disHerePushRet(
    address, NumOpsDis, secNum, data
):  ############################# AUSTIN ############################
    CODED2 = ""
    x = NumOpsDis

    if secNum != "noSec":
        section = s[secNum]

    CODED2 = data[address : (address + NumOpsDis)]
    val = ""
    val2 = []
    val3 = []
    val5 = []
    points = 0
    foundPush = False
    foundRet = False
    pushReg = ""
    CODED3 = CODED2
    for i in cs.disasm(CODED3, address):
        if secNum == "noSec":
            # add = hex(int(i.address))
            add4 = hex(int(i.address))
            addb = hex(int(i.address))
        else:
            add = hex(int(i.address))
            addb = hex(int(i.address + section.VirtualAdd))
            add2 = str(add)
            add3 = hex(int(i.address + section.startLoc))
            add4 = str(add3)
        val = (
            i.mnemonic + " " + i.op_str + "\t\t\t\t" + add4 + " (offset " + addb + ")\n"
        )
        val5.append(val)

        push = re.match(
            "^push ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)|(8|9|(1([0-5])))))",
            val,
            re.IGNORECASE,
        )
        if push:
            pushReg = i.op_str
            foundPush = True
            pushOffset = addb

        ret = re.match("^ret", val, re.IGNORECASE)
        retf = re.match("^retf", val, re.IGNORECASE)
        retNum = re.match("^ret [0-9a-f]", val, re.IGNORECASE)

        if ret and not retf and not retNum and foundPush:
            foundRet = True
            retOffset = addb

        if foundPush and foundRet:
            foundPush = False
            foundRet = False
            if rawHex:
                modSecName = peName
            else:
                modSecName = section.sectionName
            saveBasePushRet(
                address,
                NumOpsDis,
                modSecName,
                secNum,
                points,
                (pushOffset, pushReg),
                retOffset,
            )


def disHerePushRet64(
    address, NumOpsDis, secNum, data
):  ############################# AUSTIN ############################
    # print("inDisherePush ", address)
    CODED2 = ""
    x = NumOpsDis
    linesGoBack = 10
    if secNum != "noSec":
        section = s[secNum]
        # start = timeit.default_timer()
    CODED2 = data[address : (address + NumOpsDis) + 1]

    # I create the individual lines of code that will appear>
    val = ""
    val2 = []
    val3 = []
    # address2 = address + section.ImageBase + section.VirtualAdd
    val5 = []

    points = 0
    foundPush = False
    foundRet = False
    pushReg = ""
    # start = timeit.default_timer()
    CODED3 = CODED2
    for i in cs64.disasm(CODED3, address):
        if secNum == "noSec":
            # add = hex(int(i.address))
            add4 = hex(int(i.address))
            addb = hex(int(i.address))
        else:
            # print("heree")
            add = hex(int(i.address))
            addb = hex(int(i.address + section.VirtualAdd))
            add2 = str(add)
            add3 = hex(int(i.address + section.startLoc))
            add4 = str(add3)
        val = (
            i.mnemonic + " " + i.op_str + "\t\t\t\t" + add4 + " (offset " + addb + ")\n"
        )
        val5.append(val)
        # if not push:
        push = re.match(
            "^push ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)|(8|9|(1([0-5])))))",
            val,
            re.IGNORECASE,
        )
        if push:
            pushReg = i.op_str
            # points += 1
            foundPush = True
            pushOffset = addb
        ret = re.match("^ret", val, re.IGNORECASE)
        retf = re.match("^retf", val, re.IGNORECASE)
        retNum = re.match("^ret [0-9a-f]", val, re.IGNORECASE)

        if ret and not retf and not retNum and foundPush:
            foundRet = True
            retOffset = addb

    if (foundPush) and (foundRet):
        if rawHex:
            modSecName = peName
        else:
            modSecName = section.sectionName
        saveBasePushRet(
            address,
            NumOpsDis,
            modSecName,
            secNum,
            points,
            (pushOffset, pushReg),
            retOffset,
        )


def PushRetrawhex(address, secNum, data, variables: Variables, module, shellcode_label):
    # print ("PushRetrawhex", len(data))
    global linesForward
    address = hex(address)
    # linesGoBack = 10
    linesGoBack = linesBack
    # print("Lines Forward", linesForward)
    t = 0
    truth, tl1, tl2, orgListOffset, orgListDisassembly = preSyscalDiscovery(
        0, 0x0, linesGoBack, variables, module, shellcode_label, "PushRetrawhex"
    )  # arg: starting offset/entry point - leave 0 generally

    # print("------------>", orgListOffset,orgListDisassembly)
    # input()
    if variables.moduleBooleans[shellcode_label].ignoreDisDiscovery:
        truth = False

    if truth:
        # print ("truth2")
        for e in orgListDisassembly:
            pushReg = ""
            isPUSH = re.search("push", e, re.IGNORECASE)
            if isPUSH:
                try:
                    pushReg = orgListDisassembly[t].split()[1]
                except Exception as e:
                    pushReg = orgListDisassembly[t].split()

                push_offset = hex(orgListOffset[t])
                address = int(orgListOffset[t])
                index = 0
                chunk = orgListDisassembly[t + 1 : t + linesForward]
                chunkOffsets = orgListOffset[t + 1 : t + linesForward]
                for item in chunk:
                    bad = re.match(
                        "^((jmp)|(ljmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(int)|(db)|(hlt)|(loop)|(leave)|(int3)|(insd)|(enter)|(jns)|(call)|(retf)|(push))",
                        item,
                        re.M | re.I,
                    )
                    if bad:
                        break
                    isRET = re.search("ret", item, re.IGNORECASE)
                    isRETF = re.search("retf", item, re.IGNORECASE)
                    if isRET:
                        if not isRETF:
                            ret_offset = hex(orgListOffset[index + t + 1])
                            saveBasePushRet(
                                address,
                                linesForward,
                                "noSec",
                                secNum,
                                2,
                                (push_offset, pushReg),
                                ret_offset,
                            )

                            break
                    index += 1
            t += 1

    else:
        for match in PUSH_RET.values():
            if variables.shellBit == 32:
                get_PushRet_start(4, match, secNum, data)
            else:
                get_PushRet_start64(4, match, secNum, data)

    if variables.rawHex:
        module[shellcode_label].save_PushRet_info = list(
            set(module[shellcode_label].save_PushRet_info)
        )
    else:
        s[secNum].save_PushRet_info = list(set(s[secNum].save_PushRet_info))


def PushRetrawhex2(address, secNum, data):
    global bit32

    global linesForward
    address = hex(address)
    linesGoBack = 10
    t = 0
    truth, tl1, tl2, orgListOffset, orgListDisassembly = preSyscalDiscovery(
        0, 0x0, linesGoBack, "PushRetrawhex2"
    )  # arg: starting offset/entry point - leave 0 generally
    # print("------------>", orgListOffset,orgListDisassembly)
    # input()
    if moduleBooleans[shellcode_label].ignoreDisDiscovery:
        truth = False

    if truth:
        t = [orgListDisassembly.index(i) for i in orgListDisassembly if "push" in i]
        if t != []:
            t = t[0]

            # print ("truth2")
            # for e in orgListDisassembly:
            pushReg = ""
            # isPUSH = re.search("push", e, re.IGNORECASE)
            # if "push" in
            # if isPUSH:
            # print ("truth3")
            # print("ispush")
            try:
                pushReg = orgListDisassembly[t].split()[1]
            except Exception:
                pushReg = orgListDisassembly[t].split()
                # print("Push ret function", e)
                # input()
            # print ("pushreg", pushReg)
            # input()

            push_offset = hex(orgListOffset[t])
            address = int(orgListOffset[t])
            index = 0
            chunk = orgListDisassembly[t + 1 : t + linesForward]
            chunkOffsets = orgListOffset[t + 1 : t + linesForward]
            for item in chunk:
                bad = re.match(
                    "^((jmp)|(ljmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(int)|(db)|(hlt)|(loop)|(leave)|(int3)|(insd)|(enter)|(jns)|(call)|(retf))",
                    item,
                    re.M | re.I,
                )
                if bad:
                    # print("bad")
                    break
                # print("item: ",item)
                isRET = re.search("ret", item, re.IGNORECASE)
                isRETF = re.search("retf", item, re.IGNORECASE)
                if isRET:
                    if not isRETF:
                        # print ("item",item)
                        ret_offset = hex(orgListOffset[index + t + 1])

                        # print("isret")
                        # print("saved a pushret: push = ", push_offset, " ret = ", ret_offset)
                        saveBasePushRet(
                            address,
                            linesForward,
                            "noSec",
                            secNum,
                            2,
                            (push_offset, pushReg),
                            ret_offset,
                        )

                        break
                    # else:
                    # print("item ----> ", item)
                index += 1
            t += 1

    else:
        for match in PUSH_RET.values():
            if bit32:
                get_PushRet_start(4, match, secNum, data)
            else:
                get_PushRet_start64(4, match, secNum, data)


def saveBasePushRet(
    address, NumOpsDis, modSecName, secNum, points, pushOffset, retOffset
):  ################## AUSTIN ##############################
    # print ("saving", hex(address))
    # save virtaul address as well
    if secNum != "noSec":
        for each in s[secNum].save_PushRet_info:
            if retOffset == each[6]:
                return
        s[secNum].save_PushRet_info.append(
            tuple(
                (address, NumOpsDis, modSecName, secNum, points, pushOffset, retOffset)
            )
        )

    else:
        secNum = -1
        modSecName = "rawHex"
        for each in m[o].save_PushRet_info:
            if retOffset == each[6]:
                return
        # print("Saving pushoffset", pushOffset, retOffset)
        # input()

        m[o].save_PushRet_info.append(
            tuple(
                (address, NumOpsDis, modSecName, secNum, points, pushOffset, retOffset)
            )
        )


def printSavedPushRet(
    bit=32,
):  ############################## AUSTIN #############################
    # formatting
    j = 0
    if bit == 32:
        callCS = cs
    else:
        callCS = cs64
    if rawHex:
        for item in m[o].save_PushRet_info:
            CODED2 = b""

            address = item[0]
            NumOpsDis = item[1]
            modSecName = item[2]
            secNum = item[3]
            points = item[4]
            pushOffset = item[5]
            retOffset = item[6]
            printEnd = int(retOffset, 16) + 15

            # CODED2 = m[o].rawData2[address:(address+NumOpsDis)]
            CODED2 = m[o].rawData2[address:(printEnd)]

            outString = "Item: " + str(j) + " | Points: " + str(points)

            if secNum != -1:
                outString += (
                    " | Section: " + str(secNum) + " | Section name: " + str(modSecName)
                )
                # if(secNum != 0):
                # 	trash = raw_input("enter...")

            else:
                outString += " | Module: " + modSecName

            pushOffset = ", ".join(pushOffset)
            outString += (
                " | PUSH Offset: "
                + str(pushOffset)
                + " | RET Offset: "
                + str(retOffset)
            )

            print(
                "\n******************************************************************************"
            )

            print(constants.YELLOW + outString + res)
            print("\n")
            val = ""
            val2 = []
            val3 = []
            # address2 = address + section.ImageBase + section.VirtualAdd
            val5 = []

            # if bit == 32:
            for i in callCS.disasm(CODED2, address):
                if rawHex:
                    add4 = hex(int(i.address))
                    addb = hex(int(i.address))
                else:
                    add = hex(int(i.address))
                    addb = hex(int(i.address + section.VirtualAdd))
                    add2 = str(add)
                    add3 = hex(int(i.address + section.startLoc))
                    add4 = str(add3)
                val = formatPrint(i, add4, addb)
                # val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
                print(constants.GREEN + val + res)
                if addb == retOffset:
                    break
            # if bit == 64:
            # 	for i in cs64.disasm(CODED2, address):
            # 		if(rawHex):
            # 			add4 = hex(int(i.address))
            # 			addb = hex(int(i.address))
            # 		else:
            # 			add = hex(int(i.address))
            # 			addb = hex(int(i.address +  section.VirtualAdd))
            # 			add2 = str(add)
            # 			add3 = hex (int(i.address + section.startLoc	))
            # 			add4 = str(add3)
            # 		val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
            # 		print (constants.GREEN + val + res)
            # 		if(addb == retOffset):
            # 			break
            # return val5

            # print ("\n")
            t = 0
            for each in val5:
                # if (t<2):
                # print(each)
                print(each)
                t += 1
            j += 1
    else:
        h = 0
        for section in s:
            h += 1
            for item in section.save_PushRet_info:
                CODED2 = ""
                address = item[0]
                NumOpsDis = item[1]
                modSecName = item[2]
                secNum = item[3]
                points = item[4]
                pushOffset = item[5]
                retOffset = item[6]
                section = s[secNum]
                outString = "Item: " + str(j) + " | Points: " + str(points)

                if secNum != -1:
                    outString += (
                        " | Section: "
                        + str(secNum)
                        + " | Section name: "
                        + modSecName.decode()
                    )

                else:
                    outString += " | Module: " + modSecName
                pushOffset = ", ".join(pushOffset)
                outString += (
                    " | PUSH Offset: "
                    + str(pushOffset)
                    + " | RET Offset: "
                    + str(retOffset)
                )

                print(
                    "\n******************************************************************************"
                )

                print(constants.YELLOW + outString + res)
                print("\n")
                val = ""
                val2 = []
                val3 = []
                address2 = address + section.ImageBase + section.VirtualAdd
                val5 = []
                printEnd = int(retOffset, 16) + 3 - section.VirtualAdd
                # printEnd = int(retOffset, 16) + section.ImageBase
                # CODED2 = section.data2[address:(address+NumOpsDis)+2]
                # printEnd = int(retOffset, 16) - section.VirtualAdd
                CODED2 = section.data2[address:printEnd]
                # CODED2 = section.data2[address:int(retOffset, 16)]
                # print("Address: ", hex(address), "printEnd ", hex(printEnd), hex(int(retOffset, 16)))

                CODED3 = CODED2
                stopRet = False
                # print("pushret print function", CODED3.hex())
                for i in callCS.disasm(CODED3, address):
                    add = hex(int(i.address))
                    addb = hex(int(i.address + section.VirtualAdd))
                    add2 = str(add)
                    add3 = hex(int(i.address + section.startLoc))
                    add4 = str(add3)
                    val = formatPrint(i, add4, addb, pe=True)

                    # val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
                    val2.append(val)
                    val3.append(add2)
                    # val5.append(val)
                    if addb == retOffset:
                        val5.append(val)
                        break
                    else:
                        val5.append(val)
                t = 0
                for each in val5:
                    print(constants.GREEN + each + res)
                    t += 1

                j += 1


def get_FSTENV(NumOpsDis, NumOpsBack, bytesToMatch, secNum, data2):
    # change to work off of data2 - add param - get rid of secNum
    global o

    for t, v in enumerate(data2):
        found = True  # reset flag
        for i, x in enumerate(bytesToMatch):
            if not found:
                break
            found = False  # no match

        if found:
            disHereFSTENV(t, NumOpsDis, NumOpsBack, secNum, data2)


def get_PushRet_start64(
    NumOpsDis, bytesToMatch, secNum, data2
):  ######################### AUSTIN #############################
    global o
    foundCount = 0
    numOps = NumOpsDis

    t = 0
    len_data2 = len(data2)
    len_bytesToMatch = len(bytesToMatch)

    for v in data2:
        found = True  # reset flag
        # replace with bytesToMatch list if desired
        # for i in range(len(bytesToMatch)): #can break out on no match for efficiency, left as is for simplicity
        i = 0
        for x in bytesToMatch:
            # print(binaryToStr(data2[t+i-3:t+i+3]))
            if found == False:
                break
            # elif ((i+t) >= len_data2 or i >= len_bytesToMatch):
            # 	found = False # out of range
            try:
                # input("enter..")
                if (data2[t + i]) != (bytesToMatch[i]):
                    found = False  # no match
            except Exception:
                # input(e)
                pass
            i += 1

        if found:
            # input("enter..")
            # print("offset ", hex(t + s[secNum].VirtualAdd))
            # print(binaryToStr(data2[t:t+i]))
            # for match in EGGHUNT.values():
            # 	getSyscallPE(20, 20, match, secNum, data2)
            disHerePushRet64(t, numOps, secNum, data2)

        t = t + 1


def findAllPushRet64(
    data2, secNum
):  ################## AUSTIN #########################
    if secNum == "noSec":
        PushRetrawhex(0, "noSec", data2)
    else:
        for match in PUSH_RET.values():
            optimized_find(4, match, secNum, data2, "disHerePushRet64")
            # get_PushRet_start64(4, match, secNum, data2)
            # disHerePushRet64(t, numOps, secNum, data2)


# NumOpsBack: how many opcodes to search back when looking for fpu instruction
def disHereFSTENV(
    address, NumOpsDis, NumOpsBack, secNum, data
):  ############ AUSTIN ##############
    global o
    global total1
    global total2
    global fcount
    w = 0
    if variables.shellBit == 32:
        callCS = cs
    else:
        callCS = cs64

    CODED2 = ""
    x = NumOpsDis
    if secNum != "noSec":
        section = s[secNum]

    for back in range(NumOpsBack):
        CODED2 = data[(address - (NumOpsBack - back)) : (address + x)]

        # I create the individual lines of code that will appear>
        val = ""
        val2 = []
        val3 = []
        val5 = []
        valOffsets = []
        CODED3 = CODED2

        for t, i in enumerate(callCS.disasm(CODED3, (address - (NumOpsBack - back)))):
            if secNum == "noSec":
                add4 = hex(int(i.address))
                addb = hex(int(i.address))
            else:
                add = hex(int(i.address))
                addb = hex(int(i.address + section.VirtualAdd))
                add2 = str(add)
                add3 = hex(int(i.address + section.startLoc))
                add4 = str(add3)
            val = (
                i.mnemonic
                + " "
                + i.op_str
                + "\t\t\t\t"
                + add4
                + " (offset "
                + addb
                + ")\n"
            )
            val5.append(val)
            valOffsets.append(addb)
            disString = val5

            # we save when the fpu instr is the first one
            # match instructions beginning with "f" but is not fstenv or fnstenv
            FPU_instr = re.match("^f((?!n?stenv).)*$", disString[0], re.IGNORECASE)
            fstenv = False
            if FPU_instr:
                dprint2("matched fpu")
                dprint2(disString[0])
                FPU_offset = valOffsets[t]
                dprint2("FPU OFF3 = " + str(FPU_offset))
                FPU_offset = FPU_offset[:-1]
                test = valOffsets[0]
                FPU_offset = test
                for w, line in enumerate(disString):
                    FSTENV_instr = False
                    FSTENV_instr = re.match("^fn?stenv", line, re.IGNORECASE)

                    if FSTENV_instr:
                        FSTENV_offset = valOffsets[w]
                        try:
                            printEnd = valOffsets[w + 1]
                        except:
                            dprint2("bad2")
                            break
                            pass

                        fcount += 1
                        if rawHex:
                            modSecName = peName
                        else:
                            modSecName = section.sectionName
                        saveBaseFSTENV(
                            address,
                            NumOpsDis,
                            (NumOpsBack - back),
                            modSecName,
                            secNum,
                            FPU_offset,
                            FSTENV_offset,
                            printEnd,
                        )
                        break


def FSTENVrawhex(address, linesBack2, secNum, data, variables, module, shellcode_label):
    global bit32

    global linesBack
    # linesBack = 10
    linesBack = linesBack2
    # print("Lines Back --> ", linesBack)
    address = int(address)
    linesGoBack = 10

    t = 0
    truth, tl1, tl2, orgListOffset, orgListDisassembly = preSyscalDiscovery(
        0, 0x0, linesGoBack, variables, module, shellcode_label, "FSTENVrawhex"
    )

    if variables.moduleBooleans[shellcode_label].ignoreDisDiscovery:
        truth = False
    t = 0
    chunk = ""
    chunkOffsets = ""
    if truth:
        for t, e in enumerate(orgListDisassembly):
            isFSTENV = re.search("^fn?stenv", e, re.IGNORECASE)
            if isFSTENV:
                FSTENV_offset = hex(orgListOffset[t])
                address = int(orgListOffset[t])
                fpuIndex = 0

                isFPU, fpuIndex = get_FPUInstruction(
                    orgListDisassembly, orgListOffset, linesBack, t
                )

                if isFPU:
                    FPU_offset = hex(orgListOffset[fpuIndex])

                    try:
                        printEnd = hex(orgListOffset[t + 1])
                        if (t - linesGoBack) < 0:
                            linesGoBack = t
                        saveBaseFSTENV(
                            address,
                            (t - fpuIndex + 1),
                            linesGoBack,
                            peName,
                            secNum,
                            FPU_offset,
                            FSTENV_offset,
                            printEnd,
                        )

                    except Exception as e:
                        print(e)

    else:
        for match in (
            FSTENV_GET_BASE.values()
        ):  # iterate through all opcodes representing combinations of registers
            get_FSTENV(10, 15, match, secNum, data)

    if variables.rawHex:
        module[shellcode_label].save_FSTENV_info = list(
            set((module[shellcode_label].save_FSTENV_info))
        )
    else:
        s[secNum].save_FSTENV_info = list(set((s[secNum].save_FSTENV_info)))


def get_FPUInstruction(orgListDisassembly, orgListOffset, linesGoBack, FSTENV_offset):
    fpuIndex = FSTENV_offset - 1
    isFPU = False

    # print("FSTENV_offset", FSTENV_offset, "linesGoBack", linesGoBack)
    if (FSTENV_offset - linesGoBack) < 0:
        chunk = orgListDisassembly[0:FSTENV_offset]
        chunkOffsets = orgListOffset[0:FSTENV_offset]
    else:
        chunk = orgListDisassembly[FSTENV_offset - linesGoBack : FSTENV_offset]
        chunkOffsets = orgListOffset[FSTENV_offset - linesGoBack : FSTENV_offset]
    chunk.reverse()
    for i in chunk:
        # print("current inst", i)
        isFPU = re.search("^f((?!n?stenv).)*$", i, re.IGNORECASE)
        if isFPU:
            break
        fpuIndex -= 1

    return isFPU, fpuIndex


def saveBaseFSTENV(
    address,
    NumOpsDis,
    NumOpsBack,
    modSecName,
    secNum,
    FPU_offset,
    FSTENV_offset,
    printEnd,
):
    # dprint2("Saving FS")
    if secNum != "noSec":
        dprint2("FPU OFF1 = " + str(FPU_offset))
        dprint2("FPU OFF2 = " + str(FPU_offset))
        dprint2("Fstenv OFF1 = " + str(FSTENV_offset))
        dprint2("Fstenv OFF2 = " + str(FSTENV_offset))
        # input("fpu2")
        for each in s[secNum].save_FSTENV_info:
            if FSTENV_offset == each[6]:
                dprint2(
                    "not saving FSTENV_offset ",
                    FSTENV_offset,
                    " because of a match. FPU_offset = ",
                    FPU_offset,
                )
                return

        s[secNum].save_FSTENV_info.append(
            tuple(
                (
                    address,
                    NumOpsDis,
                    NumOpsBack,
                    modSecName,
                    secNum,
                    FPU_offset,
                    FSTENV_offset,
                    printEnd,
                )
            )
        )
    else:
        # dprint2("Pre-Saving one raw ", FPU_offset)
        secNum = -1
        modSecName = "rawHex"
        for each in m[o].save_FSTENV_info:
            if FPU_offset == each[5]:
                return
        dprint2("Actually Saving one raw ", FPU_offset)
        dprint2("FPU OFF1 = " + str(FPU_offset))
        dprint2("FPU OFF2 = " + str(FPU_offset))
        dprint2("Fstenv OFF1 = " + str(FSTENV_offset))
        dprint2("Fstenv OFF2 = " + str(FSTENV_offset))
        m[o].save_FSTENV_info.append(
            tuple(
                (
                    address,
                    NumOpsDis,
                    NumOpsBack,
                    modSecName,
                    secNum,
                    FPU_offset,
                    FSTENV_offset,
                    printEnd,
                )
            )
        )


def printSavedFSTENV(
    bit=32,
):  ######################## AUSTIN ###############################3
    if bit == 32:
        callCS = cs
    else:
        callCS = cs64
    # formatting
    j = 0
    if rawHex:
        for item in m[o].save_FSTENV_info:
            CODED2 = b""

            address = item[0]
            NumOpsDis = item[1]
            NumOpsBack = item[2]
            modSecName = item[3]
            secNum = item[4]
            FPU_offset = item[5]
            FSTENV_offset = item[6]
            printEnd = item[7]
            # print("OFFSETS: ")
            # print("FPU = " + str(FPU_offset))
            # print("FSTENV = " + str(FSTENV_offset))

            # CODED2 = m[o].rawData2[(address-NumOpsBack):(address+NumOpsDis)]
            CODED2 = m[o].rawData2[int(FPU_offset, 16) : (int(printEnd, 16))]
            # CODED2 = m[o].rawData2[(address - NumOpsBack):(int(printEnd, 16))]
            dprint2("PRINT START = " + hex(address - NumOpsBack))
            dprint2("PRINTEND = " + hex(int(printEnd, 16)))

            outString = "\n\nItem: " + str(j)
            if secNum != -1:
                outString += (
                    " | Section: "
                    + str(secNum)
                    + " | Section name: "
                    + str(modSecName)
                    + " | FPU Offset: "
                    + str(FPU_offset)
                    + " | FSTENV Offset: "
                    + str(FSTENV_offset)
                )

            else:
                outString += (
                    " | Module: "
                    + modSecName
                    + " | FPU Offset: "
                    + str(FPU_offset)
                    + " | FSTENV Offset: "
                    + str(FSTENV_offset)
                )

            print(
                "\n******************************************************************************"
            )
            print(constants.YELLOW + outString + res)
            print("\n")
            val = ""
            val2 = []
            val3 = []
            # address2 = address + section.ImageBase + section.VirtualAdd
            val5 = []

            # if bit==32:
            for i in callCS.disasm(CODED2, (address - NumOpsBack)):
                if rawHex:
                    add4 = hex(int(i.address))
                    addb = hex(int(i.address))
                else:
                    add = hex(int(i.address))
                    addb = hex(int(i.address + section.VirtualAdd))
                    add2 = str(add)
                    add3 = hex(int(i.address + section.startLoc))
                    add4 = str(add3)
                val = formatPrint(i, add4, addb)
                # val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
                val5.append(val)
                print(constants.GREEN + val + res)

            # print (constants.GREEN + val + res)
            # if bit==64:
            # 	for i in cs64.disasm(CODED2, (address - NumOpsBack)):
            # 		if(rawHex):
            # 			add4 = hex(int(i.address))
            # 			addb = hex(int(i.address))
            # 		else:
            # 			add = hex(int(i.address))
            # 			addb = hex(int(i.address +  section.VirtualAdd))
            # 			add2 = str(add)
            # 			add3 = hex (int(i.address + section.startLoc	))
            # 			add4 = str(add3)

            # 	# if(hex(i.address) == printEnd):
            # 	# 	break
            # 		val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
            # 		val5.append(val)

            # # print (constants.GREEN + val + res)
            # 		print(constants.GREEN + val + res)
            # return val5
            print("\n")
            j += 1
    else:
        h = 0
        for section in s:
            h += 1
            # print("PRINTING SECTION " + str(h))
            for item in section.save_FSTENV_info:
                CODED2 = ""

                address = item[0]
                NumOpsDis = item[1]
                NumOpsBack = item[2]
                modSecName = item[3]
                secNum = item[4]
                FPU_offset = item[5]
                FSTENV_offset = item[6]
                # print("OFFSETS: ")
                # print("FPU = " + FPU_offset)
                # print("FSTENV = " + FSTENV_offset)
                # print("NUMBACK = " + str(NumOpsBack))

                section = s[secNum]

                outString = "\n\nItem: " + str(j)
                if secNum != -1:
                    outString += (
                        " | Section: "
                        + str(secNum)
                        + " | Section name: "
                        + modSecName.decode()
                        + " | FPU Offset: "
                        + str(FPU_offset)
                        + " | FSTENV Offset: "
                        + str(FSTENV_offset)
                    )

                else:
                    outString += (
                        " | Module: "
                        + modSecName
                        + " | FPU Offset: "
                        + str(FPU_offset)
                        + " | FSTENV Offset: "
                        + str(FSTENV_offset)
                    )

                print(
                    "\n******************************************************************************"
                )
                print(constants.YELLOW + outString + res)
                print("\n")
                val = ""
                val2 = []
                val3 = []
                address2 = address + section.ImageBase + section.VirtualAdd
                val5 = []

                CODED2 = section.data2[(address - NumOpsBack) : (address + NumOpsDis)]

                CODED3 = CODED2
                # if bit == 32:
                for i in callCS.disasm(CODED3, address):
                    add = hex(int(i.address))
                    addb = hex(int(i.address + section.VirtualAdd - NumOpsBack))
                    add2 = str(add)
                    add3 = hex(int(i.address + section.startLoc - NumOpsBack))
                    add4 = str(add3)
                    val = formatPrint(i, add4, addb, pe=True)
                    # val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
                    val2.append(val)
                    val3.append(add2)
                    val5.append(val)
                    if str(FSTENV_offset) == addb:
                        print(constants.GREEN + val + res)
                        break
                    else:
                        print(constants.GREEN + val + res)

                print("\n")
                j += 1


def get_Callpop(NumOpsDis, bytesToMatch, secNum, data2, distance):
    # change to work off of data2 - add param - get rid of secNum
    global o
    foundCount = 0
    numOps = NumOpsDis

    t = 0
    len_data2 = len(data2)
    len_bytesToMatch = len(bytesToMatch)
    for v in data2:
        found = True  # reset flag
        # replace with bytesToMatch list if desired
        # for i in range(len(bytesToMatch)): #can break out on no match for efficiency, left as is for simplicity
        i = 0
        for x in bytesToMatch:
            if found == False:
                break
            # elif ((i+t) >= len_data2 or i >= len_bytesToMatch):
            # 	found = False # out of range
            try:
                # dprint2(data2[t+i])
                # input("enter..")
                if (data2[t + i]) != (bytesToMatch[i]):
                    found = False  # no match
            except Exception:
                # input(e)
                pass
            i += 1

        if found:
            # input("enter..")
            disHereCallpop(t, numOps, secNum, data2, distance)

        t = t + 1


def get_Callpop64(NumOpsDis, bytesToMatch, secNum, data2, distance):
    # change to work off of data2 - add param - get rid of secNum
    # print ("get_Callpop64")

    global o
    foundCount = 0
    numOps = NumOpsDis

    t = 0
    len_data2 = len(data2)
    len_bytesToMatch = len(bytesToMatch)
    for v in data2:
        found = True  # reset flag
        # replace with bytesToMatch list if desired
        # for i in range(len(bytesToMatch)): #can break out on no match for efficiency, left as is for simplicity
        i = 0
        for x in bytesToMatch:
            if found == False:
                break
            # elif ((i+t) >= len_data2 or i >= len_bytesToMatch):
            # 	found = False # out of range
            try:
                # dprint2(data2[t+i])
                # input("enter..")
                if (data2[t + i]) != (bytesToMatch[i]):
                    found = False  # no match
            except Exception:
                # input(e)
                pass
            i += 1

        if found:
            # input("enter..")
            disHereCallpop64(t, numOps, secNum, data2, distance)

        t = t + 1


def disHereCallpop(address, NumOpsDis, secNum, data, distance):
    # print("ENTERED DISHERECALLPOP")
    # dprint2("in dishere")
    pop = False
    CODED2 = ""
    x = NumOpsDis

    origAddr = address
    address = address + distance

    CODED2 = data[(origAddr) : (address + 5)]

    # I create the individual lines of code that will appear>
    val = ""
    val2 = []
    val3 = []
    # address2 = address + section.ImageBase + section.VirtualAdd
    val5 = []
    valOffsets = []

    if secNum != "noSec":
        section = s[secNum]
    # dprint2("HERE IS THE CALL LINE")
    # start = timeit.default_timer()
    CODED3 = CODED2
    for i in cs.disasm(CODED3, address):
        if secNum == "noSec":
            # add = hex(int(i.address))
            add4 = hex(int(i.address))
            addb = hex(int(i.address))
        else:
            add = hex(int(i.address))
            addb = hex(int(i.address + section.VirtualAdd))
            add2 = str(add)
            add3 = hex(int(i.address + section.startLoc))
            add4 = str(add3)
        val = (
            i.mnemonic + " " + i.op_str + "\t\t\t\t" + add4 + " (offset " + addb + ")\n"
        )
        val5.append(val)

        valOffsets.append(addb)
        # dprint2(val)

    disString = val5
    t = 0
    for line in disString:
        ##############################################

        call = re.match("^call ", line, re.IGNORECASE)
        if call:
            pop_addr = valOffsets[t]
            dprint2("POP ADDR = " + str(pop_addr))
        dprint2("POP OFFSET")
        t += 1

    if secNum != "noSec":
        section = s[secNum]
    CODED2 = data[(address) : (address + NumOpsDis)]

    # I create the individual lines of code that will appear>
    val = ""
    val2 = []
    val3 = []
    # address2 = address + section.ImageBase + section.VirtualAdd
    val5 = []

    # dprint2("2ND CHUNK")
    # start = timeit.default_timer()
    CODED3 = CODED2
    for i in cs.disasm(CODED3, address):
        if secNum == "noSec":
            # add = hex(int(i.address))
            add4 = hex(int(i.address))
            addb = hex(int(i.address))
        else:
            add = hex(int(i.address))
            addb = hex(int(i.address + section.VirtualAdd))
            add2 = str(add)
            add3 = hex(int(i.address + section.startLoc))
            add4 = str(add3)
        val = (
            i.mnemonic + " " + i.op_str + "\t\t\t\t" + add4 + " (offset " + addb + ")\n"
        )
        val5.append(val)

        valOffsets.append(addb)
        # dprint2("cpprint")
        # dprint2(val)

    disString = val5

    for line in disString:
        ##############################################

        jmp = re.match("^jmp", line, re.IGNORECASE)
        call = re.match("^call", line, re.IGNORECASE)
        bad = re.match(
            "^((jmp)|(ljmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(int)|(retf)|(db)|(hlt)|(loop)|(ret)|(leave)|(int3)|(insd)|(enter)|(jns))",
            line,
            re.M | re.I,
        )
        if jmp or call or bad:
            return

        pop = re.match(
            "^pop (e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE
        )
        if pop:
            pop_offset = line.split()[-1]
            pop_offset = pop_offset[:-1]
        # print("POP OFFSET")
        # print(pop_offset)
        if pop:
            if rawHex:
                modSecName = peName
            else:
                modSecName = section.sectionName

            # dprint2("saving one")
            # dprint2(binarytostr(line))

            saveBaseCallpop(
                origAddr, NumOpsDis, modSecName, secNum, distance, pop_offset
            )
            return


def disHereCallpop64(address, NumOpsDis, secNum, data, distance):
    # print ("disHereCallpop64")
    pop = False
    CODED2 = ""
    x = NumOpsDis

    origAddr = address
    # address = address + distance
    valOffsets = []

    CODED2 = data[(origAddr) : (address + 20)]

    # I create the individual lines of code that will appear>
    val = ""
    val2 = []
    val3 = []
    # address2 = address + section.ImageBase + section.VirtualAdd
    val5 = []
    valOpstr = []
    if secNum != "noSec":
        section = s[secNum]
    # dprint2("HERE IS THE CALL LINE")
    # start = timeit.default_timer()
    CODED3 = CODED2

    # print ("test1")
    for i in cs64.disasm(CODED3, address):
        if secNum == "noSec":
            # add = hex(int(i.address))
            add4 = hex(int(i.address))
            addb = hex(int(i.address))
        else:
            add = hex(int(i.address))
            addb = hex(int(i.address + section.VirtualAdd))
            add2 = str(add)
            add3 = hex(int(i.address + section.startLoc))
            add4 = str(add3)
        val = (
            i.mnemonic + " " + i.op_str + "\t\t\t\t" + add4 + " (offset " + addb + ")\n"
        )
        valOpstr.append(i.op_str)
        val5.append(val)

        valOffsets.append(addb)
        dprint2(val)

    dprint2(len(val5), "lenght val5")
    disString = val5
    t = 0
    # print("CODED2 Before", CODED2.hex())

    for line in disString:
        ##############################################
        dprint2(line)
        call = re.match("^call [0x]*[0-9a-f]{1,2}", disString[0], re.IGNORECASE)
        if call:
            # print("Found call")
            # input()
            # pop_addr = line.split()[1]
            # pop_addr = pop_addr[:-1]
            # print ("found call")
            pop_addr = valOpstr[t]
            # print("pop address", pop_addr)
            dprint2("POP ADDR = " + str(pop_addr))
            # dprint2(binaryToStr(CODED3))
        # dprint2("POP OFFSET")
        t += 1

    if secNum != "noSec":
        section = s[secNum]
    CODED2 = data[(address) : (address + NumOpsDis)]
    # print("CODED2 after", CODED2.hex())
    # input()
    # I create the individual lines of code that will appear>
    val = ""
    val2 = []
    val3 = []
    # address2 = address + section.ImageBase + section.VirtualAdd
    val5 = []

    # dprint2("2ND CHUNK")
    # start = timeit.default_timer()
    CODED3 = CODED2
    for i in cs64.disasm(CODED3, address):
        if secNum == "noSec":
            # add = hex(int(i.address))
            add4 = hex(int(i.address))
            addb = hex(int(i.address))
        else:
            add = hex(int(i.address))
            addb = hex(int(i.address + section.VirtualAdd))
            add2 = str(add)
            add3 = hex(int(i.address + section.startLoc))
            add4 = str(add3)
        val = (
            i.mnemonic + " " + i.op_str + "\t\t\t\t" + add4 + " (offset " + addb + ")\n"
        )
        val5.append(val)

        dprint2(val)
        valOpstr.append(addb)

    disString2 = val5

    t = 0
    dprint2(disString)
    for line in disString:
        ##############################################
        # Note that push/pop are invalid for e registers in x64. r registers are correct.
        # pop = re.match("^pop (((r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp))) | (r((8)|(9)|(1(0-5)))d?)", line, re.IGNORECASE)
        dprint2("t", t, "line", line)

        bad = re.match(
            "^((jmp)|(ljmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(int)|(retf)|(db)|(hlt)|(loop)|(ret)|(leave)|(int3)|(insd)|(enter)|(jns)|(call))",
            line,
            re.M | re.I,
        )  # addd call
        if bad:
            dprint2("got bad")
        if (bad) and (t > 0):
            # print("Returning")
            return
        t += 1

    t = 0

    for line in disString:
        # print("Line", line, "offset", valOffsets[t])
        # print("offset: ", valOffsets)
        ##############################################
        # Note that push/pop are invalid for e registers in x64. r registers are correct.
        # pop = re.match("^pop (((r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp))) | (r((8)|(9)|(1(0-5)))d?)", line, re.IGNORECASE)
        # print("disString2", line)
        # jmp = re.match("^jmp", line, re.IGNORECASE)
        # call = re.match("^call", line, re.IGNORECASE)
        # bad = re.match("^((jmp)|(ljmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(int)|(retf)|(db)|(hlt)|(loop)|(ret)|(leave)|(int3)|(insd)|(enter)|(jns))", line, re.M|re.I)
        # if(jmp or call or bad):
        # return

        pop = re.match(
            "^pop ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)|(8)|(9)|(1[0-5])))",
            line,
            re.IGNORECASE,
        )
        if pop:
            # print("offset: ", valOffsets[t])
            # print(pop)
            # input()
            # pop_offset = valOpstr[t]
            # print("Found pop offset")

            pop_offset = valOffsets[t]
            # dprint2("POP OFFSET")
            # dprint2(line)
        # dprint2(pop_offset)

        if pop:
            if rawHex:
                modSecName = peName
            else:
                modSecName = section.sectionName
            # dprint2("saving one")
            # print("Saving call pop: ", origAddr, "pop offset", pop_offset)
            # print("Saving: ", hex(origAddr), "pop_offset", pop_offset)
            saveBaseCallpop(
                origAddr, NumOpsDis, modSecName, secNum, distance, pop_offset
            )
            return
        t += 1


def callPopRawHex(
    address, linesForward2, secNum, data, variables, module, shellcode_label
):
    global maxDistance
    global linesForward
    global debugging

    # debugging = True
    address = int(address)
    linesGoBack = 10
    truth, tl1, tl2, orgListOffset, orgListDisassembly = preSyscalDiscovery(
        address, 0x0, linesGoBack, variables, module, shellcode_label, "callPopRawHex"
    )
    if variables.moduleBooleans[shellcode_label].ignoreDisDiscovery:
        truth = False

    t = 0
    if truth:
        for disasmLine in orgListDisassembly:
            distance = None
            isCall = re.match("^call (0x)?[0-9,a-f]{1,2}", disasmLine, re.IGNORECASE)
            if isCall:
                dest = disasmLine.split()[1]
                numeric = re.match(" ?(0x)?([0-9A-F])+$", dest, re.IGNORECASE)
                # print("found call with dest ", dest, "on line ", disasmLine, " ||||| NUMERIC = ", numeric)
                if numeric:
                    distance = int(dest, 0) - orgListOffset[t]
                    # print("Distance after math = ", distance)
                    w = t + 1
                    for postCallLine in orgListDisassembly[
                        t + 1 : t + 1 + linesForward + maxDistance
                    ]:
                        bad = re.match(
                            "^((jmp)|(ljmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(int)|(retf)|(db)|(hlt)|(loop)|(ret)|(leave)|(int3)|(insd)|(enter)|(jns)|(call))",
                            postCallLine,
                            re.M | re.I,
                        )
                        isPop = re.search(
                            "^pop ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)|(8)|(9)|(1[0-5])))",
                            postCallLine,
                            re.IGNORECASE,
                        )

                        # print("comparing destination ", dest, " to line ", orgListDisassembly[w], " OFFSET:", hex(orgListOffset[w]))
                        if bad and (int(dest, 0) <= orgListOffset[w]):
                            # print("got a bbad on line ", postCallLine, " | offset: ", hex(orgListOffset[w]), " | call offset: ", hex(orgListOffset[t]))
                            break
                        if isPop and (int(dest, 0) <= orgListOffset[w]):
                            # print("found a good pop on line", postCallLine, " | offset: ", hex(orgListOffset[w]), " | call offset: ", hex(orgListOffset[t]))
                            address = orgListOffset[t]
                            pop_offset = orgListOffset[w]
                            distance = pop_offset - address

                            pop_offset = hex(pop_offset)
                            saveBaseCallpop(
                                address,
                                linesForward,
                                "noSec",
                                secNum,
                                distance,
                                pop_offset,
                            )
                            break
                        w += 1

            t += 1

    else:
        for match in (
            CALLPOP_START.values()
        ):  # iterate through all opcodes representing combinations of registers
            get_Callpop(10, match[0], secNum, data, match[1])

    if variables.rawHex:
        module[shellcode_label].save_Callpop_info = list(
            set(module[shellcode_label].save_Callpop_info)
        )
    else:
        s[secNum].save_Callpop_info = list(set(s[secNum].save_Callpop_info))


def saveBaseCallpop(address, NumOpsDis, modSecName, secNum, distance, pop_offset):
    # save virtaul address as well
    tmp = tuple((address, NumOpsDis, modSecName, secNum, distance, pop_offset))

    if secNum != "noSec":
        s[secNum].save_Callpop_info.append(
            tuple((address, NumOpsDis, modSecName, secNum, distance, pop_offset))
        )
    else:
        secNum = -1
        modSecName = "rawHex"

        m[o].save_Callpop_info.append(
            tuple((address, NumOpsDis, modSecName, secNum, distance, pop_offset))
        )


def printSavedCallPop(
    bit=32,
):  ######################## AUSTIN ###############################3
    global o
    if bit == 64:
        callCS = cs64
    else:
        callCS = cs
    if rawHex:
        for j, item in enumerate(m[o].save_Callpop_info):
            CODED2 = b""

            origAddr = item[0]
            NumOpsDis = item[1]
            modSecName = item[2]
            secNum = item[3]
            distance = item[4]
            pop_offset = item[5]
            address = origAddr + distance
            popOpcLen = 1
            CODED2 = m[o].rawData2[(origAddr) : (address + NumOpsDis)]

            outString = "Item: " + str(j)
            if secNum != -1:
                outString += (
                    " | Section: " + str(secNum) + " | Section name: " + str(modSecName)
                )

            else:
                outString += (
                    " | Call address: "
                    + str(hex(origAddr))
                    + " | Pop offset: "
                    + str(pop_offset)
                    + " | Distance from call: "
                    + str(hex(distance))
                )

            print(
                "******************************************************************************"
            )
            print(constants.YELLOW + outString + res)
            val = ""
            val2 = []
            val3 = []
            # address2 = address + section.ImageBase + section.VirtualAdd
            val5 = []

            for i in callCS.disasm(CODED2, origAddr):
                if rawHex:
                    add4 = hex(int(i.address))
                    addb = hex(int(i.address))
                else:
                    add = hex(int(i.address))
                    addb = hex(int(i.address + section.VirtualAdd))
                    add2 = str(add)
                    add3 = hex(int(i.address + section.startLoc))
                    add4 = str(add3)
                val = formatPrint(i, add4, addb)

                print(constants.GREEN + val + res)
                if addb == pop_offset:
                    break
    else:
        h = 0
        for section in s:
            h += 1
            # print("PRINTING SECTION " + str(h))
            for j, item in enumerate(section.save_Callpop_info):
                CODED2 = ""
                origAddr = item[0]
                NumOpsDis = item[1]
                modSecName = item[2]
                secNum = item[3]
                distance = item[4]
                pop_offset = item[5]
                address = origAddr + distance
                popOpcLen = 1

                section = s[secNum]

                printAddress = origAddr + section.VirtualAdd
                outString = "\n\nItem: " + str(j)
                if secNum != -1:
                    outString += (
                        " | Call address: "
                        + str(hex(printAddress))
                        + " | Pop offset: "
                        + str(pop_offset)
                        + " | Distance from call: "
                        + str(hex(distance))
                    )

                else:
                    outString += " | Module: " + modSecName

                print(
                    "\n******************************************************************************"
                )
                print(constants.YELLOW + outString + constants.RESET)
                print("\n")
                val = ""
                val2 = []
                val3 = []
                address2 = address + section.ImageBase + section.VirtualAdd
                val5 = []
                CODED2 = section.data2[(origAddr) : (address + NumOpsDis)]

                CODED3 = CODED2

                for i in callCS.disasm(CODED3, origAddr):
                    add = hex(int(i.address))
                    addb = hex(int(i.address + section.VirtualAdd))
                    add2 = str(add)
                    add3 = hex(int(i.address + section.startLoc))
                    add4 = str(add3)
                    val = formatPrint(i, add4, add, pe=True)

                    val2.append(val)
                    val3.append(add2)
                    val5.append(val)
                    print(constants.GREEN + val + constants.RESET)
                    if addb == pop_offset:
                        break

                print("\n")


def identifySyscall(
    callNum,
):  # returns two lists containing lists of the format [syscall name 1, version 1, version 2.... ]. First list is results for x86 OSes, second is for x86-64
    result = []
    result64 = []
    result32 = []
    callNum = format(callNum, "#06x")
    with open(
        os.path.join(os.path.dirname(__file__), "sharem", "nt64.csv"), "r"
    ) as file:
        nt64Csv = csv.reader(file)
        nt64Header = next(nt64Csv)
        for row in nt64Csv:
            if callNum in row:
                newEntry = []
                newEntry.append(row[0])
                while callNum in row:
                    newEntry.append(nt64Header[row.index(callNum)])
                    row[row.index(callNum)] = ""
                result64.append(newEntry)

    with open(
        os.path.join(os.path.dirname(__file__), "sharem", "win32k64.csv"), "r"
    ) as file:
        w3264Csv = csv.reader(file)
        w3264header = next(w3264Csv)
        for row in w3264Csv:
            if callNum in row:
                newEntry = []
                newEntry.append(row[0])
                while callNum in row:
                    newEntry.append(w3264header[row.index(callNum)])
                    row[row.index(callNum)] = ""
                result64.append(newEntry)

    with open(os.path.join(os.path.dirname(__file__), "sharem", "nt.csv"), "r") as file:
        ntCsv = csv.reader(file)
        ntHeader = next(ntCsv)
        for row in ntCsv:
            if callNum in row:
                newEntry = []
                newEntry.append(row[0])
                while callNum in row:
                    newEntry.append(ntHeader[row.index(callNum)])
                    row[row.index(callNum)] = ""
                result32.append(newEntry)

    with open(
        os.path.join(os.path.dirname(__file__), "sharem", "win32k.csv"), "r"
    ) as file:
        w32Csv = csv.reader(file)
        w32header = next(w32Csv)
        for row in w32Csv:
            if callNum in row:
                newEntry = []
                newEntry.append(row[0])
                while callNum in row:
                    newEntry.append(w32header[row.index(callNum)])
                    row[row.index(callNum)] = ""
                result32.append(newEntry)

    result.append(result32)
    result.append(result64)
    return result


# enter callNum as hex code of syscall, bit and wanted version are optional and will return most recent 64bit OS by default
def getSyscall(callNum, bit=64, version="default"):
    apiList = identifySyscall(callNum)
    if bit == 64:
        apiList = apiList[1]
    else:
        apiList = apiList[0]

    if version == "default":
        if bit == 64:
            with open(
                os.path.join(os.path.dirname(__file__), "\\sharem\\nt64.csv"), "r"
            ) as file:
                nt64Csv = csv.reader(file)
                nt64Header = next(nt64Csv)
                version = nt64Header[-1]

        else:
            with open(
                os.path.join(os.path.dirname(__file__), "\\sharem\\nt32.csv"), "r"
            ) as file:
                nt32Csv = csv.reader(file)
                nt32Header = next(nt32Csv)
                version = nt64Header[-1]

    # some user friendliness -- handle upper/lower and differences in spaces
    version = version.lower()
    version = version.replace(" ", "")

    for item in apiList:
        name = item[0]
        osList = item[1:]

        for osItem in osList:
            if osItem.lower().replace(" ", "") == version:
                result = name
                return result


def getSyscallRecent(callNum, bit=64, print2File=None, jsonFormat=None):
    global syscallSelection
    global syscallString

    syscallString = ""
    syscallList = []
    apiList = identifySyscall(callNum)
    if bit == 64:
        apiList = apiList[1]
    else:
        apiList = apiList[0]

    if bit == 64:
        with open(
            os.path.join(os.path.dirname(__file__), "sharem", "nt64.csv"), "r"
        ) as file:
            nt64Csv = csv.reader(file)
            versions = next(nt64Csv)
            versions = versions[1:]

    else:
        with open(
            os.path.join(os.path.dirname(__file__), "sharem", "nt32.csv"), "r"
        ) as file:
            nt32Csv = csv.reader(file)
            versions = next(nt32Csv)
            versions = versions[1:]

    categories = []
    for version in versions:
        version = version.rsplit("(", 1)[0]
        if version not in categories:
            categories.append(version)
    finalCat = [[] for _ in range(len(categories))]
    finalList = ["" for _ in range(len(versions))]

    for item in apiList:
        name = item[0]
        osList = item[1:]

        for osItem in osList:
            for i in range(len(versions)):
                if osItem == versions[i]:
                    addAPI = (name, osItem)
                    finalList[i] = name
    try:
        for i in range(len(versions)):
            for sys in syscallSelection:
                syscallDict = {}

                tempName = sys.name
                if re.search("^release ", tempName, re.IGNORECASE):
                    tempName = tempName[8:]
                if (
                    sys.toggle
                    and (re.search(rf"{sys.category}", versions[i], re.IGNORECASE))
                    and (re.search(rf"{tempName}", versions[i], re.IGNORECASE))
                ):
                    if print2File == None:
                        print("OS: " + versions[i])
                        print("Syscall: " + finalList[i])
                        print("\n")
                    else:
                        syscallDict["OS"] = versions[i].strip()
                        syscallDict["syscall"] = finalList[i].strip()
                        syscallList.append(syscallDict)

                        syscallString += "OS: " + versions[i]
                        syscallString += " Syscall: " + finalList[i]
                        syscallString += "\n"

    except:
        for i in range(len(categories)):
            syscallDict = {}

            newest = "N/A"
            newestVersion = "N/A"
            for j in range(len(finalList)):
                category = versions[j].rsplit("(", 1)[0]
                if (category == categories[i]) and (finalList[j] != ""):
                    newest = finalList[j]
                    newestVersion = versions[j]
            if print2File == None:
                print(categories[i])
                print("OS: " + newestVersion)
                print("Syscall: " + newest)
                print("\n")
            else:
                syscallDict["OS"] = versions[i].strip()
                syscallDict["syscall"] = finalList[i].strip()
                syscallList.append(syscallDict)

                syscallString += "OS: " + newestVersion
                syscallString += " Syscall: " + newest
                syscallString += "\n"
    if jsonFormat:
        return syscallList
    else:
        return syscallString


def trackRegs(
    disAsm, startStates, stack
):  # disAsm: disassembly string | startStates: tuple containing starting values of each register | stack: list of items on the stack
    eax = startStates[0]
    ebx = startStates[1]
    ecx = startStates[2]
    edx = startStates[3]
    edi = startStates[4]
    esi = startStates[5]
    ebp = startStates[6]
    esp = startStates[7]

    eaxOffset = 0
    ebxOffset = 0
    ecxOffset = 0
    edxOffset = 0
    ediOffset = 0
    esiOffset = 0
    ebpOffset = 0
    espOffset = 0

    def _instructionMatch(inst: str, line: str) -> Optional[str]:
        """Use regex to match assembly instruction."""
        return re.match(
            f"^({inst}) (e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))",
            line,
            re.ignorecase,
        )

    for line in disAsm:
        line = line.rsplit("	", 1)[0]

        mov = _instructionMatch("mov", line)
        add = _instructionMatch("add", line)
        sub = _instructionMatch("sub", line)
        xor = _instructionMatch("xor", line)
        xchg = _instructionMatch("xchg", line)
        push = re.match("^(push)", line, re.IGNORECASE)
        pop = re.match("^(pop)", line, re.IGNORECASE)

        if mov:
            reg = mov.group().split(" ")[1].replace(",", "").lower()

            if reg == "eax":
                eaxOffset = 0
            elif reg == "ebx":
                ebxOffset = 0
            elif reg == "ecx":
                ecxOffset = 0
            elif reg == "edx":
                edxOffset = 0
            elif reg == "edi":
                ediOffset = 0
            elif reg == "esi":
                esiOffset = 0
            elif reg == "ebp":
                ebpOffset = 0
            elif reg == "esp":
                espOffset = 0

            line = line.split(",", 1)[-1]
            line = line.replace(" ", "")

            variable = re.search(
                " ?(e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE
            )
            numeric = re.search("^ ?(0x)?([0-9A-F])+", line, re.IGNORECASE)
            ptr = re.search(" ?(ptr)", line, re.IGNORECASE)

            if ptr:
                found = "unknown"
                if reg == "eax":
                    eax = found
                elif reg == "ebx":
                    ebx = found
                elif reg == "ecx":
                    ecx = found
                elif reg == "edx":
                    edx = found
                elif reg == "edi":
                    edi = found
                elif reg == "esi":
                    esi = found
                elif reg == "ebp":
                    ebp = found
                elif reg == "esp":
                    esp = found

            elif variable:
                found = str(variable.group())
                if found == "eax":
                    found = eax
                elif found == "ebx":
                    found = ebx
                elif found == "ecx":
                    found = ecx
                elif found == "edx":
                    found = edx
                elif found == "edi":
                    found = edi
                elif found == "esi":
                    found = esi
                elif found == "ebp":
                    found = ebp
                elif found == "esp":
                    found = esp
                else:
                    found = "unknown"

            elif numeric:
                found = int(numeric.group(), 16)
                found = hex(found)
            else:
                found = "unknown"

            if reg == "eax":
                eax = found
            elif reg == "ebx":
                ebx = found
            elif reg == "ecx":
                ecx = found
            elif reg == "edx":
                edx = found
            elif reg == "edi":
                edi = found
            elif reg == "esi":
                esi = found
            elif reg == "ebp":
                ebp = found
            elif reg == "esp":
                esp = found

        elif add:
            reg = add.group().split(" ")[1].replace(",", "").lower()

            line = line.split(",", 1)[-1]
            line = line.replace(" ", "")

            variable = re.search(
                " ?(e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE
            )
            numeric = re.search("^ ?(0x)?([0-9A-F])+", line, re.IGNORECASE)

            ptr = re.search(" ?(ptr)", line, re.IGNORECASE)

            if ptr:
                found = "unknown"
                if reg == "eax":
                    eax = found
                elif reg == "ebx":
                    ebx = found
                elif reg == "ecx":
                    ecx = found
                elif reg == "edx":
                    edx = found
                elif reg == "edi":
                    edi = found
                elif reg == "esi":
                    esi = found
                elif reg == "ebp":
                    ebp = found
                elif reg == "esp":
                    esp = found

            elif variable:
                found = str(variable.group())

                if found == "eax":
                    found = eax
                elif found == "ebx":
                    found = ebx
                elif found == "ecx":
                    found = ecx
                elif found == "edx":
                    found = edx
                elif found == "edi":
                    found = edi
                elif found == "esi":
                    found = esi
                elif found == "ebp":
                    found = ebp
                elif found == "esp":
                    found = esp
                else:
                    found = "unknown"

                found = str(found)

            elif numeric:
                found = int(numeric.group(), 0)
                found = hex(found)

            else:
                found = "unknown"

            curOffset = found

            if reg == "eax":
                if eax == "unknown":
                    if curOffset == "unknown":
                        eaxOffset = 0
                    else:
                        eaxOffset += int(curOffset, 0)

                elif found == "unknown":
                    eax = "unknown"
                else:
                    eax = int(str(eax), 0) + int(str(found), 0)
            elif reg == "ebx":
                if ebx == "unknown":
                    if curOffset == "unknown":
                        ebxOffset = 0
                    else:
                        ebxOffset += int(curOffset, 0)

                elif found == "unknown":
                    ebx = "unknown"
                else:
                    ebx = int(str(ebx), 0) + int(str(found), 0)
            elif reg == "ecx":
                if ecx == "unknown":
                    if curOffset == "unknown":
                        ecxOffset = 0
                    else:
                        ecxOffset += int(curOffset, 0)

                elif found == "unknown":
                    ecx = "unknown"
                else:
                    ecx = int(str(ecx), 0) + int(str(found), 0)
            elif reg == "edx":
                if edx == "unknown":
                    if curOffset == "unknown":
                        edxOffset = 0
                    else:
                        edxOffset += int(curOffset, 0)

                elif found == "unknown":
                    edx = "unknown"
                else:
                    edx = int(str(edx), 0) + int(str(found), 0)
            elif reg == "edi":
                if edi == "unknown":
                    if curOffset == "unknown":
                        ediOffset = 0
                    else:
                        ediOffset += int(curOffset, 0)

                elif found == "unknown":
                    edi = "unknown"
                else:
                    edi = int(str(edi), 0) + int(str(found), 0)
            elif reg == "esi":
                if esi == "unknown":
                    if curOffset == "unknown":
                        esiOffset = 0
                    else:
                        esiOffset += int(curOffset, 0)

                elif found == "unknown":
                    esi = "unknown"
                else:
                    esi = int(str(esi), 0) + int(str(found), 0)
            elif reg == "ebp":
                if ebp == "unknown":
                    if curOffset == "unknown":
                        ebpOffset = 0
                    else:
                        ebpOffset += int(curOffset, 0)

                elif found == "unknown":
                    ebp = "unknown"
                else:
                    ebp = int(str(ebp), 0) + int(str(found), 0)
            elif reg == "esp":
                if esp == "unknown":
                    if curOffset == "unknown":
                        espOffset = 0
                    else:
                        espOffset += int(curOffset, 0)

                elif found == "unknown":
                    esp = "unknown"
                else:
                    esp = int(str(esp), 0) + int(str(found), 0)

        elif sub:
            reg = sub.group().split(" ")[1].replace(",", "").lower()

            line = line.split(",", 1)[-1]
            line = line.replace(" ", "")

            variable = re.search(
                " ?(e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE
            )
            numeric = re.search("^ ?(0x)?([0-9A-F])+", line, re.IGNORECASE)

            ptr = re.search(" ?(ptr)", line, re.IGNORECASE)

            if ptr:
                found = "unknown"
                if reg == "eax":
                    eax = found
                elif reg == "ebx":
                    ebx = found
                elif reg == "ecx":
                    ecx = found
                elif reg == "edx":
                    edx = found
                elif reg == "edi":
                    edi = found
                elif reg == "esi":
                    esi = found
                elif reg == "ebp":
                    ebp = found
                elif reg == "esp":
                    esp = found

            elif variable:
                found = str(variable.group())
                # print("here is what i found:")
                # print(found)

                if found == "eax":
                    found = eax
                elif found == "ebx":
                    found = ebx
                elif found == "ecx":
                    found = ecx
                elif found == "edx":
                    found = edx
                elif found == "edi":
                    found = edi
                elif found == "esi":
                    found = esi
                elif found == "ebp":
                    found = ebp
                elif found == "esp":
                    found = esp
                else:
                    found = "unknown"

                found = str(found)

            elif numeric:
                found = int(numeric.group(), 0)
                # print("here is what i found:")
                # print(found)

                found = hex(found)

            else:
                found = "unknown"

            curOffset = found

            if reg == "eax":
                if eax == "unknown":
                    if curOffset == "unknown":
                        eaxOffset = 0
                    else:
                        eaxOffset -= int(curOffset, 0)

                elif found == "unknown":
                    eax = "unknown"
                else:
                    eax = int(str(eax), 0) - int(str(found), 0)
            elif reg == "ebx":
                if ebx == "unknown":
                    if curOffset == "unknown":
                        ebxOffset = 0
                    else:
                        ebxOffset -= int(curOffset, 0)

                elif found == "unknown":
                    ebx = "unknown"
                else:
                    ebx = int(str(ebx), 0) - int(str(found), 0)
            elif reg == "ecx":
                if ecx == "unknown":
                    if curOffset == "unknown":
                        ecxOffset = 0
                    else:
                        ecxOffset -= int(curOffset, 0)

                elif found == "unknown":
                    ecx = "unknown"
                else:
                    ecx = int(str(ecx), 0) - int(str(found), 0)
            elif reg == "edx":
                if edx == "unknown":
                    if curOffset == "unknown":
                        edxOffset = 0
                    else:
                        edxOffset -= int(curOffset, 0)

                elif found == "unknown":
                    edx = "unknown"
                else:
                    edx = int(str(edx), 0) - int(str(found), 0)
            elif reg == "edi":
                if edi == "unknown":
                    if curOffset == "unknown":
                        ediOffset = 0
                    else:
                        ediOffset -= int(curOffset, 0)

                elif found == "unknown":
                    edi = "unknown"
                else:
                    edi = int(str(edi), 0) - int(str(found), 0)
            elif reg == "esi":
                if esi == "unknown":
                    if curOffset == "unknown":
                        esiOffset = 0
                    else:
                        esiOffset -= int(curOffset, 0)

                elif found == "unknown":
                    esi = "unknown"
                else:
                    esi = int(str(esi), 0) - int(str(found), 0)
            elif reg == "ebp":
                if ebp == "unknown":
                    if curOffset == "unknown":
                        ebpOffset = 0
                    else:
                        ebpOffset -= int(curOffset, 0)

                elif found == "unknown":
                    ebp = "unknown"
                else:
                    ebp = int(str(ebp), 0) - int(str(found), 0)
            elif reg == "esp":
                if esp == "unknown":
                    if curOffset == "unknown":
                        espOffset = 0
                    else:
                        espOffset -= int(curOffset, 0)

                elif found == "unknown":
                    esp = "unknown"
                else:
                    esp = int(str(esp), 0) - int(str(found), 0)

        elif xor:
            # print("in xor")
            nullify = False
            reg = xor.group().split(" ")[1].replace(",", "").lower()

            if reg == "eax":
                eaxOffset = 0
            elif reg == "ebx":
                ebxOffset = 0
            elif reg == "ecx":
                ecxOffset = 0
            elif reg == "edx":
                edxOffset = 0
            elif reg == "edi":
                ediOffset = 0
            elif reg == "esi":
                esiOffset = 0
            elif reg == "ebp":
                ebpOffset = 0
            elif reg == "esp":
                espOffset = 0

            line = line.split(",", 1)[-1]
            line = line.replace(" ", "")

            variable = re.search(
                " ?(e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE
            )
            numeric = re.search("^ ?(0x)?([0-9A-F])+", line, re.IGNORECASE)
            ptr = re.search(" ?(ptr)", line, re.IGNORECASE)

            if ptr:
                found = "unknown"
                if reg == "eax":
                    eax = found
                elif reg == "ebx":
                    ebx = found
                elif reg == "ecx":
                    ecx = found
                elif reg == "edx":
                    edx = found
                elif reg == "edi":
                    edi = found
                elif reg == "esi":
                    esi = found
                elif reg == "ebp":
                    ebp = found
                elif reg == "esp":
                    esp = found

            elif variable:
                found = str(variable.group())
                if found == reg:
                    nullify = True

                # print("here is what i found:")
                # print(found)

                elif found == "eax":
                    found = eax
                elif found == "ebx":
                    found = ebx
                elif found == "ecx":
                    found = ecx
                elif found == "edx":
                    found = edx
                elif found == "edi":
                    found = edi
                elif found == "esi":
                    found = esi
                elif found == "ebp":
                    found = ebp
                elif found == "esp":
                    found = esp

                else:
                    found = "unknown"

                found = str(found)

            elif numeric:
                found = int(numeric.group(), 0)
                # print("here is what i found:")
                # print(found)

                found = hex(found)

            else:
                found = "unknown"

            if reg == "eax":
                if nullify:
                    eax = "0"
                elif (eax == "unknown") or (found == "unknown"):
                    eax = "unknown"
                else:
                    eax = int(str(eax), 0) ^ int(str(found), 0)
            elif reg == "ebx":
                if nullify:
                    ebx = "0"
                elif (ebx == "unknown") or (found == "unknown"):
                    ebx = "unknown"
                else:
                    ebx = int(str(ebx), 0) ^ int(str(found), 0)
            elif reg == "ecx":
                if nullify:
                    ecx = "0"
                elif (ecx == "unknown") or (found == "unknown"):
                    ecx = "unknown"
                else:
                    ecx = int(str(ecx), 0) ^ int(str(found), 0)
            elif reg == "edx":
                if nullify:
                    edx = "0"
                elif (edx == "unknown") or (found == "unknown"):
                    edx = "unknown"
                else:
                    edx = int(str(edx), 0) ^ int(str(found), 0)
            elif reg == "edi":
                if nullify:
                    edi = "0"
                elif (edi == "unknown") or (found == "unknown"):
                    edi = "unknown"
                else:
                    edi = int(str(edi), 0) ^ int(str(found), 0)
            elif reg == "esi":
                if nullify:
                    esi = "0"
                elif (esi == "unknown") or (found == "unknown"):
                    esi = "unknown"
                else:
                    esi = int(str(esi), 0) ^ int(str(found), 0)
            elif reg == "ebp":
                if nullify:
                    ebp = "0"
                elif (ebp == "unknown") or (found == "unknown"):
                    ebp = "unknown"
                else:
                    ebp = int(str(ebp), 0) ^ int(str(found), 0)
            elif reg == "esp":
                if nullify:
                    esp = "0"
                elif (esp == "unknown") or (found == "unknown"):
                    esp = "unknown"
                else:
                    esp = int(str(esp), 0) ^ int(str(found), 0)

        elif xchg:
            reg = xchg.group().split(" ")[1].replace(",", "").lower()

            if reg == "eax":
                eaxOffset = 0
            elif reg == "ebx":
                ebxOffset = 0
            elif reg == "ecx":
                ecxOffset = 0
            elif reg == "edx":
                edxOffset = 0
            elif reg == "edi":
                ediOffset = 0
            elif reg == "esi":
                esiOffset = 0
            elif reg == "ebp":
                ebpOffset = 0
            elif reg == "esp":
                espOffset = 0

            line = line.split(",", 1)[-1]
            line = line.replace(" ", "")

            variable = re.search(
                " ?(e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE
            )
            if variable:
                found = str(variable.group())
                # print("here is what i found:")
                # print(found)

                if found == "eax":
                    found = eax
                    if reg == "ebx":
                        eax = ebx
                        ebx = found
                    elif reg == "ecx":
                        eax = ecx
                        ecx = found
                    elif reg == "edx":
                        eax = edx
                        edx = found
                    elif reg == "edi":
                        eax = edi
                        edi = found
                    elif reg == "esi":
                        eax = ebx
                        ebx = found
                    elif reg == "ebp":
                        eax = ebp
                        ebp = found
                    elif reg == "esp":
                        eax = esp
                        esp = found
                elif found == "ebx":
                    found = ebx
                    if reg == "eax":
                        ebx = eax
                        eax = found
                    elif reg == "ecx":
                        ebx = ecx
                        ecx = found
                    elif reg == "edx":
                        ebx = edx
                        edx = found
                    elif reg == "edi":
                        ebx = edi
                        edi = found
                    elif reg == "esi":
                        ebx = esi
                        esi = found
                    elif reg == "ebp":
                        ebx = ebp
                        ebp = found
                    elif reg == "esp":
                        ebx = esp
                        esp = found
                elif found == "ecx":
                    found = ecx
                    if reg == "eax":
                        ecx = eax
                        eax = found
                    elif reg == "ebx":
                        ecx = ebx
                        ebx = found
                    elif reg == "edx":
                        ecx = edx
                        edx = found
                    elif reg == "edi":
                        ecx = edi
                        edi = found
                    elif reg == "esi":
                        ecx = esi
                        esi = found
                    elif reg == "ebp":
                        ecx = ebp
                        ebp = found
                    elif reg == "esp":
                        ecx = esp
                        esp = found
                elif found == "edx":
                    found = edx
                    if reg == "eax":
                        edx = eax
                        eax = found
                    elif reg == "ebx":
                        edx = ebx
                        ebx = found
                    elif reg == "ecx":
                        edx = ecx
                        ecx = found
                    elif reg == "edi":
                        edx = edi
                        edi = found
                    elif reg == "esi":
                        edx = esi
                        esi = found
                    elif reg == "ebp":
                        edx = ebp
                        ebp = found
                    elif reg == "esp":
                        edx = esp
                        esp = found
                elif found == "edi":
                    found = edi
                    if reg == "eax":
                        edi = eax
                        eax = found
                    elif reg == "ebx":
                        edi = ebx
                        ebx = found
                    elif reg == "ecx":
                        edi = ecx
                        ecx = found
                    elif reg == "edx":
                        edi = edx
                        edx = found
                    elif reg == "esi":
                        edi = esi
                        esi = found
                    elif reg == "ebp":
                        edi = ebp
                        ebp = found
                    elif reg == "esp":
                        edi = esp
                        esp = found
                elif found == "esi":
                    found = esi
                    if reg == "eax":
                        esi = eax
                        eax = found
                    elif reg == "ebx":
                        esi = ebx
                        ebx = found
                    elif reg == "ecx":
                        esi = ecx
                        ecx = found
                    elif reg == "edx":
                        esi = edx
                        edx = found
                    elif reg == "edi":
                        esi = edi
                        edi = found
                    elif reg == "ebp":
                        esi = ebp
                        ebp = found
                    elif reg == "esp":
                        esi = esp
                        esp = found
                elif found == "ebp":
                    found = ebp
                    if reg == "eax":
                        ebp = eax
                        eax = found
                    elif reg == "ebx":
                        ebp = ebx
                        ebx = found
                    elif reg == "ecx":
                        ebp = ecx
                        ecx = found
                    elif reg == "edx":
                        ebp = edx
                        edx = found
                    elif reg == "edi":
                        ebp = edi
                        edi = found
                    elif reg == "esi":
                        ebp = esi
                        esi = found
                    elif reg == "esp":
                        ebp = esp
                        esp = found
                elif found == "esp":
                    found = esp

                    if reg == "eax":
                        esp = eax
                        eax = found

                    elif reg == "ebx":
                        esp = ebx
                        ebx = found
                    elif reg == "ecx":
                        esp = ecx
                        ecx = found
                    elif reg == "edx":
                        esp = edx
                        edx = found
                    elif reg == "edi":
                        esp = edi
                        edi = found
                    elif reg == "esi":
                        esp = esi
                        esi = found
                    elif reg == "ebp":
                        esp = ebp
                        ebp = found
                else:
                    found = "unknown"

                found = str(found)

            else:
                found = "unknown"

        elif push:
            line = line.split(" ", 1)[-1]

            line = line.replace(" ", "")

            # print("PUSH LINE IS")
            # print(line)
            variable = re.search(
                " ?(e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE
            )
            numeric = re.search("^ ?(0x)?([0-9A-F])+", line, re.IGNORECASE)
            ptr = re.search(" ?(ptr)", line, re.IGNORECASE)

            if ptr:
                found = "unknown"

            elif variable:
                found = str(variable.group())

                # print("here is what i found:")
                # print(found)

                if found == "eax":
                    found = eax
                elif found == "ebx":
                    found = ebx
                elif found == "ecx":
                    found = ecx
                elif found == "edx":
                    found = edx
                elif found == "edi":
                    found = edi
                elif found == "esi":
                    found = esi
                elif found == "ebp":
                    found = ebp
                elif found == "esp":
                    found = esp
                else:
                    found = "unknown"

                found = str(found)

            elif numeric:
                try:
                    found = int(numeric.group(), 0)

                    # print("here is what i found:")
                    # print(found)

                    found = hex(found)
                except:
                    found = "unknown"
                    pass

            else:
                found = "unknown"
            stack.append(found)

            if esp != "unknown":
                if type(esp) == int:
                    esp = str(esp)
                esp = int(esp, 0) - 4
            else:
                espOffset -= 4

        elif pop:
            line = line.split(" ", 1)[-1]
            line = line.replace(" ", "")

            # print("PUSH LINE IS")
            # print(line)
            variable = re.search(
                " ?(e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE
            )
            numeric = re.search("^ ?(0x)?([0-9A-F])+", line, re.IGNORECASE)

            ptr = re.search(" ?(ptr)", line, re.IGNORECASE)

            if variable and (not ptr):
                found = str(variable.group())

                # print("here is what i found:")
                # print(found)

                if stack:
                    val = str(stack.pop())

                else:
                    val = "unknown"

                if found == "eax":
                    eax = val
                    eaxOffset = 0
                elif found == "ebx":
                    ebx = val
                    ebxOffset = 0
                elif found == "ecx":
                    ecx = val
                    ecxOffset = 0
                elif found == "edx":
                    edx = val
                    edxOffset = 0
                elif found == "edi":
                    edi = val
                    ediOffset = 0
                elif found == "esi":
                    esi = val
                    esiOffset = 0
                elif found == "ebp":
                    ebp = val
                    ebpOffset = 0
                elif found == "esp":
                    esp = val
                    espOffset = 0
                else:
                    found = "unknown"

            if esp != "unknown":
                if type(esp) == int:
                    esp = str(esp)
                # print("----> ", esp, type(esp))
                esp = int(esp, 0) + 4
            else:
                espOffset += 4

    # if(eaxOffset == 0):
    # 	print("EAX = " + str(eax))
    # else:
    # 	print("EAX = " + str(eax) + ' + ' + str(hex(eaxOffset)))
    # if(ebxOffset == 0):
    # 	print("EBX = " + str(ebx))
    # else:
    # 	print("EBX = " + str(ebx) + ' + ' + str(hex(ebxOffset)))
    # if(ecxOffset == 0):
    # 	print("ECX = " + str(ecx))
    # else:
    # 	print("ECX = " + str(ecx) + ' + ' + str(hex(ecxOffset)))
    # if(edxOffset == 0):
    # 	print("EDX = " + str(edx))
    # else:
    # 	print("EDX = " + str(edx) + ' + ' + str(hex(edxOffset)))
    # if(ediOffset == 0):
    # 	print("EDI = " + str(edi))
    # else:
    # 	print("EDI = " + str(edi) + ' + ' + str(hex(ediOffset)))
    # if(esiOffset == 0):
    # 	print("ESI = " + str(esi))
    # else:
    # 	print("ESI = " + str(esi) + ' + ' + str(hex(esiOffset)))
    # if(ebpOffset == 0):
    # 	print("EBP = " + str(ebp))
    # else:
    # 	print("EBP = " + str(ebp) + ' + ' + str(hex(ebpOffset)))
    # if(espOffset == 0):
    # 	print("ESP = " + str(esp))
    # else:
    # 	print("ESP = " + str(esp) + ' + ' + str(hex(espOffset)))

    # for item in stack:
    # 	print("STACK ITEM: " + str(item))

    regsResult = [eax, ebx, ecx, edx, edi, esi, ebp, ebp]
    for x in range(len(regsResult)):
        try:
            regsResult[x] = hex(regsResult[x])
        except Exception:
            # print(e)
            pass
    return (regsResult, stack)


def getSyscallPE(NumOpsDis, NumOpsBack, bytesToMatch, secNum, data2):
    # change to work off of data2 - add param - get rid of secNum

    # dprint2('in get, sec: ', secNum)

    global o
    foundCount = 0
    numOps = NumOpsDis

    t = 0
    len_data2 = len(data2)
    len_bytesToMatch = len(bytesToMatch)

    # dprint2("Bytes: ", len_bytesToMatch)

    for v in data2:
        found = True  # reset flag
        # replace with bytesToMatch list if desired
        # for i in range(len(bytesToMatch)): #can break out on no match for efficiency, left as is for simplicity
        i = 0
        for x in bytesToMatch:
            if found == False:
                break
            # elif ((i+t) >= len_data2 or i >= len_bytesToMatch):
            # 	found = False # out of range
            try:
                # dprint2(data2[t+i])

                # input("enter..")
                if (data2[t + i]) != (bytesToMatch[i]):
                    found = False  # no match
            except Exception:
                # input(e)
                pass
            i += 1

        if found:
            # print("Found syscall")
            # input()
            # dprint2("here's one")
            # input("enter..")
            disHereSyscall(t, numOps, NumOpsBack, secNum, data2)

        t = t + 1


def get_HeavenPE(NumOpsDis, NumOpsBack, bytesToMatch, secNum, data2):
    # change to work off of data2 - add param - get rid of secNum

    # dprint2('in get')

    global o
    foundCount = 0
    numOps = NumOpsDis

    t = 0
    len_data2 = len(data2)
    len_bytesToMatch = len(bytesToMatch)
    for v in data2:
        found = True  # reset flag
        # replace with bytesToMatch list if desired
        # for i in range(len(bytesToMatch)): #can break out on no match for efficiency, left as is for simplicity
        i = 0
        for x in bytesToMatch:
            if found == False:
                break
            # elif ((i+t) >= len_data2 or i >= len_bytesToMatch):
            # 	found = False # out of range
            try:
                # dprint2(data2[t+i])
                # input("enter..")
                if (data2[t + i]) != (bytesToMatch[i]):
                    found = False  # no match
            except Exception:
                # input(e)
                pass
            i += 1

        if found:
            # dprint2("here's one")
            # input("enter..")
            disHereHeavenPE(t, numOps, NumOpsBack, secNum, data2)

        t = t + 1


def disHereSyscall(
    address, NumOpsDis, NumOpsBack, secNum, data
):  ############ AUSTIN ##############
    global o
    global total1
    global total2
    global fcount
    global regsVals
    w = 0

    op_const = 16
    line_const = 8
    NumOpsBack = NumOpsBack + op_const

    ## Capstone does not seem to allow me to start disassemblying at a given point, so I copy out a chunk to  disassemble. I append a 0x00 because it does not always disassemble correctly (or at all) if just two bytes. I cause it not to be displayed through other means. It simply take the starting address of the jmp [reg], disassembles backwards, and copies it to a variable that I examine more closely.
    # lGoBack = linesGoBackFindOP

    # dprint2("disHere")
    # dprint2(hex(address))
    # dprint2(secNum)
    # input("addy")

    # dprint2("eggdis")

    CODED2 = ""
    x = NumOpsDis
    # start = timeit.default_timer()
    if secNum != "noSec":
        section = s[secNum]

    # this setting allows us to filter out some rare edge case bugs. Using Cs() instead of copying cs var so it doesn't leave lasting problems
    if bit32:
        syscallCs = Cs(CS_ARCH_X86, CS_MODE_32)
    else:
        syscallCs = Cs(CS_ARCH_X86, CS_MODE_64)
    syscallCs.skipdata = True
    syscallCs.skipdata_setup = ("bad instruction", None, None)
    # dprint2("------------------------------------")
    for back in range(NumOpsBack):
        unlikely = 0
        # dprint2("back = " + str(back))
        CODED2 = data[(address - (NumOpsBack - back)) : (address + x)]
        # dprint2("########################")
        # dprint2(type(CODED2))
        # dprint2("########################")
        #
        # stop = timeit.default_timer()
        # total1 += (stop - start)
        # dprint2("Time 1 PEB: " + str(stop - start))

        # I create the individual lines of code that will appear>
        # dprint2(len(CODED2))
        val = ""
        val2 = []
        val3 = []
        # address2 = address + section.ImageBase + section.VirtualAdd
        val5 = []

        # start = timeit.default_timer()
        # CODED3 = CODED2.encode()
        CODED3 = CODED2
        # dprint2("BINARY2STR")
        # dprint2(binaryToStr(CODED3))
        # dprint2("******************************************")
        for i in syscallCs.disasm(CODED3, address):
            # dprint2('address in for = ' + str(address))
            if secNum == "noSec":
                # dprint2("i = " + str(i) + " i.mnemonic = " + str(i.mnemonic))
                # add = hex(int(i.address))
                add4 = hex(int(i.address - (NumOpsBack - back)))
                addb = hex(int(i.address - (NumOpsBack - back)))
            else:
                add = hex(int(i.address))
                addb = hex(int(i.address + section.VirtualAdd - (NumOpsBack - back)))
                add2 = str(add)
                add3 = hex(int(i.address + section.startLoc - (NumOpsBack - back)))
                add4 = str(add3)
            val = (
                i.mnemonic
                + " "
                + i.op_str
                + "\t\t\t\t"
                + add4
                + " (offset "
                + addb
                + ")\n"
            )
            # val2.append(val)
            # val3.append(add2)
            val5.append(val)
            # dprint2(val)

            disString = val5
            # dprint2("before")
            # dprint2(disString)
            # disString = disString[2:]
            # dprint2("after")
            # dprint2(disString)
            c0_match = False
            # check for dword ptr fs:[reg] and verify value of register

        for line in disString:
            # if(re.match("(fs:\[0xc0\])|(fs:\[(((e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l)))))( ?\+ ?(0x)?[0-9a-f]+)?\])", line, re.IGNORECASE)):
            if (
                re.match(
                    "^((call)|(jump)) dword ptr fs:\[((((e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l)))))( ?\+ ?(0x)?[0-9a-f]+)?|(0xc0))\]",
                    line,
                    re.IGNORECASE,
                )
                or re.match("^(syscall)", line, re.IGNORECASE)
                or re.match("^(int 0x2e)", line, re.IGNORECASE)
            ):
                c0_match = True
                c0_offset = line.split()[-1]
                c0_offset = c0_offset[:-1]

            byte = re.search("byte ptr", line, re.IGNORECASE)
            insd = re.search("insd", line, re.IGNORECASE)
            outsd = re.search("outsd", line, re.IGNORECASE)
            # longNum = re.search("(0x)([0-9a-f]){6,}", line, re.IGNORECASE)
            longNum = re.search("\[?(0x)([0-9a-f]){6,}\]", line, re.IGNORECASE)
            badInstruction = re.search("bad instruction", line, re.IGNORECASE)
            # adc eax, dword[0xe0ff42]
            # dword ptr [eax + 0xe0ff4212]
            # dword ptr [0xe0ff4212]

            if badInstruction:
                unlikely = 999
            if byte or insd or longNum or outsd:
                unlikely = unlikely + 1

            # if(unlikely < 3):
            # dprint2("unlikely: ", unlikely, "c0: ", c0_match)

            if c0_match and (unlikely < 3):
                if secNum == "noSec":
                    structure = m[o]
                else:
                    structure = s[secNum]
                found = False

                for i in structure.save_Egg_info:
                    if c0_offset == i[6]:
                        found = True
                        # print("found")
                # dprint2("heavensave")
                # print("--> ", saving)
                # input()
                if not found:
                    # dprint2("c0 match")
                    # dprint2("SAVING THIS ONE")
                    # input("> ")
                    if rawHex:
                        modSecName = peName
                    else:
                        modSecName = section.sectionName

                    startStates = (
                        "unknown",
                        "unknown",
                        "unknown",
                        "unknown",
                        "unknown",
                        "unknown",
                        "unknown",
                        "unknown",
                    )
                    eax = trackRegs(disString, startStates, [])[0][0]

                    saveBaseEgg(
                        address,
                        NumOpsDis,
                        (NumOpsBack - back),
                        modSecName,
                        secNum,
                        eax,
                        c0_offset,
                    )
                    return
                else:
                    c0_match = False


# generates entire disassembley and finds all instances of syscalls
def getSyscallRawHex(
    address, linesBack, secNum, data, variables, module, shellcode_label
):
    global regsVals
    global syscallRawHexOverride
    dprint2("DISEGG2")
    address = hex(address)
    linesGoBack = linesBack
    t = 0

    addressInt = int(address, 16)
    truth, tl1, tl2, orgListOffset, orgListDisassembly = preSyscalDiscovery(
        addressInt,
        0x0,
        linesGoBack,
        variables,
        module,
        shellcode_label,
        "getSyscallRawHex",
    )  # arg: starting offset/entry point - leave 0 generally
    if variables.moduleBooleans[shellcode_label].ignoreDisDiscovery:
        truth = False
    if truth:
        ####the FULL disassembly of the shellcode
        dprint2("hello33")
        for e in orgListDisassembly:
            dprint2(str(hex(orgListOffset[t])) + "\t" + e)

            isEgg = re.search(
                "^((call)|(jump)) dword ptr fs:\[((((e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l)))))( ?\+ ?(0x)?[0-9a-f]+)?|(0xc0))\]",
                e,
                re.IGNORECASE,
            )
            eggNew = re.search("^((int 0x2e)|(syscall))", e, re.IGNORECASE)
            if isEgg or eggNew:
                c0_offset = hex(orgListOffset[t])
                address = int(orgListOffset[t])
                startChunk = t - linesBack
                if startChunk < 0:
                    startChunk = 0
                chunk = orgListDisassembly[startChunk : t + 1]
                chunkOffsets = orgListOffset[startChunk : t + 1]

                # convert to disassembly format compatible with trackRegs()
                converted = convertStringToTrack(chunk, chunkOffsets)

                startStates = (
                    "unknown",
                    "unknown",
                    "unknown",
                    "unknown",
                    "unknown",
                    "unknown",
                    "unknown",
                    "unknown",
                )
                eax = trackRegs(converted, startStates, [])[0][0]

                dprint2("THURS eax = " + str(eax) + "\n\n\n")

                modSecName = peName
                saveBaseEgg(
                    address,
                    -1,
                    (linesBack),
                    modSecName,
                    secNum,
                    eax,
                    c0_offset,
                    converted,
                )

            t += 1

    if not truth:
        syscallRawHexOverride = True
        findAllSyscall(module[shellcode_label].rawData2, "noSec")


def print_from_directory(fName, arch=None):
    dirName = slash.join(fName.split(slash)[:-1])
    fileName = fName.split(slash)[-1]
    output = "******************************\n"
    output += (
        constants.YELLOW
        + "\nFile      : "
        + constants.GREEN
        + fileName
        + constants.RESET
        + "\n"
    )

    if arch:
        output += (
            constants.YELLOW
            + "Arch      : "
            + constants.GREEN
            + str(arch)
            + "-bit"
            + constants.RESET
            + "\n"
        )

    output += (
        constants.YELLOW
        + "Directory : "
        + constants.GREEN
        + dirName
        + constants.RESET
        + "\n\n"
    )
    output += "******************************\n\n"

    return output


def parse32Shellcode():
    global filename
    global rawHex
    global rawBin
    global bit32
    global rawData2
    global known_arch

    known_arch = True

    for i in list_of_files32:
        # print("list_of_files32 ", rawHex)
        tmpName = os.path.basename(i)
        # print("Processing ", i)
        output = print_from_directory(i, 32)
        print(output)
        filename = i
        if i[-3:] == "txt":
            rawHex = True
            rawBin = False
            bit32 = True
            variables.shellBit = 32

            init2(filename)
            module[o] = newModule(o, rawData2, tmpName)
        elif i[-3:] == "bin":
            rawHex = True
            rawBin = True
            bit32 = True
            variables.shellBit = 32
            f = open(i, "rb")

            rawData2 = f.read()
            module[o] = newModule(o, rawData2, tmpName)
            f.close()
        startupPrint()
        clearAll()


def parse64Shellcode():
    global filename
    global rawHex
    global rawBin
    global bit32
    global rawData2
    global known_arch

    known_arch = True

    for i in list_of_files64:
        # print("Processing ", i)
        tmpName = os.path.basename(i)

        output = print_from_directory(i, 64)
        print(output)
        filename = i

        if i[-3:] == "txt":
            rawHex = True
            bit32 = False
            rawBin = False
            variables.shellBit = 64
            init2(filename)
            module[o] = newModule(o, rawData2, tmpName)

        elif i[-3:] == "bin":
            rawHex = True
            rawBin = True
            variables.shellBit = 64
            bit32 = False
            f = open(i, "rb")
            readRawData2 = f.read()
            module[o] = newModule(o, readRawData2, tmpName)
            f.close()
        startupPrint()
        clearAll()


def parse32PE():
    global peName
    global filename
    global rawHex
    global rawBin
    global bit32
    global known_arch

    known_arch = True

    for i in list_of_pe32:
        # print("Processing ", i)
        tmpName = os.path.basename(i)
        peName = i
        filename = i
        rawHex = False
        rawBin = False
        variables.shellBit = 32
        # print(" PE 32 --> ", rawHex)
        module[o] = newModule(i, 0, tmpName)

        Extraction()
        output = print_from_directory(i, 32)
        print(output)
        bit32 = True
        init2(i)

        startupPrint()

        clearAll()


def parse64PE():
    global peName
    global filename
    global rawHex
    global rawBin
    global bit32
    global known_arch

    # print("############", list_of_pe64)
    known_arch = True
    for i in list_of_pe64:
        # print("Processing ", i)
        peName = i
        tmpName = os.path.basename(i)

        filename = i
        rawHex = False
        # print(" PE 64 --> ", rawHex)

        rawBin = False
        # newSection()
        module[o] = newModule(i, 0, tmpName)
        Extraction()
        output = print_from_directory(i, 64)
        print(output)
        bit32 = False
        variables.shellBit = 64
        init2(i)
        startupPrint()
        clearAll()


def parseUnkownArch():
    global bit32
    global rawHex
    global rawBin
    global filename
    global rawData2
    global known_arch

    # print("parse Unknown")

    known_arch = False
    for i in list_of_unk_files:
        count = 0
        tmpName = os.path.basename(i)
        while count < 2:
            if count == 0:
                output = print_from_directory(i, 32)
            elif count == 1:
                output = print_from_directory(i, 64)

            print(output)
            filename = i
            if count == 0:
                jsonP.current_arch = 32
            else:
                jsonP.current_arch = 64

            if i[-3:] == "txt":
                if count == 0:
                    bit32 = True
                    variables.shellBit = 32
                elif count == 1:
                    bit32 = False
                    variables.shellBit = 64
                rawHex = True
                rawBin = False

                init2(filename)
                module[o] = newModule(o, rawData2, tmpName)
            elif i[-3:] == "bin":
                rawHex = True
                rawBin = True
                if count == 0:
                    bit32 = True
                    variables.shellBit = 32
                elif count == 1:
                    bit32 = False
                    variables.shellBit = 64

                f = open(i, "rb")

                rawData2 = f.read()
                # print("gName -----> ", gName)
                module[o] = newModule(o, rawData2, tmpName)
                f.close()
            startupPrint()
            clearAll()

            count += 1


def disHereHeavenPE(
    address, NumOpsDis, NumOpsBack, secNum, data
):  ############ AUSTIN ##############
    global o
    global total1
    global total2
    global fcount
    w = 0
    if variables.shellBit == 32:
        callCS = cs
    else:
        callCS = cs64
    disString = []
    destLocation = -1
    push_offset = 0xBADDBADD

    op_const = 16
    line_const = 8
    NumOpsBack = NumOpsBack + op_const

    retfBad = False
    ## Capstone does not seem to allow me to start disassemblying at a given point, so I copy out a chunk to  disassemble. I append a 0x00 because it does not always disassemble correctly (or at all) if just two bytes. I cause it not to be displayed through other means. It simply take the starting address of the jmp [reg], disassembles backwards, and copies it to a variable that I examine more closely.
    # lGoBack = linesGoBackFindOP

    # dprint2("disHere")
    # dprint2(hex(address))
    # dprint2(secNum)
    # input("addy")

    if bit32:
        syscallCs = Cs(CS_ARCH_X86, CS_MODE_32)
    else:
        syscallCs = Cs(CS_ARCH_X86, CS_MODE_64)
    syscallCs.skipdata = True
    syscallCs.skipdata_setup = ("bad instruction", None, None)

    CODED2 = ""
    x = NumOpsDis
    # start = timeit.default_timer()
    if secNum != "noSec":
        section = s[secNum]

    # dprint2("------------------------------------")
    for back in range(NumOpsBack):
        unlikely = 0
        # dprint2("back = " + str(back))
        CODED2 = data[(address - (NumOpsBack - back)) : (address + x)]

        # dprint2("########################")
        # dprint2(type(CODED2))
        # dprint2("########################")
        #
        # stop = timeit.default_timer()
        # total1 += (stop - start)
        # dprint2("Time 1 PEB: " + str(stop - start))

        # I create the individual lines of code that will appear>
        # dprint2(len(CODED2))
        val = ""
        val2 = []
        val3 = []
        # address2 = address + section.ImageBase + section.VirtualAdd
        val5 = []

        # start = timeit.default_timer()
        # CODED3 = CODED2.encode()
        CODED3 = CODED2
        # dprint2("BINARY2STR")
        # dprint2(binaryToStr(CODED3))
        # dprint2("******************************************")
        offsets = []
        for i in syscallCs.disasm(CODED3, address):
            # dprint2('address in for = ' + str(address))
            if secNum == "noSec":
                # dprint2("i = " + str(i) + " i.mnemonic = " + str(i.mnemonic))
                # add = hex(int(i.address))
                add4 = hex(int(i.address - (NumOpsBack - back)))
                addb = hex(int(i.address - (NumOpsBack - back)))
            else:
                add = hex(int(i.address))
                addb = hex(int(i.address + section.VirtualAdd - (NumOpsBack - back)))
                add2 = str(add)
                add3 = hex(int(i.address + section.startLoc - (NumOpsBack - back)))
                add4 = str(add3)
            offsets.append(addb)
            val = (
                i.mnemonic
                + " "
                + i.op_str
                + "\t\t\t\t"
                + add4
                + " (offset "
                + addb
                + ")\n"
            )
            # val2.append(val)
            # val3.append(add2)
            val5.append(val)

            # dprint2(val)

            disString = val5
            # print(disString)
            # input()
            # dprint2("before")
            # dprint2(disString)
            # disString = disString[2:]
            # dprint2("after")
            # dprint2(disString)
        heav_match = False
        # check for dword ptr fs:[reg] and verify value of register
        retf = False

        push_offset = ""
        t = 0
        # print("Length: ", len(disString))
        # input()
        for line in disString:
            # dprint2("HEAVLINE", line)
            bad = re.match(
                "^((jmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(int)|(db)|(hlt)|(loop)|(ret)|(leave)|(int3)|(insd)|(enter)|(jns)|(call))",
                line,
                re.M | re.I,
            )  # addd call
            if bad and (not retf):
                retfBad = True
                # dprint2("got bad")

            if re.match("^((ljmp)|(lcall)) 0x33:", line, re.IGNORECASE):
                heav_match = True
                offset = line.split()[-1]
                offset = offset[:-1]
                destLocation = line.split(":")[-1]
            if re.match("^retf", line, re.IGNORECASE):
                # dprint2("FOUND RETF")
                retf = True
                retfBad = False
                # heav_match = True
                offset = line.split()[-1]
                offset = offset[:-1]

            if re.search("push 0x33", line, re.IGNORECASE):
                push_offset = offsets[t]
                # dprint2("SAVED PUSH OFFSET: ", push_offset)

            byte = re.search("byte ptr", line, re.IGNORECASE)
            insd = re.search("insd", line, re.IGNORECASE)
            outsd = re.search("outsd", line, re.IGNORECASE)
            # longNum = re.search("(0x)([0-9a-f]){6,}", line, re.IGNORECASE)
            longNum = re.search("\[?(0x)([0-9a-f]){6,}\]", line, re.IGNORECASE)
            badInstr = re.search("bad instruction", line, re.IGNORECASE)

            # adc eax, dword[0xe0ff42]
            # dword ptr [eax + 0xe0ff4212]
            # dword ptr [0xe0ff4212]
            if byte or insd or longNum or outsd:
                unlikely = unlikely + 1
            if badInstr and not heav_match and not retf:
                unlikely = 999

        if heav_match and (unlikely < 3):
            # dprint2("heavenhere")
            # dprint2(line)

            if rawHex:
                modSecName = peName
            else:
                modSecName = section.sectionName
            saveBaseHeaven(
                address,
                NumOpsDis,
                (NumOpsBack - back),
                modSecName,
                secNum,
                offset,
                "ljmp/lcall",
                destLocation=destLocation,
            )
            return

        elif retf and (unlikely < 3) and (not retfBad):
            # dprint2("heavenhere")
            # dprint2(line)

            # dprint2("RETF DISSTRING = ", disString)
            startStates = (
                "unknown",
                "unknown",
                "unknown",
                "unknown",
                "unknown",
                "unknown",
                "unknown",
                "unknown",
            )
            stack = trackRegs(disString, startStates, [])[1]
            # dprint2("STACK IS HERE")
            # dprint2(stack)
            if hex(0x33) in stack:
                flag33 = False
                destLocation = -1
                for i in range(len(stack) - 1, -1, -1):
                    if flag33:
                        destLocation = stack[i]
                        flag33 = False

                    if stack[i] == hex(0x33):
                        flag33 = True

                # print (destLocation, "destLocation", type(destLocation))

                try:
                    destRegex = (
                        "push " + destLocation
                    )  # this one was the one giving the error
                except:
                    destRegex = "push " + str(destLocation)

                dprint2("DESTREGEX = ", destRegex)
                pushOffset = 0xBADDBADD
                for line in disString:
                    pushLine = re.match(destRegex, line, re.IGNORECASE)
                    if pushLine:
                        pushOffset = line.split()[-1]
                        pushOffset = pushOffset[:-1]

                if rawHex:
                    modSecName = peName
                else:
                    modSecName = section.sectionName
                try:
                    saveBaseHeaven(
                        address,
                        NumOpsDis,
                        (NumOpsBack - back),
                        modSecName,
                        secNum,
                        offset,
                        "retf",
                        destLocation=destLocation,
                        pushOffset=int(pushOffset, 0),
                    )
                except:
                    saveBaseHeaven(
                        address,
                        NumOpsDis,
                        (NumOpsBack - back),
                        modSecName,
                        secNum,
                        offset,
                        "retf",
                        destLocation=destLocation,
                        pushOffset=pushOffset,
                    )

            return

        t += 1


def getHeavenRawHex(
    address, linesBack, secNum, data, variables, module, shellcode_label
):
    global heavRawHexOverride

    address = hex(address)
    linesGoBack = linesBack
    t = 0
    truth, tl1, tl2, orgListOffset, orgListDisassembly = preSyscalDiscovery(
        0, 0x0, linesGoBack, variables, module, shellcode_label, "getHeavenRawHex"
    )  # arg: starting offset/entry point - leave 0 generally
    if variables.moduleBooleans[shellcode_label].ignoreDisDiscovery:
        truth = False

    if truth:
        push_offset = 0xBADDBADD
        destLocation = -1
        ####the FULL disassembly of the shellcode
        for e in orgListDisassembly:
            # account for if we're at the very beginning of the code

            push_offset = 0xBADDBADD
            dprint2(str(hex(orgListOffset[t])) + "\t" + e)

            isRETF = re.search("retf", e, re.IGNORECASE)
            isJMP = re.search("ljmp 0x33:", e, re.IGNORECASE)
            isCALL = re.search("lcall 0x33:", e, re.IGNORECASE)
            if isCALL or isJMP:
                offset = hex(orgListOffset[t])
                address = int(orgListOffset[t])
                t_temp = 0
                if t - linesBack < 0:
                    chunk = orgListDisassembly[0 : t + 1]
                    chunkOffsets = orgListOffset[0 : t + 1]
                else:
                    chunk = orgListDisassembly[t - linesBack : t + 1]
                    chunkOffsets = orgListOffset[t - linesBack : t + 1]

                heavString = e
                destLocation = heavString.split(":")[-1]
                converted = convertStringToTrack(chunk, chunkOffsets)
                modSecName = peName
                saveBaseHeaven(
                    address,
                    -1,
                    (linesBack),
                    modSecName,
                    secNum,
                    offset,
                    "ljmp/lcall",
                    pushOffset=push_offset,
                    converted=converted,
                    destLocation=destLocation,
                )

            elif isRETF:
                c = 0
                pushCount = 0
                pushed33 = False
                offset = hex(orgListOffset[t])
                address = int(orgListOffset[t])
                t_temp = 0
                dprint2("t-LinesBack here: ", t - linesBack)
                if t - linesBack < 0:
                    chunk = orgListDisassembly[0 : t + 1]
                    chunkOffsets = orgListOffset[0 : t + 1]
                else:
                    chunk = orgListDisassembly[t - linesBack : t + 1]
                    chunkOffsets = orgListOffset[t - linesBack : t + 1]

                converted = convertStringToTrack(chunk, chunkOffsets)
                startStates = (
                    "unknown",
                    "unknown",
                    "unknown",
                    "unknown",
                    "unknown",
                    "unknown",
                    "unknown",
                    "unknown",
                )
                stack = trackRegs(converted, startStates, [])[1]
                dprint2("STACK IS HERE")
                dprint2(stack)

                if hex(0x33) in stack:
                    dprint2("found33 in stack")
                    flag33 = False
                    destLocation = -1
                    for i in range(len(stack) - 1, -1, -1):
                        if stack[i] == hex(0x33):
                            flag33 = True
                        if flag33:
                            destLocation = stack[i]
                            flag33 = False

                    if destLocation != -1 and destLocation != "unknown":
                        c = 0
                        destRegex = "push " + destLocation
                        dprint2("DESTREGEX : ", destRegex)
                        for line in chunk:
                            if re.search(destRegex, line, re.IGNORECASE):
                                push_offset = chunkOffsets[c]

                            c += 1

                    modSecName = peName
                    saveBaseHeaven(
                        address,
                        -1,
                        (linesBack),
                        modSecName,
                        secNum,
                        offset,
                        "retf",
                        pushOffset=push_offset,
                        destLocation=destLocation,
                        converted=converted,
                    )
            t += 1

    else:
        heavRawHexOverride = True
        findAllHeaven(module[shellcode_label].rawData2, "noSec")


def saveBaseHeaven(
    address,
    NumOpsDis,
    linesBack,
    modSecName,
    secNum,
    offset,
    pivottype,
    pushOffset=0xBADDBADD,
    destLocation=-1,
    converted="",
):
    if secNum != "noSec":
        found = False
        # saving = tuple((address,NumOpsDis,linesBack,modSecName,secNum, offset, pushOffset, destLocation, pivottype))
        for i in s[secNum].save_Heaven_info:
            if offset == i[5]:
                found = True
                # print("found")
        # dprint2("heavensave")
        # print("--> ", saving)
        # input()
        if not found:
            s[secNum].save_Heaven_info.append(
                tuple(
                    (
                        address,
                        NumOpsDis,
                        linesBack,
                        modSecName,
                        secNum,
                        offset,
                        pushOffset,
                        destLocation,
                        pivottype,
                    )
                )
            )
    else:
        dprint2("Saving one raw")

        secNum = -1
        modSecName = "rawHex"
        m[o].save_Heaven_info.append(
            tuple(
                (
                    address,
                    NumOpsDis,
                    linesBack,
                    modSecName,
                    secNum,
                    offset,
                    pushOffset,
                    destLocation,
                    converted,
                    pivottype,
                )
            )
        )


def cleanOutput(data):
    data = data.replace("\t", "")

    allInstr = data.split(" ")
    # print("Everything ---> ", allInstr)
    mnemonic = allInstr[0]
    add4 = allInstr[-3]
    addb = allInstr[-2:]
    op_str = " ".join(allInstr[1:-3])
    return mnemonic, op_str, add4, addb


def printSavedHeaven(
    bit=32,
):  ######################## AUSTIN ###############################3
    # formatting
    if bit32:
        callCS = cs
    else:
        callCS = cs64

    j = 0
    if rawHex:
        # print("in rawhex")
        if heavRawHexOverride:
            # print("in override")
            for item in m[o].save_Heaven_info:
                CODED2 = ""

                address = item[0]
                NumOpsDis = item[1]
                NumOpsBack = item[2]
                modSecName = item[3]
                secNum = item[4]
                offset = item[5]
                pushOffset = item[6]
                destLocation = item[7]
                converted = item[8]
                pivottype = item[9]

                # print("NUMBACK = " + str(NumOpsBack))

                outString = "\nHeaven Item: " + str(j)
                if secNum != -1:
                    outString += (
                        " | Section: "
                        + str(secNum)
                        + " | Section name: "
                        + modSecName.decode()
                        + " | Heaven's Gate offset: "
                        + str(offset)
                        + " | Push dest. addr offset: "
                        + hex(pushOffset)
                        + " | Dest. Address: "
                        + str(destLocation)
                        + "\n"
                    )

                else:
                    outString += (
                        " | Module: "
                        + modSecName
                        + " | Heaven's Gate offset: "
                        + str(offset)
                        + " | Push dest. addr offset: "
                        + hex(pushOffset)
                        + " | Dest. Address: "
                        + str(destLocation)
                        + "\n"
                    )

                print("\n********************************************************")
                print(constants.YELLOW + outString + res)
                # print ("\n")
                val = ""
                val2 = []
                val3 = []
                # address2 = address + section.ImageBase + section.VirtualAdd
                val5 = []
                # CODED2 = section.data2[(address-NumOpsBack):(address+NumOpsDis)]
                bytesCompensation = 18
                if pivottype == "ljmp/lcall":
                    start = int(offset, 16)  # - section.VirtualAdd
                    # The 7 is for the ljmp assembly mnemonic
                    CODED2 = m[o].rawData2[(start) : (start + 7)]
                elif pivottype == "retf":
                    start = int(offset, 16)  # - section.VirtualAdd
                    # The two bytes is for the retf
                    CODED2 = m[o].rawData2[(start - bytesCompensation) : start + 2]

                CODED3 = CODED2

                # for i in callCS.disasm(CODED3, address):
                if pivottype == "ljmp/lcall":
                    bytesCompensation = 0
                elif pivottype == "retf":
                    bytesCompensation = 18
                for i in callCS.disasm(CODED3, start - bytesCompensation):
                    add = hex(int(i.address))
                    # addb = hex(int(i.address +  section.VirtualAdd - NumOpsBack))
                    addb = hex(int(i.address))
                    add2 = str(add)
                    # add3 = hex (int(i.address + section.startLoc	- NumOpsBack))
                    add3 = hex(int(i.address))
                    add4 = str(add3)
                    val = formatPrint(i, add4, addb, pe=True)

                    # val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
                    val2.append(val)
                    val3.append(add2)
                    val5.append(val)
                    print(constants.GREEN + val + res)
                j += 1

        else:
            for item in m[o].save_Heaven_info:
                address = item[0]
                NumOpsDis = item[1]
                NumOpsBack = item[2]
                modSecName = item[3]
                secNum = item[4]
                offset = item[5]
                pushOffset = item[6]
                destLocation = item[7]
                converted = item[8]
                pivottype = item[9]

                outString = "\n\nHeaven Item: " + str(j)
                if secNum != -1:
                    outString += (
                        " | Section: "
                        + str(secNum)
                        + " | Section name: "
                        + modSecName.decode()
                        + " | Heaven's Gate offset: "
                        + str(offset)
                    )

                else:
                    outString += (
                        " | Module: "
                        + modSecName
                        + " | Heaven's Gate offset: "
                        + str(offset)
                        + " | Push dest. addr offset: "
                        + hex(pushOffset)
                        + " | Dest. Address: "
                        + str(destLocation)
                    )

                print("\n********************************************************")
                print(constants.YELLOW + outString + res)
                print("\n")
                if pivottype == "ljmp/lcall":
                    converted = converted[-1:]
                elif pivottype == "retf":
                    converted = converted[-5:]

                # converted = [string.replace("\t", "") for string in converted]

                for line in converted:
                    if line != "":
                        mnemonic, op_str, add4, addb = cleanOutput(line)
                        convOut = formatPrint(
                            mnemonic + "|" + op_str, add4, addb, syscall=True
                        )

                        print(constants.GREEN + convOut + res)
                        # allInstr = line.split(" ")
                        # # print("Everything ---> ", allInstr)
                        # mnemonic = allInstr[0]
                        # add4 = allInstr[-3]
                        # addb = allInstr[-2:]
                        # op_str = ' '.join(allInstr[1:-3])

                        # print("----> mnemonic" , mnemonic, type(mnemonic))
                        # print("-----> op_str", op_str, type(op_str))
                        # input()

                # return val5
                print("\n")
                j += 1

    else:
        h = 0
        for section in s:
            h += 1
            # print("PRINTING SECTION " + str(h))
            for item in section.save_Heaven_info:
                CODED2 = ""

                address = item[0]
                NumOpsDis = item[1]
                NumOpsBack = item[2]
                modSecName = item[3]
                secNum = item[4]
                offset = item[5]
                pushOffset = item[6]
                destLocation = item[7]
                pivottype = item[8]

                # print("NUMBACK = " + str(NumOpsBack))

                section = s[secNum]

                outString = "\nHeaven Item: " + str(j)
                if secNum != -1:
                    outString += (
                        " | Section: "
                        + str(secNum)
                        + " | Section name: "
                        + modSecName.decode()
                        + " | Heaven's Gate offset: "
                        + str(offset)
                        + " | Push dest. addr offset: "
                        + hex(pushOffset)
                        + " | Dest. Address: "
                        + str(destLocation)
                        + "\n"
                    )

                else:
                    outString += (
                        " | Module: "
                        + modSecName
                        + " | Heaven's Gate offset: "
                        + str(offset)
                        + " | Push dest. addr offset: "
                        + hex(pushOffset)
                        + " | Dest. Address: "
                        + str(destLocation)
                        + "\n"
                    )

                print("\n********************************************************")
                print(constants.YELLOW + outString + res)
                # print ("\n")
                val = ""
                val2 = []
                val3 = []
                address2 = address + section.ImageBase + section.VirtualAdd
                val5 = []
                # CODED2 = section.data2[(address-NumOpsBack):(address+NumOpsDis)]
                bytesCompensation = 18
                if pivottype == "ljmp/lcall":
                    start = int(offset, 16) - section.VirtualAdd
                    # The 7 is for the ljmp assembly mnemonic
                    CODED2 = section.data2[(start) : (start + 7)]
                elif pivottype == "retf":
                    start = int(offset, 16) - section.VirtualAdd
                    # The two bytes is for the retf
                    CODED2 = section.data2[(start - bytesCompensation) : start + 2]

                CODED3 = CODED2

                # for i in callCS.disasm(CODED3, address):
                if pivottype == "ljmp/lcall":
                    bytesCompensation = 0
                elif pivottype == "retf":
                    bytesCompensation = 18
                for i in callCS.disasm(CODED3, start - bytesCompensation):
                    add = hex(int(i.address))
                    # addb = hex(int(i.address +  section.VirtualAdd - NumOpsBack))
                    addb = hex(int(i.address + section.VirtualAdd))
                    add2 = str(add)
                    # add3 = hex (int(i.address + section.startLoc	- NumOpsBack))
                    add3 = hex(int(i.address + section.startLoc))
                    add4 = str(add3)
                    val = formatPrint(i, add4, addb, pe=True)

                    # val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
                    val2.append(val)
                    val3.append(add2)
                    val5.append(val)
                    print(constants.GREEN + val + res)

                j += 1


def convertStringToTrack(dis, offsets):
    dprint2("convertcall")
    dprint2(dis)
    dprint2(offsets)
    t = 0
    result = [""]
    for item in dis:
        outstr = (
            item
            + "\t\t\t\t"
            + " "
            + hex(offsets[t])
            + " (offset "
            + hex(offsets[t])
            + ")"
        )
        result.append(outstr)
        t += 1

    return result


def saveBaseEgg(
    address, NumOpsDis, linesBack, modSecName, secNum, eax, c0_offset, converted=""
):
    if secNum != "noSec":
        # print ("before")
        # print (secNum)
        # print(type(secNum))
        s[secNum].save_Egg_info.append(
            tuple((address, NumOpsDis, linesBack, modSecName, secNum, eax, c0_offset))
        )
    else:
        dprint2("Saving one raw")
        secNum = -1
        modSecName = "rawHex"
        m[o].save_Egg_info.append(
            tuple(
                (
                    address,
                    NumOpsDis,
                    linesBack,
                    modSecName,
                    secNum,
                    eax,
                    c0_offset,
                    converted,
                )
            )
        )


def printSavedSyscall(
    bit=32, showDisassembly=True
):  ######################## AUSTIN ###############################3
    # formatting)
    j = 0
    if bit == 64:
        callCS = cs64
    else:
        callCS = cs
    if rawHex:
        if syscallRawHexOverride:
            for item in m[o].save_Egg_info:
                CODED2 = ""

                address = item[0]
                NumOpsDis = item[1]
                NumOpsBack = item[2]
                modSecName = item[3]
                secNum = item[4]
                eax = item[5]
                c0_offset = item[6]

                outString = "\n\nItem: " + str(j)
                if secNum != -1:
                    outString += " | Section: " + modSecName.decode()

                else:
                    outString += " | Module: " + modSecName

                outString += " | EAX: " + eax + " | Syscall Offset: " + c0_offset

                print(
                    "\n******************************************************************************"
                )
                print(constants.YELLOW + outString + res)
                print("\n")
                if showDisassembly:
                    val = ""
                    val2 = []
                    val3 = []
                    val5 = []

                    CODED2 = m[o].rawData2[
                        (address - NumOpsBack) : (address + NumOpsDis)
                    ]

                    CODED3 = CODED2
                    for i in callCS.disasm(CODED3, address):
                        add = hex(int(i.address))
                        addb = hex(int(i.address - NumOpsBack))
                        add2 = str(add)
                        add3 = hex(int(i.address - NumOpsBack))
                        add4 = str(add3)
                        val = formatPrint(i, add4, addb, pe=True)

                        # val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
                        val2.append(val)
                        val3.append(add2)
                        val5.append(val)
                        print(constants.GREEN + val + res)
                        if c0_offset == addb:
                            break
                    print("\n")
                j += 1
                if eax != "unknown":
                    getSyscallRecent(int(eax, 0))
        else:
            for item in m[o].save_Egg_info:
                address = item[0]
                NumOpsDis = item[1]
                NumOpsBack = item[2]
                modSecName = item[3]
                secNum = item[4]
                eax = item[5]
                c0_offset = item[6]
                converted = item[7]

                outString = "\n\nItem: " + str(j)
                if secNum != -1:
                    outString += " | Section name: " + str(modSecName)

                else:
                    outString += " | Module: " + modSecName

                outString += " | EAX: " + eax + " | Syscall Offset: " + c0_offset

                print(
                    "\n******************************************************************************"
                )
                print(constants.YELLOW + outString + res)
                print("\n")
                if showDisassembly:
                    for line in converted:
                        if line != "":
                            # print("Line --> ", line)
                            # input()
                            mnemonic, op_str, add4, addb = cleanOutput(line)
                            convOut = formatPrint(
                                mnemonic + "|" + op_str, add4, addb, syscall=True
                            )
                            print(constants.GREEN + convOut + res)

                # return val5
                print("\n")
                j += 1
                if eax != "unknown":
                    getSyscallRecent(int(eax, 0))

    else:
        # print("in else")
        h = 0

        for section in s:
            h += 1
            # print("PRINTING SECTION " + str(h))
            for item in section.save_Egg_info:
                CODED2 = ""

                address = item[0]
                NumOpsDis = item[1]
                NumOpsBack = item[2]
                modSecName = item[3]
                secNum = item[4]
                eax = item[5]
                c0_offset = item[6]

                # print("NUMBACK = " + str(NumOpsBack))

                section = s[secNum]

                outString = "\n\nItem: " + str(j)
                if secNum != -1:
                    outString += " | Section: " + modSecName.decode()

                else:
                    outString += " | Module: " + modSecName

                outString += " | EAX: " + eax + " | Syscall Offset: " + c0_offset

                print(
                    "\n******************************************************************************"
                )
                print(constants.YELLOW + outString + res)
                print("\n")
                if showDisassembly:
                    val = ""
                    val2 = []
                    val3 = []
                    address2 = address + section.ImageBase + section.VirtualAdd
                    val5 = []

                    CODED2 = section.data2[
                        (address - NumOpsBack) : (address + NumOpsDis)
                    ]

                    CODED3 = CODED2

                    for i in callCS.disasm(CODED3, address):
                        add = hex(int(i.address))
                        addb = hex(int(i.address + section.VirtualAdd - NumOpsBack))
                        add2 = str(add)
                        add3 = hex(int(i.address + section.startLoc - NumOpsBack))
                        add4 = str(add3)
                        val = formatPrint(i, add4, addb, pe=True)

                        # val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
                        val2.append(val)
                        val3.append(add2)
                        val5.append(val)
                        print(constants.GREEN + val + res)
                        if c0_offset == addb:
                            break
                    print("\n")
                j += 1
                if eax != "unknown":
                    getSyscallRecent(int(eax, 0))


def saveBasePEBWalk(
    address,
    NumOpsDis,
    modSecName,
    secNum,
    points,
    loadTIB_offset,
    loadLDR_offset,
    loadModList_offset,
    advanceDLL_Offset,
):
    # print("saving")
    # save virtaul address as well

    peb_data = tuple(
        (
            address,
            NumOpsDis,
            modSecName,
            secNum,
            points,
            loadTIB_offset,
            loadLDR_offset,
            loadModList_offset,
            advanceDLL_Offset,
        )
    )

    if secNum != "noSec":
        if peb_data not in s[secNum].save_PEB_info:
            s[secNum].save_PEB_info.append(
                tuple(
                    (
                        address,
                        NumOpsDis,
                        modSecName,
                        secNum,
                        points,
                        loadTIB_offset,
                        loadLDR_offset,
                        loadModList_offset,
                        advanceDLL_Offset,
                    )
                )
            )
    else:
        secNum = -1
        modSecName = "rawHex"
        m[o].save_PEB_info.append(
            tuple(
                (
                    address,
                    NumOpsDis,
                    modSecName,
                    secNum,
                    points,
                    loadTIB_offset,
                    loadLDR_offset,
                    loadModList_offset,
                    advanceDLL_Offset,
                )
            )
        )


def findAllFSTENV(
    data2, secNum, variables, module, shellcode_label
):  ################## AUSTIN ######################
    global linesBack
    if secNum == "noSec":
        FSTENVrawhex(0, linesBack, "noSec", data2, variables, module, shellcode_label)
    else:
        for match in (
            FSTENV_GET_BASE.values()
        ):  # iterate through all opcodes representing combinations of registers
            optimized_find(10, match, secNum, data2, "disHereFSTENV")


def findAllSyscall(data2, secNum):
    for match in EGGHUNT.values():
        getSyscallPE(20, 20, match, secNum, data2)


def findAllHeaven(data2, secNum):
    for match in HEAVEN.values():
        optimized_find(4, match, secNum, data2, "disHereHeavenPE")
        # get_HeavenPE(4, 20, match, secNum, data2)


def findAllCallpop(data2, secNum, variables, module, shellcode_label, numOps=10):
    ################## AUSTIN ######################
    # print(data2.hex())
    if secNum == "noSec":
        callPopRawHex(0, 15, secNum, data2, variables, module, shellcode_label)
    else:
        for match in (
            CALLPOP_START.values()
        ):  # iterate through all opcodes representing combinations of registers
            optimized_find(numOps, match, secNum, data2, "disHereCallpop")
            # get_Callpop(numOps, match[0], secNum, data2, match[1])


def findAllCallpop64(
    data2, secNum, variables, module, shellcode_label
):  ################## AUSTIN ######################
    for match in (
        CALLPOP_START.values()
    ):  # iterate through all opcodes representing combinations of registers
        optimized_find(10, match, secNum, data2, "disHereCallpop64")
        # get_Callpop64(10, match[0], secNum, data2, match[1])


def optimized_find(numOps, match, secNum, data2, funcName=None):
    start = 0
    if "disHereCallpop" == funcName or "disHereCallpop64" == funcName:
        patternMatch = match[0]
    else:
        patternMatch = match
    foundFS = False
    while True:
        start = data2.find(patternMatch, start)
        if start == -1:
            break
        else:
            if "disHerePEB_64" == funcName:
                disHerePEB_64(start, numOps, secNum, data2)
            elif "disHereCallpop" == funcName:
                disHereCallpop(start, numOps, secNum, data2, match[1])
            elif "disHereCallpop64" == funcName:
                disHereCallpop64(start, numOps, secNum, data2, match[1])
            elif "disHerePushRet" == funcName:
                disHerePushRet(start, numOps, secNum, data2)
            elif "disHerePushRet64" == funcName:
                disHerePushRet64(start, numOps, secNum, data2)
            elif "disHereFSTENV" == funcName:
                disHereFSTENV(start, numOps, 15, secNum, data2)
            elif "disHereSyscall" == funcName:
                disHereSyscall(start, numOps, 20, secNum, data2)
            elif "disHerePEB" == funcName:
                disHerePEB("normal", start, numOps, secNum, data2)
            elif "disHereHeavenPE" == funcName:
                matchList = ["push", "xor", "xchg", "pop", "sub", "add"]
                # dprint2("back = " + str(back))
                # CODED2 = data[(address-(NumOpsBack-back)):(address+x)]
                flag = False
                for back in range(20):
                    # dprint2("back = " + str(back))
                    # CODED2 = data[(address-(NumOpsBack-back)):(address+x)]
                    CODED3 = data2[start - (20 - back) : (start + numOps)]
                    # CODED3 = data2[start:(start+numOps)]
                    instr = ""
                    for i in cs.disasm(CODED3, start):
                        instr += i.mnemonic + " "
                    # print("intr", instr)
                    # input()
                    if "retf" in instr:
                        if (
                            "add" in instr
                            or "push" in instr
                            or "xor" in instr
                            or "xchg" in instr
                            or "pop" in instr
                            or "sub" in instr
                        ):
                            flag = True
                            # foundFS = False
                    if "lcall" in instr or "ljmp" in instr:
                        # print("CODED3", CODED3.hex(), "back --> ",back, instr, start)
                        # input()
                        flag = True
                if flag:
                    disHereHeavenPE(start, numOps, 20, secNum, data2)
            # disHerePEB(mode, t, numOps, secNum, data2)
            # disHereHeavenPE(t, numOps, NumOpsBack, secNum, data2)

            # disHerePEB_64(start, 28, secNum, data2)
            start += len(patternMatch)


def findAllPebSequences(
    mode, variables, module, shellcode_label, data2=None, secNum=None
):  ################## AUSTIN ######################
    if variables.rawHex:
        # print("in check")

        if variables.shellBit == 32:
            for match in (
                PEB_WALK.values()
            ):  # iterate through all opcodes representing combinations of registers
                # ans=get_PEB_walk_start(mode, 19, match, "noSec", data2) #19 hardcoded for now, seems like good value for peb walking sequence
                ans = get_PEB_walk_start(
                    mode, 19, match, "noSec", module[shellcode_label].rawData2
                )  # 19 hardcoded for now, seems like good value for peb walking sequence

                if mode == "decrypt" and ans is not None:
                    print("good, get peb walk")
                    print(ans)
                    return ans
        else:
            for match in PEB_WALK_MOV_64.values():
                get_PEB_walk_start_64(
                    28, match, "noSec", module[shellcode_label].rawData2
                )

    else:
        if variables.shellbit == 32:
            for secNum in range(len(s)):
                # print("Trying section: " + str(secNum))
                data2 = s[secNum].data2

                # print("before mov")
                for match in (
                    PEB_WALK.values()
                ):  # iterate through all opcodes representing combinations of registers
                    optimized_find(19, match, secNum, data2, "disHerePEB")
        else:
            for secNum in range(len(s)):
                # print("Sec Num: ", secNum)
                data2 = s[secNum].data2
                # start = time.time()
                data2Tmp = data2
                # offset = 0
                # index=0
                for match in (
                    PEB_WALK_MOV_64.values()
                ):  # iterate through all opcodes representing combinations of registers
                    # print("Finding value", match.hex())
                    optimized_find(28, match, secNum, data2, "disHerePEB_64")


def findAllPushRet(
    data2, secNum, variables: Variables, module, shellcode_label
):  ################## AUSTIN #########################
    if variables.rawHex:
        PushRetrawhex(0, "noSec", data2, variables, module, shellcode_label)
    else:
        for match in PUSH_RET.values():
            optimized_find(4, match, secNum, data2, "disHerePushRet")


def findStrings(binary, Num):  # ,t):
    dprint2("findingStrings sharem")
    global t
    global o
    global stringsTemp
    newop = " 0x00\t"
    newAscii = ""
    old = 0
    offset = 0
    word = ""
    wordSize = 0
    skip = False
    try:
        x = 0
        y = 1
        inProgress = False
        for v in binary:
            i = ord2(v)
            newop += " " + show1(i)
            if not inProgress:
                test = chr(i)
                if test.isalpha() == False:
                    skip = True

                if test.isalpha():
                    skip = False
            if (i > 31) & (i < 127) & (skip == False):
                if not inProgress:
                    offset = x
                inProgress = True
                word += "" + chr(i)
            else:
                hasNull = False
                hasNullCt = 0
                if inProgress:
                    if i == 0:
                        hasNull = True
                        pass  # future work with NULLs
                    if len(word) >= Num:
                        wordSize = len(word)
                        if hasNull and hasNullCt < 2:
                            pass
                            wordSize += 1
                        try:
                            s[t].Strings.append(tuple((word, offset, wordSize)))
                        except:
                            stringsTemp.append(tuple((word, offset, wordSize)))
                    inProgress = False
                    word = ""
                    offset = 0
            x += 1
            y += 1
            if x == len(binary):  # last byte, final end
                wordSize = len(word)
                if wordSize > 0:
                    try:
                        s[t].Strings.append(tuple((word, offset, wordSize)))
                    except:
                        stringsTemp.append(tuple((word, offset, wordSize)))

    except Exception as e:
        print("*String finding error1!!!")
        print(e)


def stripPeriod(word):
    print("stripPeriod")
    wordNodots = word.replace(".", "")
    return wordNodots


def findStringsWide(binary, Num):  # ,t):
    dprint2("findStringsWide")
    global t
    global o
    global s
    global stringsTempWide
    newop = " 0x00\t"
    newAscii = ""
    old = 0
    offset = 0
    limit = 0
    try:
        x = 0
        y = 1
        word = ""
        inProgress = False
        PossibleWide = False
        WideCnt = 0
        maxBinary = len(binary)
        for v in binary:
            i = ord2(v)
            newop += " " + show1(i)
            previous = chr(i)
            if (i > 31) & (i < 127):
                if inProgress == False:
                    offset = x
                inProgress = True
                word += "" + chr(i)
                limit = 0
                if x == maxBinary - 1:
                    if len(word) >= (Num * 2):
                        odd = True
                        even = True

                        for i in range(len(word)):
                            if (i % 2) != 0:
                                # print("I: ", i, word)
                                if word[i] != ".":
                                    odd = False

                            if i == 10:
                                break

                        if odd:
                            wordSize = len(word)
                            try:
                                s[t].wideStrings.append(tuple((word, offset, wordSize)))
                            except:
                                stringsTempWide.append(tuple((word, offset, wordSize)))
            else:
                if inProgress:
                    if i == 0:
                        WideCnt += 1
                        limit += 1
                        if limit < 2:
                            PossibleWide = True
                            word += "."

                        if limit > 1:
                            PossibleWide = False
                        try:
                            length = len(word)
                            if (
                                (word[length - 2] == " ")
                                and (word[length - 3] == ".")
                                and (WideCnt >= Num)
                            ):
                                inProgress = False
                                if len(word) >= (Num * 2):
                                    odd = True
                                    even = True

                                    for i in range(len(word)):
                                        if (i % 2) != 0:
                                            if word[i] != ".":
                                                odd = False

                                        if i == 10:
                                            break

                                        if odd:
                                            if (
                                                (ord(word[0]) > 0x40)
                                                and (ord(word[0]) < 0x5B)
                                                or (ord(word[0]) > 0x60)
                                                and (ord(word[0]) < 0x7B)
                                            ):
                                                wordSize = int(len(word))

                                                word = stripPeriod(word)
                                                if wordSize > 0:
                                                    try:
                                                        s[t].wideStrings.append(
                                                            tuple(
                                                                (word, offset, wordSize)
                                                            )
                                                        )
                                                    except:
                                                        stringsTempWide.append(
                                                            tuple(
                                                                (word, offset, wordSize)
                                                            )
                                                        )
                                word = ""
                                offset = 0
                                WideCnt = 0
                        except:
                            pass
                if i != 0:
                    PossibleWide = False
                    limit = 0
                if (inProgress and not PossibleWide) or (
                    x == maxBinary and inProgress
                ):  # & (WideCnt >= Num):
                    if len(word) >= (Num * 2):
                        odd = True
                        even = True

                        for i in range(len(word)):
                            if (i % 2) != 0:
                                if word[i] != ".":
                                    odd = False
                            if i == 8:
                                break

                        if odd:
                            if (
                                ((ord(word[0])) > 0x40)
                                and (ord(word[0]) < 0x5B)
                                or (ord(word[0]) > 0x60)
                                and (ord(word[0]) < 0x7B)
                            ):
                                wordSize = int(len(word))

                                word = stripPeriod(word)
                                if wordSize > 0:
                                    try:
                                        s[t].wideStrings.append(
                                            tuple((word, offset, wordSize))
                                        )
                                    except:
                                        stringsTempWide.append(
                                            tuple((word, offset, wordSize))
                                        )

                    inProgress = False
                    word = ""
                    offset = 0
                    WideCnt = 0
            x += 1
            y += 1
    except Exception as e:
        print(traceback.format_exc())
        print("*String finding error 2!!!")
        print(e)
    dprint2("Strings Wide")
    t = 1


def findPushAscii(binary, Num):
    global t
    global o
    newop = " 0x00\t"
    newAscii = ""
    old = 0
    offset = 0
    try:
        x = 0
        y = 1
        word = ""
        inProgress = False
        startPush = False
        start = True
        first = True
        old = ""
        z = 0
        word2 = ""
        progCount = 0
        for v in binary:
            i = ord2(v)
            newop += " " + show1(i)
            if (v == "\x68") or startPush:
                startPush = True
                if (i > 31) & (i < 127):
                    progCount += 1
                    if inProgress == False:
                        offset = x + 1
                    inProgress = True
                else:
                    if inProgress:
                        if 1 == 1:
                            for xx in binary[z - progCount : z]:
                                # print "*"
                                yy = ord2(xx)
                                zz = show1(yy)
                                try:
                                    zz = int(zz, 16)
                                    zz = chr(zz)
                                except:
                                    zz = chr(zz)
                                word2 += zz  # chr(zz)
                            end = ""
                            t3 = 0
                            validPushString = True
                            for xx in binary[z - progCount - 5 : z - progCount]:
                                # print "*"
                                if t3 == 0:
                                    if xx == "h":
                                        validPushString = True
                                    else:
                                        validPushString = False
                                if validPushString:
                                    yy = ord2(xx)
                                    zz = show1(yy)

                                    try:
                                        zz = int(zz, 16)
                                        zz = chr(zz)
                                    except:
                                        zz = chr(zz)
                                    if t3 != 0:
                                        end += zz  # chr(zz)
                                t3 += 1
                            end3 = end.lstrip()
                            end3 = end3.lstrip("\x00")
                            end3 = end3.lstrip("\x0a")
                            end3 = end3.lstrip("\x0d")
                            t2 = 1
                            tem = ""
                            spec = []
                            for dd in word2:
                                tem += dd
                                if t2 == 5:
                                    # print "\t*"+tem
                                    spec.append(tem[1::])
                                    tem = ""
                                    t2 = 0
                                t2 += 1
                            word2 = ""
                            spec.reverse()
                            word = "".join(spec) + end3
                        progCount = 0
                    if inProgress:
                        if len(word) >= Num:
                            if len(end) > 0:
                                offsetVA = offset + s[t].VirtualAdd - 6
                                offsetPlusImagebase = offsetVA + s[t].ImageBase
                            else:
                                offsetVA = offset + s[t].VirtualAdd
                                offsetPlusImagebase = offsetVA + s[t].ImageBase
                            wordLength = len(word)

                            instructionsLength = 0
                            try:
                                s[t].pushStrings.append(
                                    tuple(
                                        (
                                            word,
                                            offset,
                                            offsetVA,
                                            offsetPlusImagebase,
                                            wordLength,
                                            instructionsLength,
                                        )
                                    )
                                )  # decoded string, raw offset, raw offset + virtual address (VA may not be possible in raw binary shellcode)
                            except:
                                pushStringsTemp.append(
                                    tuple(
                                        (word4, offset, wordLength, instructionsLength)
                                    )
                                )
                        inProgress = False
                        word = ""
                        offset = 0
                        first = True
                        startPush = False
            x += 1
            y += 1
            z += 1

    except Exception as e:
        print("*String finding error3!!!")
        print(e)
    t = 0


# push
def findPushAsciiMixed(binary, Num, index=None):
    dprint2("findPushAsciiMixed")
    # global t
    global o
    global pushStringsTemp
    global chMode
    t = index
    binary += b"\x90"
    newop = " 0x00\t"
    offset = 0
    word4 = ""
    try:
        x = 0
        y = 1
        word = ""
        inProgress = False
        startPush = False
        z = 0
        word2 = ""
        altWord = ""
        progCount = 0
        old1 = 0x0
        old2 = 0x0
        old3 = 0x0
        offsetVA = 0
        offsetPlusImagebase = 0

        for v in binary:
            i = ord2(v)
            v = chr(v)
            newop += " " + show1(i)
            if (v == "\x6a") or startPush or (v == "\x68"):
                startPush = True

                if (i > 31) & (i < 127):
                    progCount += 1
                    if inProgress == False:
                        offset = x + 1
                    inProgress = True

                elif (old1 == "h") & (v == "\x00"):
                    progCount += 1
                elif (old2 == "h") & (v == "\x00"):
                    progCount += 1
                elif (old3 == "h") & (v == "\x00"):
                    progCount += 1
                elif (old4 == "h") & (v == "\x00"):
                    progCount += 1
                else:
                    if inProgress:
                        for xx in binary[z - progCount : z]:
                            yy = xx
                            zz = show1(yy)

                            try:
                                zz = int(zz, 16)
                                zz = chr(zz)
                            except:
                                zz = chr(zz)
                            word2 += zz  # stripWhite(zz)#chr(zz)
                            try:
                                dprint2("word", word2)
                            except:
                                dprint2("word2 error")
                        end = ""
                        t3 = 0
                        # alternative - off by one :-)
                        for xx in binary[z - progCount - 1 : z]:
                            yy = ord2(xx)
                            zz = show1(yy)
                            try:
                                zz = int(zz, 16)
                                zz = chr(zz)
                            except:
                                zz = chr(zz)
                            altWord += zz  # stripWhite(zz)#chr(zz)
                        end = ""
                        checkedString = False
                        if len(word2) > 2:
                            done = False
                            word4 = ""
                            valid, word4temp, checkedString = checkedString1(word2)
                            if valid:
                                word4 = word4temp
                        done = True
                        if not checkedString and (len(word2) > 2):
                            valid, word4temp, checkedString = checkedString1(altWord)
                            if valid:
                                word4 = word4temp  #   +"@"
                                progCount = progCount + 1
                            checkedString = True
                        word2 = ""
                        altWord = ""
                        instructionsLength = progCount
                        finalWord = ""
                        UsesPusByte = False
                        if len(word4) > 6:
                            if (z - progCount - 5) > 0:
                                sample = binary[z - progCount - 5 : z - progCount]
                            else:
                                sample = "\x00"
                            if sample[0] == "h":
                                sample = sample[1::]
                                sample = stripWhite(sample)
                                word4 += sample + "!"
                                offset = offset - 5
                                instructionsLength = instructionsLength + 5
                            else:
                                if (z - progCount - 8) > 0:
                                    sample = binary[z - progCount - 8 : z - progCount]
                                else:
                                    sample = "\x00"
                                if sample[0] == "j":
                                    zy = 1
                                    newWord = ""
                                    for samp in sample:
                                        newWord += samp
                                        if zy == 2:
                                            UsesPusByte = True
                                            newWord = newWord[1::]
                                            finalWord += newWord
                                            newWord = ""
                                            zy = 0
                                        zy += 1
                                    if (
                                        (
                                            (sample[7] < 31)
                                            or (sample[7] > 127)
                                            and (sample[6] != "j")
                                        )
                                        or (
                                            (sample[5] < 31)
                                            or (sample[5] > 127)
                                            and (sample[4] != "j")
                                        )
                                        or (
                                            (sample[3] < 31)
                                            or (sample[3] > 127)
                                            and (sample[2] != "j")
                                        )
                                        or (
                                            (sample[1] < 31)
                                            or (sample[1] > 127)
                                            and (sample[0] != "j")
                                        )
                                    ):
                                        dprint2("throw out " + finalWord)
                                        finalWord = ""
                        try:
                            if len(finalWord) > 0:
                                offset = offset - 8
                                instructionsLength = instructionsLength + 8
                        except Exception as e:
                            print(e)
                            pass
                        if UsesPusByte:
                            finalWord = stripWhite(finalWord)
                            finalWord = finalWord[::-1]
                            word4 += finalWord + "*"
                            UsesPusByte = False
                        progCount = 0
                    if inProgress:
                        if len(word4) >= Num:
                            offset += 1  # correcting erroroneous calculation
                            if len(end) > 0:
                                try:
                                    offsetVA = offset + s[t].VirtualAdd - 2  # - 6
                                    offsetPlusImagebase = offsetVA + s[t].ImageBase
                                except:
                                    pass
                            else:
                                try:
                                    offsetVA = offset + s[t].VirtualAdd - 2
                                    offsetPlusImagebase = offsetVA + s[t].ImageBase
                                except:
                                    pass
                            wordLength = len(word4)
                            try:
                                s[t].pushStrings.append(
                                    tuple(
                                        (
                                            word4,
                                            offset,
                                            offsetVA,
                                            offsetPlusImagebase,
                                            wordLength,
                                            instructionsLength,
                                        )
                                    )
                                )  # decoded string, raw offset, raw offset + virtual address (VA may not be possible in raw binary shellcode)
                            except:
                                try:
                                    dprint2("saving pushMixed", word4)
                                except:
                                    pass
                                pushStringsTemp.append(
                                    tuple(
                                        (word4, offset, wordLength, instructionsLength)
                                    )
                                )  #
                        inProgress = False
                        word4 = ""
                        offset = 0
                        first = True
                        startPush = False
            x += 1
            y += 1
            z += 1
            old4 = old3
            old3 = old2
            old2 = old1
            old1 = v
    except Exception as e:
        print("*String finding error!!!")
        print(e)
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
    t = 0


def disHereStrings(address, NumOpsDis, secNum, mode):  #
    global o
    w = 0
    CODED2 = ""
    section = s[secNum]
    x = NumOpsDis
    address = address - section.VirtualAdd
    for i in range(x):
        CODED2 += chr(section.data2[address + i])
    val = ""
    val2 = []
    val3 = []
    val5 = []
    startAdd = []
    nextAdd = []
    bytesPerLine = []
    cntLines = 0
    bytesEachLine = []
    asciiPerLine = []

    CODED3 = CODED2.encode()
    for i in cs.disasm(CODED3, address):
        cntLines += 1
    current = 0
    for i in cs.disasm(CODED3, address):
        if current > 0:
            nextAd = sadd1
            nextAdd.append(nextAd)
        sadd1 = hex(int(i.address))
        startAdd.append(int(sadd1, 16))
        current += 1

    t = 0
    ans = 0
    total = 0
    for each in startAdd:
        try:
            # print hex(startAdd[t+1])
            # print hex(each)
            ans = int(startAdd[t + 1]) - int(each)
            bytesPerLine.append(ans)
            # print hex(ans)
            total += ans
            # print "**"
        except:
            # print hex(total)
            ans2 = hex(NumOpsDis - total)
            # print ans2
            # print hex(NumOpsDis)
            bytesPerLine.append(int(ans2, 16))
        t += 1

    cnt = 0
    t = 0
    for i in cs.disasm(CODED3, address):
        ans = binaryToStr(CODED3[cnt : cnt + bytesPerLine[t]])  # + " " + str(t) + "\n"
        res = ""
        for y in CODED3[cnt + 1 : cnt + bytesPerLine[t]]:
            yy = ord2(y)
            zz = show1(yy)
            old = "nope"
            if (yy > 31) & (yy < 127):
                try:
                    zz = int(zz, 16)
                    zz = chr(zz)
                except:
                    zz = chr(zz)
            else:
                zz = "."
            # psqrTUVW
            firstL = CODED3[cnt : cnt + bytesPerLine[t]]
            if (
                ((old == "nope") & (zz == "P") & (firstL[0] == "f"))
                or ((old == "nope") & (zz == "S") & (firstL[0] == "f"))
                or ((old == "nope") & (zz == "Q") & (firstL[0] == "f"))
                or ((old == "nope") & (zz == "R") & (firstL[0] == "f"))
                or ((old == "nope") & (zz == "T") & (firstL[0] == "f"))
                or ((old == "nope") & (zz == "U") & (firstL[0] == "f"))
                or ((old == "nope") & (zz == "V") & (firstL[0] == "f"))
                or ((old == "nope") & (zz == "W") & (firstL[0] == "f"))
            ):
                zz = ""
            old = zz
            res += zz  # stripWhite(zz)#chr(zz)
        asciiPerLine.append(res)
        # print res
        # print ans
        bytesEachLine.append(ans)
        cnt += bytesPerLine[t]
        t += 1

    t = 0
    for i in cs.disasm(CODED3, address):
        add = hex(int(i.address))
        addb = hex(int(i.address + section.VirtualAdd))
        add2 = str(add)
        add3 = hex(int(i.address + section.startLoc))
        add4 = str(add3)
        if mode == "ascii":
            val = (
                i.mnemonic
                + " "
                + i.op_str
                + "\t\t\t\t"
                + add4
                + " ("
                + addb
                + ") \t\t"
                + bytesEachLine[t]
                + " ; \t"
                + asciiPerLine[t]
                + "\n"
            )  # + str(cntLines)
        else:
            val = (
                i.mnemonic
                + " "
                + i.op_str
                + "\t\t\t\t"
                + add4
                + " (offset "
                + addb
                + ")\n"
            )
        val2.append(val)
        val3.append(add2)
        val5.append(val)
        t += 1
    returnString = ""
    for y in val5:
        returnString += y
    return returnString


def r32hexToAscii(r1, r2, r3, r4, reverse):
    newAscii = ""
    if (r1 > 31) & (r1 < 127):
        newAscii += chr(r1)
    else:
        newAscii += "."
    if (r2 > 31) & (r2 < 127):
        newAscii += chr(r2)
    else:
        newAscii += "."
    if (r3 > 31) & (r3 < 127):
        newAscii += chr(r3)
    else:
        newAscii += "."
    if (r4 > 31) & (r4 < 127):
        newAscii += chr(r4)
    else:
        newAscii += "."

    if not reverse:
        return newAscii
    else:
        return newAscii[::-1]


def r16hexToAscii(r3, r4, reverse):
    newAscii = ""
    if (r3 > 31) & (r3 < 127):
        newAscii += chr(r3)
    else:
        newAscii += "."
    if (r4 > 31) & (r4 < 127):
        newAscii += chr(r4)
    else:
        newAscii += "."

    if not reverse:
        return newAscii
    else:
        return newAscii[::-1]


def disCheckStrings(address, NumOpsDis, secNum, mode):  #
    global realEAX
    global realEAX2
    global realEBX
    global realEBX2
    global realECX
    global realECX2
    global realEDX
    global realEDX2
    global realEDI
    global realEDI2
    global realESI
    global realESI2
    global realESP
    global realESP2
    global realEBP
    global realEBP2
    global o
    w = 0
    CODED2 = ""
    section = s[secNum]
    x = NumOpsDis
    address = address - section.VirtualAdd
    for i in range(x):
        CODED2 += chr(section.data2[address + i])
    # print binaryToStr(CODED2)
    val = ""
    val2 = []
    val3 = []
    val5 = []
    startAdd = []
    nextAdd = []
    bytesPerLine = []
    cntLines = 0
    bytesEachLine = []
    asciiPerLine = []

    CODED2 = CODED2.encode()
    for i in cs.disasm(CODED2, address):
        cntLines += 1
    current = 0
    for i in cs.disasm(CODED2, address):
        if current > 0:
            nextAd = sadd1
            nextAdd.append(nextAd)
        sadd1 = hex(int(i.address))
        startAdd.append(int(sadd1, 16))
        current += 1
    t = 0
    ans = 0
    total = 0
    for each in startAdd:
        try:
            # print hex(startAdd[t+1])
            # print hex(each)
            ans = int(startAdd[t + 1]) - int(each)
            bytesPerLine.append(ans)
            # print hex(ans)
            total += ans
            # print "**"
        except:
            # print hex(total)
            ans2 = hex(NumOpsDis - total)
            # print ans2
            # print hex(NumOpsDis)
            bytesPerLine.append(int(ans2, 16))
        t += 1

    cnt = 0
    t = 0
    for i in cs.disasm(CODED2, address):
        ans = binaryToStr(CODED2[cnt : cnt + bytesPerLine[t]])  # + " " + str(t) + "\n"
        res = ""
        for y in CODED2[cnt + 1 : cnt + bytesPerLine[t]]:
            yy = ord2(y)
            zz = show1(yy)
            old = "nope"
            if (yy > 31) & (yy < 127):
                try:
                    zz = int(zz, 16)
                    zz = chr(zz)
                except:
                    zz = chr(zz)
            else:
                zz = "."
            # psqrTUVW
            firstL = CODED2[cnt : cnt + bytesPerLine[t]]
            if (
                ((old == "nope") & (zz == "P") & (firstL[0] == "f"))
                or ((old == "nope") & (zz == "S") & (firstL[0] == "f"))
                or ((old == "nope") & (zz == "Q") & (firstL[0] == "f"))
                or ((old == "nope") & (zz == "R") & (firstL[0] == "f"))
                or ((old == "nope") & (zz == "T") & (firstL[0] == "f"))
                or ((old == "nope") & (zz == "U") & (firstL[0] == "f"))
                or ((old == "nope") & (zz == "V") & (firstL[0] == "f"))
                or ((old == "nope") & (zz == "W") & (firstL[0] == "f"))
            ):
                zz = ""
            old = zz
            res += zz
        asciiPerLine.append(res)
        # print res
        # print ans
        bytesEachLine.append(ans)
        cnt += bytesPerLine[t]
        t += 1

    t = 0
    for i in cs.disasm(CODED2, address):
        add = hex(int(i.address))
        addb = hex(int(i.address + section.VirtualAdd))
        add2 = str(add)
        add3 = hex(int(i.address + section.startLoc))
        add4 = str(add3)
        if mode == "ascii":
            val = (
                i.mnemonic
                + " "
                + i.op_str
                + "\t\t\t\t"
                + add4
                + " ("
                + addb
                + ") \t\t"
                + bytesEachLine[t]
                + " ; \t"
                + asciiPerLine[t]
                + "\n"
            )  # + str(cntLines)
        elif mode == "basic":
            val = (
                i.mnemonic + " " + i.op_str + "\n"
            )  # + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
        else:
            val = (
                i.mnemonic
                + " "
                + i.op_str
                + "\t\t\t\t"
                + add4
                + " (offset "
                + addb
                + ")\n"
            )
        val2.append(val)
        val3.append(add2)
        val5.append(val)
        t += 1

    resultA = []
    charAns = ""
    for val in val5:
        push = re.match(r"\bpush\b", val, re.M | re.I)
        if push:
            # print ("got push")
            getVal = re.search(r"0x[0-9A-F]*", val, re.M | re.I)
            getEAX = re.search(r"\beax\b", val, re.M | re.I)
            getEBX = re.search(r"\bebx\b", val, re.M | re.I)
            getECX = re.search(r"\becx\b", val, re.M | re.I)
            getEDX = re.search(r"\bedx\b", val, re.M | re.I)
            getESI = re.search(r"\besi\b", val, re.M | re.I)
            getEDI = re.search(r"\bedi\b", val, re.M | re.I)
            getESP = re.search(r"\besp\b", val, re.M | re.I)
            getEBP = re.search(r"\bebp\b", val, re.M | re.I)
            getAX = re.search(r"\bax\b", val, re.M | re.I)
            getBX = re.search(r"\bbx\b", val, re.M | re.I)
            getCX = re.search(r"\bcx\b", val, re.M | re.I)
            getDX = re.search(r"\bdx\b", val, re.M | re.I)
            getSI = re.search(r"\bsi\b", val, re.M | re.I)
            getDI = re.search(r"\bdi\b", val, re.M | re.I)
            getSP = re.search(r"\bsp\b", val, re.M | re.I)
            getBP = re.search(r"\bbp\b", val, re.M | re.I)

            if getVal:
                result = str(getVal.group())
                result = result[2 : len(result)]
                # print result
                elm = 0x0
                t = 0
                b = 2
                for x in range(4):
                    elem = result[t:b]
                    # print elem
                    t += 2
                    b += 2
                    try:
                        elm1 = "0x" + elem
                        elm = int(elm1, 16)
                    except:
                        elm = 0x17  #  Not likely to be maningful/relevant--will remove.
                    # print chr(elm)
                    charAns += chr(elm)  # stripWhite(zz)#chr(
            elif getEAX:
                # print "32:"
                r1, r2, r3, r4, strReg = realEAX2
                ans = r32hexToAscii(r1, r2, r3, r4, False)

                charAns += ans
            elif getEBX:
                # print "32:"
                r1, r2, r3, r4, strReg = realEBX2
                ans = r32hexToAscii(r1, r2, r3, r4, False)
                charAns += ans
            elif getECX:
                # print "32:"
                r1, r2, r3, r4, strReg = realECX2
                ans = r32hexToAscii(r1, r2, r3, r4, False)
                charAns += ans
            elif getEDX:
                # print "32:"
                r1, r2, r3, r4, strReg = realEDX2
                ans = r32hexToAscii(r1, r2, r3, r4, False)
                charAns += ans
            elif getEDI:
                # print "32:"
                r1, r2, r3, r4, strReg = realEDI2
                ans = r32hexToAscii(r1, r2, r3, r4, False)
                charAns += ans
            elif getESI:
                # print "32:"
                r1, r2, r3, r4, strReg = realESI2
                ans = r32hexToAscii(r1, r2, r3, r4, False)
                charAns += ans
            elif getEBP:
                # print "32:"
                r1, r2, r3, r4, strReg = realEBP2
                ans = r32hexToAscii(r1, r2, r3, r4, False)
                charAns += ans
            elif getESP:
                # print "32:"
                r1, r2, r3, r4, strReg = realESP2
                ans = r32hexToAscii(r1, r2, r3, r4, False)
                charAns += ans
            elif getAX:
                # print "16:"
                r1, r2, r3, r4, strReg = realEAX2
                ans = r16hexToAscii(r3, r4, False)
                charAns += ans
            elif getBX:
                # print "16:"
                r1, r2, r3, r4, strReg = realEBX2
                ans = r16hexToAscii(r3, r4, False)
                charAns += ans
            elif getCX:
                # print "16:"
                r1, r2, r3, r4, strReg = realECX2
                ans = r16hexToAscii(r3, r4, False)
                charAns += ans
            elif getDX:
                # print "16:"
                r1, r2, r3, r4, strReg = realEDX2
                ans = r16hexToAscii(r3, r4, False)
                charAns += ans
            elif getDI:
                # print "16:"
                r1, r2, r3, r4, strReg = realEDI2
                ans = r16hexToAscii(r3, r4, False)
                charAns += ans
            elif getSI:
                # print "16:"
                r1, r2, r3, r4, strReg = realESI2
                ans = r16hexToAscii(r3, r4, False)
                charAns += ans
            elif getBP:
                # print "16:"
                r1, r2, r3, r4, strReg = realEBP2
                ans = r16hexToAscii(r3, r4, False)
                charAns += ans
            elif getSP:
                # print "16:"
                r1, r2, r3, r4, strReg = realESP2
                ans = r16hexToAscii(r3, r4, False)
                charAns += ans

            # print charAns

            charAns = stripSpec(charAns)
            charAns = stripWhite(charAns)
            resultA.append(charAns)
            charAns = ""
    returnString = reverseListLittleEndian(resultA)
    resultA[:] = []
    return returnString


def reverseListLittleEndian(val):
    val2 = []
    for x in val:
        x = x[::-1]
        val2.append(x)

    val2.reverse()

    res = ""
    for each in val2:
        res += each
    return res


def hexStrtoAscii(word):
    word2 = ""
    for i in range(0, len(word), 2):
        word2 += chr(int(word[i : i + 2], 16))
    word2 = word2[::-1]
    if word2.isascii():
        return word2
    else:
        return "^^^^"


def checkedString1(altWord):
    global chMode
    mode = chMode
    t2 = 1
    tem = ""
    spec = []
    old = ""
    old2 = ""
    old3 = ""
    old4 = ""
    cnt = 0
    checkedString = False
    word2 = altWord
    done = False
    truncate = False
    truncateVal = 0

    for letter in word2:
        tem += letter
        if (t2 == 2) and (old == "j") and not done:
            tem = tem[1:]
            spec.append(stripWhite(tem))
            tem = ""
            t2 = 0
            checkedString = True
        elif (t2 == 5) and (old4 == "h") and not done:
            tem = tem[1:]
            spec.append(stripWhite(tem))
            tem = ""
            t2 = 0
            checkedString = True
        elif (t2 == 1) and (letter == "P") and (not done):
            tem = "^^^^"
            if mode:
                tem = retR32("eax", "n")

                tem = hexStrtoAscii(tem)
            spec.append((tem))
            t2 = 0
            tem = ""
        elif (t2 == 1) and (letter == "S") and (not done):
            dprint2("push EBX2")
            tem = "^^^^"
            if mode:
                tem = retR32("ebx", "n")
                tem = hexStrtoAscii(tem)
            spec.append((tem))
            t2 = 0
            tem = ""
        elif (t2 == 1) and (letter == "Q") and (not done):
            tem = "^^^^"
            if mode:
                tem = retR32("ecx", "n")
                tem = hexStrtoAscii(tem)

            spec.append((tem))
            t2 = 0
            tem = ""
        elif (t2 == 1) and (letter == "R") and (not done):
            tem = ""
            tem = "^^^^"
            if mode:
                tem = retR32("edx", "n")
                tem = hexStrtoAscii(tem)
            spec.append((tem))
            t2 = 0
            tem = ""
        elif (t2 == 1) and (letter == "V") and (not done):
            tem = "^^^^"
            if mode:
                tem = retR32("esi", "n")
                tem = hexStrtoAscii(tem)
            spec.append((tem))
            t2 = 0
            tem = ""
        elif (t2 == 1) and (letter == "W") and (not done):
            tem = "^^^^"
            if mode:
                tem = retR32("edi", "n")
                tem = hexStrtoAscii(tem)
            spec.append((tem))
            t2 = 0
            tem = ""
        elif t2 == 1 and letter == "T" and not done:
            if checkedString:
                word4 = ""
                spec.reverse()
                word4 = "".join(spec)
                Valid = False
                cnt = 0
                for char in word4:
                    if char.isalpha():
                        cnt += 1
                if cnt < 4:
                    word4 = ""
                if len(word4) > 2:
                    Valid = True
                return Valid, word4, checkedString

        elif (t2 == 1) and (letter == "U") and (not done):
            # print "push EBP"
            tem = "^^^^"
            if mode:
                tem = retR32("ebp", "n")
                tem = hexStrtoAscii(tem)
            spec.append((tem))
            t2 = 0
            tem = ""
        elif (t2 == 2) and (old == "f") and (letter == "P") and (not done):
            # print "push ax"
            tem = "``"
            spec.append((tem))
            t2 = 0
            tem = ""
        elif (t2 == 2) and (old == "f") and (letter == "S") and (not done):
            # print "push bx"
            tem = "``"
            spec.append((tem))
            t2 = 0
            tem = ""
        elif (t2 == 2) and (old == "f") and (letter == "Q") and (not done):
            # print "push cx"
            tem = "``"
            spec.append((tem))
            t2 = 0
            tem = ""
        elif (t2 == 2) and (old == "f") and (letter == "R") and (not done):
            # print "push dx"
            tem = "``"
            spec.append((tem))
            t2 = 0
            tem = ""
        elif (t2 == 2) and (old == "f") and (letter == "V") and (not done):
            # print "push si"
            tem = "``"
            spec.append((tem))
            t2 = 0
            tem = ""
        elif (t2 == 2) and (old == "f") and (letter == "W") and (not done):
            # print "push di"
            tem = "``"
            spec.append((tem))
            t2 = 0
            tem = ""
        elif (t2 == 2) and (old == "f") and (letter == "T") and (not done):
            # print "push sp"
            tem = "``"
            spec.append((tem))
            t2 = 0
            tem = ""
        elif (t2 == 2) and (old == "f") and (letter == "U") and (not done):
            # print "push bp"
            tem = "``"
            spec.append((tem))
            t2 = 0
            tem = ""
        t2 += 1
        old5 = old4
        old4 = old3
        old3 = old2
        old2 = old
        old = letter
    word2 = ""
    altWord = ""
    spec.reverse()
    word4 = "".join(spec)
    # print "moonpie: " + word4
    Valid = False
    if not checkedString:
        word4 = ""
    ####checking to see if any leters
    cnt = 0
    for char in word4:
        if char.isalpha():
            cnt += 1
    if cnt < 4:
        word4 = ""
    # print word4
    # print "end checkedString1"
    if len(word4) > 2:
        Valid = True
    return Valid, word4, checkedString


def hexDword(intVal):
    ans = "0x{0:08x}".format(intVal)
    return ans


def pushStringsOutput(Num):
    mode = asciiMode

    k = 0
    outText = ""
    outText += "\nNote: The offset value is created by adding the offset plus the section virtual address.\n\n"
    if filename == "":
        outfile = peName.split(".")[0]
        outfileName = peName
    else:
        outfile = filename.split(".")[0]
        outfileName = filename

    txtFileName = (
        os.getcwd() + slash + outfile + slash + "pushStrings_validation" + ".txt"
    )
    os.makedirs(os.path.dirname(txtFileName), exist_ok=True)

    t = 0

    for sec in (
        pe.sections
    ):  # @TODO, check accuracy of strings fails here because `pe` is a string
        if len(s[t].pushStrings) > 0:
            outText += "\n**Checking original stack strings found.\n\tNote: Emulation is performed by using register values provided or in regs.txt.\n\n"

            for x, rawOffset, y, offsetPlusImagebase, length, instructionsLength in s[
                t
            ].pushStrings:
                if mode == asciiMode:
                    tmp = disHereStrings(y, instructionsLength, t, mode)
                    outText += tmp

                ans = disCheckStrings(y, instructionsLength, t, "basic")
                outText += "\t" + ans + "**\n*************************\n"
                k += 1
            # LoadaryA0 (start: 0x267; end: 0x271)
            outText += "\n*Original Stack strings Found*\n\n"
            for (
                word,
                offset,
                offsetVA,
                offsetPlusImagebase,
                wordLength,
                instructionsLength,
            ) in s[t].pushStrings:
                outText += (
                    word
                    + " (start: "
                    + str(hex(offset))
                    + ";"
                    + " "
                    + "end:"
                    + str(hex(offset + instructionsLength))
                    + ")\n"
                )
        t += 1
    print(outText)

    fp = open(txtFileName, "w")

    fp.write(outText)
    fp.close()


def printStrings():
    global rawHex
    global stringsTemp
    global stringsTempWide
    global pushStringsTemp

    t = 0
    try:
        if not rawHex:
            for sec in pe.sections:
                if len(s[t].Strings) > 0 or len(s[t].wideStrings) > 0:
                    print(s[t].sectionName.decode("utf-8"))

                for x, y, z in s[t].Strings:
                    x = constants.CYAN + x + res
                    print(
                        "{:<5} {:<32s} {:<8s} {:<8s} {:<8s} {:<8}".format(
                            "",
                            str(x),
                            s[t].sectionName.decode("utf-8"),
                            str(hex(y + s[t].ImageBase + s[t].VirtualAdd)),
                            "(offset " + str(hex(y)) + ")",
                            constants.YELLOW + "Ascii" + res,
                        )
                    )

                dprint2("wideStrings res")
                # (word, offset,wordSize
                for x, y, z in s[t].wideStrings:
                    x = constants.CYAN + x + constants.RESET
                    print(
                        "{:<5} {:<32s} {:<8s} {:<8s} {:<8s} {:<8}".format(
                            "",
                            str(x),
                            s[t].sectionName.decode("utf-8"),
                            str(hex(y + s[t].ImageBase + s[t].VirtualAdd)),
                            "(" + str(hex(y)) + ")",
                            constants.RED + "Unicode",
                        )
                        + constants.RESET
                    )

                for (
                    word4,
                    offset,
                    offsetVA,
                    offsetPlusImagebase,
                    wordLength,
                    instructionsLength,
                ) in s[t].pushStrings:
                    word4 = constants.CYAN + word4 + constants.RESET
                    print(
                        "{:<5} {:<32s} {:<8s} {:<8s} {:<8s} {:<12}".format(
                            "",
                            str(word4),
                            s[t].sectionName.decode("utf-8"),
                            str(hex(offset + s[t].ImageBase + s[t].VirtualAdd)),
                            "(offset " + str(hex(offset)) + ")",
                            constants.GREEN + "Stack String" + res,
                        )
                    )

                print("\n")
                t += 1
        else:
            print("\n")
            for x, y, z in stringsTemp:
                x = constants.CYAN + x + constants.RESET
                print(
                    "{:<5} {:<42s} {:<16s} {:<12}".format(
                        "",
                        str(x),
                        "(offset " + str(hex(y)) + ")",
                        constants.YELLOW + "Ascii" + constants.RESET,
                    )
                )

            for x, y, z in stringsTempWide:
                x = constants.CYAN + x + constants.RESET
                print(
                    "{:<5} {:<42s} {:<16s} {:<12}".format(
                        "",
                        str(x),
                        "(offset " + str(hex(y)) + ")",
                        constants.RED + "Unicode" + constants.RESET,
                    )
                )

            # word4, offset, wordLength,instructionsLength
            for word4, offset, wordLength, instLen in pushStringsTemp:
                word4 = constants.CYAN + word4 + constants.RESET
                print(
                    "{:<5} {:<42s} {:<16s} {:<12}".format(
                        "",
                        str(word4),
                        "(offset " + str(hex(offset)) + ")",
                        constants.GREEN + "Stack String" + constants.RESET,
                    )
                )

    except Exception as e:
        print(e)
        print(traceback.format_exc())
    t = 0


def goodString(data, word, size):
    global stringsDeeper
    global stringReadability
    global GoodStrings
    try:
        readable = stringReadability
    except:
        readable = 0.65
    dprint2("goodstring ", word, size)
    numbers = sum(c.isdigit() for c in word)
    letters = sum(c.isalpha() for c in word)
    spaces = sum(c.isspace() for c in word)
    others = len(word) - numbers - letters - spaces
    dprint2(numbers, letters, spaces, others)

    wordSize = len(word)
    if wordSize == 0:
        wordSize = 0.0001
    # print (wordSize, "size")
    # print ((letters+numbers+spaces)/wordSize, "num")

    # print ("size", len(data), len(word))
    # if len(data) == len(word):
    if len(word) >= 0.95 * len(data):
        # print ("badsize")
        return False
    dprint2(letters, (letters + numbers + spaces) / wordSize, len(word), size)
    if (
        (letters >= 2)
        and ((letters + numbers + spaces) / wordSize > readable)
        and (len(word) >= size)
    ):
        dprint2("yes, goodString")
        return True

    if wordSize < size:
        if word.lower() in GoodStrings:
            return True

        # for each in GoodStrings:	### maybe too computationally expensive if long list??
        # 	if each.lower() in word.lower():
        # 		return True

    return False


def goodStringWide(data, word, size):  # deprecate d- use other goodstrings
    global stringsDeeper
    print("goodStringWide ", word, size)
    numbers = sum(c.isdigit() for c in word)
    letters = sum(c.isalpha() for c in word)
    spaces = sum(c.isspace() for c in word)
    others = len(word) - numbers - letters - spaces
    print(numbers, letters, spaces, others)
    size = size * 2

    wordSize = len(word) * 2
    if wordSize == 0:
        wordSize = 0.0001
    # print (wordSize, "size")
    # print ((letters+numbers+spaces)/wordSize, "num")

    # print ("size", len(data), len(word))
    # if len(data) == len(word):
    if len(word) >= 0.95 * len(data):
        return False
    print(letters, len(word), size)
    if (letters >= 5) and (len(word) >= size):
        print("yes, goodStringWide")
        return True

    if word.lower() in GoodStrings:
        return True

    for each in GoodStrings:  ### maybe too computationally expensive if long list??
        if each.lower() in word.lower():
            return True

    return False


cs = Cs(CS_ARCH_X86, CS_MODE_32)
stringLiteral = "\x31\xc9\xb9\xad\xde\x65\x64\xc1\xe9\x10\x51\x68\x77\x6f\x72\x6b\x68\x6f\x69\x74\x20\x68\x45\x78\x70\x6c\x89\xe2\xb9\xca\xad\xde\x29\xc1\xe9\x18\x51\x68\x6e\x73\x20\x3a\x68\x75\x74\x74\x6f\x68\x73\x65\x20\x62\x68\x20\x6d\x6f\x75\x68\x70\x69\x6e\x67\x68\x53\x77\x61\x70\x89\xe3\x31\xc9\x51\x52\x53\x51\xff\xd0"
# stringLiteral=test2
ArrayLiteral = "0x31, 0xC9, 0xB9, 0xAD, 0xDE, 0x65, 0x64, 0xC1, 0xE9, 0x10, 0x51, 0x68, 0x77, 0x6F, 0x72, 0x6B, 0x68, 0x6F, 0x69, 0x74, 0x20, 0x68, 0x45, 0x78, 0x70, 0x6C, 0x89, 0xE2, 0xB9, 0xCA, 0xAD, 0xDE, 0x29, 0xC1, 0xE9, 0x18, 0x51, 0x68, 0x6E, 0x73, 0x20, 0x3A, 0x68, 0x75, 0x74, 0x74, 0x6F, 0x68, 0x73, 0x65, 0x20, 0x62, 0x68, 0x20, 0x6D, 0x6F, 0x75, 0x68, 0x70, 0x69, 0x6E, 0x67, 0x68, 0x53, 0x77, 0x61, 0x70, 0x89, 0xE3, 0x31, 0xC9, 0x51, 0x52, 0x53, 0x51, 0xFF, 0xD0"
rawHex2 = "31C9B9ADDE6564C1E9105168776F726B686F697420684578706C89E2B9CAADDE29C1E91851686E73203A687574746F687365206268206D6F756870696E67685377617089E331C951525351FFD0"
# shellcode='shellcode.txt'
shellcode2 = "shellcode2.txt"
shellcode3 = "shellcode3.txt"
shellcode4 = "shellcode4.txt"
shellcode5 = "shellcode5.txt"
shellcode6 = "shellcode6.txt"
shellcode7 = "shellcode7.txt"
shellcode8 = "shellcode8.txt"


def show1(int1):
    show = "{0:02x}".format(int1)  #
    return show


def splitArrLit(word):
    array = word.split(" 0x")
    res = ""
    for each in array:
        res += each
    return res


def splitBackslashx(word):
    array = word.split("\\x")
    res = ""
    for each in array:
        res += each
    return res


def split0x(word):
    array = word.split("0x")
    res = ""
    for each in array:
        res += each
    return res


def splitNewline(word: bytes) -> bytearray:
    array = word.split(b"\n")
    array2 = bytearray()
    for word in array:
        array2 += splitRemoveAssemblyComments(word)
    res = bytearray()
    for each in array2:
        res += int.to_bytes(each, 1, "little")
    return res


def splitRemoveAssemblyComments(word: bytes) -> bytearray:
    array = word.split(b";")[0]
    res = bytearray()
    for each in array:
        res += int.to_bytes(each, 1, "little")  # Assume little endian for now?
    return res


def readShellcode(
    shellcode,
):  #  ADDED: get rid of newline (0d0a) - get rid of assembly comments   ---   ; comments -- added SplitNewline and the .join
    local_shellcode = None
    with open(shellcode, "rb") as file1:
        local_shellcode = file1.read()

    shells = splitNewline(local_shellcode)
    shells = re.sub(rf"[{string.punctuation}]", "", shells)
    dprint2(shells)
    shells = splitBackslashx(shells)
    shells = splitArrLit(shells)
    shells = split0x(shells)

    shells = "".join(shells.split())
    shells = shells.upper()
    shells = fromhexToBytes(shells)
    dprint2("\n\n\nend\n")
    return shells


def reduceShellToStrHex(shellcode):
    shells = splitBackslashx(shellcode)
    shells = splitArrLit(shells)
    shells = split0x(shells)
    dprint2(shells)
    shells = fromhexToBytes(shells)
    return shells


def printBytes(mybtes):
    for val in mybtes:
        print(hex(val), " ", end="")
    print("\n")


def printFromhexToBytes(hexadecimal_string):
    byte_array = bytearray.fromhex(hexadecimal_string)
    bytesStr = bytes(byte_array)
    printBytes(bytesStr)


def fromhexToBytes(hexadecimal_string):
    byte_array = bytearray.fromhex(hexadecimal_string)
    bytesStr = bytes(byte_array)
    return bytesStr


def checkForLabel(addb, labels):
    # dprint ("checkForLabel " + addb)
    for label in labels:
        if label == addb:
            val = "	 label_" + addb + ":\n"
            # dprint (val)
            return True, val
    return False, 0


def signedNegHexTo(signedVal):
    strSigned = str(hex(signedVal))
    ba = binascii.a2b_hex(strSigned[2:])
    new = int.from_bytes(ba, byteorder="big", signed=True)
    return new


def checkForValidAddress(val_a, val_b1, val_b2, sizeShell):
    val_b = val_b1 + " " + val_b2
    # print ("comparing: " + val_b2 + " > " + str(hex(sizeShell)) )
    try:
        controlFlow = re.match(
            r"\bcall\b|\bjmp\b|\bje\b|\bjne\b|\bjg\b|\bjge\b|\bjl\b|\bjle\b|\bjb\b|\bjbe\b|\bjo\b|\bjno\b|\bjz\b|\bjnz\b|\bjs\b|\bjns\b|\bjcxz\b|\bjrcxz\b|\bjecxz\b|\bja\b|\bloop\b|\bloopcc\b|\bloope\b|\bloopne\b|\bloopnz\b|\bloopz\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjna\b|\bjnbe\b|\bjnge\b|\bjnl\b|\bjng\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b",
            val_b1,
            re.M | re.I,
        )

        if controlFlow:
            if int(val_b2, 16) > int(sizeShell):
                # print("it is bigger")
                return (
                    val_b + " (??)"
                )  ## ?? because goes to offset that doesn't exit! Probably db or something else
    except:
        pass
    return val_b


def checkForValidAddress2(
    val_a, val_b1, val_b2, sizeShell, off_PossibleBad, data, num_bytes
):
    # print ("checkForValidAddress2")
    # val_b=checkForValidAddress(val_a,val_b1, val_b2, sizeShell, off_PossibleBad)
    val_b = val_b1 + " " + val_b2
    try:
        if str(val_b2) in off_PossibleBad:
            # dprint2 ("oh noes "  + val_b2)
            # dprint2(val_a, val_b1, val_b2)
            # res=specialDisDB(data, int(val_a,16))
            # val_b=res
            addy = int(val_a, 16)
            modifysByRange(data, addy, addy + num_bytes, "d", "checkForValidAddress2")
            # val_b =  val_b+ " (??)"

            # dprint2 ("check2: valb: "  + val_b + " " + str(num_bytes) )

            num_bytes = num_bytes - 1

            return val_b, num_bytes
    except:
        pass
    return val_b, 0


def specialDisDB2(data):
    dprint2("special2")
    out = binaryToStr(data[:1])
    out = out[1:]
    val = "db 0"
    return val + out + " (?)"


def specialDisDB(data, addy):  # //takes bytes
    cs.skipdata = True
    cs.skipdata_setup = ("db", None, None)
    dprint2(binaryToStr(data[addy : addy + 1]))
    address = 0
    val_b = ""
    for i in cs.disasm(data[addy : addy + 1], address):
        val_b = i.mnemonic + " " + i.op_str
        dprint2("hi2")
        try:
            dprint2(val_b)
            return val_b
        except:
            pass
    return val_b


def makeDBforUnknownBytes(num_bytes, val_c, addb):
    # dprint ("makeDBforUnknownBytes(num_bytes, val_c)")
    dprint2(num_bytes)
    dprint2(val_c)
    bVal_c = reduceShellToStrHex(val_c)
    # dprint("ans:")
    reducedVal_c = binaryToStr(bVal_c)
    dprint2(reducedVal_c)
    # dprint(type(bVal_c))
    new = specialDisDB2(bVal_c)
    newVal_c = val_c[:4]
    dprint2("new")
    dprint2(newVal_c)
    res = makeAsciiforDB(newVal_c)
    num_bytes = int(len(val_c) / 4)
    address = 0x0
    val = "{:<10s} {:<35s}{:<26s}{:<10s}\n".format(addb, new, newVal_c, res)
    dprint2(val)
    dprint2(num_bytes)
    dprint2("bval")
    dprint2(type(bVal_c))
    reducedVal_c = reducedVal_c[4:]
    num_bytes = int(len(reducedVal_c) / 4)

    return val, num_bytes, reducedVal_c


def disHereMakeDB(data, offset, end, mode, CheckingForDB):
    global labels

    bprint("dishereMakeDB " + str(offset) + " end: " + str(end))

    try:
        address = offset
    except:
        address = 0
    cs.skipdata = True
    cs.skipdata_setup = ("db", None, None)
    if offset == False:
        offset = 0
    if end == False:
        end = len(data) - 1
    CODED2 = data[offset:end]
    # print binaryToStr(CODED2)
    val = ""
    val2 = []
    val3 = []
    val5 = []
    startAdd = []
    nextAdd = []
    bytesPerLine = []
    cntLines = 0
    bytesEachLine = []
    asciiPerLine = []
    CODED3 = CODED2

    for i in cs.disasm(CODED3, address):
        cntLines += 1
        val = i.mnemonic + " " + i.op_str
    current = 0
    for i in cs.disasm(CODED3, address):
        if current > 0:
            nextAd = sadd1
            nextAdd.append(nextAd)
        sadd1 = int(i.address)
        startAdd.append(int(sadd1))
        current += 1
    t = 0
    ans = 0
    total = 0
    for each in startAdd:
        try:
            ans = int(startAdd[t + 1]) - int(each)
            bytesPerLine.append(ans)
            total += ans
        except:
            ans2 = hex(len(data) - total)
            bytesPerLine.append(int(ans2, 16))
        t += 1
    cnt = 0
    t = 0

    for i in cs.disasm(CODED3, address):
        ans = binaryToStr(CODED3[cnt : cnt + bytesPerLine[t]])  # + " " + str(t) + "\n"
        res = ""
        for y in CODED3[cnt : cnt + bytesPerLine[t]]:
            yy = ord2(y)
            zz = show1(yy)
            old = "nope"
            if (yy > 31) & (yy < 127):
                try:
                    zz = int(zz, 16)
                    zz = chr(zz)
                except:
                    zz = chr(zz)
            else:
                zz = "."
            old = zz
            res += zz  # stripWhite(zz)#chr(zz)
        asciiPerLine.append(res)
        bytesEachLine.append(ans)
        cnt += bytesPerLine[t]
        t += 1
    t = 0
    add = hex(int(i.address))
    sizeShell = len(CODED2)
    for i in cs.disasm(CODED2, address):
        CantSkip = True
        add = hex(int(i.address))
        addb = hex(int(i.address))
        add2 = str(add)
        # add3 = hex (int(i.address + section.startLoc	))
        add3 = 0
        add4 = str(add3)
        val_a = addb  # "\t"#\t"
        val_b = i.mnemonic + " " + i.op_str
        val_b1 = i.mnemonic
        val_b2 = i.op_str
        num_bytes = 0
        try:
            val_c = bytesEachLine[t]
            val_d = asciiPerLine[t]
        except:
            val_c = ""
            val_d = ""
        try:
            num_bytes = int(len(val_c) / 4)
        except:
            num_bytes = 1
        val_b, num_bytes = checkForValidAddress2(
            val_a, val_b1, val_b2, sizeShell, off_PossibleBad, data, num_bytes
        )
        if mode == "ascii":
            val = "{:<10s} {:<35s} {:<26s}{:<10s}\n".format(val_a, val_b, val_c, val_d)
        else:
            val = addb + ":\t" + i.mnemonic + " " + i.op_str + "\n"
            val = "{:<10s} {:<35s}\n".format(val_a, val_b)
        truth, res = checkForLabel(addb, labels)
        if truth:
            val = res + val
        valCheck = i.mnemonic + " " + i.op_str
        val, num_bytes, val_c = makeDBforUnknownBytes(num_bytes, val_c, addb)
        dprint2("truth check " + addb)
        truth, res = checkForLabel(addb, labels)
        if truth:
            val = res + val
        valCheck = i.mnemonic + " " + i.op_str
        addb = str(hex(int(addb, 16) + 1))
        dprint2("final val_c")
        dprint2(type(val_c))
        val2.append(val)
        val3.append(add2)
        val5.append(val + "(!)")
        t += 1
    returnString = ""
    dprint2("dishereMakeDB2 " + str(offset) + " end: " + str(end))
    for y in val5:
        returnString += y
    return returnString


def makeAsciiforDB(data):
    res = ""
    zz = ""
    # dprint(type(data))
    CODED3 = reduceShellToStrHex(data)
    # dprint(type(CODED3))
    for y in CODED3:
        yy = ord2(y)
        zz = show1(yy)
        if (yy > 31) & (yy < 127):
            try:
                zz = int(zz, 16)
                zz = chr(zz)
            except:
                zz = chr(zz)
        else:
            zz = "."
    res += zz  # stripWhite(zz)#chr(zz)
    # dprint (res)
    return res

    global sBy
    dprint("addEntryPoint")

    index = sBy.shAddresses.index(str(hex(shellEntry)))

    dprint2(index, sBy.shDisassemblyLine[index], sBy.shAddresses[index])
    dprint(sBy.shDisassemblyLine[index])
    # old= sBy.shDisassemblyLine[index]
    # sBy.shDisassemblyLine[index] =  "*.0x"+str(shellEntry) + "" + old +"12345678910" + "AHAHAHAHAHAHA"

    old = sBy.shDisassemblyLine[index - 1]
    sBy.shDisassemblyLine[index - 1] = old = "\t\t[*]Shellcode Entrypoint:"
    dprint(sBy.shDisassemblyLine[index - 1])
    dprint("done")


def addDis(address, line=None, mnemonic=None, op_str=None, id2="NA"):
    # print("      [*] addDis id", id2, hex(address), "line", line, "mnemonic", mnemonic, op_str)
    # print (type(address), "address type")
    # print (mnemonic, op_str, id2, "\n")
    lineSize = len(sBy.shDisassemblyLine)
    # try:
    # 	print ("previous", sBy.shDisassemblyLine[lineSize-1] )
    # 	print ("previous", sBy.shAddresses[lineSize-1] )
    # except:
    # 	pass
    sBy.shDisassemblyLine.append(line)
    sBy.shAddresses.append(address)
    sBy.shCodes.append(id2)
    sBy.shMnemonic.append(mnemonic)
    sBy.shOp_str.append(op_str)


def createDisassemblyLists(
    variables, module, shellcode_label, Colors=True, caller=None, decoder=False
):
    global off_Label
    global labels
    global res
    global sBy

    maxOpDisplay = variables.moduleBooleans[shellcode_label].maxOpDisplay

    btsV = variables.moduleBooleans[shellcode_label].btsV

    if not decoder:
        shellArg = module[shellcode_label].rawData2
    else:
        shellArg = sh.decoderStub
    showOpcodes = variables.moduleBooleans[shellcode_label].bDoshowOpcodes
    showLabels = variables.moduleBooleans[shellcode_label].bShowLabels
    if (
        caller == "final"
        and variables.moduleBooleans[shellcode_label].bDoEnableComments
    ):
        addComments(variables, module, shellcode_label)
    mode = "ascii"
    if not variables.moduleBooleans[shellcode_label].bDoShowOffsets:
        mode = "NoOffsets"
    j = 0
    nada = ""
    finalOutput = "\n"
    myStrOut = ""
    myHex = ""

    defaultBase = CODE_ADDR

    for cAddress in sBy.shAddresses:
        pAddress = constants.GREEN + str(hex(cAddress)) + constants.RESET

        test = cAddress + defaultBase

        if em.displayNonTraversedCC:
            if test in traversedAdds:
                specialpAddress = constants.GREEN + str(hex(cAddress)) + constants.RESET
            else:
                specialpAddress = constants.CYAN + str(hex(cAddress)) + constants.RESET
            if len(traversedAdds) == 0:
                specialpAddress = constants.GREEN + str(hex(cAddress)) + constants.RESET
        else:
            specialpAddress = constants.GREEN + str(hex(cAddress)) + constants.RESET

        startHex = cAddress
        try:
            endHex = sBy.shAddresses[j + 1]
        except:
            endHex = len(shellArg)
        sizeDisplay = endHex - startHex
        if mode == "ascii":
            try:
                if sizeDisplay > maxOpDisplay:
                    myHex = (
                        constants.RED
                        + binaryToStr(
                            shellArg[startHex : startHex + maxOpDisplay], btsV
                        )
                        + "..."
                        + constants.RESET
                        + ""
                    )
                    myStrOut = (
                        constants.CYAN
                        + " "
                        + toString(shellArg[startHex:endHex])
                        + constants.RESET
                        + ""
                    )
                else:
                    myHex = (
                        constants.RED
                        + binaryToStr(shellArg[startHex:endHex], btsV)
                        + constants.RESET
                        + ""
                    )
                    if variables.moduleBooleans[shellcode_label].bDoShowAscii:
                        myStrOut = (
                            constants.CYAN
                            + " "
                            + toString(shellArg[startHex:endHex])
                            + constants.RESET
                            + ""
                        )
                    else:
                        myStrOut = ""
            except Exception as e:
                print("ERROR: ", e)

            if not showOpcodes:  # If no hex, then move ASCII to left
                myHex = myStrOut
                myStrOut = ""

            pAddress = specialpAddress
            out = "{:<12s} {:<45s} {:<33s}{:<10s}\n".format(
                pAddress,
                constants.WHITE + sBy.shMnemonic[j] + " " + sBy.shOp_str[j],
                myHex,
                myStrOut,
            )
            if re.search(r"align|db 0xff x", sBy.shMnemonic[j], re.M | re.I):
                myHex = (
                    constants.RED
                    + binaryToStr(shellArg[startHex : startHex + 4], btsV)
                    + "..."
                    + constants.RESET
                    + ""
                )
                if variables.moduleBooleans[shellcode_label].bDoShowAscii:
                    myStrOut = (
                        constants.CYAN
                        + " "
                        + toString(shellArg[startHex : startHex + 4])
                        + "..."
                        + constants.RESET
                        + ""
                    )
                else:
                    myStrOut = ""

                if not showOpcodes:  # If no hex, then move ASCII to left
                    myHex = myStrOut
                    myStrOut = ""
                out = "{:<12s} {:<45s} {:<33s}{:<10s}\n".format(
                    pAddress,
                    constants.WHITE + sBy.shMnemonic[j] + " " + sBy.shOp_str[j],
                    myHex,
                    myStrOut,
                )
                pass

            # out=out+"\n"
        elif mode == "NoOffsets":
            try:
                if sizeDisplay > maxOpDisplay:
                    myHex = (
                        constants.RED
                        + binaryToStr(
                            shellArg[startHex : startHex + maxOpDisplay], btsV
                        )
                        + "..."
                        + constants.RESET
                        + ""
                    )
                    myStrOut = (
                        constants.CYAN
                        + " "
                        + toString(shellArg[startHex:endHex])
                        + constants.RESET
                        + ""
                    )
                else:
                    myHex = (
                        constants.RED
                        + binaryToStr(shellArg[startHex:endHex], btsV)
                        + constants.RESET
                        + ""
                    )
                    if variables.moduleBooleans[shellcode_label].bDoShowAscii:
                        myStrOut = (
                            constants.CYAN
                            + " "
                            + toString(shellArg[startHex:endHex])
                            + constants.RESET
                            + ""
                        )
                    else:
                        myStrOut = ""
            except Exception as e:
                print("Error:", e)

            if not showOpcodes:  # If no hex, then move ASCII to left
                myHex = myStrOut
                myStrOut = ""
            out = "   {:<45s} {:<33s}{:<10s}\n".format(
                constants.WHITE + sBy.shMnemonic[j] + " " + sBy.shOp_str[j],
                myHex,
                myStrOut,
            )
            if re.search(r"align|db 0xff x", sBy.shMnemonic[j], re.M | re.I):
                myHex = (
                    constants.RED
                    + binaryToStr(shellArg[startHex : startHex + 4], btsV)
                    + "..."
                    + constants.RESET
                    + ""
                )
                if variables.moduleBooleans[shellcode_label].bDoShowAscii:
                    myStrOut = (
                        constants.CYAN
                        + " "
                        + toString(shellArg[startHex : startHex + 4])
                        + "..."
                        + constants.RESET
                        + ""
                    )
                else:
                    myStrOut = ""

                if not showOpcodes:  # If no hex, then move ASCII to left
                    myHex = myStrOut
                    myStrOut = ""
                out = "   {:<45s} {:<33s}{:<10s}\n".format(
                    pAddress,
                    constants.WHITE + sBy.shMnemonic[j] + " " + sBy.shOp_str[j],
                    myHex,
                )
                pass
        else:
            out = "{:<12s} {:<35s}\n".format(
                pAddress, sBy.shMnemonic[j] + " " + sBy.shOp_str[j]
            )

        if variables.moduleBooleans[shellcode_label].bDoEnableComments:
            if sBy.comments[cAddress] != "":
                val_b2 = sBy.comments[cAddress]

                val_comment = "{:<10s} {:<45s} {:<33s}{:<10s}\n".format(
                    constants.MAGENTA + nada, val_b2, nada, nada
                )
                out += val_comment

        if showLabels:
            truth, myLabel = checkForLabel(str(hex(cAddress)), labels)
            if truth:
                out = constants.YELLOW + myLabel + constants.RESET + out
        if re.search(
            r"\bjmp\b|\bje\b|\bjne\b|\bjg\b|\bjge\b|\bja\b|\bjl\b|\bjle\b|\bjb\b|\bjbe\b|\bjo\b|\bjno\b|\bjz\b|\bjnz\b|\bjs\b|\bjns\b|\bjcxz\b|\bjrcxz\b|\bjecxz\b|\bret\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjna\b|\bjnbe\b|\bjnge\b|\bjnl\b|\bjng\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b",
            sBy.shMnemonic[j],
            re.M | re.I,
        ):
            out = out + "\n"

        ############Stack strings begin
        try:
            cur = cAddress
            if (sBy.pushStringEnd[cur] - 2) == cur:
                msg = (
                    constants.MAGENTA
                    + "; "
                    + sBy.pushStringValue[cur]
                    + " - Stack string"
                    + constants.RESET
                )
                newVal = "{:<12} {:<45s} {:<33}{:<10s}\n".format(nada, msg, nada, nada)
                out = newVal + out
        except Exception:
            # print ("weird error", e)
            pass
        finalOutput += out
        j += 1

    finalOutput = finalOutput + constants.RESET + ""
    finalOutputNoColors = Variables.cleanColors(self=Variables, out=finalOutput)

    return finalOutputNoColors, finalOutput


def createDisassemblyJson(Colors=True, caller=None, decoder=False):
    global off_Label
    global labels
    global sBy

    maxOpDisplay = moduleBooleans[shellcode_label].maxOpDisplay

    btsV = moduleBooleans[shellcode_label].btsV

    if not decoder:
        shellArg = m[o].rawData2
    else:
        shellArg = sh.decoderStub

    showOpcodes = moduleBooleans[shellcode_label].bDoshowOpcodes
    showLabels = moduleBooleans[shellcode_label].bShowLabels
    if caller == "final" and moduleBooleans[shellcode_label].bDoEnableComments:
        addComments()

    mode = "ascii"
    if not moduleBooleans[shellcode_label].bDoShowOffsets:
        mode = "NoOffsets"
    j = 0
    nada = ""
    finalOutput = "\n"
    myStrOut = ""
    myHex = ""

    disList = []
    disFullDict = {}
    for cAddress in sBy.shAddresses:
        disDict = {}

        pAddress = hex(cAddress)  # print address
        startHex = cAddress
        try:
            endHex = sBy.shAddresses[j + 1]
        except:
            endHex = len(shellArg)
        sizeDisplay = endHex - startHex
        if mode == "ascii":
            try:
                if sizeDisplay > maxOpDisplay:
                    myHex = (
                        binaryToStr(shellArg[startHex : startHex + maxOpDisplay], btsV)
                        + "..."
                    )
                    myStrOut = " " + toString(shellArg[startHex:endHex])
                else:
                    myHex = binaryToStr(shellArg[startHex:endHex], btsV)
                    if moduleBooleans[shellcode_label].bDoShowAscii:
                        myStrOut = " " + toString(shellArg[startHex:endHex])
                    else:
                        myStrOut = ""
            except Exception as e:
                print("ERROR: ", e)
            if not showOpcodes:  # If no hex, then move ASCII to left
                myHex = myStrOut
                myStrOut = ""
            disDict["address"] = pAddress.strip()
            disDict["instruction"] = Variables.cleanColors(
                self=Variables, out=sBy.shMnemonic[j] + " " + sBy.shOp_str[j]
            ).strip()

            disDict["hex"] = (myHex).strip()

            try:
                disDict["size"] = str(sBy.shAddresses[j + 1] - sBy.shAddresses[j])
            except:
                disDict["size"] = str(len(m[o].rawData2) - sBy.shAddresses[j])

            if fRaw.status() and fRaw.bytesInst[cAddress] == "INST":
                disDict["bytes"] = "CODE"
                disDict["dataType"] = "CODE"

            else:
                if sBy.bytesType[cAddress]:
                    disDict["bytes"] = "CODE"
                    disDict["dataType"] = "CODE"

                else:
                    disDict["bytes"] = "DATA"
                    disDict["dataType"] = "DATA"

            disDict["dataAccessed"] = "None"
            if sBy.strings[cAddress]:
                disDict["dataType"] = "String"
            elif sBy.ApiTable[cAddress]:
                disDict["dataType"] = "API Pointer"
            elif sBy.dataAccessed[cAddress]:
                disDict["dataAccessed"] = (
                    hex(sBy.dataAccessedSize[cAddress][0])
                    + ", "
                    + hex(sBy.dataAccessedSize[cAddress][1])
                )

            # pAddressInt = int(pAddress, 16)
            # print(type(pAddress), pAddress, int(pAddress, 16))
            if re.search(r"align|db 0xff x", sBy.shMnemonic[j], re.M | re.I):
                myHex = binaryToStr(shellArg[startHex : startHex + 4], btsV) + "..."
                if moduleBooleans[shellcode_label].bDoShowAscii:
                    myStrOut = (
                        constants.CYAN
                        + " "
                        + toString(shellArg[startHex : startHex + 4])
                        + "..."
                    )
                else:
                    myStrOut = ""

                if not showOpcodes:  # If no hex, then move ASCII to left
                    myHex = myStrOut
                    myStrOut = ""
            disDict["string"] = myStrOut.strip()
            # out=out+"\n"
        if moduleBooleans[shellcode_label].bDoEnableComments:
            if sBy.comments[cAddress] != "":
                val_b2 = sBy.comments[cAddress]
                val_comment = "{:<10s} {:<45s} {:<33s}{:<10s}\n".format(
                    nada, val_b2, nada, nada
                )
                disDict["comment"] = Variables.cleanColors(
                    self=Variables, out=val_comment
                ).strip()
            else:
                disDict["comment"] = ""

        if showLabels:
            truth, myLabel = checkForLabel(hex(cAddress), labels)
            if truth:
                disDict["label"] = myLabel.strip()
            else:
                disDict["label"] = ""

        try:
            cur = cAddress
            if (sBy.pushStringEnd[cur] - 2) == cur:
                msg = "; " + sBy.pushStringValue[cur] + " - Stack string"
                disDict["comment"] + Variables.cleanColors(
                    self=Variables,
                    out="; " + sBy.pushStringValue[cur] + " - Stack string",
                )
                newVal = "{:<12} {:<45s} {:<33}{:<10s}\n".format(nada, msg, nada, nada)
        except Exception:
            # print ("weird error", e)
            pass
        # disTuple = tuple(disList)
        disList.append(disDict)
        # disDict[pAddressInt] = disTuple
        j += 1

    disFullDict["disassembly"] = disList
    return json.dumps(disFullDict, indent=3)


def clearTempDis():
    global sBy
    sBy.shDisassemblyLine.clear()
    sBy.shAddresses.clear()
    sBy.shMnemonic.clear()
    sBy.shOp_str.clear()


def checkForBad00(data, offset, end):
    global sBy
    dprint2("checkForBad00")

    # dprint2 (len(sBy.shAddresses), len(sBy.shDisassemblyLine))
    sample = "add byte ptr \[eax], al"
    ans = []
    for x in range(4):
        if hex(offset) in sBy.shAddresses:
            index = sBy.shAddresses.index(hex(offset))

            print(index, len(sBy.shDisassemblyLine), len(sBy.shAddresses))
            dprint2(index, sBy.shDisassemblyLine[index], sBy.shAddresses[index])

            findBad00 = re.search(sample, sBy.shDisassemblyLine[index], re.M | re.I)
            if findBad00:
                dprint2("    ", sBy.shAddresses[index], "gots it")

                ans.append(int(sBy.shAddresses[index], 16))
                ans.append(int(sBy.shAddresses[index], 16) + 1)
        offset += 1
    dprint2(ans)
    if len(ans) > 0:
        size = len(ans) - 1
        distance = ans[size] - ans[0]
        dprint2(distance)
        dprint2(ans[0], ans[distance])
        modifysBySpecial(data, ans[0], end, "al", "al2")
        modifysByRange(data, ans[0], end, "d", "checkForBad00")


def disHereMakeDB2(data, offset, end, mode, CheckingForDB):  #### new one
    dbStart = offset
    global labels
    global sBy
    apiFound = set()
    w = 0
    length = end - offset
    dbFlag = False
    skip = True
    startAddString = ""
    stringVala = ""
    apiValA = ""
    apiStart = 0
    apiDistance = 0
    apiInProgress = False
    apiEnd = 0
    apiStartstr = ""
    stringStart = 0
    stringInProgress = False
    maxSize = offset + length
    dbOut = ""
    apiSkip = False
    while offset < maxSize:
        check = sBy.strings[offset]
        if sBy.strings[offset] and (m[o].rawData2[offset] != 0):
            dbFlag = True
            stringInProgress = True
            stringStart, stringDistance = sBy.stringsStart[offset]
            startAddString = hex(stringStart)
            if stringStart == offset:
                startAddString = hex(offset)
                stringVala = (
                    sBy.stringsValue[offset]
                    + constants.MAGENTA
                    + " ; string"
                    + constants.RESET
                    + "\t\t"
                )
        elif sBy.ApiTable[offset]:
            dbFlag = True
            apiInProgress = True
            apiStart = sBy.ApiStart[offset]
            apiDistance = sBy.ApiEnd[offset] - sBy.ApiStart[offset]
            if apiStart == offset:
                apiStartstr = hex(offset)
                apiValA = (
                    constants.MAGENTA
                    + sBy.ApiValue[offset]
                    + constants.YELLOW
                    + " - API pointer"
                    + constants.RESET
                    + "\t\t"
                )
            if apiStart + 1 == offset:
                apiEnd = sBy.ApiEnd[offset]
                apiSkip = False

        elif sBy.ApiTable[offset] == False:  #  and sBy.boolspecial[offset]==False:
            if dbFlag == False and sBy.boolspecial[offset] == False:
                getNextVal = getNextBoolDB4(
                    True,
                    True,
                    True,
                    True,
                    sBy.boolspecial,
                    sBy.ApiTable,
                    sBy.strings,
                    sBy.bytesType,
                    offset,
                )
                bytesRes = "0x" + data[offset : offset + getNextVal].hex()
                processDB(data[offset : offset + getNextVal], offset)
                offset = getNextVal + offset - 1  # -1 will add 1 later
                skip = True
            elif dbFlag:
                if stringInProgress:
                    addDis(
                        int(startAddString, 16), "", stringVala, "", "StringB"
                    )  # new Fixed
                    stringInProgress = False
                elif sBy.boolspecial[offset] == False:
                    bytesRes = "0x" + data[offset : offset + 1].hex()
                    getNextVal = getNextBoolDB4(
                        True,
                        True,
                        True,
                        True,
                        sBy.boolspecial,
                        sBy.ApiTable,
                        sBy.strings,
                        sBy.bytesType,
                        offset,
                    )
                    bytesRes = "0x" + data[offset : offset + getNextVal].hex()
                    processDB(data[offset : offset + getNextVal], offset)
                    offset = getNextVal + offset - 1
                if apiInProgress:
                    if apiStart not in apiFound:
                        addDis(int(apiStartstr, 16), "", apiValA, "", "EndStringMaker")
                        apiFound.add(apiStart)
                        apiInProgress = False
                        dbFlag = False

                dbFlag = False
                skip = True
            if not skip:
                bytesRes = "0x" + data[offset : offset + getNextVal].hex()
                processDB(data[offset : offset + getNextVal], offset)
                offset = getNextVal + offset - 1
            skip = False

        if apiEnd == offset + 3:
            if apiStart not in apiFound:
                addDis(
                    int(apiStartstr, 16),
                    "",
                    apiValA,
                    "",
                    "API PTR: making 3rdb,  distance: "
                    + hex(end - offset)
                    + " "
                    + hex(offset)
                    + " "
                    + hex(end),
                )
            apiFound.add(apiStart)
            apiInProgress = False
            apiSkip = True
            dbFlag = False

        elif sBy.boolspecial[offset] and not sBy.ApiTable[offset]:
            offset = sBy.specialEnd[offset] - 1
            if sBy.specialVal[offset] == "al":
                mnemonicVal = "align " + hex(
                    sBy.specialEnd[offset] - sBy.specialStart[offset]
                )
                addDis(
                    sBy.specialStart[offset], mnemonicVal, mnemonicVal, "", "D1"
                )  # doesn't seem to be used   --> new
            elif sBy.specialVal[offset] == "ff":
                mnemonicVal = "db 0xff x " + hex(
                    sBy.specialEnd[offset] - sBy.specialStart[offset]
                )
                addDis(
                    sBy.specialStart[offset], mnemonicVal, mnemonicVal, "", "D2"
                )  # new
            else:
                if offset == sBy.specialEnd[offset] - 1:
                    mnemonicVal = "align " + hex(
                        sBy.specialEnd[offset] - sBy.specialStart[offset]
                    )
                    addDis(
                        sBy.specialStart[offset], mnemonicVal, mnemonicVal, "", "D3"
                    )  # this is the one used    ---> new
        offset += 1
        w += 1
        if w == length:
            t = 0
            if dbFlag:
                stringVala = (
                    sBy.stringsValue[offset - 1]
                    + constants.MAGENTA
                    + " ; string"
                    + constants.RESET
                    + "\t\t"
                )
                try:
                    addDis(
                        int(startAddString, 16), "", stringVala, "", "EndStringMaker"
                    )
                except:
                    pass
                if apiInProgress and apiSkip == False:
                    if offset == apiStart + 3:
                        if apiStart not in apiFound:
                            addDis(
                                int(apiStartstr, 16), "", apiValA, "", "EndStringMaker"
                            )
                            apiInProgress = False
                dbFlag = False
            w = 0
    return ""


def processDB(binary, offset):
    # print ("processDB", len(binary), hex(offset))
    total = len(binary)
    numDD = int(total / 4)
    rem = total % 4
    # print ("total", total, "\tnumDD", int(numDD))
    # print ("remainder",rem)
    # print ("double checking math:", (numDD*4)+rem)

    start = 0

    # start=offset

    # for x in range(numDD):
    # 	bytesRes= binary[start:start+4].hex()

    # 	print (bytesRes)

    # 	addDis(offset, hex(start)+" 3 dd" + " " +bytesRes,  hex(start)+"3b dd", bytesRes,"processDB")

    # 	start+=4

    # print ("\n\n\n")
    # start=0
    while start < numDD * 4:
        bytesRes = binary[start : start + 4].hex()
        # debugInfo="\n\t" +str(len(binary)) + " " +str(hex(offset)) +" "  + str(hex(offset+start))

        # print ("dd", binary[start:start+4].hex())
        addDis(
            offset + start,
            hex(offset + start) + "dd" + " " + bytesRes,
            "dd",
            bytesRes,
            "processDB",
        )

        start += 4

    if rem == 3:
        # print ("dw", binary[start:start+2].hex())
        bytesRes = binary[start : start + 2].hex()

        addDis(
            offset + start,
            hex(offset + start) + " dw" + " " + bytesRes,
            "dw",
            bytesRes,
            "processDB",
        )

        start += 2
        bytesRes = binary[start : start + 1].hex()

        # print ("dw", binary[start:start+1].hex())
        addDis(
            offset + start,
            hex(offset + start) + " db" + " " + bytesRes,
            "db",
            bytesRes,
            "processDB",
        )
        start += 1

    if rem == 2:
        bytesRes = binary[start : start + 2].hex()

        # print ("dw", binary[start:start+2].hex())
        addDis(
            offset + start,
            hex(offset + start) + "dw" + " " + bytesRes,
            "dw",
            bytesRes,
            "processDB",
        )

        start += 2

    if rem == 1:
        bytesRes = binary[start : start + 1].hex()

        # print ("db", binary[start:start+1].hex())
        addDis(
            offset + start,
            hex(offset + start) + " db" + " " + bytesRes,
            "db",
            bytesRes,
            "processDB",
        )

        start += 1


def getNextBoolDB4(
    pattern1, pattern2, pattern3, pattern4, test1, test2, test3, test4, offset
):
    test1 = test1[offset:]
    test2 = test2[offset:]
    test3 = test3[offset:]
    test4 = test4[offset:]

    try:
        found = test1.index(pattern1)
    except:
        # print ("error1")
        found = len(test1) - 1
    try:
        found2 = test2.index(pattern2)
    except:
        # print ("error2")
        found2 = len(test2) - 1

    try:
        found3 = test3.index(pattern3)
    except:
        # print ("error3")
        found3 = len(test3) - 1

    try:
        found4 = test4.index(pattern4)
    except:
        # print ("error4")
        found4 = len(test4) - 1

    # print ("found1:", found, "\tfound2:", found2, "\tfound3", found3, "found 4", found4, "offset", hex(offset), hex(offset+found), hex(offset+found2), hex(offset+found3), hex(offset+found4))
    possible = [found, found2, found3, found4]
    minPossible = min(possible)
    if minPossible == 0:
        minPossible = 1
    return minPossible


def findDataBytesEmu(shellBytes):
    global bAddReadTuple
    global bWriteListTuple
    global bReadListTuple
    # print (constants.RED +"findDataBytesEmu\n\n\n"+constants.RESET)
    maxEmuSize = len(m[o].rawData2)

    emuOnce = bAddReadTuple | bAddWriteTuple
    emuTwice = bAddReadTwiceTuple | bAddWriteTwiceTuple
    emuThrice = bAddReadThriceTuple | bAddWriteThriceTuple

    readPercent = len(emuOnce) / maxEmuSize
    readTwicePercent = len(emuTwice) / maxEmuSize
    readThricePercent = len(emuThrice) / maxEmuSize

    maxPercent = 0.4  # if we are conveting to more than 50% data, then may be more likely each byte is being decoded more than once. hence, ignore this feature.

    if not sh.decryptSuccess:
        if readPercent < maxPercent:
            for each in emuOnce:
                # print (hex(each[0]), each[1])
                modVal = each[0] - CODE_ADDR
                modifysByRange(shellBytes, modVal, modVal + each[1], "d")
                sBy.dataAccessedFunc(each)
    else:
        if readTwicePercent < maxPercent:
            for each in emuTwice:
                # print (hex(each[0]), each[1])
                modVal = each[0] - CODE_ADDR
                modifysByRange(shellBytes, modVal, modVal + each[1], "d")
                sBy.dataAccessedFunc(each)
        elif readThricePercent < maxPercent:
            for each in emuThrice:
                # print (hex(each[0]), each[1])
                modVal = each[0] - CODE_ADDR
                modifysByRange(shellBytes, modVal, modVal + each[1], "d")
                sBy.dataAccessedFunc(each)
        else:
            print(
                "This is an advanced encoding. Some data cannot be distinguished between code."
            )


def dprint4(*args):
    debugging = True
    dprint3(*args)
    debugging = False


# debugging=False
def dprint(*args):
    # print("Debug")
    # if debugging==True:
    # print(info)
    dprint2(*args)


def dprint2(*args):
    if debugging:
        try:
            if len(args) == 1:
                if type(args[0]) == list:
                    print(args[0])
                    return

            if len(args) > 1:
                strList = ""
                for each in args:
                    try:
                        strList += each + " "
                    except:
                        strList += str(each) + " "
                print(strList)

            else:
                for each in args:
                    try:
                        print(str(each) + " ")
                    except:
                        print("dprint error: 1")
                        print(each + " ")
        except Exception as e:
            print("dprint error: 3")
            print(e)
            print(traceback.format_exc())
            print(args)


def bprint(*args):
    brDebugging = False
    if brDebugging:
        try:
            if len(args) == 1:
                if type(args[0]) == list:
                    print(args[0])
                    return

            if len(args) > 1:
                strList = ""
                for each in args:
                    try:
                        strList += each + " "
                    except:
                        strList += str(each) + " "
                print(strList)

            else:
                for each in args:
                    try:
                        print(str(each) + " ")
                    except:
                        print("dprint error: 1")
                        print(each + " ")
        except Exception as e:
            print("dprint error: 3")
            print(e)
            print(traceback.format_exc())
            print(args)


def removeBadOffsets(notBad):
    # dprint2("remove offset ", notBad)
    global off_PossibleBad
    # for x in off_PossibleBad.copy():
    # 	# print (x, type(x))
    # 	if x == notBad:
    # 		print ("it gone")
    # 		off_PossibleBad.remove (x)

    if notBad in off_PossibleBad.copy():
        off_PossibleBad.remove(notBad)

    # dprint2 (off_PossibleBad)


def removeLabels(notLabel, val):
    # dprint2("remove labels ", notLabel)
    # labels.add(str(hex(destination)))
    # off_Label.add(int(i.op_str, 16))
    global labels

    if val in labels.copy():
        labels.remove(val)
    # for x in labels.copy():
    # 	# print (x, type(x))
    # 	if x == val:
    # 		dprint ("labels it gone")
    # 		labels.remove (x)
    # 		# del off_Label[t]
    # 		dprint ("labels it gone2")
    # 	t+=1


def hiddencalls(val):
    print("TEST hidden calls:", hex(val))


def analysisFindHiddenCalls(data, startingAddress, variables, module, shellcode_label, caller=None):  # new!
    global sBy
    global codeCoverage
    dprint2("analysisFindHiddenCalls " + str(startingAddress))
    current = 0
    start = startingAddress
    max = len(sBy.bytesType) - 1
    finalPrint = ""

    variables.moduleBooleans[shellcode_label].bAnaHiddenCallsDone = True
    variables.moduleBooleans[shellcode_label].bAnaHiddenCnt = (
        variables.moduleBooleans[shellcode_label].bAnaHiddenCnt + 1
    )
    if variables.moduleBooleans[shellcode_label].bAnaHiddenCnt > 0:
        variables.moduleBooleans[shellcode_label].bAnaHiddenCallsDone = True
    start, current, distance, typeBytes, skipF = findRange2(current, variables, module, shellcode_label)
    reset = False

    while current < max:
        if max == current:
            current += 1
        if not typeBytes and not skipF:
            dprint2("AN: above is data")
            anaCombined(data, start, start + distance, variables, module, shellcode_label)

        start, current, distance, typeBytes, skipF = findRange2(current, variables, module, shellcode_label)

        if current == max:
            pass

        if not codeCoverageComplete:
            if current == max and not reset:
                reset = True
                current = 0


def analysisConvertBytes(data, startingAddress, variables, module, shellcode_label):
    global sBy
    variables.moduleBooleans[shellcode_label].bAnaConvertBytesDone = True
    dprint2("analysisConvertBytes", startingAddress)
    current = 0
    start = startingAddress
    max = len(sBy.bytesType) - 1
    finalPrint = ""
    start0, current0, distance0, typeBytes, skipF = findRange2(current, variables, module, shellcode_label)
    reset = False
    distance = 0
    dataRangeStart = []
    dataRangeEnd = []
    while current < max:
        finalPrint0 = ""
        if max == current:
            current += 1
        dprint2(binaryToStr(data[start:current]))
        finalPrint += finalPrint0
        if not typeBytes and not skipF:
            dataRangeStart.append(start)
            dataRangeEnd.append(current)
        start, current, distance, typeBytes, skipF = findRange2(current, variables, module, shellcode_label)
    t = 0
    dprint2("final ranges")
    for x in dataRangeStart:
        try:
            distance = dataRangeStart[t] - dataRangeEnd[t - 1]
        except:
            distance = 0
        try:
            dprint2(hex(dataRangeEnd[t - 1]), hex(dataRangeStart[t]))
            if str(hex(dataRangeEnd[t - 1])) not in labels:
                if distance <= 5:
                    dprint2("make data?")
                    modifysByRange(
                        data,
                        dataRangeEnd[t - 1],
                        dataRangeEnd[t - 1] + distance,
                        "d",
                        "analysisConvertBytes",
                    )
            else:
                dprint2(str(hex(dataRangeEnd[t - 1])), "****in labels")
        except:
            pass
        dprint2(hex(distance))
        dprint2("*************************\n")
        t += 1


def anaFindCallsNew(start, data):  # nEW
    global offsets
    global labels
    OP_CALL = b"\xe8"
    OP_ff = b"\xff"
    t = 0
    destination = 99999999
    searchFor = []
    test = int(data[start + t])
    if test == ord(OP_CALL):
        ans, valb_1, valb_2, num_bytes = disHereTiny(data[start + t : start + t + 5])
        if valb_1 == "call":
            modifysByRange(data, start + t, start + t + 5, "i")
            if (int(data[start + t + 4])) == ord(OP_ff):
                if (int(data[start + t + 3])) == ord(OP_ff):
                    signedNeg = signedNegHexTo(int(valb_2, 16))
                    destination = (start + t) + signedNeg
                    ans, valb_1, valb_2, num_bytes = disHereTiny(
                        data[start + t : start + t + 5]
                    )
                    if str(hex(destination)) not in labels:
                        labels.add(str(hex(destination)))
            # ok, it is positive
            elif (int(data[start + t + 4])) == 0:
                ans, valb_1, valb_2, num_bytes = disHereTiny(
                    data[start + t : start + t + 5]
                )
                destination = (start + t) + int(valb_2, 16)
                if str(hex(destination)) not in labels:
                    labels.add(str(hex(destination)))
            if str(hex(destination)) not in searchFor:
                searchFor.append(str(hex(destination)))
                offsets.add(destination)
                modifysByRange(data, destination - 2, destination, "d")
    t += 1


def anaCombined(data, start, current, variables, module, shellcode_label):  # original
    global offsets
    global labels
    OP_SHORT_JUMP = b"\xeb"
    OP_SHORT_JUMP_NEG = b"\xe9"
    OP_CALL = b"\xe8"
    OP_ff = b"\xff"
    t = 0
    destination = 99999999
    searchFor = []
    maxDest = len(module[shellcode_label].rawData2)

    for opcode in data[start:current]:
        test = int(data[start + t])
        if test == ord(OP_SHORT_JUMP):
            if b"\xff" in data[start + t : start + t + 5]:
                ans, valb_1, valb_2, num_bytes = disHereTiny(
                    data[start + t : start + t + 5]
                )
            else:
                ans, valb_1, valb_2, num_bytes = disHereTiny(
                    data[start + t : start + t + 2]
                )
            if valb_1 == "jmp":
                if "ff" in valb_2:
                    signedNeg = signedNegHexTo(int(valb_2, 16))
                    valb_2 = str(hex(signedNeg))
                destination = (start + t) + int(valb_2, 16)
                if destination < maxDest:
                    modifysByRange(
                        data, start + t, start + t + num_bytes, "i", "anaCombined"
                    )

                    if str(hex(destination)) not in labels:
                        labels.add(str(hex(destination)))

                    if str(hex(destination)) not in searchFor:
                        searchFor.append(str(hex(destination)))
        # FINE, IT IS NEGATIVE
        elif test == ord(OP_SHORT_JUMP_NEG):
            if b"\xff" in data[start + t : start + t + 5]:
                ans, valb_1, valb_2, num_bytes = disHereTiny(
                    data[start + t : start + t + 5]
                )
            else:
                ans, valb_1, valb_2, num_bytes = disHereTiny(
                    data[start + t : start + t + 2]
                )
            if valb_1 == "jmp":
                if "ff" in valb_2:
                    signedNeg = signedNegHexTo(int(valb_2, 16))
                    valb_2 = str(hex(signedNeg))
                destination = (start + t) + int(valb_2, 16)
                if destination < maxDest:
                    modifysByRange(
                        data, start + t, start + t + num_bytes, "i", "anaCombined"
                    )

                    if str(hex(destination)) not in labels:
                        labels.add(str(hex(destination)))

                    if str(hex(destination)) not in searchFor:
                        searchFor.append(str(hex(destination)))

        elif test == ord(OP_CALL):
            ans, valb_1, valb_2, num_bytes = disHereTiny(
                data[start + t : start + t + 5]
            )
            if valb_1 == "call":
                if (int(data[start + t + 4])) == ord(OP_ff):
                    if (int(data[start + t + 3])) == ord(OP_ff):
                        signedNeg = signedNegHexTo(int(valb_2, 16))
                        destination = (start + t) + signedNeg
                        ans, valb_1, valb_2, num_bytes = disHereTiny(
                            data[start + t : start + t + 5]
                        )
                        if destination < maxDest:
                            modifysByRange(
                                data, start + t, start + t + 5, "i", "anaCombined1"
                            )

                            if str(hex(destination)) not in labels:
                                labels.add(str(hex(destination)))
                # ok, it is positive
                elif (int(data[start + t + 4])) == 0:
                    ans, valb_1, valb_2, num_bytes = disHereTiny(
                        data[start + t : start + t + 5]
                    )
                    destination = (start + t) + int(valb_2, 16)
                    if destination < maxDest:
                        modifysByRange(
                            data, start + t, start + t + 5, "i", "anaCombined2"
                        )

                        if str(hex(destination)) not in labels:
                            labels.add(str(hex(destination)))
                else:
                    ans, valb_1, valb_2, num_bytes = disHereTiny(
                        data[start + t : start + t + 5]
                    )
                    destination = (start + t) + int(valb_2, 16)
                    if destination < maxDest:
                        modifysByRange(
                            data, start + t, start + t + 5, "i", "anaCombined3"
                        )

                if str(hex(destination)) not in searchFor:
                    if destination < maxDest:
                        searchFor.append(str(hex(destination)))
                        offsets.add(destination)
                        modifysByRange(
                            data, destination - 2, destination, "d", "findAna"
                        )

        t += 1
    for addy in searchFor:
        if int(addy, 16) in offsets:
            pass
        else:
            offsets.add(int(addy, 16))
            removeBadOffsets(addy)
            modifysByRange(data, int(addy, 16) - 2, int(addy, 16), "d", "findAna")


def anaFindShortJumpsNew(start, data):  # NEW
    global offsets
    global labels
    dprint2("anna2: " + " " + str(hex(start)))  # + " " + str(hex(current)) )
    OP_SHORT_JUMP = b"\xeb"
    OP_SHORT_JUMP_NEG = b"\xe9"
    OP_ff = b"\xff"
    # dprint2 (binaryToStr(data[start:current]))
    t = 0
    destination = 99999999
    searchFor = []

    test = int(data[start + t])
    # print ("sj", hex(start+t), ": ", hex(test), hex(ord(OP_SHORT_JUMP)))
    # IT IS A POSITIVE JUMP
    if test == ord(OP_SHORT_JUMP):
        # print("FOUND 0xeb!", hex(start+t))

        if b"\xff" in data[start + t : start + t + 5]:
            # print ("in it ")
            ans, valb_1, valb_2, num_bytes = disHereTiny(
                data[start + t : start + t + 5]
            )
        else:
            # print ("not in it")
            ans, valb_1, valb_2, num_bytes = disHereTiny(
                data[start + t : start + t + 2]
            )

        # print (ans, valb_1, valb_2)
        # print ("ans:",ans)
        if valb_1 == "jmp":
            # print ("checking short jump")
            modifysByRange(data, start + t, start + t + num_bytes, "i")
            if "ff" in valb_2:
                # print ("has  ff")
                signedNeg = signedNegHexTo(int(valb_2, 16))
                # print ("signedNeg", signedNeg)
                valb_2 = str(hex(signedNeg))
            destination = (start + t) + int(valb_2, 16)
            # print("eb destination: " + str(hex(destination)))
            if str(hex(destination)) not in labels:
                labels.add(str(hex(destination)))
                # print  ("3 appending label " + str(hex(destination)))

            if str(hex(destination)) not in searchFor:
                searchFor.append(str(hex(destination)))
    # FINE, IT IS NEGATIVE
    if test == ord(OP_SHORT_JUMP_NEG):
        # print("FOUND 0xe9!")
        if b"\xff" in data[start + t : start + t + 5]:
            # print ("in it ")
            ans, valb_1, valb_2, num_bytes = disHereTiny(
                data[start + t : start + t + 5]
            )
        else:
            # print ("not in it")
            ans, valb_1, valb_2, num_bytes = disHereTiny(
                data[start + t : start + t + 2]
            )

        # print (ans, valb_1, valb_2)
        # print ("ans:",ans)
        if valb_1 == "jmp":
            modifysByRange(data, start + t, start + t + num_bytes, "i")
            if "ff" in valb_2:
                # print ("has  ff")
                signedNeg = signedNegHexTo(int(valb_2, 16))
                # print ("signedNeg", signedNeg)
                valb_2 = str(hex(signedNeg))
            # print ("checking short jump negative")
            destination = (start + t) + int(valb_2, 16)
            # print("neg e9 destination: " + str(hex(destination)))
            if str(hex(destination)) not in labels:
                labels.add(str(hex(destination)))
                # print  ("4 appending label " + str(hex(destination)))

            if str(hex(destination)) not in searchFor:
                searchFor.append(str(hex(destination)))

    t += 1
    for addy in searchFor:
        if int(addy, 16) in offsets:
            dprint2("In offsets")
        else:
            dprint2("Not in offsets")
            dprint2("addy", addy)
            offsets.add(int(addy, 16))
            removeBadOffsets(addy)
            # print (type(each))
            modifysByRange(data, int(addy, 16) - 1, int(addy, 16), "d")


def disHereShellLimited(data, offset):  # current good 1/8/2022
    bprint("disHereShellLimited!!!!!!!!!!!")
    # bprint ("------------dshell", len(data),hex(offset))
    # global labels
    # global offsets
    # global off_Label
    # global off_PossibleBad
    # global bit32
    # global o

    disHereShell_start = time.time()

    # printAllsByRange(offset,end)
    # dprint2 ("dis: dishereshell - range  "  + str(hex(offset)) + " " + str(hex(end)))
    # dprint2(binaryToStr(data[offset:end]))
    # dprint2(binaryToStr(data))
    callCS = cs
    if bit32:
        callCS = cs
    else:
        callCS = cs64
    callCS.skipdata = True
    callCS.skipdata_setup = ("db", None, None)
    CODED2 = data
    val = ""
    # start = time.time()

    # start = time.time()
    # for i in callCS.disasm(CODED2, offset):
    # 	offsets.add((int(i.address)))
    # 	if re.match( r'\bcall\b|\bjmp\b|\bje\b|\bjne\b|\bja\b|\bjg\b|\bjge\b|\bjl\b|\bjle\b|\bjb\b|\bjbe\b|\bjo\b|\bjno\b|\bjz\b|\bjnz\b|\bjs\b|\bjns\b|\bjcxz\b|\bjrcxz\b|\bjecxz\b|\bloop\b|\bloopcc\b|\bloope\b|\bloopne\b|\bloopnz\b|\bloopz\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjna\b|\bjnbe\b|\bjnge\b|\bjnl\b|\bjng\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b', i.mnemonic, re.M|re.I):
    # 		val=i.op_str
    # 		if re.match( "^[0-9][x]*[A-Fa-f0-9 -]*",val, re.M|re.I):
    # 			if "x" not in val:
    # 				val="0x"+val
    # 			labels.add(val)
    # 			off_Label.add(int(i.op_str, 16))
    # 			if int(i.op_str, 16) not in offsets:
    # 				off_PossibleBad.add(i.op_str)
    # end= time.time()
    # print("\t\t[-] loop 1 ", end-start)
    # start = time.time()

    sizeShell = len(CODED2)
    for i in callCS.disasm(CODED2, offset):
        # val_b, num_bytes =checkForValidAddress2(hex(int(i.address)),i.mnemonic, i.op_str, sizeShell, off_PossibleBad,data,i.size)
        addDis(i.address, i.mnemonic + " " + i.op_str, i.mnemonic, i.op_str, "limited")
    # print("\t\t[-] loop 5 ", end-start)
    # disHereShell_end = time.time()
    # print ("\t[*]disHereShell:", disHereShell_end- disHereShell_start)
    return ""


def disHereShell(
    data, offset, end, mode, CheckingForDB, bit, caller=None
):  # current good 1/8/2022
    bprint("------------dshell", len(data), hex(offset), hex(end), "caller: ", caller)
    global labels
    global offsets
    global off_Label
    global off_PossibleBad
    global bit32
    global o

    disHereShell_start = time.time()

    # printAllsByRange(offset,end)
    # dprint2 ("dis: dishereshell - range  "  + str(hex(offset)) + " " + str(hex(end)))
    # dprint2(binaryToStr(data[offset:end]))
    # dprint2(binaryToStr(data))
    callCS = cs
    if bit32:
        callCS = cs
    else:
        callCS = cs64
    callCS.skipdata = True
    callCS.skipdata_setup = ("db", None, None)
    CODED2 = data[offset:end]
    val = ""
    start = time.time()

    start = time.time()
    for i in callCS.disasm(CODED2, offset):
        offsets.add((int(i.address)))
        if re.match(
            r"\bcall\b|\bjmp\b|\bje\b|\bjne\b|\bja\b|\bjg\b|\bjge\b|\bjl\b|\bjle\b|\bjb\b|\bjbe\b|\bjo\b|\bjno\b|\bjz\b|\bjnz\b|\bjs\b|\bjns\b|\bjcxz\b|\bjrcxz\b|\bjecxz\b|\bloop\b|\bloopcc\b|\bloope\b|\bloopne\b|\bloopnz\b|\bloopz\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjna\b|\bjnbe\b|\bjnge\b|\bjnl\b|\bjng\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b",
            i.mnemonic,
            re.M | re.I,
        ):
            val = i.op_str
            if re.match("^[0-9][x]*[A-Fa-f0-9 -]*", val, re.M | re.I):
                if "x" not in val:
                    val = "0x" + val
                labels.add(val)
                off_Label.add(int(i.op_str, 16))
                if int(i.op_str, 16) not in offsets:
                    off_PossibleBad.add(i.op_str)
    end = time.time()
    # print("\t\t[-] loop 1 ", end-start)
    start = time.time()

    sizeShell = len(CODED2)
    for i in callCS.disasm(CODED2, offset):
        val_b, num_bytes = checkForValidAddress2(
            hex(int(i.address)),
            i.mnemonic,
            i.op_str,
            sizeShell,
            off_PossibleBad,
            data,
            i.size,
        )
        addDis(i.address, i.mnemonic + " " + i.op_str, i.mnemonic, i.op_str, "main5")
    end = time.time()
    # print("\t\t[-] loop 5 ", end-start)
    disHereShell_end = time.time()
    # print ("\t[*]disHereShell:", disHereShell_end- disHereShell_start)
    return ""


def disHereAnalysis(data, offset, end, mode, CheckingForDB):  #
    bprint("------------dAnalysis", len(data), hex(offset), hex(end))
    global offsets
    global off_PossibleBad
    # dprint2 ("disHereAnalysis - range  "  + str(offset) + " " + str(end))
    global o
    CODED3 = data[offset:end]
    sizeShell = len(CODED3)

    t = 0
    for i in cs.disasm(CODED3, offset):
        offsets.add((int(i.address)))
        # print ("dAnalysis, i.address", i.address, hex(i.address))
        # if fRaw.status() and fRaw.bytesInst[i.address]=="INST":
        # 	print ("skipping")
        val_a = hex(int(i.address))  # "\t"#\t"
        val_b1 = i.mnemonic
        val_b2 = i.op_str
        val_b, num_bytes = checkForValidAddress2(
            val_a, val_b1, val_b2, sizeShell, off_PossibleBad, data, i.size
        )
        t += 1


# urnString
def disHereTiny(data):  #
    address = 0
    i = 0
    CODED2 = data
    val = ""
    val2 = []
    val3 = []
    val5 = []
    dprint2("disheretiny")
    binStr = binaryToStr(data)
    dprint2(binStr)
    first_val_b = ""
    first_val_b1 = ""
    first_val_b2 = ""
    first = True
    second = 0
    num_bytesLine1 = 0
    nop = "90"
    nop1 = fromhexToBytes(nop)
    dprint2(binaryToStr(nop1))
    for i in cs.disasm(CODED2 + nop1, address):
        add = hex(int(i.address))
        addb = hex(int(i.address))
        add2 = str(add)
        add3 = 0
        add4 = str(add3)
        val_a = addb  # "\t"#\t"
        val_b = i.mnemonic + " " + i.op_str
        val_b1 = i.mnemonic
        val_b2 = i.op_str
        num_bytes = 0
        val2.append(val)
        val3.append(add2)
        val5.append(val_b)
        if first:
            first = False
            first_val_b = val_b
            first_val_b1 = val_b1
            first_val_b2 = val_b2
        second += 1
        if second == 2:
            num_bytesLine1 = int(i.address)
            dprint2("num_bytes", num_bytesLine1)
    if num_bytesLine1 == 0:
        pass
    returnString = ""
    for y in val5:
        returnString += y + "\n"
    dprint2("\n")
    dprint2(returnString + "rs\n")
    return first_val_b, first_val_b1, first_val_b2, num_bytesLine1


def modifysByRange(data, start, end, dataType, mode=None):  # 1/8/2002
    bprint("modRange modifysByRange", hex(start), hex(end), dataType, mode)
    # print ("modRange modifysByRange", hex(start),hex(end),dataType, mode)

    global sBy
    BytesBool = False
    t = 0
    if dataType == "d":
        BytesBool = False
    if dataType == "i":
        BytesBool = True

    if dataType == "d":
        pass
        # dprint2 ("magic")
        # out=disHereCheck(data[start:end])
        # dprint2(out)
    for x in sBy.bytesType:
        if (t >= start) and (t < end):
            # print ("before", sBy.bytesType[t])
            sBy.bytesType[t] = BytesBool
            #
            # print("changing value @ " + str(hex(t)), "\t\t")
            # print (sBy.bytesType[t], " value: ", hex(sBy.values[t]))
            if BytesBool:
                sBy.boolspecial[t] = False
        t += 1

    if mode == "findAna":
        patternMatch = b"\x00"
        ###### special check to make sure it doesn't overwrite jmps/calls
        if b"\xeb" in data[end - 4 : end] and BytesBool == False:
            patternMatch = b"\xeb"
        elif b"\xe9" in data[end - 4 : end] and BytesBool == False:
            patternMatch = b"\xe9"
        else:
            return
        # print ("found an eb!!!", BytesBool)
        start1 = 0
        result1 = 0
        while True:
            start1 = data[end - 4 : end].find(patternMatch, start1)

            if start1 != -1:
                # print ("got a start", start1, hex(end-start1))
                result1 = end - start1
            if start1 == -1:
                break
            else:
                start1 += len(patternMatch)
        # print ("res", hex(result1))
        t = result1
        for x in sBy.bytesType[result1:end]:
            # if (t>=start) and (t < end):
            # print ("before", sBy.bytesType[t])
            sBy.bytesType[t] = True
            # print("Special: changing value @ " + str(hex(t)))
            # print (sBy.bytesType[t], " value: ", hex(sBy.values[t]))
            t += 1


def modifysBySpecial(data, start, end, dataType, caller):
    bprint("modRangeSpecial ", hex(start), hex(end), dataType, caller)
    global sBy
    BytesBool = False
    t = 0
    spec = ""
    if dataType == "al":
        spec = "align"
    if dataType == "ff":
        spec = "ff"

    for x in sBy.bytesType:
        if (t >= start) and (t < end):
            if sBy.ApiTable[t] == False:
                # print ("before", sBy.specialVal[t])
                sBy.specialVal[t] = spec
                sBy.specialStart[t] = start
                sBy.specialEnd[t] = end
                sBy.boolspecial[t] = True
                # print("changing value align @ " + str(hex(t)))
                # print (sBy.specialVal[t], " value: ", hex(sBy.values[t]))
                # print(sBy.boolspecial[t], hex(sBy.specialStart[t]), hex(sBy.specialEnd[t]) )
        t += 1

    # dprint2 (sBy.bytesType)


def modifyStringsRange(start, end, dataType, word):
    dprint2("modStrings ")
    dprint2(hex(start), hex(end), dataType)
    global sBy
    BytesBool = False
    t = 0
    if dataType == "ns":
        BytesBool = False
    if dataType == "s":
        BytesBool = True
    for x in sBy.bytesType:
        if (t >= start) and (t < end):
            # dprint2 (sBy.strings[t])
            sBy.strings[t] = BytesBool
            sBy.stringsStart[t] = tuple((start, end - start))
            sBy.stringsValue[t] = word
            dprint2("changing Strings value @ " + str(hex(t)))
            dprint2(sBy.strings[t], " value: ", hex(sBy.values[t]))
            dprint2(hex(t))
            # dprint2 (sBy.stringsValue[t])

            # dprint2 (hex(sBy.stringsStart[t]), " value: ", hex(sBy.values[t]))
            x, y = sBy.stringsStart[t]
            dprint2(x, y)
        t += 1
    # dprint2 (sBy.bytesType)


def modifyPushStringsRange(start, end, dataType, word):
    dprint2("modStringPush ")
    # dprint2 (hex(start),hex(end),datfaType)
    global sBy
    BytesBool = False
    t = 0
    if dataType == "ns":
        BytesBool = False
    if dataType == "s":
        BytesBool = True
    for x in sBy.bytesType:
        if (t >= start) and (t < end):
            # dprint2 (sBy.strings[t])
            sBy.strings[t] = False
            sBy.stringsStart[t] = tuple((0, 0))
            sBy.stringsValue[t] = ""
            sBy.pushStringEnd[t] = end
            sBy.pushStringValue[t] = word
            sBy.boolPushString[t] = BytesBool
            dprint2("changing StringsPush value @ " + str(hex(t)))

            dprint2(sBy.boolPushString[t], " value: ", hex(sBy.values[t]))
            dprint2("end", sBy.pushStringEnd[t])
            dprint2(hex(t))
            # dprint2 (sBy.stringsValue[t])

            # dprint2 (hex(sBy.stringsStart[t]), " value: ", hex(sBy.values[t]))
            x, y = sBy.stringsStart[t]
            dprint2(x, y)
        t += 1
    # dprint2 (sBy.bytesType)


def modifyAPIRange(start, end, word):
    bprint("modifyAPIRange ", word)
    # dprint2 (hex(start),hex(end),datfaType)
    global sBy
    t = 0
    # 	self.ApiTable =[]
    # self.ApiStart=[]
    # self.ApiEnd=[]
    # self.ApiValue=[]
    for x in sBy.bytesType:
        if (t >= start) and (t < end):
            # print ("t value", t, "size of ApiTable", len(sBy.ApiTable), len(sBy.ApiStart), len(sBy.ApiValue), len(sBy.ApiEnd) )
            sBy.ApiTable[t] = True
            sBy.ApiStart[t] = start
            sBy.ApiValue[t] = word
            sBy.ApiEnd[t] = end

            # sBy.specialVal[t]=""
            # sBy.specialStart[t]=0
            # sBy.specialEnd[t]=0
            # sBy.boolspecial[t]=False
            # print("changing APITable value @ " + str(hex(t)))
            # print (sBy.ApiTable[t], " value: ", hex(sBy.values[t]))
            # print(sBy.ApiValue[t], sBy.ApiEnd[t])
            # print ("boolspecial", sBy.boolspecial[t])
        t += 1
    t = 0


printOnce = False


def preSyscalDiscovery(
    startingAddress,
    targetAddress,
    linesGoBack,
    variables,
    module,
    shellcode_label,
    caller=None,
):
    global shellSizeLimit
    global printOnce
    global codeCoverageComplete
    shellBytes = module[shellcode_label].rawData2
    silent = None
    if not variables.moduleBooleans[shellcode_label].bPreSysDisDone:
        clearDisassemblyBytesClass()

    bprint("preSyscalDiscovery function", caller)
    shellSize = len(shellBytes) / 1000
    if (
        shellSize > 120  or
         variables.moduleBooleans[shellcode_label].ignoreDisDiscovery
    ):
        if not printOnce:
            print(
                constants.RED
                + "\n\t[*]This shellcode size is large. Output will be generated in a different way."
                + constants.RESET
            )
            print("\t[*]Shellcode size: ", shellSize)
            printOnce = True
        return False, [], [], [], []

    # print ("preSyscalDiscovery size2", shellSize )
    global sBy
    global shellEntry

    takeBytesS = time.time()

    startingAddress = 0
    i = startingAddress
    if not variables.moduleBooleans[shellcode_label].bPreSysDisDone:
        for x in shellBytes:
            sBy.offsets.append(i)
            sBy.values.append(x)
            sBy.bytesType.append(True)  # True = instructions
            sBy.strings.append(False)
            sBy.stringsStart.append(0xFFFFFFFF)
            sBy.stringsValue.append("")
            sBy.pushStringEnd.append(-1)
            sBy.pushStringValue.append("")
            sBy.boolPushString.append(False)
            sBy.specialVal.append("")
            sBy.boolspecial.append(False)
            sBy.specialStart.append(0)
            sBy.specialEnd.append(0)
            sBy.comments.append("")
            sBy.ApiTable.append(False)
            sBy.ApiStart.append(0xFFFFFFFD)
            sBy.ApiEnd.append(0xFFFFFFFD)
            sBy.ApiValue.append("")
            sBy.dataAccessed.append(False)
            sBy.dataAccessedSize.append(None)
            i += 1

    start = time.time()
    if (
        variables.moduleBooleans[shellcode_label].bDoFindStrings
        and not variables.moduleBooleans[shellcode_label].bPreSysDisDone
    ):
        # import sharem
        dprint4("\nfinding strings")
        findStrings(shellBytes, 3)
        findStringsWide(shellBytes, 3)
        findPushAsciiMixed(shellBytes, 3)
        dprint4("\nfound strings")

    end = time.time()
    bprint("\n[*] Find strings", end - start)

    start = time.time()
    anaFindAPIs()

    anaFindFF(shellBytes, "preSyscalDiscover")
    # addComments()
    end = time.time()
    bprint("\n[*] anaFindFF", end - start)

    if not variables.moduleBooleans[shellcode_label].bPreSysDisDone:
        start = time.time()
        out = findRange(
            shellBytes, startingAddress, len(sBy.offsets) - 1, variables, module, shellcode_label, "takeBytes"
        )  # 1st time helps do corrections
        end = time.time()
        bprint("\n[*] findrange #1", end - start)

        anaFindAPIs()
        if not codeCoverageComplete:
            # if 1==1:
            anaFindFF(shellBytes, "preSyscalDiscover")

        start2 = time.time()
        if not codeCoverageComplete:
            # if 1==1:
            clearTempDis()  # we must call this function before making new diassembly
            out2 = findRange(
                shellBytes, startingAddress, len(sBy.offsets) - 1, variables, module, shellcode_label, "takeBytes"
            )  # makes sure all corrections fully implemented # this creates final disassembly
        end = time.time()
        bprint("\n\t[*] findrange 2", end - start2)
        variables.moduleBooleans[shellcode_label].bPreSysDisDone = True

    bprint("\n\t[*] Presyscall TakeBytes:", end - takeBytesS)
    disassembly, disassemblyC = createDisassemblyLists(variables, module, shellcode_label, caller="preSyscalDiscovery")
    t = 0
    assembly = binaryToText(
        shellBytes
    )  # this creates the string literal, raw hex, etc.
    tl1 = sBy.shAddresses
    tl2 = sBy.shDisassemblyLine

    if len(tl1) > 0:
        return True, tl1, tl2, tl1, tl2
    else:
        return False, tl1, tl2, tl1, tl2
    return truth, tl1, tl2, l1, l2


codeCoverageComplete = False


def takeBytes(
    shellBytes,
    startingAddress,
    variables,
    module,
    shellcode_label,
    silent=None,
    decoder=False,
):
    # print ("take bytes")
    # print ("---------->o", o)

    global sBy
    global shellEntry
    global gDisassemblyText
    global gDisassemblyTextNoC
    global codeCoverageComplete
    takeBytesS = time.time()
    startingAddress = 0
    i = startingAddress

    tooBig = False
    shellSize = len(shellBytes) / 1000
    if (
        shellSize > shellSizeLimit
        or variables.moduleBooleans[shellcode_label].ignoreDisDiscovery
    ):
        tooBig = True
        print("\n\t[*]Generating a simpler disassembly -- file size too big.")
    if not variables.moduleBooleans[shellcode_label].bPreSysDisDone:
        clearDisassemblyBytesClass()

        for x in shellBytes:
            sBy.offsets.append(i)
            sBy.values.append(x)
            # sBy.instructions.append(True)
            # sBy.data.append(False)
            sBy.bytesType.append(True)  # True = instructions
            sBy.strings.append(False)
            sBy.stringsStart.append(0xFFFFFFFF)
            sBy.stringsValue.append("")
            sBy.pushStringEnd.append(-1)
            sBy.pushStringValue.append("")
            sBy.boolPushString.append(False)
            sBy.specialVal.append("")
            sBy.boolspecial.append(False)
            sBy.specialStart.append(0)
            sBy.specialEnd.append(0)
            sBy.comments.append("")
            sBy.ApiTable.append(False)
            sBy.ApiStart.append(0xFFFFFFFD)
            sBy.ApiEnd.append(0xFFFFFFFD)
            sBy.ApiValue.append("")
            sBy.dataAccessed.append(False)
            sBy.dataAccessedSize.append(None)
            i += 1

        if not tooBig:
            start = time.time()
            if variables.moduleBooleans[shellcode_label].bDoFindStrings:
                dprint4("\nfinding strings")
                findStrings(shellBytes, 3)
                findStringsWide(shellBytes, 3)
                findPushAsciiMixed(shellBytes, 3)
                dprint4("\nfound strings")

            end = time.time()
            bprint("\n[*] Find strings", end - start)

            start = time.time()
            anaFindAPIs()
            if not codeCoverageComplete:
                anaFindFF(shellBytes, "takeBytes1")

            # addComments()
            end = time.time()
            bprint("\n[*] anaFindFF", end - start)

            start = time.time()
            out = findRange(
                shellBytes, startingAddress, len(sBy.offsets) - 1, "takeBytes"
            )  # 1st time helps do corrections
            end = time.time()
            bprint("\n[*] findrange #1b", end - start)

            anaFindAPIs()
            if not codeCoverageComplete:
                anaFindFF(shellBytes, "takeBytes2")

            start2 = time.time()
            if not codeCoverageComplete:
                clearTempDis()  # we must call this function before making new diassembly
                out2 = findRange(
                    shellBytes, startingAddress, len(sBy.offsets) - 1, "takeBytes"
                )  # makes sure all corrections fully implemented # this creates final disassembly
            end = time.time()
            bprint("\n\t[*] findrange 2b", end - start2)

            bprint("\n\t[*] TakeBytes:", end - takeBytesS)
        elif tooBig:
            disHereShellLimited(shellBytes, startingAddress)

    disassembly, disassemblyC = createDisassemblyLists(
        variables, module, shellcode_label, caller="final", decoder=decoder
    )

    gDisassemblyTextNoC = disassembly
    gDisassemblyText = disassemblyC

    if silent != "silent":
        if len(module[shellcode_label].rawData2) / 1000 < 15:
            print(gDisassemblyText)
        else:
            print("\n\t[*]Disassembly is too large to print to screen.	")
    t = 0

    assembly = binaryToText(
        shellBytes
    )  # this creates the string literal, raw hex, etc.

    return disassemblyC, disassembly, assembly


def findPattern():
    asci = ""
    uni = ""
    maxPattLen = 10
    count = {""}
    # regExp = '(Lu2)|(Ku2)'
    # regExp = '(Ku2|Nu2|Ju2|Gu|Ku1|Nu1|Mu1|([a-zA-Z]?:?\\.*\\?)|intel)'
    regExp1 = "([a-z]?[A-Z][a-zA-Z0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"  # weird pattern Ku2.5.29.5,  Mu1.2.840.113549.3.7
    regExp2 = "([a-zA-Z]?:?[a-zA-Z0-9]+?\\.*\\?)"  # win path --> C:\Users\win7\AppData, C:\Program Files\Python36-32
    regExp3 = "([a-zA-Z0-9_\*\-\+]+=[a-zA-Z0-9]+)"  # assignments PATHEXT=COM;EXE;BAT, CommonProgramFiles=C:\Program
    regExp4 = "([a-z]{2}\-[A-Z]{2})"  # en-UK, ro-RO

    allRegEx = "([a-z]?[A-Z][a-zA-Z0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)|([a-zA-Z]?:?[a-zA-Z0-9]+?\\.*\\?)|([a-zA-Z0-9_\*\-\+]+=[a-zA-Z0-9]+)|([a-z]{2}\-[A-Z]{2})"
    dottedRe = 0
    pathRe = 0
    assignRe = 0
    lanRe = 0
    for x, y, z in stringsTemp:
        if re.match(allRegEx, x, re.IGNORECASE):
            if re.match(regExp1, x, re.IGNORECASE):
                dottedRe += 1
            elif re.match(regExp2, x, re.IGNORECASE):
                pathRe += 1
            elif re.match(regExp3, x, re.IGNORECASE):
                assignRe += 1
            elif re.match(regExp4, x, re.IGNORECASE):
                lanRe += 1

    return (dottedRe, pathRe, assignRe, lanRe)


def checkZeroes(data: bytes, maxZeros: int) -> tuple[bool, int]:
    """Count number of zeros in data."""
    count = 0
    for i in data:
        if i == 0:
            count += 1
    return (count >= maxZeros, count)


def isShellcode(mBoolObj, patterns, shell_code, conr: Configuration):
    p_patt, l_patt, d_w_patt, v_patt = patterns.getPatterns()

    p = mBoolObj.bPEBFound
    f = mBoolObj.bFstenvFound
    s = mBoolObj.bSyscallFound
    c = mBoolObj.bCallPopFound
    h = mBoolObj.bHeavenFound
    st = mBoolObj.bStringsFound
    l = loggedList

    dottedRe, pathRe, assignRe, lanRe = findPattern()

    classTxt = "Possibly encoded shellcode."
    reasonTxt = ""

    if l:
        classTxt = "Very likely shellcode."
        reasonTxt = "Found shellcode APIs."

    elif p:
        classTxt = "Likely shellcode."
        reasonTxt = "Found PEB walking."

    elif f or c or s or h:
        # input("here")
        if f:
            reasonTxt = "Found fstenv instructions."
        if c:
            reasonTxt = "Found callpop instructions."
        if s:
            reasonTxt = "Found syscall instructions."
        if h:
            reasonTxt = "Found heaven's gate instructions."

        classTxt = "Some shellcode characteristics."

    else:
        # input("here2")
        classTxt = "Possibly encoded shellcode."

    stub = False
    if st and not l and not p:
        if stringsTemp:
            for x, y, z in stringsTemp:
                tmp = x.lower()
                regEx = "this.*(program)?.*(DOS|run|OS|32|16|NT|PE|dynamic|95|executable|windows|requires).*"
                reFound = re.search(regEx, tmp)
                if reFound:
                    dos = x.lower()
                    if dos[-1] == "." or dos[-1] == "$":
                        dos = dos[:-1]
                    if dos in constants.DOS_PATTERNS:
                        classTxt = "Not shellcode."
                        reasonTxt = "DOS stub pattern found."
                        stub = True
                        break

    zeroes = checkZeroes(shell_code.rawData2, int(conr.search_max_num_of_zeroes))
    if zeroes[0] and not stub and not l:
        classTxt = "Not shellcode."
        reasonTxt = "Excessive amount of contiguous zeroes ({}).".format(zeroes[1])
    elif zeroes[0] and stub and not l:
        classTxt = "Not shellcode."
        reasonTxt = "DOS stub pattern found."
        reasonTxt += "Excessive amount of contiguous zeroes ({}).".format(zeroes[1])

    # dottedRe, pathRe, assignRe, lanRe
    if dottedRe > d_w_patt:
        classTxt = "Not shellcode."
        reasonTxt += (
            "\n\t Excessive amount of patterns found ({}), e.g. Ku2.5.29.5.".format(
                dottedRe
            )
        )
    if pathRe > p_patt:
        classTxt = "Not shellcode."
        reasonTxt += "\n\t Excessive amount of system paths found ({}).".format(pathRe)
    if assignRe > v_patt:
        classTxt = "Not shellcode."
        reasonTxt += "\n\t Excessive amount of variable assignments found ({}).".format(
            assignRe
        )
    if lanRe > l_patt:
        classTxt = "Not shellcode."
        reasonTxt += (
            "\n\t Excessive amount of langauge / country codes found ({}).".format(
                lanRe
            )
        )

    return classTxt, reasonTxt


def regenerateDisassemblyForPrint():
    global gDisassemblyText
    global gDisassemblyTextNoC

    disassembly, disassemblyC = createDisassemblyLists(caller="final")
    gDisassemblyText = disassemblyC
    gDisassemblyTextNoC = disassembly


commentsGiven = False


def addComments(variables, module, shellcode_label):
    global commentsGiven
    global sBy

    for each in logged_syscalls:
        # print (each)
        params = constants.MAGENTA + "(" + constants.RESET
        api = each[0]
        vals = each[4]
        limit = len(vals) - 1
        t = 0
        for v in vals:
            try:
                v = constants.BLUE + v
            except:
                try:
                    v = constants.BLUE + hex(v)
                except:
                    if isinstance(v, tuple):
                        v = v[3]
                        v = constants.BLUE + v
            if t != limit:
                params += v + constants.MAGENTA + ", " + constants.RESET
            else:
                params += v
            t += 1

        params += constants.MAGENTA + ")" + constants.RESET
        apiAddress = int(each[1], 16)
        apiAddress = apiAddress - CODE_ADDR
        if commentsGiven:
            params = ""
        if not commentsGiven:
            space1 = "      "
            try:
                if sBy.comments[apiAddress] != "":
                    sBy.comments[apiAddress] += res + "\n      " + params
                else:
                    try:
                        params = textwrap3.fill(
                            params,
                            width=105,
                            initial_indent="",
                            subsequent_indent="       ",
                        )
                        pass
                    except:
                        pass
                    sBy.comments[apiAddress] = (
                        constants.MAGENTA
                        + "; Windows syscall: "
                        + api
                        + constants.RESET
                        + "\n      "
                        + params
                    )

            except:
                print("error logging API address to disassembly - ", api)
    for each in loggedList:
        params = constants.MAGENTA + "(" + constants.RESET
        api = each[0]
        vals = each[4]
        limit = len(vals) - 1
        t = 0
        for v in vals:
            try:
                v = constants.BLUE + v
            except:
                try:
                    v = constants.BLUE + hex(v)
                except:
                    if isinstance(v, tuple):
                        v = v[3]
                        v = constants.BLUE + v
            if t != limit:
                params += v + constants.MAGENTA + ", " + constants.RESET
            else:
                params += v
            t += 1

        params += constants.MAGENTA + ")" + constants.RESET

        apiAddress = int(each[1], 16)
        apiAddress = apiAddress - CODE_ADDR
        if commentsGiven:
            params = ""
        if not commentsGiven:
            space1 = "      "
            try:
                if sBy.comments[apiAddress] != "":
                    sBy.comments[apiAddress] += res + "\n      " + params
                else:
                    try:
                        params = textwrap3.fill(
                            params,
                            width=105,
                            initial_indent="",
                            subsequent_indent="       ",
                        )
                        pass
                    except:
                        pass
                    sBy.comments[apiAddress] = (
                        constants.MAGENTA
                        + "; call to "
                        + api
                        + constants.RESET
                        + "\n      "
                        + params
                    )

            except:
                print("error logging API address to disassembly - ", api)
    commentsGiven = True
    comC = constants.MAGENTA
    for item in module[shellcode_label].save_PEB_info:
        tib = item[5]
        sBy.comments[int(tib, 16)] = comC + "; load TIB" + constants.RESET + ""
        ldr = item[6]
        sBy.comments[int(ldr, 16)] = (
            comC + "; load PEB_LDR_DATA LoaderData" + constants.RESET + ""
        )
        mods = item[7]
        modAdd = mods[0]
        modText = mods[1]
        if modAdd != -1:
            sBy.comments[int(modAdd, 16)] = comC + "; " + modText + constants.RESET + ""

        adv = item[8]
        for each in adv:
            try:
                if each != -1:
                    sBy.comments[int(each, 16)] = (
                        comC + "; advancing DLL flink" + constants.RESET + ""
                    )
            except:
                pass
    for item in module[shellcode_label].save_PushRet_info:
        push = item[5]
        pushOffset = push[0]
        pushReg = push[1]
        retOffset = item[6]
        sBy.comments[int(pushOffset, 0)] = (
            comC + "; pushing return address " + constants.RESET + ""
        )
        sBy.comments[int(retOffset, 0)] = (
            comC + "; returning to " + pushReg + constants.RESET + ""
        )

    for item in module[shellcode_label].save_Callpop_info:
        call_offset = item[0]
        pop_offset = item[5]
        sBy.comments[int(pop_offset, 16)] = comC + " ; GetPC" + constants.RESET + ""

    for item in module[shellcode_label].save_FSTENV_info:
        FPU_offset = item[5]
        FSTENV_offset = item[6]
        sBy.comments[int(FPU_offset, 16)] = (
            comC + " ; floating point to set up GetPC" + constants.RESET + ""
        )
        sBy.comments[int(FSTENV_offset, 16)] = comC + " ; GetPC" + constants.RESET + ""

    for item in module[shellcode_label].save_Heaven_info:
        heaven_offset = item[5]
        pushOffset = item[6]
        destLocation = item[7]
        sBy.comments[int(heaven_offset, 16)] = (
            comC + " ; invoking Heaven's Gate technique" + constants.RESET + ""
        )

        if hex(pushOffset) != "0xbaddbadd":
            try:
                sBy.comments[(pushOffset)] = (
                    comC
                    + " ; Heaven's gate destination address: "
                    + str(destLocation)
                    + constants.RESET
                    + ""
                )
            except:
                sBy.comments[int(pushOffset, 16)] = (
                    comC
                    + " ; Heaven's gate destination address: "
                    + str(destLocation)
                    + constants.RESET
                    + ""
                )
    for item in module[shellcode_label].save_Egg_info:
        eax = item[5]
        c0_offset = item[6]
        try:
            sBy.comments[int(c0_offset, 16)] = (
                comC
                + " ; Calling Windows syscall - value: "
                + eax
                + constants.RESET
                + ""
            )
        except:
            pass
    cur = sBy.comments[shellEntry]
    sBy.comments[shellEntry] = (
        comC
        + " ; ***Shellcode Entry Point, offset "
        + str(hex(shellEntry))
        + "***"
        + constants.RESET
        + ""
    )

    cur = sBy.comments[shellEntry - 1]

    try:
        dSEnd = sh.decoderStubEnd
        sBy.comments[dSEnd] = (
            comC
            + "; decoder stub end. Instructions below are deobfuscated."
            + constants.RESET
            + ""
        )

    except:
        pass


def findInList(listPeb, address):
    t = 0
    for x in listPeb:
        if listPeb[t] == address:
            # dprint2 ("found", t)
            return t, True
        t += 1
    return 0, False


# findrange


def anaFindAPIs():
    # print ("anaFindAPIs function")

    # for each in (fRaw.APIs):
    # 	print (each)

    apiLocs = []
    for each in fRaw.APIs:
        api = each[0]
        ansLE = each[1]
        apiSize = len(ansLE)
        funcName = each[2]
        locInMemory = each[3]
        if locInMemory != None:
            apiLocs.append(locInMemory)
            modifyAPIRange(locInMemory, locInMemory + apiSize, funcName)
            modifysByRange(
                m[o].rawData2, locInMemory, locInMemory + 4, "d", "anaFindAPIs"
            )
    try:
        locMin = min(apiLocs)
        locMax = max(apiLocs)

        # print ("locMin, locMax", locMin, locMax)
        # print (apiLocs)
        if locMin - locMax > 1:
            modifysByRange(m[o].rawData2, locMin, locMax, "d", "anaFindAPIs")
    except:
        pass


def findRange(data, startingAddress, end2, variables, module, shellcode_label, caller=None):
    # print ("findrange function")
    global codeCoverageComplete
    global bit32
    global sBy
    global shellEntry

    if bit32:
        bit = 32
    else:
        bit = 64
    current = 0

    start = startingAddress
    current = startingAddress
    max = len(sBy.bytesType) - 1
    dprint2("fr size: ", hex(max))
    finalPrint0 = ""

    dprint2("findRange start**", hex(startingAddress))
    distance = 0

    end = len(sBy.bytesType) - 1
    fr1 = time.time()

    anaFindAPIs()
    if not codeCoverageComplete:
        if (
            not variables.moduleBooleans[shellcode_label].disAnalysisDone
            and "preSyscalDiscovery" in caller
        ):
            # print ("inside disana")
            disHereAnalysis(data, startingAddress, end, "ascii", True)
            variables.moduleBooleans[shellcode_label].disAnalysisDone = True
        elif caller == "takeBytes":
            disHereAnalysis(data, startingAddress, end, "ascii", True)
    if codeCoverageComplete:
        print("codeCoverageComplete, skipping disHereAnalysis")
    fr_end = time.time()
    bprint("[*] disHereAnalysis", fr_end - fr1)

    fr1 = time.time()
    if not codeCoverageComplete:
        if (
            not variables.moduleBooleans[shellcode_label].bAnaConvertBytesDone
            and "preSyscalDiscovery" in caller
        ):
            analysisConvertBytes(data, startingAddress, variables, module, shellcode_label)
        elif caller == "takeBytes":
            analysisConvertBytes(data, startingAddress, variables, module, shellcode_label)
    if codeCoverageComplete:
        print("codeCoverageComplete, skipping analysisConvertBytes")
    fr_end = time.time()
    bprint("[*] analysisConvertBytes", fr_end - fr1)

    fr1 = time.time()
    if not codeCoverageComplete:
        if (
            not variables.moduleBooleans[shellcode_label].bAnaHiddenCallsDone
            and "preSyscalDiscovery" in caller
        ):
            analysisFindHiddenCalls(data, startingAddress, caller + " PS")
        elif (
            caller == "takeBytes" and variables.moduleBooleans[shellcode_label].bDoFindHiddenCalls
        ):
            analysisFindHiddenCalls(data, startingAddress, variables, module, shellcode_label, caller)
    else:
        print("codeCoverageComplete, skipping analysisFindHiddenCalls")

    fr_end = time.time()
    bprint("\n\t[*] analysisFindHiddenCalls", fr_end - fr1)

    fr12 = time.time()
    shellEntryPassed = False
    if (
        variables.moduleBooleans[shellcode_label].bDoFindStrings
        and not variables.moduleBooleans[shellcode_label].bAnaFindStrDone
    ):
        anaFindStrings(data, startingAddress, variables, module, shellcode_label)
    fr_end = time.time()
    bprint("\n\t[*] anaFindStrings", fr_end - fr12)

    finalPrint = ""

    s1 = time.time()
    s2 = time.time()
    inside_shell = s2 - s1
    inside_MakeDB = s2 - s1

    if fRaw.status():
        findDataBytesEmu(data)
    s1 = time.time()
    while current < max:
        start, current, distance, typeBytes, skipF = findRange2(current, variables, module, shellcode_label)
        if shellEntryPassed == False:
            if shellEntry != 0:
                if current > shellEntry - 1:
                    newDis = shellEntry - current - 1
                    current = shellEntry
                    distance = newDis
                    shellEntryPassed = True

                if current == shellEntry:
                    shellEntryPassed = True
        finalPrint0 = ""
        dprint2("findrange: max: " + str(hex(max)), "Current:  " + str(hex(current)))

        if max == current:
            current += 1

        if typeBytes:
            bprint("above is instructions")

            dShell = time.time()

            res = disHereShell(data, start, current, "ascii", True, bit, caller)
            dShellEnd = time.time()
            inside_shell += dShellEnd - dShell
            finalPrint0 += res
            dprint2("adding ", len(res), "total", len(finalPrint))
            dprint2(res)

        if not typeBytes:
            bprint("above is data")

            makeDB = time.time()

            res = disHereMakeDB2(data, start, current, "ascii", True)
            makeDBEnd = time.time()
            inside_MakeDB += makeDBEnd - makeDB
            finalPrint0 += res
            dprint2("adding ", len(res), "total", len(finalPrint))
            dprint2(res)

        finalPrint += finalPrint0
        dprint2("big ", len(finalPrint0), "total", len(finalPrint))

    fr_end = time.time()
    bprint("[*] inside dshell", inside_shell, caller)
    bprint("[*] inside makeDB", inside_MakeDB, caller)
    bprint("[*] big loop", fr_end - s1)

    return finalPrint


def getNextBool(pattern, test, current):
    # print ("getNextBool", pattern, type(pattern), "current", hex(current))
    global sBy
    test2 = 2
    bSkip = False
    # typeBytes=True
    try:
        # print ("test size", len(test))
        success = False
        try:
            found = test.index(pattern)
            success = True
        except:
            found = len(test) - 1
            success = False
        # print ("found1", found, "success", success, "pattern", pattern)
        if success and pattern == False:
            return found, False
        # if fRaw.status() and fRaw.bytesInst[current]=="INST":

        if pattern:
            seeking2 = "INST"
            seeking3 = None
            # typeBytes=True
        else:
            seeking2 = None
            seeking3 = "INST"
            # typeBytes=False

        if fRaw.status():
            # print ("fRaw.status()", fRaw.status())
            test2 = fRaw.bytesInst[current:]
            # try:
            # 	found2=test2.index(seeking2)s
            # 	print ("seeking2")

            # except:
            # 	# print ("got found2 error")
            # 	found2=test2.index(seeking3)
            # 	print ("seeking3")

            # print ("test2[current]", len(test2), hex(current))#, hex(found2))
            if test2[0] == "INST":
                try:
                    # if test2[current]=="INST":
                    test3 = fRaw.startEnd[current:]
                    # print ("checking sizes", len(fRaw.startEnd), len(fRaw.startEnd[current:]),len(fRaw.startEnd[current:]) + len(test3) )
                    startF, endF, distF = test3[current]
                    # print ("test3[found2]", test3[found2], "found2", found2)
                    # print ("fRaw INST2! startF", hex(startF), "endF", hex(endF), "distF", hex(distF))
                    newRet = startF - current
                    # print ("newRet", newRet)
                    found = newRet
                    bSkip = True
                    # typeBytes=True
                    # print ("fRaw status!", hex(startF), hex(endF), hex(distF))
                    # return	startF, endF, distF, True, True  # final True means skip static analysis disassembly
                    return found, bSkip

                except:
                    # print ("INST seeking error")
                    pass
            else:
                # print ("test3[found2] not INST")
                pass
    # except:
    except Exception as e:
        print("Exception, size", len(test))
        print(e)
        print(traceback.format_exc())
        print("test2", test2)

        found = len(sBy.bytesType) - 1
        # print ("sby.bytesType found", found)
        found = len(test) - 1
        # typeBytes=  sBy.bytesType[current]
        # print ("getNextBool error2 - test found", found)
        pass
    # print  ("*", hex(found))
    # print ("returning found", found)
    return found, bSkip


def findRange2(current, variables, module, shellcode_label):
    global sBy

    if fRaw.status() and fRaw.bytesInst[current] == "INST":
        try:
            startF, endF, distF = fRaw.startEnd[current]
            # print ("fRaw status!", hex(startF), hex(endF), hex(distF))
            if fRaw.status() and fRaw.bytesInst[current] == "INST":
                # print ("fRaw status!", hex(startF), hex(endF), hex(distF))
                return (
                    startF,
                    endF,
                    distF,
                    True,
                    True,
                )  # final True means skip static analysis disassembly
        except:
            print("error!!!!!!")

    initialBool = sBy.bytesType[current]
    seeking = False
    if not initialBool:
        seeking = True
    bSkip = False
    foundStop, bSkip = getNextBool(seeking, sBy.bytesType[current:], current)
    foundStop += current

    distance = foundStop - current
    if foundStop > len(module[shellcode_label].rawData2):
        foundStop = len(module[shellcode_label].rawData2) - 1

    return (
        current,
        foundStop,
        distance,
        initialBool,
        bSkip,
    )  # final False means do NOT skip static analysis disassembly


def anaFindStrings(data, startingAddress, variables, module, shellcode_label):
    global stringsTemp
    global stringsTempWide
    global pushStringsTemp
    global minStrLen
    global sBy

    OP_FF = b"\xff"
    variables.moduleBooleans[shellcode_label].bAnaFindStrDone = True

    for word, offset, distance in stringsTemp:  # and stringsTemp:
        dprint2("\t" + str(word) + "\t" + str(hex(offset)) + "\t" + str(hex(distance)))

        if goodString(data, word, 6):
            if fRaw.status():
                if fRaw.bytesInst[offset] != "INST":
                    # print ("making strings")
                    modifysByRange(
                        data, offset, offset + distance, "d", "anaFindStrings"
                    )
                    modifyStringsRange(offset, offset + distance, "s", word)
            else:
                modifysByRange(data, offset, offset + distance, "d", "anaFindStrings")
                modifyStringsRange(offset, offset + distance, "s", word)

            total = 0
            v = 1
            w = 0
            test = b"\xff"

    ##WIDE
    try:
        for word, offset, distance in stringsTempWide:  # and stringsTemp:
            if goodString(data, word, 6):
                modifysByRange(data, offset, offset + distance, "d", "anaFindStrings")
                modifyStringsRange(offset, offset + distance, "s", word)
                total = 0

    except Exception as e:
        print("Exception")
        print(e)
        print(traceback.format_exc())
        pass

    distance = 0

    # print ("bPushStackStrings")
    for word, offset, wordLength, instructionsLength in pushStringsTemp:
        distance = instructionsLength
        dprint2("instructionsLength", instructionsLength, type(instructionsLength))
        if goodString(data, word, 6):
            dprint2(
                "push mixed change",
                word,
                hex(offset),
                hex(offset + distance),
                hex(len(data)),
            )
            modifysByRange(
                data, offset - 2, offset + distance, "i", "anaFindStrings"
            )  # -2 is a correction
            modifyPushStringsRange(offset, offset + distance, "s", word)

def anaFindFF(data, caller):
    OP_FF = b"\xff"
    OP_00 = b"\x00"

    offset = 0
    maxV = len(data)
    escape = False
    while offset < maxV:
        escape = False
        total = 0
        total2 = 0
        v = 1
        w = 0
        vv = 1
        ww = 0
        distance = 0
        test = data[offset + distance + w : offset + distance + v]
        while test == OP_FF:
            test = data[offset + distance + w : offset + distance + v]
            test2 = data[offset + distance + w : offset + distance + v + 1]
            if test == (OP_FF) and (test2 not in FFInstructions):
                total += 1
                dprint2(
                    " OP_FF, total, gots one", total, hex(offset)
                )  # this just counts how many FF's there are that are not part of a more import instruciton'

            v += 1
            w += 1
            escape = True

        test = data[offset + distance + ww : offset + distance + vv]
        while test == OP_00:
            dprint2(
                "op_00",
                "ww",
                hex(w),
                "vv",
                hex(v),
                "offset",
                hex(offset + distance + ww),
            )
            dprint2(
                "2binaryToStrCheck",
                binaryToStr(data[offset + distance + ww : offset + distance + vv]),
            )
            test = data[offset + distance + ww : offset + distance + vv]
            if test == (OP_00):  # and (test2 not in FFInstructions):
                if sBy.ApiTable[offset + ww] == False:
                    total2 += 1
                else:
                    escape = True
                    break
                dprint2("total2", total2)
                dprint2(hex(offset), hex(offset + distance + ww))

            vv += 1
            ww += 1
            escape = True
        if total > 3:
            dprint2(total, "ffTotal2")
            modifysByRange(data, offset, offset + distance + total, "d", "anaFindFF")
            modifysBySpecial(data, offset, offset + distance + total, "ff", "ff1")
        if total2 > 3:
            modifysByRange(data, offset, offset + distance + total2, "d", "anaFindFF")
            modifysBySpecial(data, offset, offset + distance + total2, "al", "al1")
            checkForBad00(data, offset, offset + distance + total2)
        if escape:
            if total > 1 or total2 > 1:
                offset += total
                offset += total2
            else:
                offset += 1

        if not escape:
            offset += 1


def encodeShellcodeTesting(data, values):
    print("encodeShellcode")
    a = values[0]
    b = values[1]
    c = values[2]

    shells = ""
    data = bytearray(data)
    for i in range(len(data)):
        data[i] = (data[i] + a) & 255
        data[i] = (data[i] ^ b) & 255
        data[i] = (data[i] - c) & 255
    print("ENCODE BYTES")
    print(binaryToStr(data))
    return data


def encodeShellcode(data):
    print("encodeShellcode")

    # print (binaryToStr(m[o].rawData2))
    shells = ""
    for each in data:
        new = each ^ 0x3 & 255  # 3
        new = (new + 2) & 255  # 4
        new = new ^ 0x1 & 255  # 8
        # shells+=str(hex(new)) +" "

        if len(str(hex(new))) % 2 != 0:
            # print ("got one")
            new2 = str(hex(new))
            new2 = "0x0" + new2[2:]
            shells += new2 + " "
        else:
            shells += str(hex(new)) + " "
    shells = split0x(shells)
    # print(shells)
    shells = fromhexToBytes(shells)
    # print("ENCODE BYTES")
    print(binaryToStr(shells))
    return shells


def tohex(num, bits):
    v = hex((num + (1 << bits)) % (1 << bits))
    return int(v, 16)


def truncateTobyte(val):
    print("truncateTobyte", hex(val))
    if val > 255:  # and (val < 65536):  # WORD
        print("truncating")
        test = str(hex(val))
        if val < (0xFFF + 1):
            test = test[3:]
            return int(test, 16)
        elif (val > 0xFFF) and (val < (0xFFFF + 1)):
            test = test[4:]
            # print("g 4")
            return int(test, 16)
        elif (val > 0xFFFF) and (val < (0xFFFFF + 1)):
            test = test[5:]
            # print ("g 5")
            return int(test, 16)
        elif (val > 0xFFFFF) and (val < (0xFFFFFF + 1)):
            test = test[6:]
            # print("g 6")
            return int(test, 16)
        elif (val > 0xFFFFFF) and (val < (0xFFFFFFF + 1)):
            test = test[7:]
            # print("g 7")
            return int(test, 16)
        elif (val > 0xFFFFFFF) and (val < (0xFFFFFFFF + 1)):
            test = test[8:]
            # print("g 8")
            return int(test, 16)
        else:
            print("XOR value too large, error.")
            return None
    return val


def encodeShellcode2(data):
    print("encodeShellcode2")

    print(binaryToStr(m[o].rawData2))
    shells = ""

    encodeBytes = bytearray()
    for each in m[o].rawData2:
        new = each ^ 0x55
        print(1, hex(new), (hex(each), 0x55))
        print(2, hex(new))
        new = truncateTobyte(new)
        new = new ^ 0x11
        new = truncateTobyte(new)
        new = new
        print(3, hex(new))
        print(new, hex(new))
        encodeBytes.append(new)

        if len(str(hex(new))) % 2 != 0:
            print("got one")
            new2 = str(hex(new))
            new2 = "0x0" + new2[2:]
            shells += new2 + " "
        else:
            shells += str(hex(new)) + " "
    shells = split0x(shells)
    print(shells)
    shells = fromhexToBytes(shells)
    print(binaryToStr(shells))

    bytesStr = bytes(encodeBytes)
    print("\n\n\n\n\nencoder2 new", binaryToStr(bytesStr))
    return bytesStr


def decodeShellcode2(data):
    print("decodeShellcode2")
    shells = ""

    decodedBytes = bytearray()
    for each in data:
        new = each ^ 0x11
        new = truncateTobyte(new)
        new = new ^ 0x55
        new = truncateTobyte(new)
        print("cur", hex(new))
        decodedBytes.append(new)

        if len(str(hex(new))) % 2 != 0:
            print("got one")
            new2 = str(hex(new))
            new2 = "0x0" + new2[2:]
            shells += new2 + " "
        else:
            shells += str(hex(new)) + " "
    shells = split0x(shells)
    print(shells)
    shells = fromhexToBytes(shells)
    print("shells", binaryToStr(shells))

    bytesStr = bytes(decodedBytes)
    print("original", binaryToStr(data))
    print("\n\n\n\n\ndecoder2 new", binaryToStr(bytesStr))
    return bytesStr


def encodeShellcode3(data):
    print("encodeShellcode3")

    print(binaryToStr(m[o].rawData2))
    encodeBytes = bytearray()
    for each in m[o].rawData2:
        new = each
        new = tohex((new ^ 0x55), 8)
        new = tohex((new ^ 0x11), 8)
        new = tohex((new + 0x43), 8)
        new = tohex((~new), 8)
        new = tohex((new << 1), 8)
        encodeBytes.append(new)
    bytesStr = bytes(encodeBytes)
    print("\n\n\n\n\nencoder3 new", binaryToStr(bytesStr))
    print("old", binaryToStr(data))
    return bytesStr


def encodeShellcode3(data):
    print("encodeShellcode3")

    print(binaryToStr(m[o].rawData2))
    encodeBytes = bytearray()
    t = 0
    rawData3 = m[o].rawData2
    for each in rawData3:
        new = each
        new = tohex((new ^ 0x55), 8)
        new = tohex((new ^ 0x11), 8)
        new = tohex((new + 0x43), 8)
        new = tohex((~new), 8)
        new = tohex((new << 1), 8)
        # encodeBytes.append(new)
        rawData3[t] = new
        t += 1

    bytesStr = bytes(encodeBytes)
    print("\n\n\n\n\nencoder3 new", binaryToStr(bytesStr))
    print("old", binaryToStr(data))
    return bytesStr


def decodeShellcode(data):
    shells = ""
    for each in data:
        new = each ^ 0x11
        new = new - 1
        new = new ^ 0x55

        if len(str(hex(new))) % 2 != 0:
            print("got one")
            new2 = str(hex(new))
            new2 = "0x0" + new2[2:]
            shells += new2 + " "
        else:
            shells += str(hex(new)) + " "
    shells = split0x(shells)
    print(shells)
    shells = fromhexToBytes(shells)
    print(binaryToStr(shells))


def encodeShellcodeProto(target, XORval, addVAl, XORval2):
    print("encodeShellcode ", XORval, addVAl, XORval2)
    print(binaryToStr(target))
    shells = ""
    encodedBytes = bytearray()
    for each in target:
        ##XOR operation
        new = each ^ XORval
        new += addVAl
        new = new ^ XORval2

        if len(str(hex(new))) % 2 != 0:
            print("got one")
            new2 = str(hex(new))
            new2 = "0x0" + new2[2:]
            shells += new2 + " "
        else:
            shells += str(hex(new)) + " "
    shells = split0x(shells)
    print(shells)
    shells = fromhexToBytes(shells)
    print(binaryToStr(shells))
    print("new", binaryToStr(encodedBytes))
    return shells


def decodeShellcodeProto(target, XORval, addVAl, XORval2):
    print("decodeShellcode ", XORval, addVAl, XORval2)
    print(binaryToStr(target))
    shells = ""
    for each in target:
        ##XOR operation
        new = each ^ XORval2
        new -= addVAl
        new = new ^ XORval

        # FINAL PORTION

        if len(str(hex(new))) % 2 != 0:
            print("got one")
            new2 = str(hex(new))
            new2 = "0x0" + new2[2:]
            shells += new2 + " "
        else:
            shells += str(hex(new)) + " "
    shells = split0x(shells)
    print(shells)
    shells = fromhexToBytes(shells)
    print(binaryToStr(shells))
    return shells


def decodeShellcodeXOR(target, XORval):
    print("decodeShellcode ", XORval)
    print(binaryToStr(target))
    shells = ""
    for each in target:
        ##XOR operation
        new = each ^ XORval

        # FINAL PORTION

        if len(str(hex(new))) % 2 != 0:
            print("got one")
            new2 = str(hex(new))
            new2 = "0x0" + new2[2:]
            shells += new2 + " "
        else:
            shells += str(hex(new)) + " "
    shells = split0x(shells)
    print(shells)
    shells = fromhexToBytes(shells)
    print(binaryToStr(shells))
    return shells


##### START
def init2(
    filename: str,
    iat_list: list,
    pe_dlls: list,
    sections: list,
    my_bytes_list: list,
    rawHex: bool,
):
    if not rawHex:
        ObtainAndExtractSections(filename, iat_list, pe_dlls, sections, my_bytes_list)
    else:
        if filename[-3:] in (
            "txt",
            "bin",
        ):  # don't need to call readShellcode if it is a binary file
            rawData2 = readShellcode(filename)
    return rawData2


def saveBinAscii():
    global sharem_out_dir
    if sharem_out_dir == "current_dir":
        outDir = os.path.join(os.path.dirname(__file__), "sharem", "logs")
    else:
        outDir = sharem_out_dir
    if not rawHex:
        print("\nThis is for shellcode only.")
        return

    init2(filename)

    if filename == "":
        outfile = peName.split(".")[0]
        outfileName = peName
        if outfileName[-4] == ".":
            outfileName = outfileName[:-4]
    else:
        outfile = filename.split(".")[0]
        outfileName = filename
        if outfileName[-4] == ".":
            outfileName = outfileName[:-4]
    output_dir = os.getcwd()

    if sharem_out_dir == "current_dir":
        output_dir = os.path.join(os.path.dirname(__file__), "sharem", "logs")
    else:
        output_dir = sharem_out_dir

    binFileName = os.path.join(
        output_dir,
        outfileName.split("\\")[-1].strip(),
        outfileName.split("\\")[-1].strip() + "-raw.bin",
    )

    asciiFileName = os.path.join(
        output_dir,
        outfileName.split("\\")[-1].strip(),
        outfileName.split("\\")[-1].strip() + "-ascii.txt",
    )

    binsDir = os.path.join(outDir, filename[:-4], "bins")
    # directory = os.path.join(os.path.dirname(__file__), directory)
    # print (binaryToStr(m[o].rawData2))
    # print("Dir --> ",binsDir)
    # print(isDir(binsDir))
    if not os.path.isdir(binsDir):
        # print("Creating..")
        os.makedirs(binsDir)

    binasm2 = open(binFileName, "wb")
    binasm2.write(m["shellcode"].rawData2)
    binasm2.close()

    assembly = binaryToText(m[o].rawData2)
    asciiBin = open(asciiFileName, "w")
    asciiBin.write(assembly)
    asciiBin.close()
    print(
        constants.CYAN
        + " The shellcode has been saved both in binary and ASCII format:"
        + constants.RESET
    )
    print("   ", constants.GREEN + asciiFileName + constants.RESET)
    print("   ", constants.GREEN + binFileName + constants.RESET)

    #### if it was successfully deobfuscated

    if sh.decryptSuccess:
        binFileNameDecoded = os.path.join(
            output_dir, outfile, outfileName + "-decoded_body_raw.bin"
        )
        deobAsciiFileName = os.path.join(
            output_dir, outfile, outfileName + "-decoded_body_raw-ascii.txt"
        )

        assemblyD = binaryToText(sh.decodedFullBody)
        asciiDeobf = open(deobAsciiFileName, "w")
        asciiDeobf.write(assemblyD)
        asciiDeobf.close()

        binasm = open(binFileNameDecoded, "wb")
        binasm.write(sh.decodedFullBody)
        binasm.close()
        print("   ", constants.MAGENTA + binFileNameDecoded + constants.RESET)
        print("   ", constants.MAGENTA + deobAsciiFileName + constants.RESET)


# operations: enter as a list of characters EX: ["^", "+", "~"]
# findAll: whether or not to stop once a set of values works -- false stops after the first match
# distributed: toggle on distributed computing
# nodesFiles: txt file containing IPs for each node to be used for distributed computing
# cpuCount: auto to use max available, otherwise it can be limited
# outputFile: will spit out a file containing results
# fastMode: only check small portion of the shellcode for peb walking for efficiency. findAll disabled automatically for this one


# TODO:
# shellEntry
# clean up abc values DONE
# can print order as list, separate each DONE
# get name of file for the outputFile DONE
# output file true default(?)
# save peb offset DONE
# fix distance in callPopRawHex
# test inloadorder stuff DONE
# save peb list as tuple with offset then order of list DONE
# fix 64 bit savebasepebwalk and both versions of printsavedpeb
# save name of register for pushret, same thing w/ tuple DONE
# fix syscall saving fs:[0x30] in labelTest.bin --- should only be reg or 0xc0 DONE

# fstenv problem may have to do with - numopsback - back in str creation # DONE? ask tarek how many fstenv should be there.
# 		saves less than before but this is due to removing duplicates properly I think.
# 64 bit peb instr only print first line found
# no 64bit findallpeb # tarek should have this covered
# issue in uiDiscover w/ peb (see email) # fixed
# adjustable points in disherepeb # DONE
# fix 64 bit issue with peb --
# fix callpop issues # FIXED for .exe -- printing still odd? do we want pop spot or call spot? does it matter?
# bin issues still exist # DONE
# add support for int 0x2e and syscall instruction(?) DONE
# callpop should print starting at call and ending in pop # DONE
# fix weird issues in pushret -- dont save on retf, and push offset AFTER ret offset saving sometimes # FIXED these two issues -- still some odd printing
# fix extra printing
# in uidiscover -- findallpebseqold is still being used for shellcode -- why? fix for new one to work with both

# start printing at "address" in printsavedpushret() and have check for when to start
# check callpop print ending when using .exe and in diff sections - different sections still need to check
# check 64bit peb logic -- finding only 1 point where it should 2???
# fix numoperations in ui to be autogenerated
# check specialencoder5 maybe test list comprehension in decrypt?
# take a look through the decrypt for globals
# try using threading instead of parallel x
# try to optimize decoder x
# fix the int/str issues in analyzedecoder x
# use newmodule to save decoded part as new module to use DONE
# m[constants.ShellcodeLabel.SHELLCODE_DECODED_FULL_LABEL] to analyze decoded shellcode
# set bools in shellcode obj appropriately
# change analyzedecoder stubs to determine WHETHER it has a decoderstub DONE
# check w/ bramwell about automation of brute force + checking for success on other things than peb like callpop, ftsenv, etc
# for decrypt, covert pebpoints to 3 if below and ask for confirmation
# analyzedecoderstubs -- need to check if ops or nums are empty -- split find/analyze into 2 func?
# 		try all values if ops but no values
# email ip regex to jacob
# fix some formatting/wording on decoder stub
# fix trackregs issue running processhacker.exe w/ s option
# issue in generateoutputdata syscall line 22343 val5[-1] index error
# investigate other weird errors/issues with syscall etc when running processhacker
# try to eliminate more false positives
# write about brute force capabilities when bram sends emails
# compile ~50 runs of encoded shellcode w 1 op and 2 ops and record times in spreadsheet


# done
############## output file complete for decrypt stuff -- still needs formatting maybe
############## inloadorder stuff verified working
############## syscall issue with 0x30 fixed
############## fstenv issue fixed
############## disherepeb has global var named pebPoints for adjustment of sensitivity -- email name
############## callpop .exe issue fixed with addresses being wrong
############## decoder stub analysis finds operations and numbers
############## decryption now supports 1 and 2 operations
############## integration of decoder stub results into searching
############## various decrypt bug fixes
############## fixed testing function for decrypt for accurate
##############
############## added ability to change sensitivity of decrypt match to prevent false positives
############## changed analyzedecoderstubs to try to detect whether a stub exists or not -- prone to false positives however
############## analyzedecoderstubs also splits up into stub and body if found
############## when shellcode is decoded a new module is set and appropriate properties of the shellcode class is also set
############## hashes are generated of encoded/decoded shell
############## took out setting for number of nodes for distributed, now autofinds
############## distributed mode sanity checks given IPs and rejects invalid ipv4s with a warning
##############


def decryptShellcode(
    encodedShell,
    operations,
    findAll=False,
    fastMode=False,
    distributed=False,
    cpuCount="auto",
    nodesFile="nodes.txt",
    outputFile=True,
    mode="default",
    stubParams=([], []),
    listComp=False,
    successPoints=pebPoints,
):
    global shellEntry
    global decodedBytes
    global filename
    global sh
    global dOutputFile
    # print("ENCODED HERE: \n", encodedShell)

    strAdd = "new=(new +VALUE) & 255\n"
    strSub = "new=(new -VALUE) & 255\n"
    strXor = "new=(new ^ VALUE) & 255\n"
    strNot = "new=~(new) & 255\n"
    strRol = "new=rol(new,VALUE,8)\n"
    strRor = "new=ror(new,VALUE,8)\n"
    strShRight = "new=(new << VALUE) & 255\n"

    decodeOps = []
    for symbol in operations:
        if symbol == "+":
            decodeOps.append(strAdd)
        elif symbol == "-":
            decodeOps.append(strSub)
        elif symbol == "^":
            decodeOps.append(strXor)
        elif symbol == "~":
            decodeOps.append(strNot)
        elif symbol == "rl":
            decodeOps.append(strRol)
        elif symbol == "rr":
            decodeOps.append(strRor)
        elif symbol == "<":
            decodeOps.append(strShRight)
        else:
            print('Operation "' + symbol + '" not recognized. Returning.')
            return
    opsLen = len(decodeOps)

    if fastMode:
        originalEncoded = encodedShell
        encodedShell = encodedShell[:40]  # opt ion for distance

    if distributed and not (mode == "stub"):
        nodeIPs = []
        with open(nodesFile, "r") as f:
            for row in f:
                isIP = re.search(
                    "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
                    row,
                    re.IGNORECASE,
                )
                if isIP:
                    nodeIPs.append(row.rstrip("\n"))
                else:
                    print("WARNING - Invalid node IP: ", row)

        # run decoding func
        numNodes = len(nodeIPs)
        # print("setting numNodes = ", numNodes)
        decodeInfo = doDistr(
            decodeOps,
            encodedShell,
            numNodes,
            nodeIPs,
            findAll=findAll,
            successPoints=successPoints,
        )

        if fastMode:
            # to get full decrypted shellcode we need to do a single pass with full encodedShell using correct vals we found during fastmode run
            decodeInfo = decodeInfo[0][0]
            singleVals = decodeInfo[2]
            order = decodeInfo[3]

            outputs, earlyFinish, startVals = austinDecode(
                decodeOps,
                originalEncoded,
                findAll=findAll,
                mode="single",
                starts=singleVals,
                order=order,
                successPoints=successPoints,
            )
            decodeInfo = outputs
            # parse returned data structure

            for item in decodeInfo:
                print("############# DECODED ################")
                try:
                    print("Decoded Bytes: ")
                    print(binaryToStr(item[0]))
                    decodedBytes = item[0]
                    print("\n")
                except:
                    print(item[0])
                i = 1

                print("DECODE VALUES: ")
                decodeValues = item[1].splitlines()
                decodeValues = decodeValues[-1]
                isNum = False
                for item2 in decodeValues:
                    if not isNum:
                        print(item2, "= ", end="")
                    else:
                        print(item2)
                    isNum = not isNum
                operationOrder = item[3]
                print("\nOperations: ")
                for item2 in operationOrder:
                    print(item2, end="")
                print("\n\n")

        # only runs if we didn't do fastmode
        else:
            for item in decodeInfo:
                if item == []:
                    return
                c = 0
                print("############# DECODED ################")
                for x in item:
                    try:
                        # x[0] = binaryToStr(x[0])
                        # print("Decoded item info:")
                        # for i in range(len(x)):
                        # print("PRINTING I = ", i, " C = ", c)
                        # if(i == 0):
                        print("Decoded Bytes: ")
                        print(binaryToStr(x[0]))
                        decodedBytes = x[0]
                        print("\n")

                        decodeValues = x[1].splitlines()
                        print("DECODE VALUES: ")
                        decodeValues = decodeValues[-1]
                        isNum = False
                        for item2 in decodeValues:
                            if not isNum:
                                print(item2, "= ", end="")
                            else:
                                print(item2)
                            isNum = not isNum
                        operationOrder = x[3]
                        # print("Decoding Values: ", decodeValues)
                        # print("Operations: ", operationOrder)
                        print("\nOperations: ")
                        for item2 in operationOrder:
                            print(item2, end="")
                    except Exception as e:
                        print("Error: " + str(e))
                        print(x)
                    print("\n\n")
                    c += 1

                print("\n\n")
            # return

    # non-distributed
    elif mode == "stub":
        stubNums = stubParams[0]
        stubOps = stubParams[1]
        if len(stubOps) <= 0:
            print("No operations found within stub, returning...")
            return
        else:
            if len(stubNums) > 0:
                outputs, earlyFinish, startVals = austinDecode(
                    decodeOps,
                    encodedShell,
                    findAll=findAll,
                    cpuCount=cpuCount,
                    mode="stub",
                    stubParams=stubParams,
                    successPoints=successPoints,
                )
                decodeInfo = outputs
            else:
                decodeOps = []
                # print("OPERATIONS:")
                # print(operations)
                for symbol in stubOps:
                    if symbol == "+":
                        decodeOps.append(strAdd)
                    elif symbol == "-":
                        decodeOps.append(strSub)
                    elif symbol == "^":
                        decodeOps.append(strXor)
                    elif symbol == "~":
                        decodeOps.append(strNot)
                    elif symbol == "rl":
                        decodeOps.append(strRol)
                    elif symbol == "rr":
                        decodeOps.append(strRor)
                    elif symbol == "<":
                        decodeOps.append(strShRight)
                    else:
                        print('Operation "' + symbol + '" not recognized. Returning.')
                        return

                outputs, earlyFinish, startVals = austinDecode(
                    decodeOps,
                    encodedShell,
                    findAll=findAll,
                    cpuCount=cpuCount,
                    successPoints=successPoints,
                )
                decodeInfo = outputs

            for item in decodeInfo:
                print("############# DECODED ################")
                try:
                    print("Decoded Bytes: ")
                    print(binaryToStr(item[0]))
                    decodedBytes = item[0]
                    print("\n")
                except:
                    print(item[0])
                i = 1

                decodeValues = item[1].splitlines()
                decodeValues = decodeValues[-1]
                print("Decoding Values: ")
                decodeValues = re.findall("(\d+|[A-Za-z]+)", decodeValues)
                isNum = False
                for item2 in decodeValues:
                    if not isNum:
                        print(item2, "= ", end="")
                    else:
                        print(item2)
                    isNum = not isNum
                    # print(item2)
                operationOrder = item[3]
                print("\nOperations: ")
                for item2 in operationOrder:
                    print(item2, end="")
                print("\n\n")
    else:
        if opsLen >= 1 and opsLen <= 5:
            outputs, earlyFinish, startVals = austinDecode(
                decodeOps,
                encodedShell,
                findAll=findAll,
                cpuCount=cpuCount,
                successPoints=successPoints,
            )
            decodeInfo = outputs
            if fastMode:
                if len(decodeInfo) > 0:
                    decodeInfo = decodeInfo[0]

                    singleVals = decodeInfo[2]
                    order = decodeInfo[3]
                    # only save the first output of decode -- it won't end early and startvals doesn't matter either
                    outputs, earlyFinish, startVals = austinDecode(
                        decodeOps,
                        originalEncoded,
                        findAll=findAll,
                        mode="single",
                        starts=singleVals,
                        order=order,
                        successPoints=successPoints,
                    )
                    # parse returned data structure
                    decodeInfo = outputs

            for item in decodeInfo:
                print("############# DECODED ################")
                try:
                    print("Decoded Bytes: ")
                    print(binaryToStr(item[0]))
                    decodedBytes = item[0]
                    print("\n")
                except:
                    print(item[0])
                i = 1

                decodeValues = item[1].splitlines()
                decodeValues = decodeValues[-1]
                print("Decoding Values: ")
                decodeValues = re.findall("(\d+|[A-Za-z]+)", decodeValues)
                isNum = False
                for item2 in decodeValues:
                    if not isNum:
                        print(item2, "= ", end="")
                    else:
                        print(item2)
                    isNum = not isNum
                    # print(item2)
                operationOrder = item[3]
                print("\nOperations: ")
                for item2 in operationOrder:
                    print(item2, end="")
                print("\n\n")
            # return

    if len(decodeInfo) > 0:
        sh.setDecodedBody(decodedBytes)
        sh.decryptSuccess = True
        if mode == "stub":
            hashShellcode(decodedBytes, unencryptedBodyShell)
            orgStub = sh.decoderStub
            decodedBytes = orgStub + decodedBytes
            sh.setDecoded(decodedBytes)
        else:
            hashShellcode(decodedBytes, unencryptedShell)
            # create newModule for decrypted shellcode
        module[constants.ShellcodeLabel.SHELLCODE_DECODED_FULL_LABEL] = newModule(
            constants.ShellcodeLabel.SHELLCODE_DECODED_FULL_LABEL, decodedBytes
        )
        print("Setting default to decoded shellcode...")

        if outputFile:
            disassembly, disassemblyNoC, assemblyBytes = takeBytes(
                decodedBytes, shellEntry
            )
            try:
                rawBytes = decodedBytes
                directory = "." + slash
                if not os.path.exists(directory + "outputs"):
                    os.makedirs(directory + "outputs")
                print(directory + "outputs" + slash + "decoded" + ".bin")
                newBin = open(
                    directory + "outputs" + slash + "decrypted-" + filename + ".bin",
                    "wb",
                )
                newBin.write(rawBytes)
                newBin.close()
                newDis = open(
                    directory
                    + "outputs"
                    + slash
                    + "decrypted-"
                    + filename
                    + "-disassembly.txt",
                    "w",
                )
                newDis.write(disassemblyNoC)
                newDis.close()
            except:
                pass


decryptInput = "default"
decryptNumOps = 3
decryptOpTypes = ["^", "-", "+"]
decryptEncodingVals = [3, 3, 3]
decryptFile = filename
decryptBytes = b""


dFastMode = False
dFindAll = False
dDistr = False
dCPUcount = "auto"
dNodesFile = "nodes.txt"
dOutputFile = False


# initialize decryptFile to be the name of m[o].rawData2 arg by default DONE
# same w/ decryptBytes
# if they change inputfile, set rdata2 again
def decryptUI():
    global decodedBytes
    global decryptInput
    global decryptNumOps
    global decryptOpTypes
    global decryptEncodingVals
    global dFastMode
    global dFindAll
    global dDistr
    global dCPUcount
    global dNodesFile
    global dOutputFile
    global decryptBytes
    global decryptFile
    global filename
    global stubFile
    global pebPoints

    successPoints = pebPoints

    try:
        decryptFile = filename
        if decryptFile[-4:] == ".txt":
            decryptBytes = readShellcode(decryptFile)
        else:
            decryptBytes = rawData2
    except:
        print(
            "Couldn't read command line input file, please provide only a shellcode file."
        )
        decryptBytes = b""
        decryptFile = "default.txt"

    while True:
        printDecryptHelpUI()
        print(
            constants.CYAN
            + "\n Sharem>"
            + constants.YELLOW
            + "Decoder> "
            + constants.RESET,
            end="",
        )
        entry = input()

        if entry == "i":
            print(constants.CYAN + "Enter input file: " + res, end="")

            decryptFile = input()
            try:
                decryptBytes = readShellcode(decryptFile)
            except:
                print(constants.RED + "Invalid file." + res)
                pass
        elif entry == "x":
            return

        elif entry == "o":
            # TODO: this should match num of operations selected, use that param for a for loop or something instead of current way
            # separate my spaces OR commas
            print("\n\nVALID OPERATIONS:\n")
            print("+ | add")
            print("- | subtract")
            print("^ | xor")
            print("~ | not")
            print("rl | rotate left")
            print("rr | rotate right")
            print("< | shift right")

            invalid = True
            while invalid:
                ops = input(
                    "\n\nEnter 1-5 operations, separated by commas [E.g. +,-,^]: \n> "
                )
                ops = ops.split(",")
                decryptOpTypes = ops
                invalid = False
                print("Selected: ")
                for item in decryptOpTypes:
                    if item == "+":
                        print("add")
                    elif item == "-":
                        print("subtract")
                    elif item == "^":
                        print("xor")
                    elif item == "~":
                        print("not")
                    elif item == "rl":
                        print("rotate left")
                    elif item == "rr":
                        print("rotate right")
                    elif item == "<":
                        print("shift right")
                    else:
                        print("Invalid selection.")
                        invalid = True
                decryptNumOps = len(decryptOpTypes)

        elif entry == "d":
            advancedDecryptMenu()
        elif entry == "h":
            printDecryptHelpUI()
        elif entry == "c":
            decryptEncodingVals = []
            invalid = True
            while invalid:
                invalid = False
                try:
                    num = int(input("Enter value 1: "))
                except:
                    invalid = True
                    print("Invalid input.")
            decryptEncodingVals.append(num)

            invalid = True
            while invalid:
                invalid = False
                try:
                    num = int(input("Enter value 2: "))
                except:
                    invalid = True
                    print("Invalid input.")
            decryptEncodingVals.append(num)

            invalid = True
            while invalid:
                invalid = False
                try:
                    num = int(input("Enter value 3: "))
                except:
                    invalid = True
                    print("Invalid input.")
            decryptEncodingVals.append(num)

        elif entry == "e":
            print("Encoding...")
            decryptBytes = encodeShellcodeTesting(decryptBytes, decryptEncodingVals)

        elif entry == "s":
            print("Entering decoder stub mode...")
            sameFile = True
            altFile = input("Use different file for decoder stub? y/n: ")
            if altFile == "n":
                stubFile = decryptFile
            else:
                sameFile = False
                stubFile = input("Enter decoder stub filename: ")

            stubEntry = input("Enter entrypoint: ")
            stubEnd = "-1"  # leaving it on default (autodetect) for now.
            # stubEnd = input("Enter offset for end of stub: ")

            numVals, opTypes, stubEnd = analyzeDecoderStubs(
                shellArg=stubFile, entryPoint=stubEntry, stubEnd=stubEnd
            )
            if stubEnd != -1:
                if sameFile:
                    decryptBytes = decryptBytes[stubEnd:]
                print("Got these values from stub: ", numVals)
                print("Got these operations from stub: ", opTypes)
                print("Got stubEnd offset: ", stubEnd)
                input("press enter to proceed...")
                decodedBytes = decryptShellcode(
                    decryptBytes,
                    decryptOpTypes,
                    findAll=dFindAll,
                    fastMode=dFastMode,
                    distributed=dDistr,
                    cpuCount=dCPUcount,
                    nodesFile=dNodesFile,
                    outputFile=dOutputFile,
                    mode="stub",
                    stubParams=(numVals, opTypes),
                )

            else:
                print("No decoder detected.")

        elif entry == "g":
            print(
                constants.CYAN + " Operations: ",
                constants.GREEN + str(decryptOpTypes) + constants.RESET,
            )
            print(
                constants.CYAN + " FindAll: ",
                constants.GREEN + str(dFindAll) + constants.RESET,
            )
            print(
                constants.CYAN + " FastMode: ",
                constants.GREEN + str(dFastMode) + constants.RESET,
            )
            print(
                constants.CYAN + " Distributed: ",
                constants.GREEN + str(dDistr) + constants.RESET,
            )
            print(
                constants.CYAN + " CPUs: ",
                constants.GREEN + str(dCPUcount) + constants.RESET,
            )
            print(
                constants.CYAN + " Nodes File: ",
                constants.YELLOW + str(dNodesFile) + constants.RESET,
            )
            print(
                constants.CYAN + " OutputFile: ",
                constants.GREEN + str(dOutputFile) + constants.RESET,
            )

            if successPoints < 3:
                print(
                    constants.YELLOW
                    + "\npebPoints for shellcode detection is currently set to: ["
                    + constants.RESET
                    + constants.CYAN
                    + str(successPoints)
                    + constants.YELLOW
                    + "] \nSet to recommended value of 3 to avoid false positives?"
                    + constants.GREEN
                    + "[y/n] ? "
                    + res,
                    end="",
                )
                pebConfirm = input()
                if pebConfirm == "y":
                    successPoints = 3
            confirm = print(
                constants.YELLOW
                + "\n Run decryption with these settings "
                + constants.RESET
                + constants.GREEN
                + "[y/n] ? "
                + constants.RESET,
                end="",
            )

            confirm = input()
            if confirm == "y":
                decodedBytes = decryptShellcode(
                    decryptBytes,
                    decryptOpTypes,
                    findAll=dFindAll,
                    fastMode=dFastMode,
                    distributed=dDistr,
                    cpuCount=dCPUcount,
                    nodesFile=dNodesFile,
                    outputFile=dOutputFile,
                    successPoints=successPoints,
                )
                return

        elif entry == "l":
            confirm = print("Run listcomp decryption with these settings?")
            print("Operations: ", decryptOpTypes)
            print("FindAll: ", dFindAll)
            print("FastMode: ", dFastMode)
            print("Distributed: ", dDistr)
            print("CPUs: ", dCPUcount)
            print("Nodes File: ", dNodesFile)
            print("OutputFile: ", dOutputFile)
            confirm = input("y/n? >")
            if confirm == "y":
                decodedBytes = decryptShellcode(
                    decryptBytes,
                    decryptOpTypes,
                    findAll=dFindAll,
                    fastMode=dFastMode,
                    distributed=dDistr,
                    cpuCount=dCPUcount,
                    nodesFile=dNodesFile,
                    outputFile=dOutputFile,
                    listComp=True,
                )
                return

        else:
            print("Invalid selection.")


def advancedDecryptMenu():
    global dFastMode
    global dFindAll
    global dDistr
    global dCPUcount
    global dNodesFile
    global dOutputFile
    global decryptInput
    global decryptNumOps
    global decryptOpTypes
    global decryptEncodingVals
    global decryptBytes
    global decryptFile

    printAdvDecryptHelp()
    while True:
        print(
            constants.CYAN
            + "\n Sharem>"
            + constants.YELLOW
            + "Decoder>"
            + constants.GREEN
            + "Advanced> "
            + constants.RESET,
            end="",
        )
        entry = input()

        if entry == "fm":
            dFastMode = not dFastMode
            printAdvDecryptHelp()
        elif entry == "fa":
            dFindAll = not dFindAll
            printAdvDecryptHelp()
        elif entry == "d":
            dDistr = not dDistr
            printAdvDecryptHelp()
        elif entry == "c":
            while True:
                dCPUcount = input(
                    '\nEnter amount of CPUs to use ("auto" to automatically use max): '
                )
                if dCPUcount == "auto":
                    break
                else:
                    try:
                        dCPUcount = int(dCPUcount)
                        if dCPUcount < 1:
                            print("Please enter a positive whole number.")
                        else:
                            break
                    except:
                        print("Invalid entry.")
                        pass

            printAdvDecryptHelp()
        elif entry == "n":
            dNodesFile = input("\nEnter name of nodes config file: ")
            printAdvDecryptHelp()
        elif entry == "o":
            dOutputFile = not dOutputFile
            printAdvDecryptHelp()
        elif entry == "h":
            printAdvDecryptHelp()
        elif entry == "x":
            return


def printAdvDecryptHelp():
    global dFastMode
    global dFindAll
    global dDistr
    global dCPUcount
    global dNodesFile
    global dOutputFile
    global decryptInput
    global decryptNumOps
    global decryptOpTypes
    global decryptEncodingVals
    global decryptBytes
    global decryptFile

    print(
        constants.YELLOW
        + "\n\n ....................\n    Advanced menu\n ...................."
        + constants.RESET
    )
    print(
        "\n\n {} - Toggle fast mode [{}]".format(
            constants.CYAN + "fm" + constants.RESET,
            constants.GREEN + str(dFastMode) + constants.RESET,
        )
    )
    print(
        " {} - Toggle find all [".format(constants.CYAN + "fa" + constants.RESET),
        constants.GREEN + str(dFindAll) + constants.RESET,
        "]",
    )
    print(
        " {}  - Toggle distributed mode [".format(
            constants.CYAN + "d" + constants.RESET
        ),
        constants.GREEN + str(dDistr) + constants.RESET,
        "]",
    )
    print(
        " {}  - Enter CPU count [".format(constants.CYAN + "c" + constants.RESET),
        constants.GREEN + str(dCPUcount) + constants.RESET,
        "]",
    )
    print(
        " {}  - Enter nodes file for distributed [".format(
            constants.CYAN + "n" + constants.RESET
        ),
        constants.GREEN + str(dNodesFile) + constants.RESET,
        "]",
    )
    print(
        " {}  - Toggle separate file output for decrypt function [".format(
            constants.CYAN + "o" + constants.RESET
        ),
        constants.GREEN + str(dOutputFile) + constants.RESET,
        "]",
    )
    print(
        " {}  - Help (show this screen)".format(constants.CYAN + "h" + constants.RESET)
    )
    print(" {}  - Exit".format(constants.CYAN + "x" + constants.RESET))


def printDecryptHelpUI():
    global dFastMode
    global dFindAll
    global dDistr
    global dCPUcount
    global dNodesFile
    global dOutputFile
    global decryptInput
    global decryptNumOps
    global decryptOpTypes
    global decryptEncodingVals
    global decryptBytes
    global decryptFile

    print(
        constants.YELLOW
        + "\n\n .....................\n     Decrypt menu\n .....................\n"
        + constants.RESET
    )
    print(
        " {} - Set input file {}".format(
            constants.CYAN + "i" + constants.RESET,
            constants.GREEN + "[" + decryptFile + "]" + constants.RESET,
        )
    )

    # print(" {} - Set input file [".format(constants.CYAN + "i" + res), constants.GREEN +decryptFile+constants.RESET,"]")
    # print(" {} - Set number of operations {:>20}".format(constants.CYAN + "n" + res, constants.GREEN + "["+str(decryptNumOps) +"]"+ res))
    print(
        " {} - Set operation types ".format(constants.CYAN + "o" + constants.RESET),
        constants.GREEN + str(decryptOpTypes) + constants.RESET,
    )
    print(" {} - Advanced settings menu".format(constants.CYAN + "d" + constants.RESET))
    print(" {} - Decoder stub testing".format(constants.CYAN + "s" + constants.RESET))

    print(
        " {} - Go (run decrypt function)".format(constants.CYAN + "g" + constants.RESET)
    )
    print(
        " {} - Help (show this screen)".format(constants.CYAN + "h" + constants.RESET)
    )
    print(" {} - Exit".format(constants.CYAN + "x" + constants.RESET))

    print(
        constants.YELLOW
        + "\n .....................\n     Testing\n .....................\n"
        + constants.RESET
    )

    # print(constants.YELLOW + "\n+----------------Testing-----------------+\n"+constants.RESET)
    print(
        " {} - Apply encoding to input".format(constants.CYAN + "e" + constants.RESET)
    )
    print(
        " {} - Change encoding values ".format(constants.CYAN + "c" + constants.RESET),
        constants.GREEN + str(decryptEncodingVals) + constants.RESET,
    )


def toggleDecodedModule(shell_code):
    global o
    global m

    if shell_code is None or not shell_code.decryptSuccess:
        print(
            'No shellcode has been decoded. To decode an obfuscated shellcode, use the "b - Brute-force deobfuscation of shellcode." option.'
        )
    else:
        if o == constants.ShellcodeLabel.SHELLCODE_LABEL:
            print(
                "  Currently performing operations on obfuscated shellcode. Switch to deobfuscated shellcode?"
            )
            while True:
                userAns = input(" y/n>")
                if userAns == "y" or userAns == "Y":
                    print("  Switching to deobfuscated shellcode...")
                    o = constants.ShellcodeLabel.SHELLCODE_DECODED_FULL_LABEL
                    return
                elif userAns == "n" or userAns == "N":
                    return
        elif o == constants.ShellcodeLabel.SHELLCODE_DECODED_FULL_LABEL:
            print(
                "  Currently performing operations on deobfuscated shellcode. Switch back to obfuscated shellcode?"
            )
            while True:
                userAns = input("y/n>")
                if userAns == "y" or userAns == "Y":
                    print("  Switching to obfuscated shellcode...")
                    o = constants.ShellcodeLabel.SHELLCODE_LABEL
                    return
                elif userAns == "n" or userAns == "N":
                    return


# stubEnd goes to end of file by default
# returns: 1. list of detected values | 2. list of detected operations | 3. offset for the end of the decoder stub portion
def analyzeDecoderStubs(shellArg="default", entryPoint=0, stubEnd=-1):
    global sh
    entryPoint = int(entryPoint, 0)
    # handle type issues with param
    try:
        stubEnd = int(stubEnd, 0)
    except:
        pass
    rawBytes = b""

    if shellArg == "default":
        print(constants.YELLOW + " Enter decoder stub file: " + constants.RESET, end="")
        shellArg = input()

        try:
            rawBytes = readShellcode(shellArg)
        except:
            print(constants.RED + " Error: Couldn't read file." + constants.RESET)
            return -1, -1, -1
    else:
        try:
            rawBytes = readShellcode(shellArg)
        except:
            print(constants.RED + " Error: Couldn't read file." + constants.RESET)
            return -1, -1, -1
    if stubEnd == -1:
        stubEnd = len(rawBytes)
    CODED3 = rawBytes[entryPoint:stubEnd]

    val = ""
    val2 = []
    val3 = []
    val5 = []

    disString = ""
    numVals = []
    opTypes = []

    for i in cs.disasm(CODED3, entryPoint):
        add4 = hex(int(i.address))
        addb = hex(int(i.address))
        size = hex(int(i.size))
        val = (
            i.mnemonic + " " + i.op_str + "\t\t\t\t" + add4 + " (offset " + addb + ")\n"
        )
        # val2.append(val)
        # val3.append(add2)
        disString += val

        # print("checking this one: ", i.op_str)
        #
        numeric = re.search("(0x)?([0-9a-f]+)$", i.op_str, re.IGNORECASE)
        isLoop = re.match(
            "^((jmp)|(ljmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(loop)|(jns))",
            i.mnemonic,
            re.M | re.I,
        )

        if numeric and not isLoop:
            numVals.append(numeric.group())
        elif isLoop:
            print("Decoder disasm: ")
            print(disString)
            sh.setDecoderStub(rawBytes[: (int(addb, 16) + int(size, 16))])
            sh.isEncoded = True
            sh.decryptSuccess = True
            decoderEnd = int(addb, 16) + int(size, 16)
            sh.setDecoderStubEnd(decoderEnd)

            hashShellcode(rawBytes[: (int(addb, 16) + int(size, 16))], decoderShell)
            return (numVals, opTypes, (int(addb, 16) + int(size, 16)))

        isXor = re.search("^(xor)", i.mnemonic, re.IGNORECASE)
        isAdd = re.search("^(add)|(adc)", i.mnemonic, re.IGNORECASE)
        isSub = re.search("^(sub)|(sbb)", i.mnemonic, re.IGNORECASE)
        isRol = re.search("^(rol)", i.mnemonic, re.IGNORECASE)
        isRor = re.search("^(ror)", i.mnemonic, re.IGNORECASE)
        isNot = re.search("^(not)", i.mnemonic, re.IGNORECASE)
        isShr = re.search("^(shr)", i.mnemonic, re.IGNORECASE)

        if isXor:
            opTypes.append("^")
        elif isAdd:
            opTypes.append("+")
        elif isSub:
            opTypes.append("-")
        elif isRor:
            opTypes.append("rr")
        elif isRol:
            opTypes.append("rl")
        elif isNot:
            opTypes.append("~")
        elif isShr:
            opTypes.append("<")

    return -1, -1, -1


def dp(out):
    txtDis = open("dp-out.txt", "w")
    txtDis.write(out)
    txtDis.close()


def dp2(out):
    with open(
        os.path.join(
            os.path.abspath(os.path.dirname(__file__)), "sharem", "logs", "logging.txt"
        ),
        "a",
    ) as txtDis:
        txtDis.write(out + "\n")


def dprint3(*args):
    try:
        if len(args) == 1:
            if type(args[0]) == list:
                dp2(args[0])
                return

        if len(args) > 1:
            strList = ""
            for each in args:
                try:
                    strList += each + " "
                except:
                    strList += str(each) + " "
            dp2(strList)

        else:
            for each in args:
                try:
                    dp2(str(each) + " ")
                except:
                    dp2("dprint error: 1")
                    dp2(each + " ")
    except Exception as e:
        dp2("dprint error: 3")
        dp2(e)
        dp2(traceback.format_exc())
        dp2(args)


def shellDisassemblyInit(shellArg, shell_code: shellcode, variables: Variables, module, shellcode_label, silent=None):
    global filename
    global gDisassemblyText
    global gDisassemblyTextNoC
    global save_bin_file
    global shellEntry

    startAddress = shellEntry

    mode = ""

    if not variables.moduleBooleans[shellcode_label].bFstenvFound:
        findAllFSTENV(shellArg, "noSec", variables, module, shellcode_label)
    if not variables.moduleBooleans[shellcode_label].bPushRetFound:
        findAllPushRet(shellArg, "noSec", variables, module, shellcode_label)
    if not variables.moduleBooleans[shellcode_label].bCallPopFound:
        findAllCallpop(shellArg, "noSec", variables, module, shellcode_label)
    if not variables.moduleBooleans[shellcode_label].bHeavenFound:
        getHeavenRawHex(0, 8, "noSec", shellArg, variables, module, shellcode_label)
    if not variables.moduleBooleans[shellcode_label].bSyscallFound:
        getSyscallRawHex(0, 8, "noSec", shellArg, variables, module, shellcode_label)
    if not variables.moduleBooleans[shellcode_label].bPEBFound:
        findAllPebSequences(
            "normal", variables, module, shellcode_label, shellArg, "noSec"
        )

    variables.moduleBooleans[shellcode_label].bAnaFindStrDone = False
    variables.moduleBooleans[shellcode_label].bAnaHiddenCallsDone = False
    variables.moduleBooleans[shellcode_label].bAnaHiddenCnt = 0
    variables.moduleBooleans[shellcode_label].bAnaConvertBytesDone = False
    variables.moduleBooleans[shellcode_label].disAnalysisDone = False

    # parameterize
    disassembly, disassemblyNoC, assemblyBytes = takeBytes(
        shellArg, startAddress, variables, module, shellcode_label, silent
    )

    allowPrint()
    gDisassemblyText = disassembly
    gDisassemblyTextNoC = disassemblyNoC

    ### Saving disassembly and .bin
    filename = os.path.basename(filename)

    directory = ""

    bytesOutput = shellArg

    if not os.path.exists(
        os.path.join(
            os.path.abspath(os.path.dirname(__file__)), "sharem", "logs", "disassembly"
        )
    ):
        os.makedirs(
            os.path.join(
                os.path.abspath(os.path.dirname(__file__)),
                "sharem",
                "logs",
                "disassembly",
            )
        )

    global useHash
    global filename2

    allowPrint()
    colorama.init()

    try:
        hashShellcode(sh.decodedFullBody, unencryptedBodyShell)
        dStub = shHash.unecryptedBodyMd5
    except:
        dStub = filename

    if not useHash:
        txtDis = open(
            os.path.join(
                os.path.abspath(os.path.dirname(__file__)),
                "sharem",
                "logs",
                "disassembly",
                (filename[:-4] + "-disassembly.txt"),
            ),
            "w",
        )
        printOUT = (
            "\tDisassembly printed to disassembly"
            + slash
            + filename[:-4]
            + "-disassembly.txt"
        )
        if save_bin_file:
            binasm = open(
                os.path.join(
                    os.path.abspath(os.path.dirname(__file__)),
                    "sharem",
                    "logs",
                    "disassembly",
                    (filename[:-4] + "-raw.bin"),
                ),
                "wb",
            )
            asciiBin = open(
                os.path.join(
                    os.path.abspath(os.path.dirname(__file__)),
                    "sharem",
                    "logs",
                    "disassembly",
                    (filename[:-4] + "-ascii.txt"),
                ),
                "w",
            )
            assembly = binaryToText(module[shellcode_label].rawData2)

            if not shell_code.decryptSuccess:
                binasm.write(module[shellcode_label].rawData2)
                asciiBin.write(assembly)
                asciiBin.close()

            if shell_code.decryptSuccess:
                binasm2 = open(
                    os.path.join(
                        os.path.abspath(os.path.dirname(__file__)),
                        "sharem",
                        "logs",
                        "disassembly",
                        (filename[:-4] + "-decoded_body_raw.bin"),
                    ),
                    "wb",
                )
                asciiDeobf = open(
                    os.path.join(
                        os.path.abspath(os.path.dirname(__file__)),
                        "sharem",
                        "logs",
                        "disassembly",
                        (filename[:-4] + "-decoded_body_raw-ascii.txt"),
                    ),
                    "w",
                )
                binasm2.write(sh.decodedFullBody)
                binasm.write(module["shellcode"].rawData2)
                binasm2.close()

                asciiBin.write(assembly)
                asciiBin.close()
                assemblyD = binaryToText(sh.decodedFullBody)
                asciiDeobf.write(assemblyD)
                asciiDeobf.close()

            binasm.close()

    else:
        txtDis = open(
            os.path.join(
                os.path.abspath(os.path.dirname(__file__)),
                "sharem",
                "logs",
                "disassembly",
                (filename2 + "-disassembly.txt"),
            ),
            "w",
        )
        printOUT = (
            "\tDisassembly printed to disassembly"
            + slash
            + filename2
            + "-disassembly.txt"
        )
        if save_bin_file:
            binasm = open(
                os.path.join(
                    os.path.abspath(os.path.dirname(__file__)),
                    "sharem",
                    "logs",
                    "disassembly",
                    (filename2 + "-raw.bin"),
                ),
                "wb",
            )

            if not sh.decryptSuccess:
                binasm.write(m[o].rawData2)
            if sh.decryptSuccess:
                binasm2 = open(
                    os.path.join(
                        os.path.abspath(os.path.dirname(__file__)),
                        "sharem",
                        "logs",
                        "disassembly",
                        (dStub + "-decoded_body_raw.bin2"),
                    ),
                    "wb",
                )
                binasm2.write(sh.decodedFullBody)
                binasm.write(m["shellcode"].rawData2)
                binasm2.close()

    if silent != "silent":
        print(printOUT)

    txtDis.write(disassemblyNoC + assemblyBytes)

    txtDis.close()


def disPrintStyleMenu():
    while True:
        print(
            constants.YELLOW
            + " Sharem>"
            + constants.CYAN
            + "Disasm>"
            + constants.RESET
            + constants.WHITE
            + "PrintStyle> "
            + constants.RESET,
            end="",
        )

        choice = input()
        if choice == "g":
            disPrintStyleTogg()
        elif choice == "x":
            break
        elif choice == "h":
            disPrintStyle(moduleBooleans[shellcode_label].bPreSysDisDone, toggList)
        elif choice == "m":
            opnum = input(" Enter maximum opcodes number: ")
            try:
                opnum = int(opnum)
                moduleBooleans[shellcode_label].maxOpDisplay = opnum
                toggList["max_opcodes"] = opnum

            except:
                print(
                    constants.RED
                    + "\tPlease enter integer, not string."
                    + constants.RESET
                )
                continue
        elif choice == "p":
            pstyle = input(" Enter opcode print style [1-3]: ")
            try:
                pstyle = int(pstyle)
                if pstyle > 3 or pstyle < 1:
                    print(
                        constants.RED
                        + "\t Please enter number between 1 and 3."
                        + constants.RESET
                    )
                    continue

                moduleBooleans[shellcode_label].btsV = pstyle
                toggList["binary_to_string"] = pstyle

            except:
                print(
                    constants.RED
                    + "\tPlease enter integer, not string."
                    + constants.RESET
                )
                continue

        elif choice == "r":
            if gDisassemblyText != "":
                regenerateDisassemblyForPrint()
                print(gDisassemblyText)
            else:
                print(
                    constants.RED + "\tDisassembly is not generated." + constants.RESET
                )
                mchoice = input(
                    " Do you want to generate the disassembly first [y/n] ? "
                )
                mchoice = mchoice.lower()
                if mchoice == "y":
                    if rawHex:
                        if bfindShell:
                            # print ("hello??")
                            # dontPrint()
                            shellDisassemblyInit(m[o].rawData2, "silent")
                            # allowPrint()

                            if gDisassemblyText == "":
                                print("\nUnable to find any disassembly.\n")
                            else:
                                # print("\nFound disassembly instructions.\n")
                                moduleBooleans[shellcode_label].bDisassemblyFound = True
                else:
                    continue

        else:
            print("Invalid input.")


def disPrintStyleTogg():
    print("  Enter input delimited by commas or spaces. (x to exit)")
    print("\tE.g. c, a, o, l, f\n")
    while True:
        print(
            constants.YELLOW
            + " Sharem>"
            + constants.CYAN
            + "Disasm>"
            + constants.RESET
            + constants.WHITE
            + "PrintStyle>"
            + constants.GREEN
            + "Toggles> "
            + constants.RESET,
            end="",
        )

        togg = input()
        togg = togg.lower()
        if togg == "x":
            break
        elif togg == "h":
            print("  Enter input delimited by commas or spaces. (x to exit)\n")
            continue
        togg = togg.replace(",", " ")
        togg = re.sub(" +", " ", togg)
        toggOptions = togg.split(" ")

        for t in toggOptions:
            if t == "d":
                toggList["deobfCode"] = not toggList["deobfCode"]
                bdeobfCode = not bdeobfCode

            elif t == "c":
                toggList["comments"] = not toggList["comments"]
                moduleBooleans[shellcode_label].bDoEnableComments = not moduleBooleans[
                    shellcode_label
                ].bDoEnableComments

            elif t == "o":
                toggList["opcodes"] = not toggList["opcodes"]
                moduleBooleans[shellcode_label].bDoShowOpcodes = not moduleBooleans[
                    shellcode_label
                ].bDoShowOpcodes

            elif t == "a":
                toggList["show_ascii"] = not toggList["show_ascii"]
                moduleBooleans[shellcode_label].bDoShowAscii = not moduleBooleans[
                    shellcode_label
                ].bDoShowAscii

            elif t == "l":
                toggList["labels"] = not toggList["labels"]
                moduleBooleans[shellcode_label].bShowLabels = not moduleBooleans[
                    shellcode_label
                ].bShowLabels

            elif t == "f":
                toggList["offsets"] = not toggList["offsets"]
                moduleBooleans[shellcode_label].bDoShowOffsets = not moduleBooleans[
                    shellcode_label
                ].bDoShowOffsets

            elif t == "x":
                return

        disPrintStyle(moduleBooleans[shellcode_label].bPreSysDisDone, toggList)
        return


def disassembleSubMenu():
    # disToggleMenu()
    global shellSizeLimit
    global shellEntry
    while True:
        print(
            constants.YELLOW
            + " Sharem>"
            + constants.CYAN
            + "Disasm> "
            + constants.RESET,
            end="",
        )
        choice = input()
        choice = choice.lower()
        if choice == "":
            continue
        elif choice == "x":
            # print("\nGoing back to main menu..\n")
            break
        elif choice == "m":
            tmp = input(" Enter new shellcode size: ")
            try:
                tmp = int(tmp)
            except:
                print(constants.RED + " Please enter integer only." + constants.RESET)
                continue

            print(
                constants.YELLOW + " Shellcode size has been changed." + constants.RESET
            )
            shellSizeLimit = tmp

            # modifysByRangeUser()
        elif choice == "h" or choice == "help":
            disToggleMenu(
                shellEntry,
                shellSizeLimit,
                moduleBooleans[shellcode_label].bPreSysDisDone,
                toggList,
            )
            # disassembleUiMenu(shellEntry)
        elif choice == "g":
            disassembleToggles()

        elif choice == "r":
            disPrintStyle(moduleBooleans[shellcode_label].bPreSysDisDone, toggList)
            disPrintStyleMenu()
        elif choice == "e":
            changeEntryPoint()
        elif choice == "j":
            raw_shellcode = binaryToText(m[o].rawData2, "json")
            Text2Json(raw_shellcode)
        elif choice == "u":
            useMd5asFilename()
        elif choice == "p":
            if gDisassemblyText != "":
                print(gDisassemblyText)

        elif choice == "i":
            moduleBooleans[shellcode_label].ignoreDisDiscovery = not moduleBooleans[
                shellcode_label
            ].ignoreDisDiscovery
            toggList["ignore_dis_discovery"] = not toggList["ignore_dis_discovery"]
        elif choice == "z" or choice == "d":
            if rawHex:
                if bfindShell:
                    shellDisassemblyInit(m[o].rawData2, "silent")

                    if gDisassemblyText == "":
                        print("\nUnable to find any disassembly.\n")
                    else:
                        moduleBooleans[shellcode_label].bDisassemblyFound = True
            else:
                print("\nThis option is for shellcode only")

        else:
            print("Invalid input??")


def checkHex(s):
    for ch in s:
        if (ch < "0" or ch > "9") and (ch < "a" or ch > "f"):
            return False

    return True


def changeEntryPoint():
    global shellEntry
    result = False
    while result != True:
        entrypoint = input("Enter entry point as hex: ")
        entrypoint = entrypoint.lower()
        if "0x" in entrypoint:
            entrypoint = entrypoint.split("0x")[1]
        result = checkHex(entrypoint)
        if not result:
            print("Please enter a valid hex address")
    shellEntry = int(entrypoint, 16)
    em.entryOffset = shellEntry
    print("\nEntry point: " + str(hex(shellEntry)) + "\n")


def disassembleToggles():
    global bPushRet
    global bdeobfCode
    global bfindString
    global bComments
    global bfindShell

    print("  Enter input delimited by commas or spaces. (x to exit)")
    print("\tE.g. s, d, p\n")
    while True:
        togg = input("Sharem>Disasm> ")
        togg = togg.lower()
        if togg == "x":
            break
        elif togg == "h":
            print("  Enter input delimited by commas or spaces. (x to exit)\n")
            continue
        togg = togg.replace(",", " ")
        togg = re.sub(" +", " ", togg)
        toggOptions = togg.split(" ")

        for t in toggOptions:
            if t == "s":
                toggList["findString"] = not toggList["findString"]
                moduleBooleans[shellcode_label].bDoFindStrings = not moduleBooleans[
                    shellcode_label
                ].bDoFindStrings

            elif t == "d":
                toggList["deobfCode"] = not toggList["deobfCode"]
                bdeobfCode = not bdeobfCode

            elif t == "c":
                toggList["hidden_calls"] = not toggList["hidden_calls"]
                moduleBooleans[shellcode_label].bDoFindHiddenCalls = not moduleBooleans[
                    shellcode_label
                ].bDoFindHiddenCalls

            elif t == "i":
                toggList["ignore_dis_discovery"] = not toggList["ignore_dis_discovery"]
                moduleBooleans[shellcode_label].ignoreDisDiscovery = not moduleBooleans[
                    shellcode_label
                ].ignoreDisDiscovery

        disToggleMenu(
            shellEntry,
            shellSizeLimit,
            moduleBooleans[shellcode_label].bPreSysDisDone,
            toggList,
        )
        return


def initSysCallSelect():  # Initialize our list of syscalls to print
    global syscallSelection
    global syscallPrintBit
    global bit32
    global os
    syscallPrintBit = 64
    syscallSelection = []

    # Read our syscall file to find OS versions
    if bit32:
        with open(
            os.path.join(
                os.path.abspath(os.path.dirname(__file__)), "sharem", "nt64.csv"
            ),
            "r",
        ) as file:
            nt64Csv = csv.reader(file)
            versions = next(nt64Csv)
            versions = versions[1:]
    else:
        with open(
            os.path.join(
                os.path.abspath(os.path.dirname(__file__)), "sharem", "nt.csv"
            ),
            "r",
        ) as file:
            nt32Csv = csv.reader(file)
            versions = next(nt32Csv)
            versions = versions[1:]

    # Loop through the list of versions
    for version in versions:
        obj = OSVersion()
        t = 0
        code = "new"

        # Get the version from the list
        for char in version:
            if char == "(":
                break
            t += 1
        w = 0
        for char in version:
            if char == ")":
                break
            w += 1
        name = version[t + 1 : w]
        # Get the category from the list
        category = version[0 : t - 1]

        # Setup our category's opcode
        if category == "Windows XP":
            code = "xp"
        elif category == "Windows Vista":
            code = "v"
        elif category == "Windows 7":
            code = "w7"
        elif category == "Windows 8":
            code = "w8"
        elif category == "Windows 10":
            code = "w10"
        elif category == "Windows Server 2003":
            code = "s3"
        elif category == "Windows Server 2008":
            code = "s8"
        elif category == "Windows Server 2012":
            code = "s12"
        elif category == "Windows NT":
            code = "nt"
        elif category == "Windows 2000":
            code = "w20"

        # See if our category exists in the list
        categoryFound = False
        for osv in syscallSelection:
            if osv.category == category:
                categoryFound = True
                break

        # If not, put it in
        if not categoryFound:
            obj._init_(category, category, False, code)
            syscallSelection.append(obj)
            obj = OSVersion()
        if category == "Windows 10":
            name = "release " + name

        # Set the code (no way around hardcoded here)
        # Defaults to "new" otherwise
        # For selecting
        if version == "Windows XP (SP1)":
            code = "xp1"
        elif version == "Windows XP (SP2)":
            code = "xp2"
        elif version == "Windows Vista (SP0)":
            code = "v0"
        elif version == "Windows Vista (SP1)":
            code = "v1"
        elif version == "Windows Vista (SP2)":
            code = "v2"
        elif version == "Windows 7 (SP0)":
            code = "w70"
        elif version == "Windows 7 (SP1)":
            code = "w71"
        elif version == "Windows 8 (8.0)":
            code = "w80"
        elif version == "Windows 8 (8.1)":
            code = "w81"
        elif version == "Windows 10 (1507)":
            code = "r0"
        elif version == "Windows 10 (1511)":
            code = "r1"
        elif version == "Windows 10 (1607)":
            code = "r2"
        elif version == "Windows 10 (1703)":
            code = "r3"
        elif version == "Windows 10 (1709)":
            code = "r4"
        elif version == "Windows 10 (1803)":
            code = "r5"
        elif version == "Windows 10 (1809)":
            code = "r6"
        elif version == "Windows 10 (1903)":
            code = "r7"
        elif version == "Windows 10 (1909)":
            code = "r8"
        elif version == "Windows 10 (2004)":
            code = "r9"
        elif version == "Windows 10 (20H2)":
            code = "r10"
        elif version == "Windows Server 2003 (SP0)":
            code = "s30"
        elif version == "Windows Server 2003 (SP2)":
            code = "s32"
        elif version == "Windows Server 2003 (R2)":
            code = "s3r"
        elif version == "Windows Server 2003 (R2 SP2)":
            code = "s3r2"
        elif version == "Windows Server 2008 (SP0)":
            code = "s80"
        elif version == "Windows Server 2008 (SP2)":
            code = "s82"
        elif version == "Windows Server 2008 (R2)":
            code = "s8r"
        elif version == "Windows Server 2008 (R2 SP1)":
            code = "s8r1"
        elif version == "Windows Server 2012 (SP0)":
            code = "s120"
        elif version == "Windows Server 2012 (R2)":
            code = "s12r"
        elif version == "Windows 2000 (SP0)":
            code = "w200"
        elif version == "Windows 2000 (SP1)":
            code = "w201"
        elif version == "Windows 2000 (SP2)":
            code = "w202"
        elif version == "Windows 2000 (SP3)":
            code = "w203"
        elif version == "Windows 2000 (SP4)":
            code = "w204"
        elif version == "Windows NT (SP3 TS)":
            code = "nt3t"
        elif version == "Windows NT (SP3)":
            code = "nt3"
        elif version == "Windows NT (SP4)":
            code = "nt4"
        elif version == "Windows NT (SP5)":
            code = "nt5"
        elif version == "Windows NT (SP6)":
            code = "nt6"
        obj._init_(name, category, False, code)
        syscallSelection.append(obj)

    # Add our multiselect objects
    # print("########## OS initsyscall ###########", os)

    category = "server Column multiselect variables"
    obj = OSVersion()
    obj._init_("All releases", category, False, "all")
    syscallSelection.append(obj)
    obj = OSVersion()
    obj._init_("Only latest releases", category, False, "l")
    syscallSelection.append(obj)
    obj = OSVersion()
    obj._init_("Current Windows 10", category, False, "d")
    syscallSelection.append(obj)
    obj = OSVersion()
    obj._init_("Current Windows 10 and Windows 7", category, False, "D")
    syscallSelection.append(obj)

    # Set Win10 Default
    t = len(syscallSelection) - 1
    for osv in syscallSelection:
        if syscallSelection[t].category == "Windows 10":
            syscallSelection[t].toggle = False
            break
        t -= 1


def modConf():
    global bPushRet
    global bCallPop
    global bFstenv
    global bSyscall
    global bHeaven
    global bPEB
    global bDisassembly
    global pebPoints
    global configOptions
    global p2screen
    global bytesForward
    global bytesBack
    global linesForward
    global linesBack
    global bPushStackStrings
    global bWideCharStrings
    global bAsciiStrings
    global syscallSelection
    global dFastMode
    global dFindAll
    global dDistr
    global dCPUcount
    global dNodesFile
    global dOutputFile
    global decryptOpTypes
    global decryptFile
    global stubFilef
    global sameFile
    global stubEntry
    global stubEnd
    global minStrLen
    global maxDistance
    global sharem_out_dir
    global bPrintEmulation
    global emulation_verbose
    global emulation_multiline
    global emuObj
    global emuSimVals
    global emuSyscallSelection

    listofStrings = [
        "pushret",
        "callpop",
        "fstenv",
        "syscall",
        "heaven",
        "peb",
        "disassembly",
        "pebpresent",
        "bit32",
        "max_bytes_forward",
        "max_bytes_backward",
        "max_lines_forward",
        "max_lines_backward",
        "print_to_screen",
        "push_stack_strings",
        "ascii_strings",
        "wide_char_strings",
        "fast_mode",
        "find_all",
        "dist_mode",
        "cpu_count",
        "nodes_file",
        "output_file",
        "dec_operation_type",
        "decrypt_file",
        "stub_file",
        "use_same_file",
        "stub_entry_point",
        "stub_end",
        "shellEntry",
        "pebpoints",
        "minimum_str_length",
        "max_callpop_distance",
        "default_outdir",
        "print_emulation_result",
        "emulation_verbose_mode",
        "emulation_multiline",
        "max_num_of_instr",
        "iterations_before_break",
        "break_infinite_loops",
        "timeless_debugging",
        "complete_code_coverage",
        "current_user",
        "computer_name",
        "temp_file_prefix",
        "default_registry_value",
        "computer_ip_address",
        "timezone",
        "system_time_since_epoch",
        "system_uptime_minutes",
        "clipboard_data",
        "users",
        "drive_letter",
        "start_directory",
        "ccctest",
        "ccc_write_to_temp_file_slower",
    ]

    maxEmuInstr = emuObj.maxEmuInstr
    numOfIter = emuObj.numOfIter
    numOfIter = em.maxLoop

    listofBools = [
        bPushRet,
        bCallPop,
        bFstenv,
        bSyscall,
        bHeaven,
        bPEB,
        bDisassembly,
        bit32,
        bytesForward,
        bytesBack,
        linesForward,
        linesBack,
        p2screen,
        bPushStackStrings,
        bAsciiStrings,
        bWideCharStrings,
        dFastMode,
        dFindAll,
        dDistr,
        dCPUcount,
        dNodesFile,
        dOutputFile,
        decryptOpTypes,
        decryptFile,
        stubFile,
        sameFile,
        stubEntry,
        stubEnd,
        shellEntry,
        pebPoints,
        minStrLen,
        maxDistance,
        sharem_out_dir,
        bPrintEmulation,
        emulation_verbose,
        emulation_multiline,
        maxEmuInstr,
        numOfIter,
        emuObj.breakLoop,
        emuObj.verbose,
        em.codeCoverage,
        conr.simulatedValues_current_user,
        conr.simulatedValues_computer_name,
        conr.simulatedValues_temp_file_prefix,
        conr.simulatedValues_default_registry_value,
        conr.simulatedValues_computer_ip_address,
        conr.simulatedValues_timezone,
        conr.simulatedValues_system_time_since_epoch,
        conr.simulatedValues_system_uptime_minutes,
        conr.simulatedValues_clipboard_data,
        conr.simulatedValues_users,
        conr.simulatedValues_drive_letter,
        conr.simulatedValues_start_directory,
        False,
    ]

    listofSyscalls = []
    for osv in syscallSelection:
        if osv.toggle:
            listofSyscalls.append(osv.code)
    listofStrings.append("selected_syscalls")
    listofBools.append(listofSyscalls)

    for booli, boolStr in zip(listofBools, listofStrings):
        configOptions[boolStr] = booli

    configOptions["windows_version"] = em.winVersion
    configOptions["windows_release_osbuild"] = em.winSP
    configOptions["windows_syscall_code"] = emuSyscallCode
    configOptions["timeless_debugging_stack"] = em.timeless_debugging_stack
    configOptions["ccc_stack_amount_to_save_for_each_ccc_object"] = (
        em.codeCoverageStackAmt
    )
    configOptions["ccc_write_to_temp_file_slower"] = str(em.writeToTempFile)
    configOptions[
        "stop_executing_after_revisiting_previously_traversed_instructions_if_emu_restarted_by_ccc"
    ] = em.StopExecutingAfterTraversed
    configOptions[
        "display_non_traversed_code_and_data_as_cyan_in_disassembly_if_ccc_used"
    ] = em.displayNonTraversedCC
    configOptions["include_call_instruction_in_code_coverage"] = str(em.includeCallInCC)
    configOptions["display_ccc_debug_info_on_screen"] = em.showCCDebugInfo
    configOptions["include_jmp_instruction_in_code_coverage"] = em.includeJmpInCC
    configOptions["exclude_jmp_call_addresses_in_json"] = em.excludeJmpCallCoverage
    # print (configOptions)


def emulationConf(conr):
    global bPrintEmulation
    global emulation_verbose
    global emulation_multiline
    global emuObj
    global emuSyscallCode
    global emuSyscallSelection

    bPrintEmulation = conr.getboolean("SHAREM EMULATION", "print_emulation_result")
    emulation_verbose = conr.getboolean("SHAREM EMULATION", "emulation_verbose_mode")
    emulation_multiline = conr.getboolean("SHAREM EMULATION", "emulation_multiline")
    emuObj.maxEmuInstr = int(conr["SHAREM EMULATION"]["max_num_of_instr"])
    em.maxCounter = int(conr["SHAREM EMULATION"]["max_num_of_instr"])
    emuObj.numOfIter = int(conr["SHAREM EMULATION"]["iterations_before_break"])
    em.maxLoop = int(conr["SHAREM EMULATION"]["iterations_before_break"])

    emuObj.breakLoop = conr.getboolean("SHAREM EMULATION", "break_infinite_loops")
    em.breakOutOfLoops = conr.getboolean("SHAREM EMULATION", "break_infinite_loops")
    emuObj.verbose = conr.getboolean("SHAREM EMULATION", "timeless_debugging")
    em.timeless_debugging_stack = conr.getboolean(
        "SHAREM EMULATION", "timeless_debugging_stack"
    )

    em.codeCoverage = conr.getboolean("SHAREM EMULATION", "complete_code_coverage")

    em.winVersion = conr["SHAREM EMULATION"]["windows_version"]
    em.winSP = conr["SHAREM EMULATION"]["windows_release_osbuild"]
    emuSyscallCode = conr["SHAREM EMULATION"]["windows_syscall_code"]

    validKeys = emuSyscallSelection.keys()
    foundKey = False
    for key in validKeys:
        if emuSyscallCode == key:
            emuSyscallSelection[key][0] = True
            foundKey = True
        else:
            emuSyscallSelection[key][0] = False
    if not foundKey:
        print("Invalid code in config for windows_syscall_code.")


def codeCoverageConf(conr):
    global bPrintEmulation
    global emulation_verbose
    global emulation_multiline
    global emuObj
    global emuSyscallCode
    global emuSyscallSelection

    em.writeToTempFile = conr.getboolean(
        "COMPLETE CODE COVERAGE CCC", "ccc_write_to_temp_file_slower"
    )
    em.StopExecutingAfterTraversed = conr.getboolean(
        "COMPLETE CODE COVERAGE CCC",
        "stop_executing_after_revisiting_previously_traversed_instructions_if_emu_restarted_by_ccc",
    )
    em.displayNonTraversedCC = conr.getboolean(
        "COMPLETE CODE COVERAGE CCC",
        "display_non_traversed_code_and_data_as_cyan_in_disassembly_if_CCC_used",
    )
    em.includeCallInCC = conr.getboolean(
        "COMPLETE CODE COVERAGE CCC", "include_call_instruction_in_code_coverage"
    )
    em.showCCDebugInfo = conr.getboolean(
        "COMPLETE CODE COVERAGE CCC", "display_ccc_debug_info_on_screen"
    )
    em.codeCoverageStackAmt = int(
        conr["COMPLETE CODE COVERAGE CCC"][
            "ccc_stack_amount_to_save_for_each_ccc_object"
        ]
    )
    em.includeJmpInCC = conr.getboolean(
        "COMPLETE CODE COVERAGE CCC", "include_jmp_instruction_in_code_coverage"
    )
    em.excludeJmpCallCoverage = conr.getboolean(
        "COMPLETE CODE COVERAGE CCC", "exclude_jmp_call_addresses_in_json"
    )


def emulationSimValueConf(conr):
    global emuSimVals
    global SimFileSystem

    conr.simulatedValues_current_user = conr["SHAREM EMULATION SIMULATED VALUES"][
        "current_user"
    ]
    conr.simulatedValues_computer_name = conr["SHAREM EMULATION SIMULATED VALUES"][
        "computer_name"
    ]
    conr.simulatedValues_temp_file_prefix = conr["SHAREM EMULATION SIMULATED VALUES"][
        "temp_file_prefix"
    ]
    conr.simulatedValues_default_registry_value = conr[
        "SHAREM EMULATION SIMULATED VALUES"
    ]["default_registry_value"]
    conr.simulatedValues_computer_ip_address = conr[
        "SHAREM EMULATION SIMULATED VALUES"
    ]["computer_ip_address"]
    conr.simulatedValues_timezone = conr["SHAREM EMULATION SIMULATED VALUES"][
        "timezone"
    ]
    conr.simulatedValues_system_time_since_epoch = int(
        conr["SHAREM EMULATION SIMULATED VALUES"]["system_time_since_epoch"]
    )
    conr.simulatedValues_system_uptime_minutes = int(
        conr["SHAREM EMULATION SIMULATED VALUES"]["system_uptime_minutes"]
    )
    conr.simulatedValues_clipboard_data = conr["SHAREM EMULATION SIMULATED VALUES"][
        "clipboard_data"
    ]
    conr.simulatedValues_users = ast.literal_eval(
        conr["SHAREM EMULATION SIMULATED VALUES"]["users"]
    )
    conr.simulatedValues_drive_letter = conr["SHAREM EMULATION SIMULATED VALUES"][
        "drive_letter"
    ]
    conr.simulatedValues_start_directory = conr["SHAREM EMULATION SIMULATED VALUES"][
        "start_directory"
    ]

    # Create Simulated File System
    SimFileSystem.InitializeFileSystem()


def SharemSearchConfig(conr):
    global bPushRet
    global bCallPop
    global bFstenv
    global bSyscall
    global bHeaven
    global bPEB
    global bDisassembly
    global pebPoints
    global bit32
    global p2screen
    global bytesForward
    global bytesBack
    global linesForward
    global linesBack
    global print_style
    global save_bin_file
    global shellEntry
    global sharem_out_dir
    global maxDistance
    global bpEvilImports
    global maxZeroes
    # max_num_of_zeroes

    sharem_out_dir = conr["SHAREM SEARCH"]["default_outdir"]
    maxDistance = int(conr["SHAREM SEARCH"]["max_callpop_distance"])
    maxZeroes = int(conr["SHAREM SEARCH"]["max_num_of_zeroes"])
    bPushRet = conr.getboolean("SHAREM SEARCH", "pushret")
    bCallPop = conr.getboolean("SHAREM SEARCH", "callpop")
    bFstenv = conr.getboolean("SHAREM SEARCH", "fstenv")
    bSyscall = conr.getboolean("SHAREM SEARCH", "syscall")
    bHeaven = conr.getboolean("SHAREM SEARCH", "heaven")
    bPEB = conr.getboolean("SHAREM SEARCH", "peb")
    save_bin_file = conr.getboolean("SHAREM SEARCH", "save_bin_file")
    bDisassembly = conr.getboolean("SHAREM SEARCH", "disassembly")
    pebPresent = conr.getboolean("SHAREM SEARCH", "pebpresent")

    bpEvilImports = conr.getboolean("SHAREM SEARCH", "imports")

    if rawHex and not bit32_argparse:
        bit32 = conr.getboolean("SHAREM SEARCH", "bit32")

        if bit32:
            variables.shellBit = 32
        else:
            variables.shellBit = 64

    p2screen = conr.getboolean("SHAREM SEARCH", "print_to_screen")
    pebPoints = int(conr["SHAREM SEARCH"]["pebpoints"])
    if pebPoints > 4:
        pebPoints = 4
    try:
        shellEntry = int(conr["SHAREM SEARCH"]["shellEntry"])
    except:
        shellEntry = int(conr["SHAREM SEARCH"]["shellEntry"], 16)
    try:
        em.entryOffset = shellEntry
    # except:
    except Exception as e:
        print("Config error: emu object not initialized. 2")
        print(e)
        print(traceback.format_exc())
    try:
        bytesForward = int(conr["SHAREM SEARCH"]["max_bytes_forward"])
    except:
        bytesForward = int(conr["SHAREM SEARCH"]["max_bytes_forward"], 16)

    try:
        bytesBack = int(conr["SHAREM SEARCH"]["max_lines_backward"])
    except:
        bytesBack = int(conr["SHAREM SEARCH"]["max_lines_backward"], 16)

    try:
        linesForward = int(conr["SHAREM SEARCH"]["max_lines_forward"])
    except:
        linesForward = int(conr["SHAREM SEARCH"]["max_lines_forward"], 16)

    try:
        linesBack = int(conr["SHAREM SEARCH"]["max_lines_backward"])
    except:
        linesBack = int(conr["SHAREM SEARCH"]["max_lines_backward"], 16)

    print_style = conr["SHAREM SEARCH"]["print_format_style"]


def stringsConf(conr):
    global bPushStackStrings
    global bWideCharStrings
    global bAsciiStrings
    global minStrLen

    bPushStackStrings = conr.getboolean("SHAREM STRINGS", "push_stack_strings")

    bAsciiStrings = conr.getboolean("SHAREM STRINGS", "ascii_strings")
    bWideCharStrings = conr.getboolean("SHAREM STRINGS", "wide_char_strings")
    minStrLen = int(conr["SHAREM STRINGS"]["minimum_str_length"])


def decryptConf(conr):
    global dFastMode
    global dFindAll
    global dDistr
    global dCPUcount
    global dNodesFile
    global dOutputFile
    global decryptOpTypes
    global decryptFile
    global stubFile
    global sameFile
    global stubEntry
    global stubEnd

    dFastMode = conr.getboolean("SHAREM DECRYPT", "fast_mode")
    dFindAll = conr.getboolean("SHAREM DECRYPT", "find_all")
    dDistr = conr.getboolean("SHAREM DECRYPT", "dist_mode")
    dOutputFile = conr.getboolean("SHAREM DECRYPT", "output_file")
    try:
        dCPUcount = int(conr["SHAREM DECRYPT"]["cpu_count"])
    except:
        dCPUcount = "auto"
    dNodesFile = conr["SHAREM DECRYPT"]["nodes_file"]
    if not (os.path.exists(dNodesFile)):
        # print(constants.RED +"\n\nConfig file Error:", constants.YELLOW + dNodesFile + res, constants.RED + "doesn't exist!" + res)
        pass
    decryptOpTypes = conr["SHAREM DECRYPT"]["dec_operation_type"]
    try:
        decryptOpTypes = ast.literal_eval(decryptOpTypes)
    except:
        print(
            constants.YELLOW + "The value of",
            constants.RED + decryptOpTypes,
            constants.YELLOW + "is not correct or malformed!!" + res,
        )
        sys.exit()
    decryptFile = conr["SHAREM DECRYPT"]["decrypt_file"]
    if not (os.path.exists(decryptFile)):
        # print(constants.RED +"\n\nConfig file Error:", constants.YELLOW + decryptFile + res, constants.RED + "doesn't exist!" + res)
        pass
    stubFile = conr["SHAREM DECRYPT"]["stub_file"]
    if not (os.path.exists(stubFile)):
        # print(constants.RED +"\n\nConfig file Error:", constants.YELLOW + stubFile + res, constants.RED + "doesn't exist!" + res)
        pass
    sameFile = conr.getboolean("SHAREM DECRYPT", "use_same_file")
    try:
        stubEntry = int(conr["SHAREM DECRYPT"]["stub_entry_point"])
    except:
        stubEntry = int(conr["SHAREM DECRYPT"]["stub_entry_point"], 16)

    try:
        stubEnd = int(conr["SHAREM DECRYPT"]["stub_end"])
    except:
        stubEnd = int(conr["SHAREM DECRYPT"]["stub_end"], 16)


def syscallsConf(conr):
    global syscallSelection

    initSysCallSelect()

    list_of_syscalls = str(conr["SHAREM SYSCALLS"]["selected_syscalls"])

    try:
        list_of_syscalls = ast.literal_eval(list_of_syscalls)
        if type(list_of_syscalls) != list:
            print("Error:", list_of_syscalls, "<-- this should be a list.")

    except:
        print(
            constants.YELLOW + "The value of",
            constants.RED + list_of_syscalls,
            constants.YELLOW + "is not correct or malformed!!" + res,
        )
        sys.exit()

    for selected in list_of_syscalls:
        for osv in syscallSelection:
            if osv.code == selected:
                osv.toggle = True


def printStyleConf(conr):
    global print_style

    # print_format_style = left
    print_style = str(conr["SHAREM SEARCH"]["print_format_style"])
    if print_style != "right" and print_style != "left":
        print(
            constants.YELLOW
            + "\n\nError: format style in config file is not correct."
            + res,
            constants.RED + print_style + constants.RESET,
            constants.YELLOW + "<-- should be either right, or left." + constants.RESET,
        )
        sys.exit()


def patternConf(conr):
    global patt
    # patt.setPatterns(int(conr['SHAREM PATTERNS']['path_pattern']))
    patt.path_pattern = int(conr["SHAREM PATTERNS"]["path_pattern"])
    patt.lang_pattern = int(conr["SHAREM PATTERNS"]["lang_code_pattern"])
    patt.dotted_w_pattern = int(conr["SHAREM PATTERNS"]["dotted_word_pattern"])
    patt.variable_pattern = int(conr["SHAREM PATTERNS"]["variable_pattern"])


def readConf(variables: Variables):
    con = Configuration(conFile)
    conr = con.readConf()

    decryptConf(conr)
    SharemSearchConfig(conr)
    con.disassemblyConf(conr, variables)
    emulationConf(conr)
    emulationSimValueConf(conr)
    stringsConf(conr)
    syscallsConf(conr)
    printStyleConf(conr)
    patternConf(conr)
    codeCoverageConf(conr)
    startupBool = conr.getboolean("SHAREM STARTUP", "startup_enabled")

    return startupBool


def discoverUnicodeStrings(
    pe: typing.Union[pefile.PE, shellcode],
    variables: Variables,
    module,
    shellcode_label,
    max_len=None,
):
    global bWideCharStrings

    if not max_len:
        max_len = 42
    variables.moduleBooleans[shellcode_label].bWideStringFound = False
    print("\n" + constants.YELLOW + " Finding unicode strings..", end="")
    curLen = len("Finding unicode strings..")

    if variables.rawHex:
        findStringsWide(module[shellcode_label].rawData2, 3)
        if len(stringsTempWide) > 0:
            variables.moduleBooleans[shellcode_label].bWideStringFound = True
            variables.moduleBooleans[shellcode_label].bStringsFound = True
    else:
        t = 0
        for sec in pe.sections:
            if (
                variables.moduleBooleans[shellcode_label].bWideCharStrings
                and not variables.moduleBooleans[shellcode_label].bWideStringFound
            ):
                findStringsWide(s[t].data2, minStrLen)
            t += 1
        t = 0
        variables.moduleBooleans[shellcode_label].bWideStringFound = False
        for sec in pe.sections:
            if len(s[t].wideStrings) > 0:
                variables.moduleBooleans[shellcode_label].bWideStringFound = True
                variables.moduleBooleans[shellcode_label].bStringsFound = True

            t += 1
    if variables.moduleBooleans[shellcode_label].bWideStringFound:
        print(
            "{:>{x}}{}".format(
                "",
                constants.GREEN + "[Found]" + constants.RESET,
                x=15 + (max_len - curLen),
            )
        )
    else:
        print(
            "{:>{x}}{}".format(
                "",
                constants.RED + "[Not Found]" + constants.RESET,
                x=15 + (max_len - curLen),
            )
        )


def discoverAsciiStrings(
    pe: typing.Union[pefile.PE, shellcode],
    variables: Variables,
    module,
    shellcode_label,
    max_len=None,
):
    if max_len == None:
        max_len = 42

    curLen = len("Finding Ascii strings..")
    print(constants.YELLOW + " Finding Ascii strings.." + constants.RESET, end="")
    if variables.rawHex:
        findStrings(module[shellcode_label].rawData2, 3)
        if len(stringsTemp) > 0:
            variables.moduleBooleans[shellcode_label].bStringsFound = True
    else:
        t = 0
        for sec in pe.sections:
            if (
                variables.moduleBooleans[shellcode_label].bAsciiStrings
                and not variables.moduleBooleans[shellcode_label].bStringsFound
            ):
                findStrings(s[t].data2, minStrLen)
            t += 1
        t = 0
        for sec in pe.sections:
            if len(s[t].Strings) > 0:
                variables.moduleBooleans[shellcode_label].bStringsFound = True
            t += 1
    if variables.moduleBooleans[shellcode_label].bStringsFound:
        print(
            "{:>{x}}{}".format(
                "",
                constants.GREEN + "[Found]" + constants.RESET,
                x=15 + (max_len - curLen),
            )
        )
    else:
        print(
            "{:>{x}}{}".format(
                "",
                constants.RED + "[Not Found]" + constants.RESET,
                x=15 + (max_len - curLen),
            )
        )


def discoverStackStrings(
    pe: typing.Union[pefile.PE, shellcode],
    variables,
    module,
    shellcode_label,
    max_len=None,
):
    global bPushStackStrings
    if max_len == None:
        max_len = 42

    print(constants.YELLOW + " Finding push stack strings..", end="")
    curLen = len("Finding push stack strings..")
    if variables.rawHex:
        findPushAsciiMixed(module[shellcode_label].rawData2, 3)
        if len(pushStringsTemp) > 0:
            variables.moduleBooleans[shellcode_label].bPushStringsFound = True
    else:
        t = 0
        for sec in pe.sections:
            if (
                bPushStackStrings
                and not variables.moduleBooleans[shellcode_label].bPushStringsFound
            ):
                findPushAsciiMixed(s[t].data2, 5, t)
            t += 1
        t = 0
        for sec in pe.sections:
            if len(s[t].pushStrings) > 0:
                variables.moduleBooleans[shellcode_label].bPushStringsFound = True
            t += 1
    if variables.moduleBooleans[shellcode_label].bPushStringsFound:
        print(
            "{:>{x}}{}".format(
                "",
                constants.GREEN + "[Found]" + constants.RESET,
                x=15 + (max_len - curLen),
            )
        )
    else:
        print(
            "{:>{x}}{}".format(
                "",
                constants.RED + "[Not Found]" + constants.RESET,
                x=15 + (max_len - curLen),
            )
        )


class emulationOptions:
    def __init__(self):
        self.verbose = False
        self.timeless_debugging_stack = False
        self.maxEmuInstr = 500000
        self.cpuArch = 32
        self.breakLoop = True
        self.numOfIter = 30000


def under_dev_function() -> None:
    """Display message indicating feature is under development."""
    print(constants.RED + "\tThis feature is under development.\n" + constants.RESET)


def emulationEntryPoint():
    while True:
        etrPoint = input(" Enter new entry point: ")
        if etrPoint == "exit" or etrPoint == "x":
            return
        try:
            etrPoint = int(etrPoint)
            em.entryOffset = etrPoint
            print(" Emulation entry point has been changed.")
            break
        except Exception:
            # print(e)
            print(" Please enter an integer")


def emuCheckDeobfSuccess(shell_code: shellcode):
    if fRaw.status():
        ssdeepHash1 = ssdeep.hash(fRaw.originalRaw)
        ssdeepHash2 = ssdeep.hash(fRaw.merged2)

        percent = ssdeep.compare(ssdeepHash1, ssdeepHash2)
        if percent < 60:
            t = 0
            stop = False
            notEqual = False
            decoderEnd = 0
            try:
                for t, each in enumerate(fRaw.originalRaw):
                    if fRaw.merged2[:t] != fRaw.originalRaw[:t]:
                        if not notEqual:
                            notEqual = True
                            mode = "stub"
                            decoderEnd = t - 1
                            break
            except:
                stop = True
                mode = "notstub"  # maybe build this later?

            if not stop:
                print("  SSDeep: Only " + str(percent) + "% of the original shellcode.")
                shell_code.setDecoderStubEnd(decoderEnd)
                shell_code.setDecoderStub(fRaw.originalRaw[:decoderEnd])
                shell_code.setDecodedBody(fRaw.merged2[decoderEnd:])
                shell_code.isEncoded = True

    (decoderstub_hash, decodedfullbody_hash, unencrypted_shell_hash) = emuDeobfuSuccess(
        fRaw.merged2, mode
    )


def emuCCCSubmenu():
    global emuObj
    global shellEntry
    global bit32
    em.maxCounter = emuObj.maxEmuInstr
    global emulation_verbose
    global emulation_multiline

    while True:
        print(
            constants.YELLOW
            + " Sharem>"
            + constants.CYAN
            + "Emulator>"
            + constants.GREEN
            + "CompleteCodeCoverage> "
            + constants.RESET,
            end="",
        )
        choice = input()
        if choice == "x":
            return
        elif choice == "t":
            em.StopExecutingAfterTraversed = not em.StopExecutingAfterTraversed
            if em.StopExecutingAfterTraversed:
                print(
                    "\tComplete code coverage will stop after revisiting previously traversed code."
                )
            else:
                print(
                    "\tComplete code coverage will continue after revisiting previously traversed code."
                )
        elif choice == "c":
            em.includeCallInCC = not em.includeCallInCC
            if em.includeCallInCC:
                print("\tComplete code coverage will include CALL.")
            else:
                print("\tComplete code coverage will exclude CALL.")
        elif choice == "w":
            em.writeToTempFile = not em.writeToTempFile
            if em.writeToTempFile:
                print("\tSHAREM will write temporary file to disk for code coverage.")
            else:
                print("\tSHAREM will not use temporary files for code coverage.")
        elif choice == "d":
            em.showCCDebugInfo = not em.showCCDebugInfo
            if em.showCCDebugInfo:
                print(
                    "\tSHAREM will display verbose debugging information pertaining to code coverage."
                )
            else:
                print(
                    "\tSHAREM has disabled verbose debugging information pertaining to code coverage."
                )
        elif choice == "o":
            em.displayNonTraversedCC = not em.displayNonTraversedCC
            if em.displayNonTraversedCC:
                print(
                    "\tSHAREM will color the offsets for non-traversed code or data in cyan, if complete code coverage\n\tis enabled."
                )
            else:
                print("\tAll offsets will remain green.")
        elif choice == "j":
            em.includeJmpInCC = not em.includeJmpInCC
            if em.includeJmpInCC:
                print("\tComplete code coverage will include JMP.")
            else:
                print("\tComplete code coverage will exclude JMP.")
        elif choice == "e":
            em.excludeJmpCallCoverage = not em.excludeJmpCallCoverage
            if em.excludeJmpCallCoverage:
                print(
                    "\tComplete code coverage will now "
                    + constants.MAGENTA
                    + "exclude addresses"
                    + constants.RESET
                    + " that immediately follow a CALL or JMP.\n\tThese must be provided in the JSON. Give the address followed by the size of the region.\n\t\tE.g."
                    + constants.CYAN
                    + ' {"0x12000005": 4, "0xdeadc0de": 3}'
                    + constants.RESET
                    + "\n\tAddresses from 0x12000005 thru 0x12000008 would be excluded. The base address is 0x12000000.\n\tAdd offset to base address.\n\n\tThe JSON may be found at "
                    + constants.MAGENTA
                    + "sharem\\sharem\\sharem\\sharem\\skipAddressesCCC.json"
                    + constants.RESET
                    + ".\n\n\tThis feature ordinarily would not be used, but could be useful in cases where DATA immediately\n\tfollows a JMP. We generally do not recommend including JMP for complete code coverage, unless \n\tyou are trying to get coverage for something like jump tables.\n"
                )
            else:
                print(
                    "\tNo addresses after JMP or CALL will be excluded from code coverage."
                )

        elif choice == "s":
            while True:
                try:
                    sSize = input(
                        "\tPlease enter the respective sizes for memory pointed to by ESP and EBP: "
                    )
                    if sSize == "x":
                        break
                    try:
                        sSize = int(sSize)
                    except:
                        sSize = int(sSize, 16)

                    em.codeCoverageStackAmt = sSize
                    print(
                        "\tStack size for each is "
                        + str(em.codeCoverageStackAmt)
                        + " ("
                        + hex(em.codeCoverageStackAmt)
                        + ") bytes."
                    )
                    break
                except:
                    print(constants.RED + "\tPlease enter only a number." + res)
                    break
        elif choice == "r":
            em.codeCoverageStackAmt = 4000
            em.writeToTempFile = False
            em.StopExecutingAfterTraversed = True
            em.displayNonTraversedCC = True
            em.includeCallInCC = True
            em.showCCDebugInfo = False
            em.includeJmpInCC = False
            em.excludeJmpCallCoverage = False
            print("\tReset to defaults.")

        elif choice == "h":
            emuCodeCoverageUI()


def emulationSubmenu():
    global emuObj
    global shellEntry
    global bit32
    em.maxCounter = emuObj.maxEmuInstr
    global emulation_verbose
    global emulation_multiline

    while True:
        print(
            constants.YELLOW
            + " Sharem>"
            + constants.CYAN
            + "Emulator> "
            + constants.RESET,
            end="",
        )
        choice = input()
        if choice == "z":
            startEmu(m[o].rawData2, emuObj.verbose, fRaw)
            emulation_txt_out(loggedList, logged_syscalls)
            emuCheckDeobfSuccess()
        elif choice == "x":
            return

        if choice == "p":
            under_dev_function()
            if False:
                if emulation_verbose:
                    emulation_verbose = False
                    print(constants.CYAN + " Emulation verbose mode disabled.\n" + res)
                else:
                    emulation_verbose = True
                    print(constants.CYAN + " Emulation verbose mode enabled.\n" + res)

        elif choice == "h":
            emulatorUI(emuObj, emulation_multiline, emulation_verbose)
        elif choice == "wOld":
            emulationEntryPoint()
        elif choice == "v":
            print("\tVerbosity changed.\n")
            emuObj.verbose = not emuObj.verbose
        elif choice == "t":
            if not em.timeless_debugging_stack:
                print("\tStack timeless debugging enabled.\n")
            else:
                print("\tStack timeless debugging disabled.\n")
            emuObj.timeless_debugging_stack = not emuObj.timeless_debugging_stack
            em.timeless_debugging_stack = not em.timeless_debugging_stack
        elif choice == "w":
            print("\tPrint style of artifacts changed.\n")
            emulation_multiline = not emulation_multiline
        elif choice == "b":
            if not em.breakOutOfLoops:
                em.breakOutOfLoops = True
                emuObj.breakLoop = True
                print("\tBreaking out of loops enabled.\n")
            elif em.breakOutOfLoops:
                em.breakOutOfLoops = False
                emuObj.breakLoop = False
                print("\tBreaking out of loops disabled.\n")
        elif choice == "c":
            if not em.codeCoverage:
                em.codeCoverage = True
                print("\tCode coverage enabled.\n")
            elif em.codeCoverage:
                em.codeCoverage = False
                print("\tCode coverage disabled.\n")

        elif choice == "m":
            while True:
                try:
                    minst = input("\tEnter maximum number of instructions to emulate: ")
                    if minst == "x":
                        break
                    try:
                        minst = int(minst)
                    except:
                        minst = int(minst, 16)

                    emuObj.maxEmuInstr = minst
                    em.maxCounter = minst
                    # sharemu.maxCounter = minst
                    break
                except:
                    print(constants.RED + "\tPlease enter only a number." + res)
                    break
        elif choice == "e":
            while True:
                try:
                    sEinst = input("\tEnter shellcode entrypoint: ")
                    if sEinst == "x":
                        break
                    try:
                        sEinst = int(sEinst)
                    except:
                        sEinst = int(sEinst, 16)
                    shellEntry = sEinst
                    em.entryOffset = sEinst
                    # sharemu.maxCounter = minst
                    break
                except:
                    print(constants.RED + "\tPlease enter only a number." + res)
                    break

        elif choice == "n":
            while True:
                try:
                    bLinst = input("\tBreak out of loops after how many instructions: ")
                    if bLinst == "x":
                        break
                    try:
                        bLinst = int(bLinst)
                    except:
                        bLinst = int(bLinst, 16)

                    emuObj.numOfIter = bLinst
                    em.maxLoop = bLinst
                    # print (emuObj.numOfIter, em.maxLoop)
                    break
                except:
                    print(constants.RED + "\tPlease enter only a number." + res)
                    break
        elif choice == "a":
            under_dev_function()

        elif choice == "s":
            # syscallSelectionMenu()
            emuSyscallSubMenu()

        elif choice == "d":
            emuSimValuesMenu()
        elif choice == "o":
            emuCodeCoverageUI()
            emuCCCSubmenu()


def startupPrint(
    shell_code: shellcode,
    shellcode_label,
    variables: Variables,
    conr: Configuration,
    module,
):
    global minStrLen
    global modulesMode
    elapsed_time = 0.0

    # minStrLen = 7
    l_of_strings = [
        "Finding Ascii strings..",
        "Finding unicode strings..",
        "Finding push stack strings..",
        "Searching for disassembly..",
        "Searching for Fstenv instructions..",
        "Searching for push ret instructions..",
        "Searching for call pop instructions..",
        "Searching for heaven's gate instructions..",
        "Searching for syscall instructions..",
        "Searching for PEB instructions..",
    ]
    max_len = get_max_length(l_of_strings)

    # print ("\n\n Analyzing ", filename)
    if (
        bPrintEmulation
        and not variables.moduleBooleans[shellcode_label].bEmulationFound
    ):
        newTime = discoverEmulation(max_len)
        elapsed_time += newTime

    print(constants.CYAN + "\n\n Finding Strings\n\n" + constants.RESET)

    if (
        variables.moduleBooleans[shellcode_label].bAsciiStrings
        and not variables.moduleBooleans[shellcode_label].bStringsFound
    ):
        discoverAsciiStrings(shell_code, variables, module, shellcode_label, max_len)
    if (
        variables.moduleBooleans[shellcode_label].bWideCharStrings
        and not variables.moduleBooleans[shellcode_label].bWideStringFound
    ):
        discoverUnicodeStrings(shell_code, variables, module, shellcode_label, max_len)
    if (
        variables.moduleBooleans[shellcode_label].bPushStackStrings
        and not variables.moduleBooleans[shellcode_label].bPushStringsFound
    ):
        discoverStackStrings(shell_code, variables, module, shellcode_label, max_len)

    print("\n\n")
    if (
        variables.moduleBooleans[shellcode_label].bFstenv
        and not variables.moduleBooleans[shellcode_label].bFstenvFound
    ):
        newTime = discoverFstenv(
            shell_code, variables, module, shellcode_label, max_len
        )
        elapsed_time += newTime

    if (
        variables.moduleBooleans[shellcode_label].bPushRet
        and not variables.moduleBooleans[shellcode_label].bPushRetFound
    ):
        newTime = discoverPushRet(
            shell_code, variables, module, shellcode_label, max_len
        )
        elapsed_time += newTime

    if (
        variables.moduleBooleans[shellcode_label].bCallPop
        and not variables.moduleBooleans[shellcode_label].bCallPopFound
    ):
        newTime = discoverCallPop(
            shell_code, variables, module, shellcode_label, max_len
        )
        elapsed_time += newTime

    if (
        variables.moduleBooleans[shellcode_label].bHeaven
        and not variables.moduleBooleans[shellcode_label].bHeavenFound
    ):
        newTime = discoverHeaven(
            shell_code, variables, module, shellcode_label, max_len
        )
        elapsed_time += newTime

    if (
        variables.moduleBooleans[shellcode_label].bSyscall
        and not variables.moduleBooleans[shellcode_label].bSyscallFound
    ):
        newTime = discoverSyscal(
            shell_code, variables, module, shellcode_label, max_len
        )
        elapsed_time += newTime

    if (
        variables.moduleBooleans[shellcode_label].bPEB
        and not variables.moduleBooleans[shellcode_label].bPEBFound
    ):
        newTime = discoverPEB(shell_code, variables, module, shellcode_label, max_len)
        elapsed_time += newTime

    if (
        variables.moduleBooleans[shellcode_label].bDisassembly
        and not variables.moduleBooleans[shellcode_label].bDisassemblyFound
    ):
        newTime = discoverDisassembly(
            shell_code, variables, module, shellcode_label, max_len
        )
        elapsed_time += newTime

    if (
        variables.moduleBooleans[shellcode_label].bpEvilImports
        and not variables.moduleBooleans[shellcode_label].bEvilImportsFound
    ):
        if not variables.rawHex:
            findEvilImports()

            print(showImports())
    if not variables.rawHex:
        modulesMode = 3
        runInMem()
        print(giveLoadedModules())
        giveLoadedModules("save")

    starTime = time.time()
    if variables.rawHex:
        shellClass = isShellcode(
            variables.moduleBooleans[shellcode_label], patt, shell_code, conr
        )
    endTime = time.time() - starTime

    if variables.rawHex:
        print(
            constants.CYAN + "\n Classification: ",
            constants.YELLOW + shellClass[0] + constants.RESET,
        )
        if shellClass[1]:
            print(
                constants.CYAN + "\n Reason:",
                constants.YELLOW + shellClass[1] + constants.RESET,
            )
    elapsed_time += endTime
    # Saving data

    outputData = generateOutputData(shell_code, rawHex, conr)
    print(constants.CYAN + "\n\nSaving to Json...", end="")
    printToJson(outputData, filename, rawHex, sharem_out_dir, FoundApisName)
    print(constants.GREEN + "Done" + constants.RESET)

    print(constants.CYAN + "\nSaving to Text...", end="")

    printToText(outputData)
    print(constants.GREEN + "Done\n\n" + constants.RESET)

    print(" Elapsed time: ", elapsed_time)

    return outputData


def saveConf(con):
    global configOptions
    try:
        con.changeConf(configOptions)
        con.save()
        con.changeConf(configOptions)
        con.save()
        print(constants.YELLOW + " Configuration has been Saved.\n" + constants.RESET)
    except Exception as e:
        print(constants.YELLOW + "Could not save configuration." + constants.RESET, e)


def notAvailable(rawHex: bool):
    """Print error message for features that are not available for the type of file."""
    if rawHex:
        print(
            constants.RED
            + "  This option is not available for shellcode."
            + constants.RESET
        )
    else:
        print(
            constants.RED
            + "   This option is not available for a PE file."
            + constants.RESET
        )


def ui(
    shell_code: shellcode,
    shellcode_label,
    variables: Variables,
    conr: Configuration,
    module,
):  # UI menu loop
    global maxDistance  # Max distance that a callpop can call
    # Disassembly option variables
    global linesForward
    global linesBack
    global bytesForward
    global bytesBack
    global bit32
    global syscallSelection  # Array of osversions for syscall
    global showDisassembly  # Show dis on syscall submenu
    global minStrLen  # Min len of strings to search for
    global modulesMode  # For option selection in uiModulesSubMenu()
    global pushStringRegisters  # The register setup for pushString emulation
    global stringsDeeper  # Do a deeper search for goodstrings
    global stringReadability  # What % of string should be letters, numbers, or spaces
    global checkGoodStrings  # Whether or not we check if a string is good
    global shellEntry

    global configOptions
    global emuObj

    stringsDeeper = False
    checkGoodStrings = True
    modulesMode = 3
    pushStringRegisters = "unset"
    showDisassembly = True
    stringReadability = 0.65
    clearConsole()

    x = ""
    showOptions(
        variables.shellBit,
        rawHex,
        module[shellcode_label].name,
        module[shellcode_label].getMd5(),
    )
    while x != "e":  # Loops on keyboard input
        try:  # Will break the loop on entering x
            print(constants.YELLOW + " Sharem> " + constants.RESET, end="")
            userIN = input()
            print(constants.RESET)
            if userIN[0:1] == "x":
                print("\nExiting program.\n")
                break

            elif userIN[0:1] == "h":
                showOptions(
                    variables.shellBit,
                    rawHex,
                    module[shellcode_label].name,
                    module[shellcode_label].getMd5(),
                )

            elif userIN[0:1] == "D":
                if not rawHex:
                    print("\nThis option is for shellcode only.\n")
                else:
                    shellDisassemblyInit(rawData2)
                    createDisassemblyJson()
            elif userIN[0:1] == "d":
                if not rawHex:
                    notAvailable(rawHex)
                else:
                    disToggleMenu(
                        shellEntry,
                        shellSizeLimit,
                        variables.moduleBooleans[shellcode_label].bPreSysDisDone,
                        toggList,
                    )

                    disassembleSubMenu()
            elif (
                userIN[0:1] == "s"
            ):  # "find assembly instrucitons associated with shellcode"
                uiDiscover(shell_code, variables, module, shellcode_label)

            elif userIN[0:1] == "l":
                if rawHex:
                    em.arch = variables.shellBit
                    emulatorUI(emuObj, emulation_multiline, emulation_verbose)
                    emulationSubmenu()
                else:
                    notAvailable(rawHex)
            elif re.match("^b$", userIN):
                if rawHex:
                    decryptUI()
                else:
                    notAvailable(rawHex)

            elif userIN[0:1] == "U" or userIN[0:1] == "u":
                if rawHex:
                    toggleDecodedModule(shell_code)
                else:
                    notAvailable(rawHex)

            elif userIN[0:1] == "a":  # "change architecture, 32-bit or 64-bit"
                uiBits()
                initSysCallSelect()

            elif re.match("^c$", userIN):  # "save configuration"
                modConf()
                saveConf(con)
            elif userIN[0:1] == "z":
                startupPrint(shell_code, shellcode_label, variables, conr, module)
            elif userIN[0:2] == "ut":
                Text2Json(module[shellcode_label].rawData2)
            elif userIN[0:1] == "p":  # We want to print
                uiPrint()
            elif userIN[0:1] == "i":
                if rawHex:
                    info = showBasicInfo()
                    print(info)
                    hashShellcodeTestShow(sample)
                    # print("No PE file selected.\n")
                else:
                    info = showBasicInfoSections()
                    print(info)
            elif userIN[0:1] == "k":
                uiFindStrings()
                # print("\nReturning to main menu.\n")
            elif userIN[0:2] == "j!":
                uiShellcodeStrings()  ### deprecated
                # print("\nReturning to main menu.\n")
            elif userIN[0:1] == "e":  # "find imports"
                if not rawHex:
                    uiFindImports()
                else:
                    notAvailable(rawHex)
            elif userIN[0:1] == "q":  # "quick find all"
                findAll()
            elif userIN[0:1] == "o":
                saveBinAscii()  # "output bins and ascii"
            elif userIN[0:1] == "m":  # "find modules in the iat and beyond"
                if not rawHex:
                    uiModulesSubMenu()
                else:
                    notAvailable(rawHex)
            elif userIN[0:1] == "r":  # reset
                # SharemMainResetGlobals()
                pass
            else:
                print("\nInvalid input.\n")

        except Exception as e:
            print(e)
            print(traceback.format_exc())
            print("exception")


def uiBits():  # Change the bit mode
    global bit32
    print("\n ........\n Bit Mode\n ........")
    printBitMenu()
    bitIN = input("> ")
    y = ""
    while True:  # Loop until we break
        if bitIN == "32":
            bit32 = True
            variables.shellBit = 32
            em.arch = 32
            print("\nBits set to 32\n")
            break
        elif bitIN == "64":
            bit32 = False
            variables.shellBit = 64
            em.arch = 64
            print("\nBits set to 64\n")
            break
        elif bitIN == "x":
            break
        else:
            print("Invalid input...\n")
        print("\n ........\nBit Mode\n ........")
        bitIN = input("> ")


def discoverEmulation(maxLen=42):
    global emuObj
    global fRaw

    start = time.time()
    if rawHex:
        curLen = len("  Emulation of shellcode...")
        print(
            constants.CYAN + " Starting emulation of shellcode..." + constants.RESET,
            flush=True,
        )

        emuArch = variables.shellBit
        startEmu(m[o].rawData2, emuObj.verbose, fRaw)
        emuCheckDeobfSuccess()
        mBool[
            o
        ].bEmulationFound = True  # if we run it, it is done - if we have not objective way of quantifying how successful it issues
        # depending on shellcode, could miss some, a lot, or be perfect. We just run it.

        print(
            constants.CYAN + " Emulation of shellcode..." + constants.RESET,
            end="",
            flush=True,
        )

        if moduleBooleans[shellcode_label].bEmulationFound:
            print(
                "{:>{x}}[{}]".format(
                    "",
                    constants.GREEN + "COMPLETED" + constants.RESET,
                    x=15 + (maxLen - curLen),
                )
            )
        else:
            print(
                "{:>{x}}[{}]".format(
                    "",
                    constants.RED + "NOT COMPLETED" + constants.RESET,
                    x=15 + (maxLen - curLen),
                )
            )
    return time.time() - start


def discoverPEB(
    shell_code: shellcode, variables: Variables, module, shellcode_label, maxLen=42
):
    start = time.time()
    curLen = len("Searching for PEB walking instructions")
    print(
        constants.CYAN + " Searching for PEB walking instructions..." + constants.RESET,
        end="",
        flush=True,
    )
    if rawHex:
        findAllPebSequences(
            "normal",
            variables,
            module,
            shellcode_label,
            module[shellcode_label].rawData2,
            "noSec",
        )
    else:
        if variables.shellBit == 64:
            data2 = 0
            secNum = 0
            findAllPebSequences(
                "normal", variables, module, shellcode_label, data2, secNum
            )
        else:
            secNum = 0
            data2 = 0
            findAllPebSequences(
                "normal", variables, module, shellcode_label, data2, secNum
            )
    for i in s:
        if len(i.save_PEB_info) > 0:
            variables.moduleBooleans[shellcode_label].bPEBFound = True
    if variables.rawHex:
        if len(module[shellcode_label].save_PEB_info) > 0:
            variables.moduleBooleans[shellcode_label].bPEBFound = True
    if variables.moduleBooleans[shellcode_label].bPEBFound:
        print(
            "{:>{x}}[{}]".format(
                "",
                constants.GREEN + "Found" + constants.RESET,
                x=15 + (maxLen - curLen),
            )
        )
    else:
        print(
            "{:>{x}}[{}]".format(
                "",
                constants.RED + "Not Found" + constants.RESET,
                x=15 + (maxLen - curLen),
            )
        )
    return time.time() - start


def discoverSyscal(
    shell_code: shellcode, variables: Variables, module, shellcode_label, maxLen=42
):
    start = time.time()
    curLen = len("Searching for Windows syscall instructions")
    print(
        constants.CYAN
        + " Searching for Windows syscall instructions..."
        + constants.RESET,
        end="",
        flush=True,
    )
    if rawHex:
        getSyscallRawHex(0, linesBack, "noSec", module[shellcode_label].rawData2)

    else:
        for secNum in range(len(s)):
            data2 = s[secNum].data2
            for match in EGGHUNT.values():
                optimized_find(20, match, secNum, data2, "disHereSyscall")
    for i in s:
        if len(i.save_Egg_info) > 0:
            variables.moduleBooleans[shellcode_label].bSyscallFound = True

    if rawHex:
        if len(module[shellcode_label].save_Egg_info) > 0:
            variables.moduleBooleans[shellcode_label].bSyscallFound = True
    if variables.moduleBooleans[shellcode_label].bSyscallFound:
        print(
            "{:>{x}}[{}]".format(
                "",
                constants.GREEN + "Found" + constants.RESET,
                x=15 + (maxLen - curLen),
            )
        )
    else:
        print(
            "{:>{x}}[{}]".format(
                "",
                constants.RED + "Not Found" + constants.RESET,
                x=15 + (maxLen - curLen),
            )
        )
    end = time.time()
    return time.time() - start


def discoverDisassembly(
    shell_code: shellcode, variables: Variables, module, shellcode_label, maxLen=42
):
    global gDisassemblyText

    curLen = len("Searching for disassembly")
    print(
        constants.CYAN + " Searching for disassembly..." + constants.RESET,
        end="",
        flush=True,
    )
    start = time.time()

    if variables.rawHex:
        shellDisassemblyInit(
            module[shellcode_label].rawData2,
            shell_code,
            variables,
            module,
            shellcode_label,
            "silent",
        )
    if gDisassemblyText != "":
        print(
            "{:>{x}}[{}]".format(
                "",
                constants.GREEN + "Found" + constants.RESET,
                x=15 + (maxLen - curLen),
            )
        )
        variables.moduleBooleans[shellcode_label].bDisassemblyFound = True
    else:
        print(
            "{:>{x}}[{}]".format(
                "",
                constants.RED + "Not Found" + constants.RESET,
                x=15 + (maxLen - curLen),
            )
        )
    end = time.time()

    return time.time() - start


def discoverHeaven(
    shell_code: shellcode, variables: Variables, module, shellcode_label, maxLen=42
):
    start = time.time()
    curLen = len("Searching for heaven's gate instructions")
    print(
        constants.CYAN
        + " Searching for heaven's gate instructions..."
        + constants.RESET,
        end="",
        flush=True,
    )
    if rawHex:
        getHeavenRawHex(0, linesBack, "noSec", module[shellcode_label].rawData2)

    else:
        for secNum in range(len(s)):
            data2 = s[secNum].data2
            findAllHeaven(data2, secNum)
    for i in s:
        if len(i.save_Heaven_info) > 0:
            variables.moduleBooleans[shellcode_label].bHeavenFound = True
    if rawHex:
        if len(module[shellcode_label].save_Heaven_info) > 0:
            variables.moduleBooleans[shellcode_label].bHeavenFound = True
    if variables.moduleBooleans[shellcode_label].bHeavenFound:
        print(
            "{:>{x}}[{}]".format(
                "",
                constants.GREEN + "Found" + constants.RESET,
                x=15 + (maxLen - curLen),
            )
        )
    else:
        print(
            "{:>{x}}[{}]".format(
                "",
                constants.RED + "Not Found" + constants.RESET,
                x=15 + (maxLen - curLen),
            )
        )
    return time.time() - start


def discoverCallPop(
    shell_code: shellcode, variables: Variables, module, shellcode_label, maxLen=42
):
    start = time.time()
    curLen = len("Searching for call pop instructions")
    print(
        constants.CYAN + " Searching for call pop instructions..." + constants.RESET,
        end="",
        flush=True,
    )
    if variables.rawHex:
        if variables.shellBit == 32:
            findAllCallpop(
                module[shellcode_label].rawData2,
                "noSec",
                variables,
                module,
                shellcode_label,
            )
        else:
            findAllCallpop64(
                module[shellcode_label].rawData2,
                "noSec",
                variables,
                module,
                shellcode_label,
            )
    else:
        for secNum in range(len(s)):
            data2 = s[secNum].data2
            if variables.shellBit == 32:
                findAllCallpop(data2, secNum)
            else:
                findAllCallpop64(data2, secNum)
    for i in s:
        if len(i.save_Callpop_info) > 0:
            variables.moduleBooleans[shellcode_label].bCallPopFound = True
    if rawHex:
        if len(module[shellcode_label].save_Callpop_info) > 0:
            variables.moduleBooleans[shellcode_label].bCallPopFound = True
    if variables.moduleBooleans[shellcode_label].bCallPopFound:
        print(
            "{:>{x}}[{}]".format(
                "",
                constants.GREEN + "Found" + constants.RESET,
                x=15 + (maxLen - curLen),
            )
        )
    else:
        print(
            "{:>{x}}[{}]".format(
                "",
                constants.RED + "Not Found" + constants.RESET,
                x=15 + (maxLen - curLen),
            )
        )
    end = time.time()
    return end - start


def discoverFstenv(shell_code, variables, module, shellcode_label, maxLen=42):
    curLen = len("Searching for fstenv instructions")
    print(
        constants.CYAN + " Searching for fstenv instructions..." + constants.RESET,
        end="",
        flush=True,
    )
    start = time.time()

    if variables.rawHex:
        findAllFSTENV(
            module[shellcode_label].rawData2,
            "noSec",
            variables,
            module,
            shellcode_label,
        )

    else:
        for secNum in range(len(s)):
            data2 = s[secNum].data2
            findAllFSTENV(data2, secNum)
    for i in s:
        if len(i.save_FSTENV_info) > 0:
            variables.moduleBooleans[shellcode_label].bFstenvFound = True

    if variables.rawHex:
        if len(module[shellcode_label].save_FSTENV_info) > 0:
            variables.moduleBooleans[shellcode_label].bFstenvFound = True
    if variables.moduleBooleans[shellcode_label].bFstenvFound:
        print(
            "{:>{x}}[{}]".format(
                "",
                constants.GREEN + "Found" + constants.RESET,
                x=15 + (maxLen - curLen),
            )
        )
    else:
        print(
            "{:>{x}}[{}]".format(
                "",
                constants.RED + "Not Found" + constants.RESET,
                x=15 + (maxLen - curLen),
            )
        )
    return time.time() - start


def discoverPushRet(
    shell_code: shellcode, variables: Variables, module, shellcode_label, maxLen=42
):
    start = time.time()
    curLen = len("Searching for push ret instructions")
    print(
        constants.CYAN + " Searching for push ret instructions..." + constants.RESET,
        end="",
        flush=True,
    )
    if rawHex:
        if bit32:
            findAllPushRet(module[shellcode_label].rawData2, "noSec")
        else:
            findAllPushRet64(module[shellcode_label].rawData2, "noSec")
    else:
        for secNum in range(len(s)):
            data2 = s[secNum].data2
            if bit32:
                findAllPushRet(data2, secNum)
            else:
                # pass
                findAllPushRet64(data2, secNum)
    for i in s:
        if len(i.save_PushRet_info) > 0:
            variables.moduleBooleans[shellcode_label].bPushRetFound = True

    if rawHex:
        if len(module[shellcode_label].save_PushRet_info) > 0:
            variables.moduleBooleans[shellcode_label].bPushRetFound = True

    if variables.moduleBooleans[shellcode_label].bPushRetFound:
        print(
            "{:>{x}}[{}]".format(
                "",
                constants.GREEN + "Found" + constants.RESET,
                x=15 + (maxLen - curLen),
            )
        )
    else:
        print(
            "{:>{x}}[{}]".format(
                "",
                constants.RED + "Not Found" + constants.RESET,
                x=15 + (maxLen - curLen),
            )
        )
    end = time.time()
    return end - start


def uiDiscover(
    shell_code: shellcode, variables: Variables, module, shellcode_label
):  # Discover shellcode instructions
    global minStrLen
    global elapsed_time
    global configOptions

    print(
        constants.YELLOW
        + "\n ...........................\n Find Shellcode Instructions\n ..........................."
        + constants.RESET
    )
    instructionsMenu(variables, shellcode_label)

    x = ""
    while True:  # Loop until we break on x
        print(constants.YELLOW + " Sharem>" + constants.RESET, end="")
        print(constants.CYAN + "Shell> " + constants.RESET, end="")
        listIN = input()
        if re.match("^t$", listIN, re.IGNORECASE):
            uiDiscoverTechMenu()

        elif re.match("^h$", listIN, re.IGNORECASE):
            instructionsMenu(variables, shellcode_label)

        elif re.match("^all$", listIN, re.IGNORECASE):
            variables.moduleBooleans[shellcode_label].bPushRet = True
            variables.moduleBooleans[shellcode_label].bFstenv = True
            variables.moduleBooleans[shellcode_label].bSyscall = True
            variables.moduleBooleans[shellcode_label].bHeaven = True
            variables.moduleBooleans[shellcode_label].bPEB = True
            variables.moduleBooleans[shellcode_label].bCallPop = True
            variables.moduleBooleans[shellcode_label].bDisassembly = True
            variables.moduleBooleans[shellcode_label].bShellcodeAll = True
            print("\n")
            print("Shellcode selections changed.\n")
            print(displayCurrentInstructions(variables, shellcode_label))
        elif re.match("^c$", listIN):
            variables.moduleBooleans[shellcode_label].bPushRet = False
            variables.moduleBooleans[shellcode_label].bFstenv = False
            variables.moduleBooleans[shellcode_label].bSyscall = False
            variables.moduleBooleans[shellcode_label].bHeaven = False
            variables.moduleBooleans[shellcode_label].bPEB = False
            variables.moduleBooleans[shellcode_label].bCallPop = False
            variables.moduleBooleans[shellcode_label].bDisassembly = False
            variables.moduleBooleans[shellcode_label].bShellcodeAll = False
            print("\n")
            print("Shellcode selections changed.\n")
            print(displayCurrentInstructions(variables, shellcode_label))
        elif re.match("^r$", listIN):
            clearInstructions(variables, module, shellcode_label)
            print("Found shellcode instructions cleared.\n")

        elif re.match("^z$", listIN, re.IGNORECASE):
            maxLen = get_max_length(constants.LIST_OF_LABELS)
            # For each boolean set, we execute the finding functions

            if (
                variables.moduleBooleans[shellcode_label].bFstenv
                and not variables.moduleBooleans[shellcode_label].bFstenvFound
            ):
                newTime = discoverFstenv(
                    shell_code, variables, module, shellcode_label, maxLen
                )
                elapsed_time += newTime

            if (
                variables.moduleBooleans[shellcode_label].bPushRet
                and not variables.moduleBooleans[shellcode_label].bPushRetFound
            ):
                newTime = discoverPushRet(
                    shell_code, variables, module, shellcode_label, maxLen
                )
                elapsed_time += newTime

            if (
                variables.moduleBooleans[shellcode_label].bCallPop
                and not variables.moduleBooleans[shellcode_label].bCallPopFound
            ):
                newTime = discoverCallPop(
                    shell_code, variables, module, shellcode_label, maxLen
                )
                elapsed_time += newTime

            if (
                variables.moduleBooleans[shellcode_label].bHeaven
                and not variables.moduleBooleans[shellcode_label].bHeavenFound
            ):
                newTime = discoverHeaven(
                    shell_code, variables, module, shellcode_label, maxLen
                )
                elapsed_time += newTime

            if (
                variables.moduleBooleans[shellcode_label].bSyscall
                and not variables.moduleBooleans[shellcode_label].bSyscallFound
            ):
                newTime = discoverSyscal(
                    shell_code, variables, module, shellcode_label, maxLen
                )
                elapsed_time += newTime

            if (
                variables.moduleBooleans[shellcode_label].bPEB
                and not variables.moduleBooleans[shellcode_label].bPEBFound
            ):
                newTime = discoverPEB(
                    shell_code, variables, module, shellcode_label, maxLen
                )
                elapsed_time += newTime

            if (
                variables.moduleBooleans[shellcode_label].bDisassembly
                and not variables.moduleBooleans[shellcode_label].bDisassemblyFound
            ):
                newTime = discoverDisassembly(
                    shell_code, variables, module, shellcode_label, maxLen
                )

            print(".........................\n")
            print(
                constants.YELLOW
                + " Search for shellcode instructions completed.\n"
                + constants.RESET
            )

            print(
                constants.YELLOW + " Elapsed time:" + constants.RESET,
                format(elapsed_time, ".5f"),
            )

            # print("Exiting discovery menu\n")
            # break
        elif re.match("^x$", listIN, re.IGNORECASE):
            # print("\nReturning to main menu.\n")
            break
        elif re.match("^g$", listIN, re.IGNORECASE):
            print(
                " Enter input delimited by commas or spaces. (x to exit)\n\tE.g. pr, pb, hg\n"
            )
            while x != "e":
                instructionSelectIn = input("> ")
                if re.match("^x$", instructionSelectIn, re.IGNORECASE):
                    break
                bPR = re.search("( |,|^)PR( |,|$)", instructionSelectIn, re.IGNORECASE)
                bFE = re.search("( |,|^)FE( |,|$)", instructionSelectIn, re.IGNORECASE)
                bCP = re.search("( |,|^)CP( |,|$)", instructionSelectIn, re.IGNORECASE)
                bSy = re.search("( |,|^)SY( |,|$)", instructionSelectIn, re.IGNORECASE)
                bPB = re.search("( |,|^)PB( |,|$)", instructionSelectIn, re.IGNORECASE)
                bHG = re.search("( |,|^)HG( |,|$)", instructionSelectIn, re.IGNORECASE)
                bFD = re.search("( |,|^)FD( |,|$)", instructionSelectIn, re.IGNORECASE)

                bShellcodeAll = re.search(
                    "( |,|^)all( |,|$)", instructionSelectIn, re.IGNORECASE
                )
                print("\n")
                if bPR:
                    variables.moduleBooleans[
                        shellcode_label
                    ].bPushRet = not variables.moduleBooleans[shellcode_label].bPushRet
                if bFE:
                    variables.moduleBooleans[
                        shellcode_label
                    ].bFstenv = not variables.moduleBooleans[shellcode_label].bFstenv
                if bCP:
                    variables.moduleBooleans[
                        shellcode_label
                    ].bCallPop = not variables.moduleBooleans[shellcode_label].bCallPop
                if bSy:
                    variables.moduleBooleans[
                        shellcode_label
                    ].bSyscall = not variables.moduleBooleans[shellcode_label].bSyscall
                if bPB:
                    variables.moduleBooleans[
                        shellcode_label
                    ].bPEB = not variables.moduleBooleans[shellcode_label].bPEB
                if bHG:
                    variables.moduleBooleans[
                        shellcode_label
                    ].bHeaven = not variables.moduleBooleans[shellcode_label].bHeaven
                if bFD:
                    variables.moduleBooleans[
                        shellcode_label
                    ].bDisassembly = not variables.moduleBooleans[
                        shellcode_label
                    ].bDisassembly
                if variables.moduleBooleans[shellcode_label].bShellcodeAll:
                    variables.moduleBooleans[shellcode_label].bPushRet = bPR = True
                    variables.moduleBooleans[shellcode_label].bFstenv = bFE = True
                    variables.moduleBooleans[shellcode_label].bCallPop = bCP = True
                    variables.moduleBooleans[shellcode_label].bSyscall = bSy = True
                    variables.moduleBooleans[shellcode_label].bPEB = bPB = True
                    variables.moduleBooleans[shellcode_label].bHeaven = bHG = True
                    variables.moduleBooleans[shellcode_label].bDisassembly = bFD = True
                if (
                    variables.moduleBooleans[shellcode_label].bPushRet
                    and variables.moduleBooleans[shellcode_label].bFstenv
                    and variables.moduleBooleans[shellcode_label].bCallPop
                    and variables.moduleBooleans[shellcode_label].bSyscall
                    and variables.moduleBooleans[shellcode_label].bPEB
                    and variables.moduleBooleans[shellcode_label].bHeaven
                    and variables.moduleBooleans[shellcode_label].bDisassembly
                ):
                    variables.moduleBooleans[shellcode_label].bShellcodeAll = True
                if bPR or bFE or bCP or bSy or bPB or bHG or bFD:
                    print(" Shellcode selections changed.\n")
                    print(displayCurrentInstructions(variables, shellcode_label))
                    break
                else:
                    print(" Input not recognized.\n")
        else:
            print("\n Input not recognized.\n")


def uiDiscoverTechMenu():  # Tech settings for shellcode discovery
    global linesForward
    global linesBack
    global bytesForward
    global bytesBack
    global minStrLen
    global rawHex
    x = ""
    print("\n ..................\n Technical Settings\n ..................\n")
    techSettingsMenu(bytesForward, bytesBack, linesForward, linesBack, rawHex)

    while True:
        print(
            constants.YELLOW
            + " Sharem>"
            + constants.CYAN
            + "Shell>"
            + constants.RESET
            + constants.RED
            + "Tech> "
            + constants.RESET,
            end="",
        )
        techIN = input()
        if techIN[0:1] == "x":
            # print("Returning to find shellcode instructions menu.\n")
            break
        elif techIN[0:1] == "g":
            uiGlobalTechMenu()
            # print("Returning to tech settings submenu.\n")
        elif techIN[0:1] == "c":
            uiCPTechMenu()
            # print("Returning to tech settings submenu.\n")
        elif techIN[0:1] == "p":
            uiPebTechMenu()
            # print("Returning to tech settings submenu.\n")
        elif techIN[0:1] == "k":
            uiStringTechMenu()
        elif techIN[0:1] == "h":
            techSettingsMenu(bytesForward, bytesBack, linesForward, linesBack, rawHex)
        else:
            print("Invalid input")
        # print("\n..................\nTechnical Settings\n..................\n")
        # techIN = input("> ")


def uiGlobalTechMenu():
    global bytesForward
    global bytesBack
    global linesForward
    global linesBack
    global rawHex
    x = ""
    # print("\n............................\nGlobal settings for PE files\n............................\n")
    globalTechMenu(bytesForward, bytesBack, linesForward, linesBack, rawHex)
    while True:
        print(
            constants.YELLOW
            + " Sharem>"
            + constants.CYAN
            + "Shell>"
            + constants.RESET
            + constants.RED
            + "Tech>"
            + constants.RESET
            + constants.WHITE
            + "Global> "
            + constants.RESET,
            end="",
        )
        gtIN = input()
        if gtIN == "x":
            break
        elif gtIN == "":
            continue
        elif gtIN == "fb":
            val = input("\tBelow enter the number of bytes to disassemble forward.\n\n")
            try:
                bytesForward = int(val)
                print(
                    "\tMax bytes to dissassemble forward:"
                    + constants.YELLOW
                    + str(bytesForward)
                    + constants.RESET
                )
            except:
                print("Invalid input. Enter input as decimal.")
        elif gtIN == "bb":
            val = input(
                "\tBelow enter the number of bytes to disassemble backwards.\n\n"
            )
            try:
                bytesBack = int(val)
                print(
                    "\tMax bytes to dissassemble backward:"
                    + constants.YELLOW
                    + str(bytesBack)
                    + constants.RESET
                )
            except:
                print("Invalid input. Enter input as decimal.")
        elif gtIN == "fi":
            val = input("\tBelow enter value for number of lines to check forward.\n\n")
            try:
                linesForward = int(val)
                print(
                    "\tMax lines to check forward: "
                    + constants.YELLOW
                    + str(linesForward)
                    + res
                )
            except:
                print("Invalid input. Enter input as decimal.")
        elif gtIN == "bi":
            val = input(
                "\tBelow enter value for number of lines to check backward.\n\n"
            )
            try:
                linesBack = int(val)
                print(
                    "\tMax lines to check forward: "
                    + constants.YELLOW
                    + str(linesBack)
                    + res
                )
            except:
                print("Invalid input. Enter input as decimal.")
        else:
            print("Invalid input. Type x to exit.")


def uiCPTechMenu():  # Tech settings for callpop
    global maxDistance
    cpTechMenu(maxDistance)
    x = ""
    while x != "e":
        print(
            constants.YELLOW
            + " Sharem>"
            + constants.CYAN
            + "Shell>"
            + constants.RESET
            + constants.RED
            + "Tech>"
            + constants.RESET
            + constants.WHITE
            + "CallPop> "
            + constants.RESET,
            end="",
        )
        cptIN = input()

        if re.match("^[0-9]*$", cptIN, re.IGNORECASE):
            try:
                maxDistance = int(cptIN)
            except:
                maxDistance = int(cptIN, 16)

            print(
                "\tMax call distance changed: "
                + constants.YELLOW
                + str(maxDistance)
                + constants.RESET
                + "\n"
            )
            break
        elif cptIN == "x":
            break
        else:
            print("\nInput invalid; please enter a decimal number or x to exit: ")


def changeStrLen():
    global minStrLen
    print(
        "\n Current string length: "
        + constants.YELLOW
        + str(minStrLen)
        + constants.RESET
        + "\n"
    )

    strLen = input(" Enter minimum string length: ")
    try:
        minStrLen = int(strLen)
        print(
            "\n Minimum string length changed to "
            + constants.YELLOW
            + str(minStrLen)
            + constants.RESET
            + ".\n"
        )
    except:
        print(" Sorry, input not recognized.")


def uiStringTechMenu():
    global minStrLen
    print(
        "\n Current string length: "
        + constants.YELLOW
        + str(minStrLen)
        + constants.RESET
        + "\n"
    )

    print("\n Enter minimum string length below.\n")
    x = ""
    while x != "e":
        print(
            constants.YELLOW
            + " Sharem>"
            + constants.CYAN
            + "Shell>"
            + constants.RESET
            + constants.RED
            + "Tech>"
            + constants.RESET
            + "Strings> ",
            end="",
        )
        stLenIn = input()
        if re.match("^x$", stLenIn, re.IGNORECASE):
            break
        elif not (re.match("^[0-9]*$", stLenIn, re.IGNORECASE)):
            print(" Input not recognized. Please enter a decimal.\n")
        elif stLenIn == "x":
            break
        else:
            try:
                minStrLen = int(stLenIn)
                print(
                    "\n Minimum string length changed to "
                    + constants.YELLOW
                    + str(minStrLen)
                    + constants.RESET
                    + ".\n"
                )
                break
            except:
                print(" Sorry, input not recognized.")


def uiPebTechMenu():
    # Tech settings for peb
    global pebPoints
    # global pointsLimit
    pebTechMenu(pebPoints)
    x = ""
    print("  Enter number of PEB features below.\n")
    while True:
        print(
            constants.YELLOW
            + " Sharem>"
            + constants.CYAN
            + "Shell>"
            + constants.RESET
            + constants.RED
            + "Tech>"
            + constants.RESET
            + constants.WHITE
            + "PEB> "
            + constants.RESET,
            end="",
        )

        pebtIN = input("")
        if pebtIN.isnumeric():
            try:
                pebPoints = int(pebtIN)
                if pebPoints > 4:
                    pebPoints = 4
                    print("\tPEB points may not exceed 4.")
                    print(
                        "\tNumber of PEB features changed: "
                        + constants.YELLOW
                        + str(pebPoints)
                        + constants.RESET
                        + "\n"
                    )
                    break
            except:
                pass
        elif pebtIN == "x":
            break
        else:
            print("\nInput invalid; please enter a decimal number or x to exit: ")


def pebTechMenu(pointsLimit):
    pebTMenu = constants.GREEN + "\nPEB Points Settings\n\n" + constants.RESET
    pebTMenu += (
        "Current minimum number of likely features: "
        + constants.YELLOW
        + str(pointsLimit)
        + constants.RESET
        + "\n"
    )
    pebTMenu += constants.CYAN + "\tThese unique features to identify PEB wakling.\n"
    pebTMenu += (
        "\tLess than 3 generally is not recommended, due to excess of false positives.\n"
        + constants.RESET
    )

    print(pebTMenu)


def changePrintGlobals(value: bool) -> None:
    global bpPushRet
    global bpFstenv
    global bpCallPop
    global bpSyscall
    global bpPEB
    global bpHeaven
    global bpModules
    global bpEvilImports
    global bpStrings
    global bpPushStrings
    global bpAll
    global bDisassembly
    global bPrintEmulation

    bpPushRet = value
    bpFstenv = value
    bpCallPop = value
    bpSyscall = value
    bpPEB = value
    bpHeaven = value
    bpModules = value
    bpEvilImports = value
    bpStrings = value
    bpPushStrings = value
    bpAll = value
    bDisassembly = value
    bPrintEmulation = value


def uiPrintPushStrings(bPushStringsFound):
    if moduleBooleans[shellcode_label].bPushStringsFound:
        print(
            constants.CYAN
            + "\n************\nPush Strings\n************\n"
            + constants.RESET
        )
        t = 0
        try:
            if not rawHex:
                for sec in pe.sections:
                    # print (s[t].sectionName)
                    # word4, offset, offsetVA,offsetPlusImagebase, wordLength,instructionsLength
                    for (
                        word4,
                        offset,
                        offsetVA,
                        offsetPlusImagebase,
                        wordLength,
                        instructionsLength,
                    ) in s[t].pushStrings:
                        word4 = constants.CYAN + word4 + res
                        # print ('{:<5} {:<32s} {:<20s} {:<11s}'.format("",str(word4), "Offset: " + str(hex(offset)),"Size: "+ str(wordLength)))
                        print(
                            "{:<5} {:<32s} {:<8s} {:<8s} {:<8s} {:<12}".format(
                                "",
                                str(word4),
                                s[t].sectionName.decode("utf-8"),
                                str(hex(offset + s[t].ImageBase + s[t].VirtualAdd)),
                                "(offset " + str(hex(offset + s[t].VirtualAdd)) + ")",
                                constants.GREEN + "Stack String" + res,
                            )
                        )
                    print("\n")
                    t += 1
            else:
                for word4, offset, wordLength, instLen in pushStringsTemp:
                    word4 = constants.CYAN + word4 + res
                    if wordLength >= minStrLen:
                        # print ("\t"+ str(word4) + "\t" + hex(offset) + "\t" + str(hex(wordLength)))
                        print(
                            "{:<5} {:<32s} {:<16s} {:<12}".format(
                                "",
                                str(word4),
                                "(offset " + str(hex(offset)) + ")",
                                constants.GREEN + "Stack String" + res,
                            )
                        )
                    # print('{:<5} {:<32s} {:<20s} {:<11s}'.format("",str(word4), "Offset: " + str(hex(offset)),"Size: "+ str(wordLength)))

        except Exception as e:
            print(traceback.format_exc())
            print(e)
    else:
        print("\nNo push strings found.\n")


def uiPrintStrings(bStringsFound):
    if moduleBooleans[shellcode_label].bStringsFound:
        print("\n***********\nStrings\n***********\n")
        t = 0

        try:
            if not rawHex:
                # if (len(s[t].Strings)) or (len(s[t].wideStrings)) or (len(s[t].pushStrings)):
                totalStrings = 0

                if (
                    moduleBooleans[shellcode_label].bStringsFound
                    or moduleBooleans[shellcode_label].bWideStringFound
                    or moduleBooleans[shellcode_label].bPushStringsFound
                ):
                    totalStrings = 0
                    if moduleBooleans[shellcode_label].bStringsFound:
                        for sec in range(len(s)):
                            totalStrings += len(s[t].Strings)
                            t += 1
                    t = 0
                    if moduleBooleans[shellcode_label].bWideStringFound:
                        for sec in range(len(s)):
                            totalStrings += len(s[t].wideStrings)
                            t += 1
                    t = 0
                    if moduleBooleans[shellcode_label].bPushStringsFound:
                        for sec in range(len(s)):
                            totalStrings += len(s[t].pushStrings)
                            t += 1
                    # print ("totalStrings", totalStrings)
                    t = 0
                    if totalStrings > 150:
                        print(
                            "There are too many ASCII/Unicode strings ("
                            + str(totalStrings)
                            + ") - output saved to disk."
                        )
                    else:
                        print("else", totalStrings)
                        for sec in range(len(s)):
                            if len(s[t].Strings) > 0 or len(s[t].wideStrings) > 0:
                                print(s[t].sectionName.decode("utf-8"))
                            if (
                                (len(s[t].pushStrings))
                                or (len(s[t].Strings))
                                or (len(s[t].wideStrings))
                            ):
                                for x, y, z in s[t].Strings:
                                    x = constants.CYAN + x + res
                                    # print ('{:<5} {:<32s} {:<20s} {:<11s} {:<4} {:<8}'.format("",str(x), "Offset: " + str(hex(y)), str(hex(y + s[t].ImageBase + s[t].VirtualAdd)),"Size: "+ str(z) , "Ascii"))
                                    print(
                                        "{:<5} {:<32s} {:<8s} {:<8s} {:<8s} {:<8}".format(
                                            "",
                                            str(x),
                                            s[t].sectionName.decode("utf-8"),
                                            str(
                                                hex(
                                                    y + s[t].ImageBase + s[t].VirtualAdd
                                                )
                                            ),
                                            "(offset "
                                            + str(hex(y + s[t].VirtualAdd))
                                            + ")",
                                            constants.YELLOW
                                            + "Ascii"
                                            + constants.RESET,
                                        )
                                    )

                                    # print ("\t"+ str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z)))
                                    # for x,y in s[t].wideStrings:
                                    # print ("\t"+ str(x) + "\t" + str(hex(y)))
                                for x, y, z in s[t].wideStrings:
                                    x = constants.CYAN + x + res
                                    # print ('{:<5} {:<32s} {:<20s} {:<11s} {:<4} {:<8}'.format("",str(word), "Offset: " + str(hex(offset)), str(hex(y + s[t].ImageBase + s[t].VirtualAdd)),"Size: "+ str(int(wordSize)), "Unicode"))
                                    print(
                                        "{:<5} {:<32s} {:<8s} {:<8s} {:<8s} {:<8}".format(
                                            "",
                                            str(x),
                                            s[t].sectionName.decode("utf-8"),
                                            str(
                                                hex(
                                                    y + s[t].ImageBase + s[t].VirtualAdd
                                                )
                                            ),
                                            "(" + str(hex(y + s[t].VirtualAdd)) + ")",
                                            constants.RED + "Unicode" + res,
                                        )
                                    )

                                    # print ("\t"+ str(word) + "\t" + hex(offset) + "\t" + str(wordSize))
                            t += 1
            else:
                for x, y, z in stringsTemp:
                    x = constants.CYAN + x + res
                    if z >= minStrLen:
                        # print('{:<5} {:<32s} {:<20s} {:<11s}'.format("",str(x), "Offset: " + str(hex(y)),"Size: "+ str(z)))
                        print(
                            "{:<5} {:<32s} {:<16s} {:<12}".format(
                                "",
                                str(x),
                                "(offset " + str(hex(y)) + ")",
                                constants.YELLOW + "Ascii" + res,
                            )
                        )

                    # print ("\t"+ str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z)))
                for x, y, z in stringsTempWide:
                    if z >= minStrLen:
                        x = constants.CYAN + x + res
                        # print('{:<5} {:<32s} {:<20s} {:<11s}'.format("",str(x), "Offset: " + str(hex(y)),"Size: "+ str(z)))
                        print(
                            "{:<5} {:<32s} {:<16s} {:<12}".format(
                                "",
                                str(x),
                                "(offset " + str(hex(y)) + ")",
                                constants.RED + "Unicode" + res,
                            )
                        )

                    # print ("\t"+ str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z)))

        except Exception as e:
            print(traceback.format_exc())
            print(e)
    else:
        print("\nNo strings found.\n")


def uiPrint():  # Print instructions
    global o
    # print ("uiPrint o", o)
    global bpPushRet
    global bpFstenv
    global bpSyscall
    global bpHeaven
    global bpPEB
    global bpCallPop
    global bpStrings
    global bpPushStrings
    global bpModules
    global bpEvilImports
    global bDisassembly
    global syscallSelection
    global bpAll
    global bExportAll
    global stringsTempWide
    global pushStringsTemp
    global stringsTemp
    global p2screen
    global bPrintEmulation
    global sharem_out_dir
    global emulation_verbose
    global emulation_multiline
    global rawHex

    if sharem_out_dir == "current_dir":
        sh_out_dir = os.path.join(os.path.dirname(__file__), "sharem")
    else:
        sh_out_dir = sharem_out_dir

    # clearConsole()
    print(
        constants.YELLOW + "\n ..........\n Print Menu\n ..........\n" + constants.RESET
    )

    printMenu(
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
        bDisassembly,
        bpAll,
        sh_out_dir,
        emulation_verbose,
        emulation_multiline,
        bPrintEmulation,
        p2screen,
    )
    if (
        (not moduleBooleans[shellcode_label].bPushRetFound)
        and (not moduleBooleans[shellcode_label].bFstenvFound)
        and (not moduleBooleans[shellcode_label].bSyscallFound)
        and (not moduleBooleans[shellcode_label].bHeavenFound)
        and (not moduleBooleans[shellcode_label].bPEBFound)
        and (not moduleBooleans[shellcode_label].bCallPopFound)
        and (not moduleBooleans[shellcode_label].bStringsFound)
        and (not moduleBooleans[shellcode_label].bPushStringsFound)
        and (not moduleBooleans[shellcode_label].bModulesFound)
        and (not moduleBooleans[shellcode_label].bDisassemblyFound)
    ):
        print(
            constants.RED
            + " Warning: "
            + constants.RESET
            + "No selections have been discovered yet. Search first.\n"
        )

    x = ""
    while True:
        print(
            constants.YELLOW
            + " Sharem>"
            + constants.GREEN
            + "Print> "
            + constants.RESET,
            end="",
        )
        listIN = input()
        if re.match("^x$", listIN, re.IGNORECASE):
            break
        elif re.match("^p$", listIN, re.IGNORECASE):
            if p2screen:
                print("Print to screen disabled")
                p2screen = False
            else:
                print("Print to screen enabled")
                p2screen = True
        elif re.match("^d$", listIN, re.IGNORECASE):
            sharem_out_dir = input(" Enter output path: ")
            sh_out_dir = sharem_out_dir
            print(" Output path has been changed.")
        elif re.match("^z$", listIN, re.IGNORECASE):
            if sh.decryptSuccess and o == "shellcode":
                print(
                    constants.BLUE
                    + "  It appears this shellcode may have been deobfuscated. Switching output to decoded."
                    + constants.RESET
                )
                o = constants.ShellcodeLabel.SHELLCODE_DECODED_FULL_LABEL

            if bDisassembly and p2screen:
                if moduleBooleans[shellcode_label].bDisassemblyFound:
                    print(
                        constants.CYAN
                        + "\n***********\nDisassembly\n***********"
                        + constants.RESET
                    )
                    if len(m[o].rawData2) / 1000 < 15:
                        print(gDisassemblyText)
                    else:
                        print(
                            "\n\tDisassembly to large to print to screen. It has been printed to file."
                        )
                else:
                    print("\nNo disassembly found.\n")
            if (
                bpEvilImports
                and moduleBooleans[shellcode_label].bEvilImportsFound
                and p2screen
            ):
                # print(showImports())
                print(constants.YELLOW + "Imports are saved to file." + constants.RESET)
            if bpPushRet and p2screen:
                if moduleBooleans[shellcode_label].bPushRetFound:
                    print(
                        constants.CYAN
                        + "\n***********\nPush ret\n***********\n"
                        + constants.RESET
                    )
                    printSavedPushRet(variables.shellBit)
                else:
                    print("\nNo push ret instructions found.\n")
            if bpModules and moduleBooleans[shellcode_label].bModulesFound and p2screen:
                print(
                    constants.CYAN
                    + "\n\n*******\nModules\n*******\n\n"
                    + constants.RESET
                )
                print(giveLoadedModules("save"))
            if bpStrings and p2screen:
                uiPrintStrings(moduleBooleans[shellcode_label].bStringsFound)
            if bpPushStrings and p2screen:
                uiPrintPushStrings(moduleBooleans[shellcode_label].bPushStringsFound)
            if bpFstenv and p2screen:
                if moduleBooleans[shellcode_label].bFstenvFound:
                    print(
                        constants.CYAN
                        + "\n***********\nFstenv\n***********\n"
                        + constants.RESET
                    )
                    printSavedFSTENV(variables.shellBit)
                else:
                    print("\nNo fstenv instructions found.\n")
            if bpCallPop and p2screen:
                if moduleBooleans[shellcode_label].bCallPopFound:
                    print(
                        constants.CYAN
                        + "\n***********\nCall Pop\n***********\n"
                        + constants.RESET
                    )
                    printSavedCallPop(variables.shellBit)
                else:
                    print("\nNo call pop instructions found.\n")
            if bpSyscall and p2screen:
                if moduleBooleans[shellcode_label].bSyscallFound:
                    print(
                        constants.CYAN
                        + "\n***************\nWindows Syscall\n***************\n"
                        + constants.RESET
                    )
                    printSavedSyscall(variables.shellBit)
                else:
                    print("\nNo syscall instructions found.\n")
            if bpPEB and p2screen:
                if moduleBooleans[shellcode_label].bPEBFound:
                    print(
                        constants.CYAN
                        + "\n***************\nWalking the PEB\n***************\n"
                        + constants.RESET
                    )
                    if variables.shellBit == 32:
                        printSavedPEB()
                    else:
                        printSavedPEB_64()
                else:
                    print("\nNo peb walking instructions found.\n")

            if bpHeaven and p2screen:
                if moduleBooleans[shellcode_label].bHeavenFound:
                    print(
                        constants.CYAN
                        + "\n***************\nHeaven's Gate\n***************\n"
                        + constants.RESET
                    )
                    printSavedHeaven(variables.shellBit)
                else:
                    print("No heaven's gate instructions found.\n")
            if bPrintEmulation and p2screen and rawHex:
                if len(loggedList) > 0 or len(logged_syscalls) > 0:
                    emulation_txt_out(loggedList, logged_syscalls)
                else:
                    print("\nNo emulation results.")
            if rawHex:
                shellClass = isShellcode(
                    moduleBooleans[shellcode_label], patt, shell_code, conr
                )
                print(
                    constants.CYAN
                    + "\n Classification: "
                    + constants.YELLOW
                    + shellClass[0]
                    + constants.RESET
                    + "\n"
                )
                if shellClass[1]:
                    print(
                        constants.CYAN
                        + " Reason: "
                        + constants.YELLOW
                        + shellClass[1]
                        + constants.RESET
                        + "\n"
                    )

            if (
                shell_code.decryptSuccess
                and o == constants.ShellcodeLabel.SHELLCODE_LABEL
            ):
                print(
                    constants.BLUE
                    + "  It appears this shellcode may have been deobfuscated. Switching output to decoded."
                    + constants.RESET
                )
                o = constants.ShellcodeLabel.SHELLCODE_DECODED_FULL_LABEL
            outputData = generateOutputData(shell_code, rawHex, conr)

            printToJson(bpAll, outputData)
            printToText(outputData)
            if not p2screen:
                print("Data saved.")
        elif re.match("^h$", listIN, re.IGNORECASE):
            print("\n.......\n")
            printMenu(
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
                bDisassembly,
                bpAll,
                sh_out_dir,
                emulation_verbose,
                emulation_multiline,
                bPrintEmulation,
                p2screen,
            )
        elif re.match("^s$", listIN, re.IGNORECASE):
            uiPrintSyscallSubMenu()

        elif re.match("^e$", listIN, re.IGNORECASE):
            if emulation_verbose:
                emulation_verbose = False
                print(constants.CYAN + " Emulation verbose mode disabled.\n" + res)
            else:
                emulation_verbose = True
                print(constants.CYAN + " Emulation verbose mode enabled.\n" + res)

        elif re.match("^m$", listIN, re.IGNORECASE):
            if emulation_multiline:
                emulation_multiline = False
                print(constants.CYAN + " Emulation multiline format disabled.\n" + res)
            else:
                emulation_multiline = True
                print(constants.CYAN + " Emulation multiline format enabled.\n" + res)

        elif re.match("^j$", listIN, re.IGNORECASE):
            if bExportAll:
                bExportAll = False
                print("\nJSON export all disabled\n")
            else:
                bExportAll = True
                print("\nJSON export all enabled\n")
        elif re.match("^c$", listIN, re.IGNORECASE):
            changePrintGlobals("reset")
            print("Selections changed.\n")
            print(
                displayCurrentSelections(
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
                    bDisassembly,
                    bPrintEmulation,
                    bpAll,
                )
            )
        elif re.match("^all$", listIN, re.IGNORECASE):
            changePrintGlobals("all")
            print("Selections changed.\n")
            print(
                displayCurrentSelections(
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
                    bDisassembly,
                    bPrintEmulation,
                    bpAll,
                )
            )

        elif re.match("^g$", listIN, re.IGNORECASE):
            print(
                "  Enter input delimited by commas or spaces. (x to exit)\n\tE.g. pr, pb, hg\n"
            )
            while x != "e":
                printSelectIn = input("> ")
                if re.match("^x$", printSelectIn, re.IGNORECASE):
                    break
                bPR = re.search("( |,|^)PR( |,|$)", printSelectIn, re.IGNORECASE)
                bFE = re.search("( |,|^)FE( |,|$)", printSelectIn, re.IGNORECASE)
                bCP = re.search("( |,|^)CP( |,|$)", printSelectIn, re.IGNORECASE)
                bSy = re.search("( |,|^)Sy( |,|$)", printSelectIn, re.IGNORECASE)
                bPB = re.search("( |,|^)PB( |,|$)", printSelectIn, re.IGNORECASE)
                bHG = re.search("( |,|^)HG( |,|$)", printSelectIn, re.IGNORECASE)
                bpAll = re.search("( |,|^)all( |,|$)", printSelectIn, re.IGNORECASE)
                bNone = re.search("( |,|^)none( |,|$)", printSelectIn, re.IGNORECASE)
                bST = re.search("( |,|^)ST( |,|$)", printSelectIn, re.IGNORECASE)
                bPS = re.search("( |,|^)PS( |,|$)", printSelectIn, re.IGNORECASE)
                bLM = re.search("( |,|^)lm( |,|$)", printSelectIn, re.IGNORECASE)
                bIM = re.search("( |,|^)im( |,|$)", printSelectIn, re.IGNORECASE)
                bFD = re.search("( |,|^)FD( |,|$)", printSelectIn, re.IGNORECASE)
                bPM = re.search("( |,|^)EM( |,|$)", printSelectIn, re.IGNORECASE)

                print("\n")
                if bFD:
                    bDisassembly = False if bDisassembly else True

                if bPM:
                    bPrintEmulation = False if bPrintEmulation else True

                if bPR:
                    bpPushRet = False if bpPushRet else True
                if bFE:
                    bpFstenv = False if bpFstenv else True
                if bCP:
                    bpCallPop = False if bpCallPop else True
                if bSy:
                    bpSyscall = False if bpSyscall else True
                if bPB:
                    bpPEB = False if bpPEB else True
                if bHG:
                    bpHeaven = False if bpHeaven else True
                if bST:
                    bpStrings = False if bpStrings else True
                if bPS:
                    bpPushStrings = False if bpPushStrings else True
                if bIM:
                    bpEvilImports = False if bpEvilImports else True
                if bLM:
                    bpModules = False if bpModules else True
                if bpAll:
                    changePrintGlobals("all")
                if bNone:
                    changePrintGlobals("reset")
                if (
                    bpPushRet
                    and bpFstenv
                    and bpCallPop
                    and bpSyscall
                    and bpPEB
                    and bDisassembly
                    and bpHeaven
                    and bpStrings
                    and bpEvilImports
                    and bpModules
                    and bpPushStrings
                ):
                    bpAll = True
                if (
                    bPR
                    or bFE
                    or bCP
                    or bSy
                    or bPB
                    or bHG
                    or bST
                    or bPS
                    or bIM
                    or bLM
                    or bFD
                    or bPM
                ):
                    print("Selections changed.\n")
                    print(
                        displayCurrentSelections(
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
                            bDisassembly,
                            bPrintEmulation,
                            bpAll,
                        )
                    )
                    break
                else:
                    print("\nInput not recognized.\n")
        else:
            print("\nInput not recognized.\n")
        # print(constants.YELLOW + "\n ..........\n Print Menu\n ..........\n")


def uiPrintSyscallSubMenu():  # Printing/settings for syscalls
    global syscallSelection
    global showDisassembly
    global syscallPrintBit

    print(
        constants.YELLOW
        + "\n ...................\n Syscall Settings\n ...................\n"
        + constants.RESET
    )
    syscallPrintSubMenu(syscallSelection, showDisassembly, syscallPrintBit, True)
    x = ""
    while x != "e":
        print(
            constants.CYAN
            + " Sharem>"
            + constants.GREEN
            + "Print>"
            + constants.YELLOW
            + "Syscalls> "
            + constants.RESET,
            end="",
        )
        syscallIN = input()
        if re.match("^x$", syscallIN, re.IGNORECASE):
            # print("Returning to print menu.")
            break
        elif re.match("^h$", syscallIN, re.IGNORECASE):
            syscallPrintSubMenu(
                syscallSelection, showDisassembly, syscallPrintBit, True
            )
        elif re.match("^g$", syscallIN, re.IGNORECASE):
            syscallSelectionsSubMenu()
            print("\nChanges applied: ")
            syscallPrintSubMenu(
                syscallSelection, showDisassembly, syscallPrintBit, False
            )
        elif re.match("^z$", syscallIN, re.IGNORECASE):
            printSavedSyscall(syscallPrintBit, showDisassembly)
        elif re.match("^c$", syscallIN, re.IGNORECASE):
            for osv in syscallSelection:
                osv.toggle = False
            print("\nChanges applied: ")
            syscallPrintSubMenu(
                syscallSelection, showDisassembly, syscallPrintBit, False
            )

        elif re.match("^b$", syscallIN, re.IGNORECASE):
            print(
                constants.RED
                + "Warning: "
                + constants.RESET
                + "64-bit is standard for all syscalls.\n\tDeviate with extreme care.\nChange architecture:\n\n\t"
                + constants.CYAN
                + "1"
                + constants.RESET
                + " - 32-bit\n\t"
                + constants.CYAN
                + "2"
                + constants.RESET
                + " - 64-bit\n"
            )
            syscallBitIN = input("> ")
            if syscallBitIN[0:1] == "1":
                syscallPrintBit = 32
            elif syscallBitIN[0:1] == "2":
                syscallPrintBit = 64
            print("\tArchitecture changed.")
            # print("Returning to syscall selection submenu.\n")

        elif re.match("^d$", syscallIN, re.IGNORECASE):
            showDisassembly = False if showDisassembly else True
            print("\tShow disassembly set to " + str(showDisassembly) + ".")
        # print("\n................\nSyscall Settings\n................\n")


def emuSyscallSubMenu():  # Printing/settings for syscalls
    global emuSyscallSelection
    global showDisassembly
    global syscallPrintBit

    print(
        constants.YELLOW
        + "\n ...................\n Emulation Syscall Settings\n ...................\n"
        + constants.RESET
    )
    emuSyscallPrintSubMenu(emuSyscallSelection)
    x = ""
    while x != "e":
        print(
            constants.YELLOW
            + " Sharem>"
            + constants.CYAN
            + "Emulator>"
            + constants.GREEN
            + "Syscalls> "
            + constants.RESET,
            end="",
        )
        syscallIN = input()
        if re.match("^x$", syscallIN, re.IGNORECASE):
            # print("Returning to print menu.")
            break

        elif re.match("^h$", syscallIN, re.IGNORECASE):
            emuSyscallPrintSubMenu(emuSyscallSelection)

        elif re.match("^g$", syscallIN, re.IGNORECASE):
            emuSyscallSelectionsSubMenu()

        elif re.match("^c$", syscallIN, re.IGNORECASE):
            for key in emuSyscallSelection.keys():
                emuSyscallSelection[key][0] = False
            print("\nChanges applied: ")
            emuSyscallPrintSubMenu(emuSyscallSelection)


def uiModulesSubMenu():  # Find and display loaded modules
    global bpModules

    global modulesMode  # 1-3, whichever option we want
    # global gMS_API_MIN_skip
    print(
        "\n"
        + constants.YELLOW
        + "............................\nFind Modules Beyond the IAT\n............................\n"
        + constants.RESET
    )
    print("This feature will statically discover modules used in the PE file.\n")
    if rawHex:
        print(constants.RED + "Warning: " + constants.RESET + "No PE file selected.\n")
    printModulesMenu(modulesMode)
    x = "i"
    while x != "e":
        print(constants.YELLOW + " .......\n Modules\n .......\n" + constants.RESET)
        print(
            constants.YELLOW
            + " Sharem>"
            + constants.RESET
            + constants.CYAN
            + "Modules> "
            + constants.RESET,
            end="",
        )
        modIn = input("")
        if re.match("^x$", modIn, re.IGNORECASE):
            break
        elif re.match("^[1-3]$", modIn, re.IGNORECASE):
            modulesMode = int(modIn)
            if modulesMode == 1:
                print(
                    "Selection changed to: "
                    + constants.GREEN
                    + "Find only DLLs in IAT\n"
                    + constants.RESET
                )
            if modulesMode == 2:
                print(
                    "Selection changed to: "
                    + constants.GREEN
                    + "Find DLLs in IAT and beyond\n"
                    + constants.RESET
                )
            if modulesMode == 3:
                print(
                    "Selection changed to: "
                    + constants.GREEN
                    + "Find DLLs in IAT, beyond, and more\n"
                    + constants.RESET
                )
        elif re.match("^h$", modIn, re.IGNORECASE):
            printModulesMenu(modulesMode)

        elif re.match("^p$", modIn, re.IGNORECASE):
            print(giveLoadedModules("save"))

        elif re.match("^r$", modIn, re.IGNORECASE):
            clearMods()
            print("Loaded modules cleared.\n")

        elif re.match("^z$|^m$", modIn, re.IGNORECASE):
            if rawHex:
                print("\nNo PE file selected\n")
            else:
                runInMem()
                print(giveLoadedModules())
                giveLoadedModules("save")

        else:
            print("Input not recognized.\n")

    return


def runInMem():
    global modulesMode
    global IATs

    clearMods()
    print("\nFinding DLLs in IAT\n")
    getDLLs()
    if modulesMode > 1:
        print("Finding DLLs beyond the IAT\n")
        digDeeper(PE_DLLS)
    if modulesMode > 2:
        print("Finding even more DLLs\n")
        if platformType == "Windows":
            digDeeper2()
    InMem2()

    if len(IATs.foundDll) > 0:
        moduleBooleans[shellcode_label].bModulesFound = True


def checkRegVal(regName, regVal):
    while checkHex(regVal) != True:
        try:
            regVal = input("Enter valid {} value> ".format(regName))
            return True

        except KeyboardInterrupt:
            print("\n")
            return False

    return True


def manualRegisters():
    global regsTemp

    eax = ebx = ecx = edx = edi = esi = ebp = esp = False
    print("  Enter register values, Ctrl+C to exit")
    print("   *Note: recent strings found will be cleared\n")
    validatipon = True
    while True:
        try:
            eax = input("EAX> ")
            if not checkRegVal("EAX", eax):
                return
            ebx = input("EBX> ")
            if not checkRegVal("EBX", ebx):
                return
            ecx = input("ECX> ")
            if not checkRegVal("ECX", ecx):
                return
            edx = input("EDX> ")
            if not checkRegVal("EDX", edx):
                return
            edi = input("EDI> ")
            if not checkRegVal("EDI", edi):
                return
            esi = input("ESI> ")
            if not checkRegVal("ESI", esi):
                return
            ebp = input("EBP> ")
            if not checkRegVal("EBP", ebp):
                return
            esp = input("ESP> ")
            if not checkRegVal("ESP", esp):
                return
            break
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(e)

    if eax:
        eax = hexDword(int(eax, 16))
        setReg(eax, False, "eax")

    if ebx:
        ebx = hexDword(int(ebx, 16))
        setReg(ebx, False, "ebx")

    if ecx:
        ecx = hexDword(int(ecx, 16))
        setReg(ecx, False, "ecx")

    if edx:
        edx = hexDword(int(edx, 16))
        setReg(edx, False, "edx")

    if edi:
        edi = hexDword(int(edi, 16))
        setReg(edi, False, "edi")

    if esi:
        esi = hexDword(int(esi, 16))
        setReg(esi, False, "esi")

    if ebp:
        ebp = hexDword(int(ebp, 16))
        setReg(ebp, False, "ebp")

    if esp:
        esp = hexDword(int(esp, 16))
        setReg(esp, False, "esp")

    clearStrings()


def changeRegsFile():
    global regFilePath
    regFilePath = ""
    while True:
        try:
            print("  Enter registers file. Ctrl+C to exit\n")
            regFilePath = input("> ")
            tmpFile = open(regFilePath, "r")
            regsFile = regFilePath
            print("\nRegisters file changed to {}\n".format(regFilePath))
            tmpFile.close()
            break
        except Exception:
            print("File doesn't exit")
        except KeyboardInterrupt:
            break
    if regFilePath:
        tmpFile.close()
        assemblyx86.regsFile = regFilePath
        readRegs()


def uiFindStrings():
    global bAsciiStrings
    global bPushStrings
    global bWideCharStrings
    global bPushStackStrings
    global bAllStrings
    global minStrLen
    global pushStringRegisters
    global stringsTemp
    global stringsTempWide
    global pushStringsTemp

    global useStringsFile
    global chMode

    #

    if bAsciiStrings and bWideCharStrings and bPushStackStrings:
        bAllStrings = True
    else:
        bAllStrings = False

    print(
        constants.YELLOW
        + "\n ...............\n  Find Strings\n ...............\n"
        + constants.RESET
    )
    stringMenu(
        bAsciiStrings,
        bWideCharStrings,
        bPushStackStrings,
        bAllStrings,
        s,
        useStringsFile,
        chMode,
    )
    x = ""
    while True:
        # print("\n............\nFind Strings\n............\n")
        print(
            constants.CYAN
            + " Sharem>"
            + constants.GREEN
            + "Strings> "
            + constants.RESET,
            end="",
        )
        stringIN = input()
        if re.match("^x$", stringIN, re.IGNORECASE):
            break
        elif re.match("^h$", stringIN, re.IGNORECASE):
            stringMenu(
                bAsciiStrings,
                bWideCharStrings,
                bPushStackStrings,
                bAllStrings,
                s,
                useStringsFile,
                chMode,
            )
        elif re.match("^r$", stringIN, re.IGNORECASE):
            clearStrings()
            print("Found strings cleared.\n")

        elif re.match("^m$", stringIN, re.IGNORECASE):
            manualRegisters()
        elif re.match("^e$", stringIN, re.IGNORECASE):
            chMode = True
            print("\nEmulation enabled\n")
        elif re.match("^s$", stringIN, re.IGNORECASE):
            pushStringsOutput(5)  # Testing only
        elif re.match("^k$", stringIN, re.IGNORECASE):
            changeStrLen()
        elif re.match("^n$", stringIN, re.IGNORECASE):
            changeRegsFile()
            useStringsFile = True
        elif re.match("^z$", stringIN, re.IGNORECASE):
            if bAsciiStrings and not variables.moduleBooleans[shellcode_label].bStringsFound:
                discoverAsciiStrings()
            elif variables.moduleBooleans[shellcode_label].bStringsFound:
                print(
                    constants.RED
                    + "\tAscii strings already found; reset if need be."
                    + constants.RESET
                )
            if (
                bWideCharStrings
                and not variables.moduleBooleans[shellcode_label].bWideStringFound
            ):
                discoverUnicodeStrings()
            elif variables.moduleBooleans[shellcode_label].bWideStringFound:
                print(
                    constants.RED
                    + "\tUnicode strings already found; reset if need be."
                    + constants.RESET
                )
            if (
                bPushStackStrings
                and not variables.moduleBooleans[shellcode_label].bPushStringsFound
            ):
                discoverStackStrings()
            elif variables.moduleBooleans[shellcode_label].bPushStringsFound:
                print(
                    constants.RED
                    + "\tStack strings already found; reset if need be."
                    + constants.RESET
                )

        elif re.match("^p$", stringIN, re.IGNORECASE):
            printStrings()

        elif re.match("^g$", stringIN, re.IGNORECASE):
            print(
                "  Enter input delimited by commas or spaces. (x to exit)\n\tE.g. as, wc\n"
            )
            while x != "e":
                sSelectIn = input("> ")
                if re.match("^x$", sSelectIn, re.IGNORECASE):
                    break
                bAS = re.search("( |,|^)AS( |,|$)", sSelectIn, re.IGNORECASE)
                bWC = re.search("( |,|^)WC( |,|$)", sSelectIn, re.IGNORECASE)
                bPS = re.search("( |,|^)PS( |,|$)", sSelectIn, re.IGNORECASE)
                bAll = re.search("( |,|^)ALL( |,|$)", sSelectIn, re.IGNORECASE)
                if bAS:
                    bAsciiStrings = not bAsciiStrings
                if bWC:
                    bWideCharStrings = not bWideCharStrings
                if bPS:
                    bPushStackStrings = not bPushStackStrings
                if bAll:
                    bAsciiStrings = not bAsciiStrings
                    bWideCharStrings = not bWideCharStrings
                    bPushStackStrings = not bPushStackStrings
                if bAsciiStrings and bWideCharStrings and bPushStackStrings:
                    bAllStrings = True
                else:
                    bAllStrings = False
                if bAS or bWC or bPS or bAll:
                    showStringSelections(
                        bAsciiStrings,
                        bWideCharStrings,
                        bPushStackStrings,
                        bAllStrings,
                        s,
                    )
                    break
                else:
                    print("Input not recognized.\n")
        elif re.match("^c$", stringIN, re.IGNORECASE):
            bAsciiStrings = False
            bWideCharStrings = False
            bPushStackStrings = False
            bAllStrings = False
            showStringSelections(
                bAsciiStrings, bWideCharStrings, bPushStackStrings, bAllStrings, s
            )
        elif re.match("^all$", stringIN, re.IGNORECASE):
            bAsciiStrings = True
            bWideCharStrings = True
            bPushStackStrings = True
            bAllStrings = True
            showStringSelections(
                bAsciiStrings, bWideCharStrings, bPushStackStrings, bAllStrings, s
            )

        else:
            print("\nInput not recognized.\n")


def uiShellcodeStrings():
    global minStrLen
    global stringReadability
    global checkGoodStrings
    global sBy

    global bAsciiStrings
    global bWideCharStrings
    global bPushStackStrings
    global bAllStrings
    global minStrLen
    global pushStringRegisters
    global stringsTemp
    global stringsTempWide
    global pushStringsTemp
    global shellcodeStrings
    global shellcodeStringsWide
    global shellcodePushStrings

    if bAsciiStrings and bWideCharStrings and bPushStackStrings:
        bAllStrings = True
    else:
        bAllStrings = False
    print(
        constants.RED
        + "\nThis function is deprecated!"
        + constants.RESET
        + "\n............\nFind Shellcode Strings\n............\n"
    )
    shellcodeStringMenu(
        bAsciiStrings, bWideCharStrings, bPushStackStrings, bAllStrings, s
    )
    x = ""
    while x != "e":
        print("\n............\nFind Shellcode Strings\n............\n")
        stringIN = input("> ")
        if re.match("^x$", stringIN, re.IGNORECASE):
            break
        elif re.match("^z$", stringIN, re.IGNORECASE):
            shellcodeStrings = []
            shellcodeStringsWide = []
            shellcodePushStrings = []
            preSyscalDiscovery(0, 0x0, 20)
            for x, y, z in stringsTemp:
                if goodString(m[o].rawData2, x, minStrLen):
                    shellcodeStrings.append(tuple((x, y, z)))
            for x, y, z in shellcodeStrings:
                print("\t" + str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z)))
        elif re.match("^m$", stringIN, re.IGNORECASE):
            print("\nEnter a minimum length for strings:\n")
            while x != "e":
                minLenIn = input("> ")
                if re.match("^[0-9]*$", minLenIn, re.IGNORECASE):
                    minStrLen = int(minLenIn)
                    shellcodeStrings = []
                    for x, y, z in stringsTemp:
                        if goodString(m[o].rawData2, x, minStrLen):
                            shellcodeStrings.append(tuple((x, y, z)))
                    for x, y, z in shellcodeStrings:
                        print("\t" + str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z)))
                    break
                elif re.match("^x$", minLenIn, re.IGNORECASE):
                    break
                else:
                    print("\nInput not recognized.\n")
        elif re.match("^h$", stringIN, re.IGNORECASE):
            shellcodeStringMenu(
                bAsciiStrings, bWideCharStrings, bPushStackStrings, bAllStrings, s
            )
        elif re.match("^p$", stringIN, re.IGNORECASE):
            for x, y, z in shellcodeStrings:
                print("\t" + str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z)))
        elif re.match("^r$", stringIN, re.IGNORECASE):
            clearStrings()


def uiFindImports():
    print("\n ............\n Find Imports\n ............\n")

    if rawHex:
        print(constants.RED + "Warning: " + constants.RESET + "No PE file selected.\n")
    importsMenu()
    x = ""
    while x != "e":
        print("\n ............\n Find Imports\n ............\n")
        print(
            constants.YELLOW + " Sharem>" + constants.CYAN + "Imports> " + res, end=""
        )
        importsIN = input()
        if re.match("^x$", importsIN, re.IGNORECASE):
            break
        elif re.match("^h$", importsIN, re.IGNORECASE):
            importsMenu()
        elif re.match("^r$", importsIN, re.IGNORECASE):
            clearImports()
        elif re.match("^z$", importsIN, re.IGNORECASE):
            if not rawHex:
                if not moduleBooleans[shellcode_label].bEvilImportsFound:
                    findEvilImports()
                if len(FoundApisName) > 0:
                    moduleBooleans[shellcode_label].bEvilImportsFound = True
                    print(showImports())
            else:
                print("No PE file selected.\n")
        elif re.match("^p$", importsIN, re.IGNORECASE):
            print(showImports())
        else:
            print("Input not recognized.\n")


def hashShellcode(shell=None, mode=None) -> shellHash:
    global rawHex
    global sh

    shHash = shellHash()

    if not rawHex:
        return
    if shell is not None:
        ssdeepHash = ssdeep.hash(shell)
        md5sum = hashlib.md5(shell).hexdigest()
        sha256 = hashlib.sha256(shell).hexdigest()

    if mode == sample:
        shHash.setMd5(md5sum)
        shHash.setSha256(sha256)
        shHash.setSsdeep(ssdeepHash)
    if mode == unencryptedShell:
        shHash.setMd5(md5sum, unencryptedShell)
        shHash.setSha256(sha256, unencryptedShell)
        shHash.setSsdeep(ssdeepHash, unencryptedShell)
    if mode == decoderShell:
        shHash.setSha256(sha256, decoderShell)
        shHash.setSsdeep(ssdeepHash, decoderShell)
        shHash.setMd5(md5sum, decoderShell)
    if mode == unencryptedBodyShell:
        shHash.setMd5(md5sum, unencryptedBodyShell)
        shHash.setSha256(sha256, unencryptedBodyShell)
        shHash.setSsdeep(ssdeepHash, unencryptedBodyShell)
    if shell is None and (mode == allObject or mode is None):
        ssdeepHash = ssdeep.hash(m[o].rawData2)
        md5sum = hashlib.md5(m[o].rawData2).hexdigest()
        sha256 = hashlib.sha256(m[o].rawData2).hexdigest()
        shHash.setMd5(md5sum)
        shHash.setSha256(sha256)
        shHash.setSsdeep(ssdeepHash)

        ssdeepHash = ssdeep.hash(sh.unencrypted)
        md5sum = hashlib.md5(sh.unencrypted).hexdigest()
        sha256 = hashlib.sha256(sh.unencrypted).hexdigest()
        shHash.setMd5(md5sum, unencryptedShell)
        shHash.setSha256(sha256, unencryptedShell)
        shHash.setSsdeep(ssdeepHash, unencryptedShell)

        ssdeepHash = ssdeep.hash(sh.decoderStub)
        md5sum = hashlib.md5(sh.decoderStub).hexdigest()
        sha256 = hashlib.sha256(sh.decoderStub).hexdigest()
        shHash.setSha256(sha256, decoderShell)
        shHash.setSsdeep(ssdeepHash, decoderShell)
        shHash.setMd5(md5sum, decoderShell)

        ssdeepHash = ssdeep.hash(sh.decodedBody)
        md5sum = hashlib.md5(sh.decodedBody).hexdigest()
        sha256 = hashlib.sha256(sh.decodedBody).hexdigest()
        shHash.setMd5(md5sum, unencryptedBodyShell)
        shHash.setSha256(sha256, unencryptedBodyShell)
        shHash.setSsdeep(ssdeepHash, unencryptedBodyShell)

    return shHash


def hashShellcodeTestShow(mode=None):
    global shHash
    if mode == sample:
        print(shHash.show())
    if mode == unencryptedShell:
        print(shHash.show(unencryptedShell))
    if mode == decoderShell:
        print(shHash.show(decoderShell))
    if mode == unencryptedBodyShell:
        print(shHash.show(unencryptedBodyShell))
    if mode == None:
        print(shHash.show())
        print(shHash.show(unencryptedShell))
        print(shHash.show(decoderShell))
        print(shHash.show(unencryptedBodyShell))


def useMd5asFilename():
    global useHash
    global filename2
    useHash = True
    if useHash:
        filename2 = shHash.md5
    print("\tMd5 hash will be used to save output.")


def findAll():  # Find everything
    global peName

    global bDisassembly
    global bPrintEmulation

    global modulesMode
    global minStrLen
    global elapsed_time

    moduleBooleans[shellcode_label].bWideStringFound = False

    max_len = get_max_length(constants.LIST_OF_LABELS)
    if not rawHex:
        print("Finding imports.\n")
        if not moduleBooleans[shellcode_label].bEvilImportsFound:
            findEvilImports()
        if len(FoundApisName) > 0:
            moduleBooleans[shellcode_label].bEvilImportsFound = True

    if not rawHex:
        runInMem()

    if bPrintEmulation and not moduleBooleans[shellcode_label].bEmulationFound:
        newTime = discoverEmulation(max_len)
        elapsed_time += newTime

    if not moduleBooleans[shellcode_label].bStringsFound:
        print("Finding strings.\n")
        discoverAsciiStrings(max_len)

    if not moduleBooleans[shellcode_label].bWideStringFound:
        discoverUnicodeStrings(max_len)

    if not moduleBooleans[shellcode_label].bPushStringsFound:
        discoverStackStrings(max_len)

    print("\n\n")

    if bFstenv and not moduleBooleans[shellcode_label].bFstenvFound:
        newTime = discoverFstenv(max_len)
        elapsed_time += newTime

    if bPushRet and not moduleBooleans[shellcode_label].bPushRetFound:
        newTime = discoverPushRet(max_len)
        elapsed_time += newTime

    if bCallPop and not moduleBooleans[shellcode_label].bCallPopFound:
        newTime = discoverCallPop(max_len)
        elapsed_time += newTime

    if bHeaven and not moduleBooleans[shellcode_label].bHeavenFound:
        newTime = discoverHeaven(max_len)
        elapsed_time += newTime

    if bSyscall and not moduleBooleans[shellcode_label].bSyscallFound:
        newTime = discoverSyscal(max_len)
        elapsed_time += newTime

    if bPEB and not moduleBooleans[shellcode_label].bPEBFound:
        newTime = discoverPEB(max_len)
        elapsed_time += newTime

    if bDisassembly and not moduleBooleans[shellcode_label].bDisassemblyFound:
        newTime = discoverDisassembly(max_len)

    print("\n")
    print(" Search completed.\n")


def emuSyscallSelectionsSubMenu():  # Select osversions for syscalls
    global emuSyscallSelection
    global em
    global configOptions
    global emuSyscallCode

    # currently modified to only work for one version.
    print("\nEnter code for desired syscall ID version.\n\tE.g. v3\n")
    print(
        constants.CYAN
        + " Sharem>"
        + constants.GREEN
        + "Print>"
        + constants.YELLOW
        + "Syscalls>"
        + constants.RED
        + "Input> "
        + res,
        end="",
    )

    sysSelectIN = input()
    selections = sysSelectIN.replace(",", " ")
    selectionList = selections.split()
    while len(selectionList) > 1:
        sysSelectIN = input("Please enter only one code.\n> ")
        selections = sysSelectIN.replace(",", " ")
        selectionList = selections.split()

    selection = selectionList[0]

    validKeys = emuSyscallSelection.keys()
    foundKey = False
    for key in validKeys:
        if selection == key:
            emuSyscallSelection[key][0] = True
            foundKey = True
        else:
            emuSyscallSelection[key][0] = False
    if not foundKey:
        print("Invalid code.")
    else:
        em.winVersion = emuSyscallSelection[selection][1]
        em.winSP = emuSyscallSelection[selection][2]
        emuSyscallCode = selection

    print("\tYou selected:", em.winVersion, em.winSP)


def syscallSelectionsSubMenu():  # Select osversions for syscalls
    global syscallSelection
    x = ""

    print("\nEnter input deliminted by commas or spaces.\n\tE.g. v3, xp2, r3\n")
    while x != "e":
        sysSelectIN = input("> ")
        print("...")
        # print(type(syscallSelection[1]))
        v = "asdf"
        # print(type(v))
        # Recursively loop through to check each OS
        for osv in syscallSelection:
            # If we make changes, our multiselects no longer apply
            if osv.category == "server Column multiselect variables":
                osv.toggle = False

            # If we find a match between the selection codes and our input, toggle that os
            if re.search(rf"(^| |,){osv.code}($| |,)", sysSelectIN):
                osv.toggle = False if osv.toggle else True

                # If we toggle a category, toggle everything in that category
                if osv.name == osv.category:
                    for ver in syscallSelection:
                        if ver.category == osv.category:
                            ver.toggle = osv.toggle

                # If we toggle a multiselect, do a multiselect
                if osv.code == "all":  # Toggle all
                    osv.toggle = True
                    for ver in syscallSelection:
                        if not (ver.category == "server Column multiselect variables"):
                            ver.toggle = True
                if osv.code == "l":  # Only latest releases
                    osv.toggle = True
                    for ver in syscallSelection:
                        if not (ver.category == "server Column multiselect variables"):
                            ver.toggle = False
                    currentCategory = ""
                    for t, ver in enumerate(syscallSelection):
                        if t == 0:
                            currentCategory = ver.category
                        elif currentCategory != ver.category:
                            currentCategory = ver.category
                            syscallSelection[t - 1].toggle = True
                if osv.code == "d":  # Only current win10
                    osv.toggle = True
                    for ver in syscallSelection:
                        if not (ver.category == "server Column multiselect variables"):
                            ver.toggle = False
                    t = len(syscallSelection) - 1
                    for ver in syscallSelection:
                        if syscallSelection[t].category == "Windows 10":
                            syscallSelection[t].toggle = True
                            break
                        t -= 1
                if osv.code == "D":  # only current win10 and 7
                    osv.toggle = True
                    for ver in syscallSelection:
                        if not (ver.category == "server Column multiselect variables"):
                            ver.toggle = False
                    t = len(syscallSelection) - 1
                    for ver in syscallSelection:
                        if syscallSelection[t].category == "Windows 10":
                            syscallSelection[t].toggle = True
                            break
                        t -= 1
                    t = len(syscallSelection) - 1
                    for ver in syscallSelection:
                        if syscallSelection[t].category == "Windows 7":
                            syscallSelection[t].toggle = True
                            break
                        t -= 1
        break


def clearInstructions(variables, module, shellcode_label):  # Clears
    for secNum in s:
        secNum.save_PEB_info.clear()
        secNum.save_FSTENV_info.clear()
        secNum.save_Egg_info.clear()
        secNum.save_Heaven_info.clear()
        secNum.save_Callpop_info.clear()
        secNum.save_PushRet_info.clear()

    for d in (constants.ShellcodeLabel.SHELLCODE_LABEL, constants.ShellcodeLabel.SHELLCODE_DECODED_BODY_LABEL, constants.ShellcodeLabel.SHELLCODE_DECODED_FULL_LABEL, constants.ShellcodeLabel.SHELLCODE_DECODED_STUB_LABEL):
        try:
            module[d].save_PEB_info.clear()
        except KeyError as ke:
            continue
        try:
            module[d].save_FSTENV_info.clear()
        except KeyError as ke:
            continue
        try:
            module[d].save_Egg_info.clear()
        except KeyError as ke:
            continue
        try:
            module[d].save_Heaven_info.clear()
        except KeyError as ke:
            continue
        try:
            module[d].save_Callpop_info.clear()
        except KeyError as ke:
            continue
        try:
            module[d].save_PushRet_info.clear()
        except KeyError as ke:
            continue

    clearFoundBooleans(variables, shellcode_label)


def clearMods():  # Clears our module list
    global IATs
    IATs.foundDll = []
    FoundApisName = []
    IATs.found = []
    IATs.path = []
    IATs.originate = []
    moduleBooleans[shellcode_label].bModulesFound = False


def clearFoundBooleans(variables, shellcode_label):  # Clears bools saying we've found data
    for d in (constants.ShellcodeLabel.SHELLCODE_LABEL, constants.ShellcodeLabel.SHELLCODE_DECODED_BODY_LABEL, constants.ShellcodeLabel.SHELLCODE_DECODED_FULL_LABEL, constants.ShellcodeLabel.SHELLCODE_DECODED_STUB_LABEL):
        variables.moduleBooleans[d].bPushRetFound = False
        variables.moduleBooleans[d].bFstenvFound = False
        variables.moduleBooleans[d].bSyscallFound = False
        variables.moduleBooleans[d].bHeavenFound = False
        variables.moduleBooleans[d].bPEBFound = False
        variables.moduleBooleans[d].bCallPopFound = False
        variables.moduleBooleans[d].bStringsFound = False
        variables.moduleBooleans[d].bEvilImportsFound = False
        variables.moduleBooleans[d].bModulesFound = False
        variables.moduleBooleans[d].bWideStringFound = False
        variables.moduleBooleans[d].bPushStringsFound = False


def clearAll():  # Clears all found data and booleans
    clearInstructions()
    clearMods()
    clearFoundBooleans()
    clearStrings()
    clearImports()
    commentsGiven = False


def clearStrings():
    global stringsTemp
    global stringsTempWide
    global pushStringsTemp

    for d in m:
        mBool[d].bStringsFound = False
        mBool[d].bWideStringFound = False
        mBool[d].bPushStringsFound = False
    try:
        for sec in s:
            sec.Strings.clear()
            sec.wideStrings.clear()
            sec.pushStrings.clear()

    except Exception as e:
        print("Clear strings Here", e)
        pass
    stringsTempWide.clear()
    pushStringsTemp.clear()
    stringsTemp.clear()
    clearFoundBooleans()


def clearImports():
    FoundApisName.clear()
    moduleBooleans[shellcode_label].bEvilImportsFound = False


def build_emu_results(apiList):
    api_names = []
    api_params_values = []
    api_params_types = []
    api_params_names = []
    api_address = []
    ret_values = []
    ret_type = []
    api_bruteforce = []
    dll_name = []
    sysCallID = []

    for i in apiList:
        api_names.append(i[0])
        api_address.append(i[1])
        ret_values.append(i[2])
        ret_type.append(i[3])
        api_params_values.append(i[4])
        api_params_types.append(i[5])
        api_params_names.append(i[6])
        api_bruteforce.append(i[7])

        if len(i) > 8:
            sysCallID.append(i[8])

    return (
        api_names,
        api_params_values,
        api_params_types,
        api_params_names,
        api_address,
        ret_values,
        ret_type,
        api_bruteforce,
        sysCallID,
    )


def emulation_txt_out(apiList, logged_syscalls):
    sample = [
        (
            "WinExec",
            "0x123123",
            "0x20",
            "INT",
            ["cmd.exe /c ping google.com > C:\\result.txt", "0x5"],
            ["LPCSTR", "UINT"],
            ["lpCmdLine", "uCmdShow"],
            False,
            "kernel32.dll",
        ),
        (
            "EncyptFileA",
            "0x321321",
            "0x20",
            "INT",
            ["C:\\result.txt"],
            ["LPCSTR"],
            ["lpFileName"],
            False,
            "kernel32.dll",
        ),
        (
            "LoadLibraryA",
            "0x1337c0de",
            "0x45664c88",
            "HINSTANCE",
            ["user32.dll"],
            ["LPCTSTR"],
            ["lpLibFileName"],
            False,
            "kernel32.dll",
        ),
        (
            "MessageBoxA",
            "0xdeadc0de",
            "0x20",
            "INT",
            [
                "0x987987",
                "You have been hacked by an elite haxor. Your IP address is now stored in C:\\result.txt but it is encrypted :)cmd.exe /c ping google.com > C:\\result.txt",
                "You have been hacked by an elite haxor. Your IP address is now stored in C:\\result.txt but it is encrypted :)cmd.exe /c ping google.com > C:\\result.txt",
                "0x0",
            ],
            ["HWND", "LPCSTR", "LPCSTR", "UINT"],
            ["hWnd", "lpText", "lpCaption", "uType"],
            True,
            "user32.dll",
        ),
    ]

    # artifacts, net_artifacts, file_artifacts, exec_artifacts = findArtifacts()
    # path_artifacts, file_artifacts, commandLine_artifacts, web_artifacts, registry_artifacts, exe_dll_artifacts = findArtifacts()
    findArtifacts()
    (
        api_names,
        api_params_values,
        api_params_types,
        api_params_names,
        api_address,
        ret_values,
        ret_type,
        api_bruteforce,
        syscallID,
    ) = build_emu_results(apiList)

    api_par_bundle = []
    txt_output = ""

    txt_output += "\n**************************\n"
    txt_output += "     Emulation\n"
    txt_output += "**************************\n\n"

    txt_output += (
        constants.MAGENTA + "\n************* APIs *************\n\n" + constants.RESET
    )
    txt_output = printOut.apisOut(
        emulation_verbose,
        api_names,
        api_params_values,
        api_params_types,
        api_params_names,
        api_address,
        ret_values,
        ret_type,
        api_bruteforce,
        syscallID,
    )

    if len(logged_syscalls):
        (
            syscall_names,
            syscall_params_values,
            syscall_params_types,
            syscall_params_names,
            syscall_address,
            ret_values,
            ret_type,
            syscall_bruteforce,
            syscallID,
        ) = build_emu_results(logged_syscalls)
        txt_output += printOut.syscallsOut(
            emulation_verbose,
            syscall_names,
            syscall_params_values,
            syscall_params_types,
            syscall_params_names,
            syscall_address,
            ret_values,
            ret_type,
            syscall_bruteforce,
            syscallID,
            em,
        )

    txt_output += printOut.artifactsOut(logged_dlls)

    no_colors_out = Variables.cleanColors(self=Variables, out=txt_output)

    if bPrintEmulation:
        if len(apiList) > 0 or len(logged_syscalls) > 0:
            print(txt_output)
        else:
            print(
                constants.GREEN
                + "\n\t[*] No APIs discovered through emulation."
                + constants.RESET
            )

    else:
        return no_colors_out


def printToJson(
    outputData, filename, rawHex, sharem_out_dir, FoundApisName
):  # Output data to json
    # takes outputdata from generateoutputdata
    disResults = createDisassemblyJson()
    jsonP.importData(
        importedData=outputData,
        FoundApisName=FoundApisName,
        filename=filename,
        importDiss=disResults,
    )
    jsonP.generateJson(filename, peName, sharem_out_dir, rawHex)


def formatPrint(i, add4, addb, pe=False, syscall=False):
    if print_style == "right":
        length = 35

        if not pe:
            if not syscall:
                val = "{0:<6s} {1:<{2}s} {3:<8s}".format(
                    i.mnemonic, i.op_str, length, add4
                )
                return val
            else:
                monic = i.split("|")[0]
                op_str = "".join(i.split("|")[1])

                val = "{0:<6s} {1:<{2}s} {3:<8s}".format(monic, op_str, length, add4)
                return val

        else:
            val = "{0:<6s} {1:<{2}s} {3:<12s} {4:<10}".format(
                i.mnemonic, i.op_str, length, add4, "(offset " + addb + ")"
            )
            return val
    elif print_style == "left":
        length = 30
        if not pe:
            if not syscall:
                val = "{0:<10s} {1:<4s} {2} ".format(add4, i.mnemonic, i.op_str)
                return val
            else:
                monic = i.split("|")[0]
                op_str = i.split("|")[1]
                # print(op_str)
                # input()

                val = "{0:<6s} {1:<{2}s} {3:<8s}".format(monic, op_str, length, add4)
                return val

        else:
            val = "{0:<10s} {1:<4s} {2:<{3}s} {4}".format(
                add4, i.mnemonic, i.op_str, length, "(offset " + addb + ")"
            )

            # val =('{0:<6s} {1:<{2}s} {3:<12s} {4:<10}'.format(i.mnemonic, i.op_str, length, add4, "(offset " + addb + ")"))
            return val
    else:
        print("Error: format style is not correct, it should be either right, or left.")
        sys.exit()


def hashesJson(shell_code):
    global o

    binLit = ""
    tmpDict = {}

    if shell_code.decryptSuccess:
        for i in shell_code.decoderStub:
            binLit += "\\x" + "{:02x}".format(i) + ""
        tmpDict["deobfuscated"] = True

        tmpDict["decoded_stub"] = binLit
        tmpDict["md5"] = m[o].getMd5()
        tmpDict["sha256"] = m[o].getSha256()
        tmpDict["ssdeep"] = m[o].getSsdeep()

    else:
        tmpDict["deobfuscated"] = False
        tmpDict["decoded_stub"] = "N/A"
        tmpDict["md5"] = "N/A"
        tmpDict["sha256"] = "N/A"
        tmpDict["ssdeep"] = "N/A"

    return tmpDict


def generateOutputData(
    shell_code, rawHex, conr
):  # Generate the dictionary for json out
    global brawHex
    global bstrLit
    global IATs
    global art

    time = datetime.datetime.now()
    epoch = time.timestamp()
    filetime = time.strftime("%Y%m%d'T'%H%M%S%z")
    time = time.strftime("%Y-%m-%d %H:%M:%S")
    # jsonFileName = "output_" + peName + "_" + filetime + ".json"
    jsonFileName = peName + "_" + filetime + ".json"
    # jsonData is a dictionary, we add fields to it below
    jsonData = {}
    if rawHex:
        shellClass = isShellcode(
            moduleBooleans[shellcode_label], patt, shell_code, conr
        )
    jsonData["dateAnalyzed"] = time
    if rawHex:
        jsonData["classification"] = shellClass[0]
        jsonData["reason"] = shellClass[1]
    jsonData["secondsSinceEpoch"] = epoch
    jsonData["fileType"] = ""
    jsonData["bits"] = variables.shellBit
    if not rawHex:
        jsonData["md5"] = m[o].getMd5()
        jsonData["sha256"] = m[o].getSha256()
        jsonData["ssdeep"] = m[o].getSsdeep()

    if not rawHex:
        jsonData["modules"] = []
        jsonData["imports"] = []
    if rawHex:
        try:
            jsonData["entryPoint"] = str(hex(shellEntry))
            jsonData["md5"] = m[constants.ShellcodeLabel.SHELLCODE_LABEL].getMd5()
            jsonData["sha256"] = m[constants.ShellcodeLabel.SHELLCODE_LABEL].getSha256()
            jsonData["ssdeep"] = m[constants.ShellcodeLabel.SHELLCODE_LABEL].getSsdeep()

        except:
            jsonData["entryPoint"] = str(shellEntry)
            jsonData["md5"] = m[constants.ShellcodeLabel.SHELLCODE_LABEL].getMd5()
            jsonData["sha256"] = m[constants.ShellcodeLabel.SHELLCODE_LABEL].getSha256()
            jsonData["ssdeep"] = m[constants.ShellcodeLabel.SHELLCODE_LABEL].getSsdeep()
    else:
        jsonData["peInfo"] = []
    if rawHex:
        jsonData["fileType"] = "rawHex"
    else:
        jsonData["fileType"] = "PE"
    jsonData["pushret"] = []
    jsonData["callpop"] = []
    jsonData["PEB"] = []
    jsonData["fstenv"] = []
    jsonData["heavensGate"] = []
    jsonData["syscall"] = []
    if not rawHex:
        jsonData["strings"] = {}
    else:
        # print("---------------- RAWHEX-------------------")
        jsonData["strings"] = []

    jsonData["shellcode"] = {"rawhex": brawHex, "strlit": bstrLit}

    jsonData["deobfuscation"] = hashesJson(shell_code)

    jsonData["emulation"] = jsonP.generateEmulationResults(
        loggedList, logged_syscalls, em, art
    )

    # We grab the saved info, and loop through it, adding an object to the respective category's list and add a new object for each. The method is the same as the printsaved____() functions
    if bit32:
        callCS = cs
    else:
        callCS = cs64
    # Handle Sections
    if rawHex:
        entryPoint = str(hex(m[o].entryPoint))
        jsonData["entryPoint"] = entryPoint
        jsonData["md5"] = m[constants.ShellcodeLabel.SHELLCODE_LABEL].getMd5()
        jsonData["sha256"] = m[constants.ShellcodeLabel.SHELLCODE_LABEL].getSha256()
        jsonData["ssdeep"] = m[constants.ShellcodeLabel.SHELLCODE_LABEL].getSsdeep()

    else:
        t = 0
        # print("Sections --> ", s)
        for sec in sections:
            try:
                secName = s[t].sectionName.decode()
            except:
                secName = s[t].sectionName
            entryPoint = str(hex(s[t].entryPoint))
            virtualAddress = str(hex(s[t].VirtualAdd))
            imageBase = str(hex(s[t].ImageBase))
            virtualSize = str(hex(s[t].vSize))
            secSize = str(hex(s[t].SizeOfRawData))
            imageBasePlusVirtualAdd = str(hex(s[t].startLoc))
            DEP = str(s[t].depStatus)
            ASLR = str(s[t].aslrStatus)
            SEH = str(s[t].sehSTATUS)
            CFG = str(s[t].CFGstatus)
            Sha256 = s[t].Hash_sha256_section
            md5 = s[t].Hash_md5_section
            jsonData["peInfo"].append(
                {
                    "sectionName": secName,
                    "entryPoint": {
                        "offset": entryPoint,
                        "imageBasePlusVirtualAdd": imageBasePlusVirtualAdd,
                        "imageBase": imageBase,
                    },
                    "virtualAddress": virtualAddress,
                    "virtualSize": virtualSize,
                    "sectionSizeOfRawData": secSize,
                    "mitigations": {"DEP": DEP, "ASLR": ASLR, "SEH": SEH, "CFG": CFG},
                    "hashes": {"Sha256": Sha256, "md5": md5},
                }
            )
            t += 1

    if moduleBooleans[shellcode_label].bStringsFound:
        if rawHex:
            # jsonData['strings'] = {'shellcode':[]}
            for value, offset, wordLength in stringsTemp:
                if wordLength >= minStrLen:
                    jsonData["strings"].append(
                        {
                            "type": "ascii",
                            "offset": hex(offset),
                            "length": str(wordLength),
                            "value": str(value),
                            "source": "shellcode",
                        }
                    )

            # 	jsonData['strings'][]
            # 	print ("\t"+ str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z)))
            for value, offset, wordLength in stringsTempWide:
                if wordLength >= minStrLen:
                    jsonData["strings"].append(
                        {
                            "type": "unicode",
                            "offset": hex(offset),
                            "length": str(wordLength),
                            "value": str(value),
                            "source": "shellcode",
                        }
                    )

            # 	print ("\t"+ str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z)))
            # #word4, offset, wordLength,instructionsLength
            for value, offset, wordLength, instLen in pushStringsTemp:
                if wordLength >= minStrLen:
                    jsonData["strings"].append(
                        {
                            "type": "pushString",
                            "offset": hex(offset),
                            "length": str(wordLength),
                            "value": str(value),
                            "source": "shellcode",
                        }
                    )
            # 	print ("\t"+ str(word4) + "\t" + hex(offset) + "\t" + str(hex(wordLength)))

        # global stringsTemp ascii
        # global stringsTempWide
        # global pushStringsTemp
        else:
            t = 0
            for secNum in range(len(s)):
                jsonData["strings"][s[t].sectionName.decode()] = []
                for value, offset, length in s[t].Strings:
                    jsonData["strings"][s[t].sectionName.decode()].append(
                        {
                            "type": "string",
                            "section": s[t].sectionName.decode(),
                            "offset": hex(offset + s[t].VirtualAdd),
                            "address": hex(s[t].ImageBase + s[t].VirtualAdd + offset),
                            "length": str(length),
                            "value": str(value),
                        }
                    )
                for value, offset, length in s[t].wideStrings:
                    # format widestring to string
                    tempVal = ""
                    j = 0
                    for char in value:
                        if not (j % 2):
                            tempVal += char
                        j += 1
                    jsonData["strings"][s[t].sectionName.decode()].append(
                        {
                            "type": "wideString",
                            "section": s[t].sectionName.decode(),
                            "offset": hex(offset + s[t].VirtualAdd),
                            "address": hex(s[t].ImageBase + s[t].VirtualAdd + offset),
                            "length": str(length),
                            "value": tempVal,
                        }
                    )
                # for value, offset, length in s[t].pushStrings:
                # word4, offset, offsetVA,offsetPlusImagebase, wordLength,instructionsLength
                for word4, offset, offsetVA, offsetpImage, wordLen, instLen in s[
                    t
                ].pushStrings:
                    # jsonData['strings'][s[t].sectionName.decode()].append({'type':'pushString',
                    # 														'section':s[t].sectionName.decode(),
                    # 														"word4":word4, 'offset': hex(offset),
                    # 														"address":hex(s[t].ImageBase + s[t].VirtualAdd + offset),
                    # 														'length':str(length),
                    # 														'value':str(value)})

                    jsonData["strings"][s[t].sectionName.decode()].append(
                        {
                            "type": "pushString",
                            "section": s[t].sectionName.decode(),
                            "value": word4,
                            "offset": hex(offset + s[t].VirtualAdd),
                            "length": str(wordLen),
                        }
                    )
                t += 1
            # for value,offset,length  in stringsTemp:
            # 	jsonData['strings'][s[t].sectionName.decode()].append({'type':'tempString', 'section':s[t].sectionName.decode(), 'offset': hex(offset), "address":hex(s[t].ImageBase + s[t].VirtualAdd + offset), 'length':sstr(length), 'value':str(value)})
    if moduleBooleans[shellcode_label].bPushRetFound:
        if rawHex:
            # for i in m[o].save_PushRet_info:

            for item in m[o].save_PushRet_info:
                address = item[0]
                NumOpsDis = item[1]
                modSecName = item[2]
                secNum = item[3]
                points = item[4]
                pushOffset = item[5]
                # print ("printoffset", pushOffset)
                pushAdd = int(pushOffset[0], 16)
                retOffset = item[6]
                # print ("retOffset", retOffset)
                printEnd = int(retOffset, 16) + 15
                # print ("printEnd", printEnd)
                CODED2 = m[o].rawData2[address:(printEnd)]
                # print ("1",binaryToStr(CODED2))
                # print ("\n2",binaryToStr(m[o].rawData2[pushAdd:(printEnd)]))

                val = ""
                val2 = []
                val3 = []
                val5 = []
                jsonDis = {}
                jsonList = []
                stopRet = False
                for i in callCS.disasm(CODED2, address):
                    if rawHex:
                        add4 = hex(int(i.address))
                        addb = hex(int(i.address))
                    else:
                        add = hex(int(i.address))
                        addb = hex(int(i.address + section.VirtualAdd))
                        add2 = str(add)
                        add3 = hex(int(i.address + section.startLoc))
                        add4 = str(add3)

                    val = formatPrint(i, add4, addb).strip()
                    # val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
                    checkRet = re.search(retOffset, val, re.M | re.I)
                    # if str(retOffset) == addb:
                    # 	val5.append(val)
                    # 	break
                    # else:
                    # 	val5.append(val)
                    # i.mnemonic, i.op_str, length, add4
                    jsonDis = {}
                    if checkRet:
                        if not stopRet:
                            jsonDis["offset"] = add4
                            jsonDis["instruction"] = (
                                i.mnemonic + " " + i.op_str
                            ).strip()
                            val5.append(val)
                            stopRet = True

                    if not stopRet:
                        jsonDis["offset"] = add4
                        jsonDis["instruction"] = i.mnemonic + " " + i.op_str
                        val5.append(val)

                    if jsonDis != {}:
                        jsonList.append(jsonDis)

                jsonData["pushret"].append(
                    {
                        "address": hex(address),
                        "pushOffset": pushOffset,
                        "retOffset": retOffset,
                        "modSecName": modSecName,
                        "disassembly": val5,
                        "internalData": {
                            "secNum": secNum,
                            "NumOpsDis": NumOpsDis,
                            "points": points,
                        },
                        "disasm": jsonList,
                    }
                )
        else:
            for section in s:
                for item in section.save_PushRet_info:
                    address = item[0]
                    NumOpsDis = item[1]
                    modSecName = item[2].decode()
                    secNum = item[3]
                    points = item[4]
                    pushOffset = item[5]
                    retOffset = item[6]
                    section = s[secNum]
                    printEnd = int(retOffset, 16) + 3 - section.VirtualAdd
                    val = ""
                    val2 = []
                    val3 = []
                    address2 = address + section.ImageBase + section.VirtualAdd
                    val5 = []
                    CODED2 = section.data2[address:printEnd]
                    CODED3 = CODED2
                    stopRet = False
                    for i in callCS.disasm(CODED3, address):
                        add = hex(int(i.address))
                        addb = hex(int(i.address + section.VirtualAdd))
                        add2 = str(add)
                        add3 = hex(int(i.address + section.startLoc))
                        add4 = str(add3)
                        val = formatPrint(i, add4, addb, pe=True)
                        val2.append(val)
                        val3.append(add2)
                        checkRet = re.search(retOffset, val, re.M | re.I)

                        if retOffset == addb:
                            val5.append(val)
                            break
                        else:
                            val5.append(val)
                    jsonData["pushret"].append(
                        {
                            "address": hex(address),
                            "pushOffset": pushOffset,
                            "retOffset": retOffset,
                            "modSecName": modSecName,
                            "disassembly": val5,
                            "internalData": {
                                "secNum": secNum,
                                "NumOpsDis": NumOpsDis,
                                "points": points,
                            },
                        }
                    )

    if moduleBooleans[shellcode_label].bCallPopFound:
        if rawHex:
            jsonList = []
            for item in m[o].save_Callpop_info:
                address = item[0]
                NumOpsDis = item[1]
                modSecName = item[2]
                secNum = item[3]
                distance = item[4]
                pop_offset = item[5]
                CODED2 = m[o].rawData2[(address) : int(pop_offset, 16) + 1]
                CODED3 = CODED2
                val = ""
                val2 = []
                val3 = []
                val5 = []

                for i in callCS.disasm(CODED2, address):
                    jsonDis = {}

                    if rawHex:
                        add4 = hex(int(i.address))
                        addb = hex(int(i.address))
                    # else:
                    # 	add = hex(int(i.address))
                    # 	addb = hex(int(i.address +  section.VirtualAdd))
                    # 	add2 = str(add)
                    # 	add3 = hex (int(i.address + section.startLoc))
                    # 	add4 = str(add3)
                    jsonDis["offset"] = add4
                    jsonDis["instruction"] = (i.mnemonic + " " + i.op_str).strip()
                    val = formatPrint(i, add4, addb)
                    # val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
                    val5.append(val)
                    jsonList.append(jsonDis)
                jsonData["callpop"].append(
                    {
                        "address": hex(address),
                        "modSecName": modSecName,
                        "pop_offset": pop_offset,
                        "distance": distance,
                        "disassembly": val5,
                        "disasm": jsonList,
                        "internalData": {"secNum": secNum, "NumOpsDis": NumOpsDis},
                    }
                )
        else:
            for section in s:
                for item in section.save_Callpop_info:
                    # address = item[0]
                    origAddr = item[0]
                    NumOpsDis = item[1]
                    modSecName = item[2].decode()
                    secNum = item[3]
                    distance = item[4]
                    pop_offset = item[5]
                    # print("pop_offset in generateoutputdata", pop_offset)
                    # input()
                    address = origAddr + distance
                    section = s[secNum]
                    CODED2 = section.data2[(origAddr) : (address + NumOpsDis)]
                    # print(CODED2)
                    # input()
                    # CODED2 = section.data2[(address):(address+1+distance)]
                    CODED3 = CODED2
                    val = ""
                    val2 = []
                    val3 = []
                    val5 = []
                    # print("Disassm", CODED3.hex())
                    # input()
                    # print("origAddr: ", address, "CODED3", CODED3)
                    # print("origAddr: ", origAddr, "CODED3", CODED3, "Address", address)
                    # print("Generate output", CODED3.hex())
                    for i in callCS.disasm(CODED3, origAddr):
                        add = hex(int(i.address))
                        addb = hex(int(i.address + section.VirtualAdd))
                        add2 = str(add)
                        add3 = hex(int(i.address + section.startLoc))
                        add4 = str(add3)
                        val = formatPrint(i, add4, addb, pe=True)

                        # val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
                        val2.append(val)
                        val3.append(add2)
                        val5.append(val)
                        if addb == pop_offset:
                            break
                    address = origAddr + section.VirtualAdd
                    jsonData["callpop"].append(
                        {
                            "address": hex(address),
                            "modSecName": modSecName,
                            "pop_offset": pop_offset,
                            "distance": distance,
                            "disassembly": val5,
                            "internalData": {"secNum": secNum, "NumOpsDis": NumOpsDis},
                        }
                    )

    if moduleBooleans[shellcode_label].bFstenvFound:
        if rawHex:
            for item in m[o].save_FSTENV_info:
                address = item[0]
                NumOpsDis = item[1]
                NumOpsBack = item[2]
                modSecName = item[3]
                secNum = item[4]
                FPU_offset = item[5]
                FSTENV_offset = item[6]
                printEnd = item[7]
                CODED2 = m[o].rawData2[int(FPU_offset, 16) : (int(printEnd, 16))]
                CODED3 = CODED2
                val = ""
                val2 = []
                val3 = []
                val5 = []
                jsonList = []
                for i in callCS.disasm(CODED2, (int(FPU_offset, 16))):
                    jsonDis = {}
                    add4 = hex(int(i.address))
                    addb = hex(int(i.address))

                    val = formatPrint(i, add4, addb).strip()

                    # val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
                    val5.append(val)
                    jsonDis["offset"] = add4
                    jsonDis["instruction"] = (i.mnemonic + " " + i.op_str).strip()
                    jsonList.append(jsonDis)

                jsonData["fstenv"].append(
                    {
                        "address": hex(address),
                        "modSecName": modSecName,
                        "FPU_offset": FPU_offset,
                        "FSTENV_offset": FSTENV_offset,
                        "disassembly": val5,
                        "disasm": jsonList,
                        "internalData": {
                            "secNum": secNum,
                            "NumOpsDis": NumOpsDis,
                            "NumOpsBack": NumOpsBack,
                            "printEnd": printEnd,
                        },
                    }
                )
        else:
            for section in s:
                for item in section.save_FSTENV_info:
                    address = item[0]
                    NumOpsDis = item[1]
                    NumOpsBack = item[2]
                    modSecName = item[3].decode()
                    secNum = item[4]
                    FPU_offset = item[5]
                    FSTENV_offset = item[6]
                    printEnd = item[7]
                    section = s[secNum]
                    CODED2 = section.data2[
                        (address - NumOpsBack) : (address + NumOpsDis)
                    ]
                    CODED3 = CODED2
                    val = ""
                    val2 = []
                    val3 = []
                    val5 = []
                    for i in callCS.disasm(CODED3, address):
                        add = hex(int(i.address))
                        addb = hex(int(i.address + section.VirtualAdd - NumOpsBack))
                        add2 = str(add)
                        add3 = hex(int(i.address + section.startLoc - NumOpsBack))
                        add4 = str(add3)
                        val = formatPrint(i, add4, addb, pe=True)

                        # val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
                        val2.append(val)
                        val3.append(add2)
                        val5.append(val)
                        if str(FSTENV_offset) == addb:
                            break
                        # if(addb == printEnd):
                        # break
                    jsonData["fstenv"].append(
                        {
                            "address": hex(address),
                            "modSecName": modSecName,
                            "FPU_offset": FPU_offset,
                            "FSTENV_offset": FSTENV_offset,
                            "disassembly": val5,
                            "internalData": {
                                "secNum": secNum,
                                "NumOpsDis": NumOpsDis,
                                "NumOpsBack": NumOpsBack,
                                "printEnd": printEnd,
                            },
                        }
                    )

    # jsonheav
    if moduleBooleans[shellcode_label].bHeavenFound:
        if rawHex:
            if heavRawHexOverride:
                # print("in override")
                j = 0
                for item in m[o].save_Heaven_info:
                    CODED2 = ""

                    address = item[0]
                    NumOpsDis = item[1]
                    NumOpsBack = item[2]
                    modSecName = item[3]
                    secNum = item[4]
                    offset = item[5]
                    pushOffset = item[6]
                    destLocation = item[7]
                    if destLocation != -1:
                        for char in range(len(destLocation)):
                            if destLocation[char] == "\t":
                                destLocation = destLocation[0 : char - 1]
                                break
                    converted = item[8]
                    pivottype = item[9]

                    # for char in range(len(destLocation)):
                    # 	if (destLocation[char] == '\t'):
                    # 		destLocation = destLocation[0:char-1]
                    # 		break
                    # print("NUMBACK = " + str(NumOpsBack))

                    val = ""
                    val2 = []
                    val3 = []
                    # address2 = address + section.ImageBase + section.VirtualAdd
                    jsonList = []
                    val5 = []
                    # CODED2 = section.data2[(address-NumOpsBack):(address+NumOpsDis)]
                    bytesCompensation = 18
                    if pivottype == "ljmp/lcall":
                        start = int(offset, 16)  # - section.VirtualAdd
                        # The 7 is for the ljmp assembly mnemonic
                        CODED2 = m[o].rawData2[(start) : (start + 7)]
                    elif pivottype == "retf":
                        start = int(offset, 16)  # - section.VirtualAdd
                        # The two bytes is for the retf
                        CODED2 = m[o].rawData2[(start - bytesCompensation) : start + 2]

                    CODED3 = CODED2

                    # for i in callCS.disasm(CODED3, address):
                    if pivottype == "ljmp/lcall":
                        bytesCompensation = 0
                    elif pivottype == "retf":
                        bytesCompensation = 18
                    for i in callCS.disasm(CODED3, start - bytesCompensation):
                        add = hex(int(i.address))
                        addb = hex(int(i.address))
                        add2 = str(add)
                        add3 = hex(int(i.address))
                        add4 = str(add3)
                        val = formatPrint(i, add4, addb, pe=True)

                        # val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
                        val2.append(val)
                        val3.append(add2)
                        val5.append(val)
                        jsonDis = {}
                        # print("Line: ", line, type(line), repr(line))
                        # instr =  ' '.join(line.split(" ")[:-3]).strip()
                        # off = line.split(" ")[-3]
                        jsonDis["offset"] = add4
                        jsonDis["instruction"] = (i.mnemonic + " " + i.op_str).strip()
                        jsonList.append(jsonDis)
                        # print (constants.GREEN + val + res)
                    j += 1

                    pushOffset = str(hex(pushOffset))
                    # print("Offset", pushOffset)
                    jsonData["heavensGate"].append(
                        {
                            "address": hex(address),
                            "modSecName": modSecName,
                            "pushOffset": pushOffset,
                            "heaven_offset": offset,
                            "destLocation": destLocation,
                            "disassembly": val5,
                            "disasm": jsonList,
                            "internalData": {
                                "secNum": secNum,
                                "NumOpsDis": NumOpsDis,
                                "NumOpsBack": NumOpsBack,
                                "pivottype": pivottype,
                            },
                        }
                    )

            else:
                for item in m[o].save_Heaven_info:
                    address = hex(item[0])
                    NumOpsDis = item[1]
                    NumOpsBack = item[2]
                    modSecName = item[3]
                    secNum = item[4]
                    offset = item[5]
                    pushOffset = item[6]
                    destLocation = item[7]
                    converted = item[8]
                    pivottype = item[9]
                    if pivottype == "ljmp/lcall":
                        converted = converted[-1:]
                    elif pivottype == "retf":
                        converted = converted[-5:]
                    converted2 = []
                    jsonList = []
                    val5 = []
                    for line in converted:
                        line = line.replace("\t", " ")
                        jsonDis = {}
                        allInstr = line.split(" ")
                        # print("Everything ---> ", allInstr)
                        mnemonic = allInstr[0]
                        add4 = allInstr[-3]
                        addb = allInstr[-2:]
                        op_str = " ".join(allInstr[1:-3])

                        # print("----> mnemonic" , mnemonic, type(mnemonic))
                        # print("-----> op_str", op_str, type(op_str))
                        # input()
                        convOut = formatPrint(
                            mnemonic + "|" + op_str, add4, addb, syscall=True
                        )
                        val5.append(convOut.strip())
                        jsonDis = {}
                        # print("Line: ", line, type(line), repr(line))
                        # instr =  ' '.join(line.split(" ")[:-3]).strip()
                        # off = line.split(" ")[-3]
                        jsonDis["offset"] = add4
                        jsonDis["instruction"] = (mnemonic + " " + op_str).strip()
                        jsonList.append(jsonDis)
                        converted2.append(line)
                    converted = converted2

                    jsonData["heavensGate"].append(
                        {
                            "address": address,
                            "modSecName": modSecName,
                            "pushOffset": pushOffset,
                            "heaven_offset": offset,
                            "destLocation": destLocation,
                            "disassembly": val5,
                            "disasm": jsonList,
                            "internalData": {
                                "secNum": secNum,
                                "NumOpsDis": NumOpsDis,
                                "NumOpsBack": NumOpsBack,
                                "pivottype": pivottype,
                            },
                        }
                    )
                    # Heaven Item: 0 | Section: -1 | Section name: rawHex | Heaven's Gate offset: 0x1ad
        else:
            for section in s:
                for item in section.save_Heaven_info:
                    address = item[0]
                    NumOpsDis = item[1]
                    NumOpsBack = item[2]
                    modSecName = item[3].decode()
                    secNum = item[4]
                    offset = item[5]
                    pushOffset = item[6]
                    destLocation = item[7]
                    for char in range(len(destLocation)):
                        if destLocation[char] == "\t":
                            destLocation = destLocation[0 : char - 1]
                            break
                    pivottype = item[8]
                    val = ""
                    val2 = []
                    val3 = []
                    val5 = []
                    bytesCompensation = 18
                    if pivottype == "ljmp/lcall":
                        start = int(offset, 16) - section.VirtualAdd
                        # The 7 is for the ljmp assembly mnemonic
                        CODED2 = section.data2[(start) : (start + 7)]
                    elif pivottype == "retf":
                        start = int(offset, 16) - section.VirtualAdd
                        # The two bytes is for the retf
                        CODED2 = section.data2[(start - bytesCompensation) : start + 2]

                    CODED3 = CODED2
                    if pivottype == "ljmp/lcall":
                        bytesCompensation = 0
                    elif pivottype == "retf":
                        bytesCompensation = 18
                    for i in callCS.disasm(CODED3, start - bytesCompensation):
                        add = hex(int(i.address))
                        addb = hex(int(i.address + section.VirtualAdd))
                        add2 = str(add)
                        add3 = hex(int(i.address + section.startLoc))
                        add4 = str(add3)
                        val = formatPrint(i, add4, addb, pe=True)

                        # val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
                        val2.append(val)
                        val3.append(add2)
                        val5.append(val)
                    # print("Push offset: ", pushOffset)
                    # input()
                    pushOffset = str(hex(pushOffset))
                    # print("Offset", pushOffset)
                    jsonData["heavensGate"].append(
                        {
                            "address": hex(address),
                            "modSecName": modSecName,
                            "pushOffset": pushOffset,
                            "heaven_offset": offset,
                            "destLocation": destLocation,
                            "disassembly": val5,
                            "internalData": {
                                "secNum": secNum,
                                "NumOpsDis": NumOpsDis,
                                "NumOpsBack": NumOpsBack,
                                "pivottype": pivottype,
                            },
                        }
                    )
    # jsonpeb
    if moduleBooleans[shellcode_label].bPEBFound:
        if rawHex:
            if variables.shellBit == 64:
                callCS = cs64
            else:
                callCS = cs
            jsonList = []
            for item in m[o].save_PEB_info:
                address = item[0]
                NumOpsDis = item[1]
                modSecName = item[2]
                secNum = item[3]
                points = item[4]
                val = ""
                val2 = []
                val3 = []
                # address2 = address + section.ImageBase + section.VirtualAdd
                val5 = []
                CODED2 = m[o].rawData2[address : (address + NumOpsDis)]

                for i in callCS.disasm(CODED2, address):
                    jsonDis = {}
                    if rawHex:
                        add4 = hex(int(i.address))
                        addb = hex(int(i.address))
                    else:
                        add = hex(int(i.address))
                        addb = hex(int(i.address + section.VirtualAdd))
                        add2 = str(add)
                        add3 = hex(int(i.address + section.startLoc))
                        add4 = str(add3)
                    val = formatPrint(i, add4, addb)

                    # val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
                    if "db" in val:
                        break

                    val5.append(val)
                    jsonDis["offset"] = add4
                    jsonDis["instruction"] = i.mnemonic + " " + i.op_str
                    jsonList.append(jsonDis)
                    if "ret" in val:
                        break

                jsonData["PEB"].append(
                    {
                        "address": hex(address),
                        "modSecName": modSecName,
                        "disassembly": val5,
                        "disasm": jsonList,
                        "internalData": {
                            "secNum": secNum,
                            "NumOpsDis": NumOpsDis,
                            "points": points,
                        },
                    }
                )
        else:
            for section in s:
                for item in section.save_PEB_info:
                    if variables.shellBit == 64:
                        address = item[0]
                        NumOpsDis = item[1]
                        modSecName = item[2].decode()
                        secNum = item[3]
                        points = item[4]
                        val = ""
                        val2 = []
                        val3 = []
                        val5 = []
                        CODED2 = section.data2[address : (address + NumOpsDis)]
                        CODED3 = CODED2
                        for i in cs64.disasm(CODED3, address):
                            add = hex(int(i.address))
                            addb = hex(int(i.address + section.VirtualAdd))
                            add2 = str(add)
                            add3 = hex(int(i.address + section.startLoc))
                            add4 = str(add3)
                            val = formatPrint(i, add4, addb, pe=True)

                            val2.append(val)
                            val3.append(add2)
                            val5.append(val)
                        jsonData["PEB"].append(
                            {
                                "address": hex(address),
                                "modSecName": modSecName,
                                "disassembly": val5,
                                "internalData": {
                                    "secNum": secNum,
                                    "NumOpsDis": NumOpsDis,
                                    "points": points,
                                },
                            }
                        )
                    else:
                        address = item[0]
                        NumOpsDis = item[1]
                        modSecName = item[2].decode()
                        secNum = item[3]
                        points = item[4]
                        tib = str(item[5])
                        ldr = str(item[6])
                        mods = item[7]
                        adv = []
                        adv2 = ""
                        for ad in item[8]:
                            try:
                                adv.append(ad)
                            except:
                                adv.append(hex(ad))

                        val = ""
                        val2 = []
                        val3 = []
                        val5 = []
                        CODED2 = section.data2[address : (address + NumOpsDis)]
                        CODED3 = CODED2
                        for i in callCS.disasm(CODED3, address):
                            add = hex(int(i.address))
                            addb = hex(int(i.address + section.VirtualAdd))
                            add2 = str(add)
                            add3 = hex(int(i.address + section.startLoc))
                            add4 = str(add3)
                            val = formatPrint(i, add4, addb, pe=True)

                            # val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
                            val2.append(val)
                            val3.append(add2)
                            val5.append(val)

                        jsonData["PEB"].append(
                            {
                                "address": hex(address),
                                "modSecName": modSecName,
                                "tib": tib,
                                "ldr": ldr,
                                "mods": mods,
                                "adv": adv,
                                "disassembly": val5,
                                "internalData": {
                                    "secNum": secNum,
                                    "NumOpsDis": NumOpsDis,
                                    "points": points,
                                },
                            }
                        )
    if moduleBooleans[shellcode_label].bSyscallFound:
        if rawHex:
            if syscallRawHexOverride:
                j = 0
                for item in m[o].save_Egg_info:
                    CODED2 = ""

                    address = item[0]
                    NumOpsDis = item[1]
                    NumOpsBack = item[2]
                    modSecName = item[3]
                    secNum = item[4]
                    eax = item[5]
                    c0_offset = item[6]

                    val = ""
                    val2 = []
                    val3 = []
                    val5 = []
                    jsonList = []
                    CODED2 = m[o].rawData2[
                        (address - NumOpsBack) : (address + NumOpsDis)
                    ]

                    CODED3 = CODED2
                    for i in callCS.disasm(CODED3, address):
                        add = hex(int(i.address))
                        addb = hex(int(i.address - NumOpsBack))
                        add2 = str(add)
                        add3 = hex(int(i.address - NumOpsBack))
                        add4 = str(add3)
                        val = formatPrint(i, add4, addb, pe=True)

                        jsonDis = {}
                        val2.append(val)
                        val3.append(add2)
                        val5.append(val)
                        jsonDis["offset"] = add4
                        jsonDis["instruction"] = (i.mnemonic + " " + i.op_str).strip()
                        jsonList.append(jsonDis)
                        if c0_offset == addb:
                            break
                    j += 1
                    syscalls = "not found"
                    if eax != "unknown":
                        syscalls = getSyscallRecent(int(eax, 0), 64, "print2Json")
                    try:
                        if "syscall" in val5[-1]:
                            offsetLabel = "syscall offset"
                        elif "int" in val5[-1]:
                            offsetLabel = "int offset"
                        else:
                            offsetLabel = "c0_offset"
                    except Exception:
                        pass
                    jsonData["syscall"].append(
                        {
                            "address": hex(address),
                            "modSecName": modSecName,
                            "eax": eax,
                            offsetLabel: c0_offset,
                            "disassembly": val5,
                            "disasm": jsonList,
                            "syscalls": syscalls,
                            "internalData": {
                                "NumOpsDis": NumOpsDis,
                                "NumOpsBack": NumOpsBack,
                                "secNum": secNum,
                            },
                        }
                    )

            else:
                for item in m[o].save_Egg_info:
                    address = item[0]
                    NumOpsDis = item[1]
                    NumOpsBack = item[2]
                    modSecName = item[3]
                    secNum = item[4]
                    eax = item[5]
                    c0_offset = item[6]
                    converted = item[7]
                    syscalls = "not found"

                    CODED2 = m[o].rawData2[address : (address + 20)]
                    converted = [string.replace("\t", "") for string in converted]
                    if eax != "unknown":
                        syscalls = getSyscallRecent(
                            int(eax, 0), 64, "print2Json", jsonFormat=True
                        )

                    val5 = []
                    jsonList = []
                    for i in converted:
                        if i != "":
                            jsonDis = {}
                            allInstr = i.split(" ")
                            mnemonic = allInstr[0]
                            add4 = allInstr[-3]
                            addb = allInstr[-2:]
                            op_str = " ".join(allInstr[1:-3])

                            convOut = formatPrint(
                                mnemonic + "|" + op_str, add4, addb, syscall=True
                            )
                            val5.append(convOut.strip())
                            jsonDis["offset"] = add4
                            jsonDis["instruction"] = mnemonic + " " + op_str
                            jsonList.append(jsonDis)

                    jsonData["syscall"].append(
                        {
                            "address": hex(address),
                            "modSecName": modSecName,
                            "eax": eax,
                            "c0_offset": c0_offset,
                            "disassembly": val5,
                            "disasm": jsonList,
                            "syscalls": syscalls,
                            "internalData": {
                                "NumOpsDis": NumOpsDis,
                                "NumOpsBack": NumOpsBack,
                                "secNum": secNum,
                            },
                        }
                    )
        else:
            for section in s:
                for item in section.save_Egg_info:
                    address = item[0]
                    NumOpsDis = item[1]
                    NumOpsBack = item[2]
                    modSecName = item[3].decode()
                    secNum = item[4]
                    eax = item[5]
                    c0_offset = item[6]
                    val = ""
                    val2 = []
                    val3 = []
                    val5 = []
                    CODED2 = section.data2[
                        (address - NumOpsBack) : (address + NumOpsDis)
                    ]
                    CODED3 = CODED2

                    for i in callCS.disasm(CODED3, address):
                        add = hex(int(i.address))
                        addb = hex(int(i.address + section.VirtualAdd - NumOpsBack))
                        add2 = str(add)
                        add3 = hex(int(i.address + section.startLoc - NumOpsBack))
                        add4 = str(add3)
                        val = formatPrint(i, add4, addb, pe=True)
                        val2.append(val)
                        val3.append(add2)
                        val5.append(val)
                        if c0_offset == addb:
                            break
                    if eax != "unknown":
                        syscalls = getSyscallRecent(int(eax, 0), 64, "print2Json")
                    else:
                        syscalls = "not found"
                    if "syscall" in val5[-1]:
                        offsetLabel = "syscall offset"
                    elif "int" in val5[-1]:
                        offsetLabel = "int offset"
                    else:
                        offsetLabel = "c0_offset"
                    jsonData["syscall"].append(
                        {
                            "address": hex(address),
                            "modSecName": modSecName,
                            "eax": eax,
                            offsetLabel: c0_offset,
                            "disassembly": val5,
                            "syscalls": syscalls,
                            "internalData": {
                                "NumOpsDis": NumOpsDis,
                                "NumOpsBack": NumOpsBack,
                                "secNum": secNum,
                            },
                        }
                    )
    if moduleBooleans[shellcode_label].bModulesFound:
        t = 0
        for x in IATs.foundDll:
            try:
                x = x.decode()
            except:
                pass
            try:
                IATs.path[t] = IATs.path[t].decode()
            except:
                pass
            try:
                IATs.originate[t] = IATs.originate[t].decode()
            except:
                pass
            jsonData["modules"].append(
                {
                    "position": t,
                    "module": (x),
                    "path": IATs.path[t],
                    "caller": IATs.originate[t],
                }
            )
            t += 1
    if moduleBooleans[shellcode_label].bEvilImportsFound:
        for dll, api, offset in FoundApisName:
            jsonData["imports"].append(
                {"dll": dll.decode(), "api": api.decode(), "address": str(offset)}
            )

    return jsonData


def dontPrint():
    sys.stdout = open(os.devnull, "w")


def allowPrint():
    sys.stdout = sys.__stdout__


def printToTextPushRet(bPushRetFound, data):
    if moduleBooleans[shellcode_label].bPushRetFound:
        outString = "\n\n***********\nPush ret\n***********\n\n"
        itemNum = 0

        for item in data["pushret"]:
            outString += "********************************************************************************************************\n"

            pOffset = item["pushOffset"]
            pOffset = ", ".join(pOffset)
            pOffset = str(pOffset)

            outString += "Push ret Item: " + str(itemNum)
            if rawHex:
                outString += (
                    " | Section: "
                    + str(item["internalData"]["secNum"])
                    + " | Section name: "
                    + str(item["modSecName"])
                )
            else:
                outString += " | Module: " + item["modSecName"]

            outString += (
                " | PUSH Offset: "
                + pOffset
                + " | RET Offset: "
                + str(item["retOffset"])
                + "\n"
            )
            for line in item["disassembly"]:
                outString += line + "\n"
            itemNum += 1
    else:
        outString = "\nNo push ret instructions found.\n"
    return outString


def printToTextStrings(bStringsFound):
    if moduleBooleans[shellcode_label].bStringsFound:
        outString = "\n\n***********\nStrings\n***********\n\n"
        outString += "Note: The offset value is created by adding the offset plus the section virtual address."
        t = 0
        try:
            if not rawHex:
                if (
                    (len(s[t].Strings))
                    or (len(s[t].wideStrings))
                    or (len(s[t].pushStrings))
                ):
                    outString += "Strings from PE file:\n"

                    for secNum in range(len(s)):
                        if (
                            (len(s[t].pushStrings))
                            or (len(s[t].Strings))
                            or (len(s[t].wideStrings))
                        ):
                            outString += "Section: " + s[t].sectionName.decode()
                            outString += "\n"
                            for x, y, z in s[t].Strings:
                                outString += (
                                    "{:<5} {:<32s} {:<10s} {:<16} {:<10} {:<10}".format(
                                        "",
                                        str(x),
                                        str(hex(y + s[t].ImageBase + s[t].VirtualAdd)),
                                        "Offset: " + str(hex(y + s[t].VirtualAdd)),
                                        "size: " + str(int(z)),
                                        "Ascii",
                                    )
                                )
                                outString += "\n"
                            for x, y, z in s[t].wideStrings:
                                tempX = ""
                                j = 0
                                for char in x:
                                    if not (j % 2):
                                        tempX += char
                                    j += 1
                                outString += (
                                    "{:<5} {:<32s} {:<10s} {:<16} {:<10} {:<10}".format(
                                        "",
                                        str(x),
                                        str(hex(y + s[t].ImageBase + s[t].VirtualAdd)),
                                        "Offset: " + str(hex(y + s[t].VirtualAdd)),
                                        "size: " + str(int(z)),
                                        "Unicode",
                                    )
                                )
                                outString += "\n"

                            outString += "\n\n**Push Stack Strings**\n\n"
                            if not len(s[t].pushStrings):
                                outString += "none\n"
                            for (
                                word4,
                                offset,
                                offsetVA,
                                offsetPlusImagebase,
                                wordLength,
                                instLen,
                            ) in s[t].pushStrings:
                                outString += (
                                    "{:<5} {:<32s} {:<10s} {:<16} {:<10} {:<10}".format(
                                        "",
                                        str(word4),
                                        str(hex(y + s[t].ImageBase + s[t].VirtualAdd)),
                                        "Offset: " + str(hex(offset + s[t].VirtualAdd)),
                                        "size: " + str(int(wordLength)),
                                        "Stack String",
                                    )
                                )
                                outString += "\n"
                            outString += "\n"
                        t += 1
            else:
                outString += "Strings from shellcode:\n\n"

                if len(stringsTemp) > 0:
                    for x, y, z in stringsTemp:
                        if z >= minStrLen:
                            outString += "{:<5} {:<32s} {:<16s} {:<8s} {:<10}\n".format(
                                "",
                                str(x),
                                "Offset: " + hex(y),
                                "size: " + str(int(z)),
                                "Ascii",
                            )
                outString += "\n"
                if len(stringsTempWide) > 0:
                    for x, y, z in stringsTempWide:
                        if z >= minStrLen:
                            outString += "{:<5} {:<32s} {:<16s} {:<8s} {:<10}\n".format(
                                "",
                                str(x),
                                "Offset: " + hex(y),
                                "size: " + str(int(z)),
                                "Unicode",
                            )
                outString += "\n"
                if len(pushStringsTemp) > 0:
                    outString += "\n\n**Push Stack Strings**\n\n"
                    for word4, offset, wordLength, instLen in pushStringsTemp:
                        if wordLength >= minStrLen:
                            outString += "{:<5} {:<32s} {:<16s} {:<8s} {:<10}\n".format(
                                "",
                                str(word4),
                                "Offset: " + hex(offset),
                                "size: " + str(int(wordLength)),
                                "Stack String",
                            )
                outString += "\n"

        except Exception as e:
            print(traceback.format_exc())
            outString += str(e)
            outString += "\n"
            pass

    else:
        outString = "\nNo strings found.\n"
    return outString


def printToText(outputData):  # Output data to text doc
    # output data from generateoutputdata
    global bDisassembly
    global gDisassemblyText
    global bpModules
    global bpEvilImports
    global stringsTemp
    global stringsTempWide
    global pushStringsTemp
    global syscallString
    global gDisassemblyText
    global save_bin_file
    global filename
    global sharem_out_dir
    global bEvilImportsFound
    global bPrintEmulation
    global gDisassemblyTextNoC
    global rawHex

    data = outputData
    # Used for section info

    if rawHex:
        info = showBasicInfo()
    else:
        info = showBasicInfoSections()
    info = Variables.cleanColors(self=Variables, out=info)

    time = datetime.datetime.now()
    epoch = time.timestamp()
    filetime = time.strftime("%Y%m%d_%H%M%S")
    time = time.strftime("%Y-%m-%d %H:%M:%S")

    filename = filename.split(slash)[-1]
    if filename == "":
        outfile = peName.split(".")[0]
        outfileName = peName
        if outfileName[-4] == ".":
            outfileName = outfileName[:-4]
        chkExt = peName[-4]
    else:
        outfile = filename.split(".")[0]
        outfileName = filename
        if outfileName[-4] == ".":
            outfileName = outfileName[:-4]
            # print (outfileName)
        chkExt = filename[-4]

    # print ("outfilename",outfileName)

    filler = ""
    if chkExt == ".":
        filler = ""
    else:
        filler = "-output"
        filler = ""
    output_dir = os.getcwd()

    if sharem_out_dir == "current_dir":
        output_dir = os.path.join(os.path.dirname(__file__), "sharem", "logs")
    else:
        output_dir = sharem_out_dir

    # txtFileName =  os.getcwd() + slash + outfile + "\\output_" + outfileName + "_" + filetime + ".txt"
    outfile = outfile.strip()
    if useDirectory and not known_arch:
        if jsonP.current_arch == 32:
            # txtFileName =  output_dir + slash + outfile + filler+slash + slash + outfileName+"-32" + "_" + filetime + ".txt"

            importsName = os.path.join(
                output_dir,
                outfileName.split("\\")[-1].strip(),
                outfileName.split("\\")[-1].strip() + "-imports.txt",
            )

            txtFileName = os.path.join(
                output_dir,
                outfileName.split("\\")[-1].strip(),
                outfileName.split("\\")[-1].strip() + "-32" + "_" + filetime + ".txt",
            )

        elif jsonP.current_arch == 64:
            # txtFileName =  output_dir + slash + outfile + filler+slash + slash + outfileName + "-64"+ "_" + filetime + ".txt"

            txtFileName = os.path.join(
                output_dir,
                outfileName.split("\\")[-1].strip(),
                outfileName.split("\\")[-1].strip() + "-64" + "_" + filetime + ".txt",
            )
    else:
        if variables.shellBit == 32:
            # txtFileName =  output_dir + slash + outfile +filler+ slash + outfileName + "-32"+"_" + filetime + ".txt"

            txtFileName = os.path.join(
                output_dir,
                outfileName.split("\\")[-1].strip(),
                outfileName.split("\\")[-1].strip() + "-32" + "_" + filetime + ".txt",
            )

        else:
            # txtFileName =  output_dir + slash + outfile +filler+ slash + outfileName + "-64"+"_" + filetime + ".txt"

            txtFileName = os.path.join(
                output_dir,
                outfileName.split("\\")[-1].strip(),
                outfileName.split("\\")[-1].strip() + "-64" + "_" + filetime + ".txt",
            )

    os.makedirs(os.path.dirname(txtFileName), exist_ok=True)
    text = open(txtFileName, "w")

    output_dir = output_dir.strip()
    disFileName = os.path.join(
        output_dir,
        outfileName.split("\\")[-1].strip(),
        outfileName.split("\\")[-1].strip() + "-disassembly.txt",
    )
    binFileName = os.path.join(output_dir, outfile + filler, outfileName + "-raw.bin")
    asciiFileName = os.path.join(
        output_dir, outfile + filler, outfileName + "-ascii.txt"
    )

    if moduleBooleans[shellcode_label].bEvilImportsFound:
        importsName = os.path.join(
            output_dir,
            outfileName.split("\\")[-1].strip(),
            outfileName.split("\\")[-1].strip() + "-imports.txt",
        )
        importData = showImports(out2File=True)
        importFp = open(importsName, "w")
        importFp.write(importData)
        importFp.close()
        # print ("importsName", importsName)

    os.makedirs(os.path.dirname(disFileName), exist_ok=True)

    if rawHex:
        disasm = open(disFileName, "w")
        disasm.write(gDisassemblyTextNoC)
        disasm.close()

    if rawHex:
        assembly = binaryToText(m["shellcode"].rawData2)
        asciiBin = open(asciiFileName, "w")
        asciiBin.write(assembly)
        asciiBin.close()
        if not sh.decryptSuccess:
            binasm = open(binFileName, "wb")
            binasm.write(m[o].rawData2)
        if sh.decryptSuccess:
            binFileNameDecoded = os.path.join(
                output_dir, outfile + filler, outfileName + "-decoded_body_raw.bin"
            )
            deobAsciiFileName = os.path.join(
                output_dir,
                outfile + filler,
                outfileName + "-decoded_body_raw-ascii.txt",
            )

            assemblyD = binaryToText(sh.decodedFullBody)
            asciiDeobf = open(deobAsciiFileName, "w")
            asciiDeobf.write(assemblyD)
            asciiDeobf.close()

            binasm = open(binFileNameDecoded, "wb")
            binasm.write(sh.decodedFullBody)

            binasm2 = open(binFileName, "wb")
            binasm2.write(m["shellcode"].rawData2)
            binasm2.close()
        binasm.close()

    if rawHex:
        shellClass = isShellcode(variables.moduleBooleans[shellcode_label], patt)

    outString = "Filename: " + outfileName + "\n"
    outString += "File Type: " + outputData["fileType"] + "\n"
    outString += "Architecture: " + str(variables.shellBit) + "-bit\n"
    outString += "Date Analyzed: " + time + "\n"

    if rawHex:
        outString += "classification: " + shellClass[0] + "\n"
        outString += "\tReason: " + shellClass[1] + "\n"

        outString += "Seconds since last epoch: " + str(epoch) + "\n\n"
    outString += info

    # If we've found and are printing a category, then do so
    if bpModules and variables.moduleBooleans[shellcode_label].bModulesFound:
        outString += "\n\n*******\nModules\n*******\n\n"
        outString += giveLoadedModules("save")
    if bpEvilImports and variables.moduleBooleans[shellcode_label].bEvilImportsFound:
        outString += "\n\n*****************\nImports\n*****************\n"
        # outString+= showImports()
        for api, dll, offset in FoundApisName:
            try:
                outString += (
                    " {:<14s} {:<32s} {:<0}".format(
                        api.decode(), dll.decode(), str(offset)
                    )
                ) + "\n"
            except:
                pass

    if bpPushRet:
        outString += printToTextPushRet(
            moduleBooleans[shellcode_label].bStringsFound, data
        )

    if bpFstenv:
        if moduleBooleans[shellcode_label].bFstenvFound:
            outString += "\n\n***********\nFstenv\n***********\n\n"
            itemNum = 0

            for item in data["fstenv"]:
                outString += "********************************************************************************************************\n"

                outString += "Fstenv Item: " + str(itemNum)
                if rawHex:
                    outString += (
                        " | Section: "
                        + str(item["internalData"]["secNum"])
                        + " | Section name: "
                        + str(item["modSecName"])
                        + " | FPU Offset: "
                        + str(item["FPU_offset"])
                        + " | FSTENV Offset: "
                        + str(item["FSTENV_offset"])
                    )
                else:
                    outString += (
                        " | Module: "
                        + item["modSecName"]
                        + " | FPU Offset: "
                        + str(item["FPU_offset"])
                        + " | FSTENV Offset: "
                        + str(item["FSTENV_offset"])
                    )
                outString += "\n"
                for line in item["disassembly"]:
                    outString += line + "\n"
                itemNum += 1
        else:
            outString += "\nNo fstenv instructions found.\n"

    if bpCallPop:
        if moduleBooleans[shellcode_label].bCallPopFound:
            outString += "\n\n***********\nCall Pop\n***********\n\n"
            itemNum = 0

            for item in data["callpop"]:
                outString += "********************************************************************************************************\n"

                outString += "Call pop Item: " + str(itemNum)
                if rawHex:
                    outString += (
                        " | Section: "
                        + str(item["internalData"]["secNum"])
                        + " | Section name: "
                        + str(item["modSecName"])
                    )
                else:
                    outString += (
                        " | Call address: "
                        + str(item["address"])
                        + " | Pop offset: "
                        + str(item["pop_offset"])
                        + " | Distance from call: "
                        + str(hex(item["distance"]))
                    )
                outString += "\n"
                for line in item["disassembly"]:
                    outString += line + "\n"
                itemNum += 1
        else:
            outString += "\nNo call pop instructions found.\n"

    if bpSyscall:
        if moduleBooleans[shellcode_label].bSyscallFound:
            outString += "\n\n***************\nWindows syscall\n***************\n\n"
            itemNum = 0

            for item in data["syscall"]:
                if "c0_offset" in item:
                    offsetLabel = "c0_offset"
                    offString = " | 0xc0 offset: "
                elif "syscall offset" in item:
                    offsetLabel = "syscall offset"
                    offString = " | syscall offset: "
                elif "int offset" in item:
                    offsetLabel = "int offset"
                    offString = " | int offset: "
                else:
                    offsetLabel = "c0_offset"
                    offString = " | 0xc0 offset: "
                outString += "********************************************************************************************************\n"

                outString += "Syscall Item: " + str(itemNum)
                if rawHex:
                    outString += " | Section name: " + str(item["modSecName"])
                else:
                    outString += " | Module: " + item["modSecName"]
                outString += " | EAX: " + item["eax"] + offString + item[offsetLabel]
                outString += "\n"
                for line in item["disassembly"]:
                    outString += line + "\n"

                if item["syscalls"] == "not found":
                    outString += "\nSyscall cannot be determined\n"

                else:
                    outString += "\n"
                    outString += getSyscallRecent(int(item["eax"], 0), 64, "print2Text")
                itemNum += 1
        else:
            outString += "\nNo syscall instructions found.\n"

    if bpPEB:
        if moduleBooleans[shellcode_label].bPEBFound:
            outString += "\n\n***************\nWalking the PEB\n***************\n\n"
            itemNum = 0

            for item in data["PEB"]:
                outString += "********************************************************************************************************\n"

                outString += (
                    "PEB Item: "
                    + str(itemNum)
                    + " | Points: "
                    + str(item["internalData"]["points"])
                )
                if rawHex:
                    outString += (
                        " | Section: "
                        + str(item["internalData"]["secNum"])
                        + " | Section name: "
                        + str(item["modSecName"])
                    )
                else:
                    outString += " | Module: " + item["modSecName"]
                outString += "\n"
                try:
                    mods = item["mods"]
                    mods = ", ".join(mods)
                    offString = "Offsets:\n"
                    offString += "TIB: " + item["tib"] + "\n"
                    offString += "LDR: " + item["ldr"] + "\n"
                    offString += "MODS: " + mods + "\n"
                    outString += offString + "\n"

                    adv = item["adv"]
                    for num, value in enumerate(adv):
                        if value == -1:
                            adv[num] = "N/A"

                    adv = ", ".join(adv)
                    offString = f"Adv: {adv}\n"
                    outString += offString + "\n"

                except Exception:
                    pass
                    # print("Exception", e)
                for line in item["disassembly"]:
                    outString += line + "\n"
                itemNum += 1
        else:
            outString += "\nNo peb walking instructions found.\n"

    if bpHeaven:
        if moduleBooleans[shellcode_label].bHeavenFound:
            outString += "\n\n***************\nHeaven's Gate\n***************\n\n"
            itemNum = 0

            for item in data["heavensGate"]:
                outString += "********************************************************************************************************\n"

                outString += "Heaven Item: " + str(itemNum)
                if rawHex and not heavRawHexOverride:
                    outString += (
                        " | Section: "
                        + str(item["internalData"]["secNum"])
                        + " | Section name: "
                        + item["modSecName"]
                        + " | PushOffset: "
                        + hex(item["pushOffset"])
                        + " | Heaven's Gate offset: "
                        + str(item["heaven_offset"])
                    )
                else:
                    outString += (
                        " | Module: "
                        + item["modSecName"]
                        + " | Heaven's Gate offset: "
                        + str(item["heaven_offset"])
                        + " | Push dest. addr offset: "
                        + item["pushOffset"]
                        + " | Dest. Address: "
                        + str(item["destLocation"])
                    )

                outString += "\n"
                for line in item["disassembly"]:
                    outString += line + "\n"
                itemNum += 1
        else:
            outString += "\nNo heaven's gate instructions found.\n"

    if bpStrings:
        outString += printToTextStrings(moduleBooleans[shellcode_label].bStringsFound)

    if bDisassembly:
        if moduleBooleans[shellcode_label].bDisassemblyFound:
            outString += "\n\n****************\nDisassembly\n****************\n\n"
            outString += gDisassemblyTextNoC
    else:
        outString += "\nNo Disassembly found.\n"
    bPrintEmulation = False

    if len(loggedList) > 0 or len(logged_syscalls) > 0:
        outString += emulation_txt_out(loggedList, logged_syscalls)
    else:
        outString += "\nNo APIs or artifacts discovered through emulation.\n"
    bPrintEmulation = True
    text.write(outString)
    # text.write(emulation_txt)
    text.close()
    try:
        rawSh = binaryToText(m["shellcode"].rawData2, "json")[1]
        generateTester(outfile, rawSh, shellEntry)
    except:
        pass


def SharemMainResetGlobals():
    # region Setting up global locals start
    global iatList
    global m
    global mBool
    global s
    global list_of_files
    global list_of_files32
    global list_of_files64
    global list_of_pe32
    global list_of_pe64
    global list_of_unk_files
    global sharem_out_dir
    global emulation_verbose
    global labels
    global offsets
    global off_Label
    global off_PossibleBad
    global elapsed_time
    global doneAlready1
    global syscallString
    global chMode
    global sections
    global numArgs
    global peName
    global PEsList
    global PE_path
    global PEsList_Index
    global skipZero
    global numPE
    global skipPath
    global FoundApisAddress
    global FoundApisName
    global shellEntry
    global decodedBytes
    global maxZeroes
    global shellEntry
    global useDirectory
    global VA
    global MA
    global GPA
    global pe
    global GPAl
    global MAl
    global Remove
    global fname
    global entryPoint
    global VirtualAdd
    global ImageBase
    global vSize
    global startAddress
    global endAddy
    global gName
    global o
    global t
    global sectionName
    global cs
    global cs64
    global directory
    global newpath
    global PEtemp
    global PE_DLL
    global PE_DLLS
    global PE_DLLS2
    global paths
    global bit32
    global PE_Protect
    global index
    global CheckallModules
    global present
    global new
    global new2
    global deeperLevel
    global asciiMode
    global stringsTemp
    global stringsTempWide
    global pushStringsTemp
    global filename
    global filename2
    global filenameRaw
    global skipExtraction
    global rawHex
    global rawData2
    global useHash
    global known_arch
    global numArgs
    global rawBin
    global isPe
    global pointsLimit
    global maxDistance
    global useStringsFile
    global minStrLen
    global mEAX
    global mEBX
    global mEDX
    global mECX
    global mEBP
    global mESP
    global gDisassemblyText
    global gDisassemblyTextNoC
    global emulation_multiline
    global linesForward
    global bPushRet
    global bFstenv
    global bSyscall
    global bHeaven
    global bCallPop
    global bPrintEmulation
    global bDisassembly
    global bAnaHiddenCallsDone
    global bAnaConvertBytesDone
    global bAnaFindStrDone
    global deobfShell
    global fastMode
    global pebPoints
    global p2screen
    global configOptions
    global print_style
    global stubFile
    global sameFile
    global stubEntry
    global stubEnd
    global shellSizeLimit
    global conFile
    global workDir
    global bit32_argparse
    global save_bin_file
    global linesForward
    global linesBack
    global bytesForward
    global bytesBack
    global unencryptedShell
    global decoderShell
    global unencryptedBodyShell
    global sample
    global allObject
    global gDirectory
    global debugging
    global shHash
    global emuObj
    global patt
    global sBy
    global sh
    global IATs
    global syscallRawHexOverride
    global heavRawHexOverride
    global fstenvRawHexOverride
    global emuSyscallSelection
    global GoodStrings
    global toggList
    global brawHex
    global bstrLit
    global bfindString
    global bdeobfCode
    global bdeobfCodeFound
    global bfindShell
    global bfindShellFound
    global bComments
    global filename
    # HookAPI Emulation Values
    global HandlesDict
    global HeapsDict
    global RegistryKeys
    global commandLine_arg
    global registry_values
    global registry_keys
    # Sharemu values
    global artifacts
    global net_artifacts
    global file_artifacts
    global exec_artifacts
    global coverage_objects
    global programCounter
    global loggedList
    global logged_syscalls
    global logged_dlls
    global paramValues
    global network_activity
    global jmpInstructs
    global traversedAdds
    global loadModsFromFile
    global cleanStackFlag
    global stopProcess
    global cleanBytes
    global bad_instruct_count
    # endregion Setting up global locals end

    # region Resetting Globals Start
    iatList = []
    m = {}  # []   # start modules CHANGED to dicitonary
    mBool = {}  # []   # start modules CHANGED to dicitonary

    s = []  # start sections
    list_of_files = []
    list_of_files32 = []
    list_of_files64 = []
    list_of_pe32 = []
    list_of_pe64 = []

    list_of_unk_files = []
    sharem_out_dir = "current_dir"
    emulation_verbose = True

    labels = set()
    offsets = set()
    off_Label = set()
    off_PossibleBad = set()

    elapsed_time = 0
    doneAlready1 = []
    syscallString = ""
    chMode = False
    sections = []
    numArgs = len(sys.argv)
    peName = ""
    PEsList = []
    PE_path = ""
    PEsList_Index = 0
    skipZero = False
    numPE = 1
    skipPath = False
    FoundApisAddress = []
    FoundApisName = []

    shellEntry = 0x00
    decodedBytes = b""
    maxZeroes = 0
    shellEntry = 0x0
    useDirectory = False

    GPA = ""
    pe = ""
    GPAl = []
    MAl = []
    Remove = []
    fname = ""
    entryPoint = 0
    VirtualAdd = 0
    ImageBase = 0
    vSize = 0
    startAddress = 0
    endAddy = 0
    # o=0
    gName = ""
    o = constants.ShellcodeLabel.SHELLCODE_LABEL
    t = 0
    sectionName = ""
    cs = Cs(CS_ARCH_X86, CS_MODE_32)
    cs64 = Cs(CS_ARCH_X86, CS_MODE_64)
    directory = ""
    newpath = ""
    PEtemp = ""
    PE_DLL = []
    PE_DLLS = []
    PE_DLLS2 = []
    paths = []
    bit32 = True
    PE_Protect = ""
    index = 0
    CheckallModules = False
    present = []
    new = []
    new2 = []
    deeperLevel = []
    asciiMode = "ascii"
    stringsTemp = []
    stringsTempWide = []
    pushStringsTemp = []
    filename = ""
    filename2 = ""
    filenameRaw = ""
    skipExtraction = False
    rawHex = False
    rawData2 = b""
    useHash = False
    known_arch = False
    numArgs = len(sys.argv)
    rawBin = False  # only if .bin, not .txt
    isPe = False
    pointsLimit = 3
    maxDistance = 15
    useStringsFile = False
    minStrLen = 6
    mEAX = ""
    mEBX = ""
    mEDX = ""
    mECX = ""
    mEBP = ""
    mESP = ""

    gDisassemblyText = ""
    gDisassemblyTextNoC = ""
    emulation_multiline = False
    # Moved from viewBool's work area
    linesForward = 40
    bPushRet = True
    bFstenv = True
    bSyscall = True
    bHeaven = True
    bCallPop = True
    bPrintEmulation = True
    bDisassembly = True
    bAnaHiddenCallsDone = False
    bAnaConvertBytesDone = False
    bAnaFindStrDone = False
    deobfShell = True
    fastMode = False
    pebPoints = 3
    p2screen = True
    configOptions = {}
    print_style = "left"
    stubFile = "stub.txt"
    sameFile = True
    stubEntry = 0
    stubEnd = 0
    # moduleBooleans[shellcode_label].ignoreDisDiscovery=False
    shellSizeLimit = 120
    conFile = str("config.cfg")
    workDir = False
    bit32_argparse = False
    save_bin_file = True
    linesForward = 7
    linesBack = 10
    bytesForward = 15
    bytesBack = 15

    gDirectory = ""  # #used to hold original directory --immutable
    # debugging=True
    debugging = False

    # emuObj=None
    patt = patterns()
    sBy = None
    IATs = None

    syscallRawHexOverride = False
    heavRawHexOverride = False
    fstenvRawHexOverride = False

    del emuSyscallSelection
    emuSyscallSelection = copy.deepcopy(SYSCALL_BOOL_DICT)
    emuSyscallCode = ""

    GoodStrings = {
        "cmd",
        "net",
        "add",
        "win",
        "http",
        "dll",
        "sub",
        "calc",
        "https",
        "recv",
    }
    toggList = {
        "findString": True,
        "deobfCode": False,
        "findShell": False,
        "comments": True,
        "hidden_calls": True,
        "show_ascii": True,
        "ignore_dis_discovery": False,
        "opcodes": True,
        "labels": True,
        "offsets": True,
        "max_opcodes": 8,
        "binary_to_string": 3,
    }

    brawHex = ""
    bstrLit = ""
    bfindString = True
    bdeobfCode = False
    bdeobfCodeFound = False

    bfindShell = True
    bfindShellFound = False
    bComments = True

    # HookAPI Emulation Reset
    HandlesDict = {}
    HeapsDict = {}
    RegistryKeys = {}
    commandLine_arg = set()
    registry_values = set()
    registry_keys = set()

    # Sharemu values
    artifacts = []
    net_artifacts = []
    file_artifacts = []
    exec_artifacts = []
    coverage_objects = []
    programCounter = 0

    loggedList = []
    logged_syscalls = []
    logged_dlls = []
    paramValues = []
    network_activity = {}
    jmpInstructs = {}

    loadModsFromFile = True
    cleanStackFlag = False
    stopProcess = False
    cleanBytes = 0
    bad_instruct_count = 0

    #####SAME AS FROM SHAREM
    filename = ""
    # endregion Resetting Global End


def SharemMain(parserNamespace: Namespace):
    global emuObj
    global patt
    global sBy
    IATs: FoundIATs = FoundIATs()
    sBy = DisassemblyBytes()
    emuObj = emulationOptions()
    iatList: list[IATS] = []
    PE_DLLS: list = []
    SECTIONS: list = []
    MY_BYTES_LIST: list = []
    variables: Variables = Variables()
    module: dict[str, MyBytes] = {}
    shellcode_label: str = ""
    shellcode_hash: shellHash = shellHash()

    sharemContext: SharemContext = CliParser(parserNamespace)
    with open(sharemContext.fullFileName, "rb") as f:
        sharemContext.rawData = f.read()

    configuration: Configuration = Configuration(sharemContext.confFile)

    # Treat as raw hex if file extension in list
    variables.rawHex = bool(sharemContext.fileExtension in ("txt", "bin"))

    # I think trying to parse hex text and raw bin, something isn't right @TODO
    # init2(sharemContext.fullFileName, iatList, PE_DLLS, SECTIONS, MY_BYTES_LIST, rawHex)

    if variables.rawHex:
        shellcode_label = constants.ShellcodeLabel.SHELLCODE_LABEL
        module[shellcode_label] = newModule(
            constants.ShellcodeLabel.SHELLCODE_LABEL, sharemContext, variables
        )
    else:
        shellcode_label = sharemContext.fullFileName
        module[sharemContext.fullFileName] = newModule(None, sharemContext, variables)
        Extraction()

    try:
        shellcode_hash = shellHash(sharemContext.rawData)
    except Exception as e:
        print(e)
        exit()
    shell_code = shellcode(sharemContext.rawData)
    shell_code_deobfuscation = sharDeobf(sharemContext.rawData)

    shell_code_deobfuscation.giveSize(sharemContext.rawData)

    if variables.rawHex:
        shellcode_hash = hashShellcode(
            module[shellcode_label].rawData2, sample
        )  # if comes after args parser
        if useHash:
            filename2 = shellcode_hash.md5sum

        if not readConf(variables):
            ui(shell_code, shellcode_label, variables, configuration, module)
        else:
            print(constants.GREEN + "\n\n[Attention] Startup config has been used.\n")
            print(
                constants.WHITE
                + "Change the startup value to disabled in the config file if you want to use the UI menu.\n"
                + constants.RESET
            )
            startupPrint(shell_code, shellcode_label, variables, configuration)
