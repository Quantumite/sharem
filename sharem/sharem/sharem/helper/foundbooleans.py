from typing import Optional

class foundBooleans:
    """Storage of all boolean configurations for module."""
    def __init__(self, name: Optional[str]=None):
        self.bAnaHiddenCallsDone = False
        self.bAnaHiddenCnt = 0
        self.bAnaConvertBytesDone = False
        self.bDoFindHiddenCalls = True
        self.bDoEnableComments = True
        self.bDoShowAscii = True
        self.bDoShowOffsets = True
        self.bDoshowOpcodes = True
        self.bDoFindStrings = True
        self.bShowLabels = True
        self.ignoreDisDiscovery = False
        self.bAnaFindStrDone = False
        self.bPreSysDisDone = False
        self.disAnalysisDone = False
        self.maxOpDisplay = 8
        self.btsV = 3  # value/option for binary to string function. #3 is default - this is just to be used so users can change how disassembly is printed.

        self.name = name
        self.bPushRetFound = False
        self.bDisassemblyFound = False
        self.bFstenvFound = False
        self.bSyscallFound = False
        self.bHeavenFound = False
        self.bPEBFound = False
        self.bCallPopFound = False
        self.bEvilImportsFound = False
        self.bModulesFound = False
        self.bWideStringFound = False
        self.bPushStringsFound = False
        self.bAsciiStrings = False
        self.bStringsFound = False
        self.bEmulationFound = False

        self.bStrings = True
        self.bAsciiStrings = True
        self.bWideCharStrings = True
        self.bModules = True
        self.bpEvilImports = True
        self.bEvilImports = True
        self.bpPushRet = True
        self.bpFstenv = True
        self.bFstenv = True
        self.bpSyscall = True
        self.bSyscall = True
        self.bpHeaven = True
        self.bHeaven = True
        self.bpPEB = True
        self.bPEB = True
        self.bPushRet = True
        self.bpCallPop = True
        self.bCallPop = True
        self.bpStrings = True
        self.bPushStackStrings = True
        self.bpPushStrings = True
        self.bpEvilImports = True
        self.bpModules = True
        self.bPushStrings = True
        self.bShellcodeAll = True
        self.bExportAll = True
        self.bDisassembly = True
        self.bEgg = True
        self.bpAll = True
        self.bAll = True