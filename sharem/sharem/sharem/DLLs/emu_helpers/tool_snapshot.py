
from .structures import MODULEENTRY32, PROCESSENTRY32, THREADENTRY32


class System_SnapShot: # Needs Reworked For new Struct System
    def __init__(self, fakeThreads: bool, fakeModules: bool):
        self.processOffset = 0
        self.threadOffset = 0
        self.moduleOffset = 0
        self.baseThreadID = 1000
        self.processDict = {4: PROCESSENTRY32(0, 10, 0, 0, 'System'),
                            2688: PROCESSENTRY32(2688, 16, 0, 4, 'explorer.exe'),
                            9172: PROCESSENTRY32(9172, 10, 2688, 10, 'calc.exe'),
                            8280: PROCESSENTRY32(8280, 50, 2688, 16, 'chrome.exe'),
                            11676: PROCESSENTRY32(11676, 78, 2688, 15, 'notepad.exe'),
                            8768: PROCESSENTRY32(8768, 20, 2688, 4, 'firefox.exe')}
        self.threadDict: dict[int, THREADENTRY32] = {}
        self.moduleList: list[MODULEENTRY32] = []
        if fakeThreads:
            self.fakeThreads()
        # if fakeModules: # Need To Fix Modules Thing
            # self.fakeModules()
        self.resetOffsets()

    def fakeThreads(self):
        for k, v in self.processDict.items():  # Create Fake Threads
            for i in range(v.cntThreads):
                self.threadDict.update(
                    {self.baseThreadID: THREADENTRY32(self.baseThreadID, v.th32ProcessID, v.pcPriClassBase)})
                self.baseThreadID += 1

    def resetOffsets(self):
        try:
            self.processOffset = list(self.processDict.keys())[0]
            self.threadOffset = list(self.threadDict.keys())[0]
            self.moduleOffset = 0
        except:
            pass