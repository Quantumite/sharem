#!/usr/bin/env python

from __future__ import print_function
from unicorn import UcError, Uc, UC_ARCH_X86
from unicorn.x86_const import *
from unicorn.unicorn_const import *
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from .modules import initMods, saveDLLAddsToFile, allocateWinStructs32, allocateWinStructs64
from .DLLs.dict_signatures import *  # noqa: F403
from .DLLs.dict2_signatures import *  # noqa: F403
from .DLLs.dict3_w32 import dict3_w32
from .DLLs.dict4_ALL import *  # noqa: F403
from .DLLs.dict5_signatures import *  # noqa: F403
from sharem.sharem.DLLs.hookAPIs import CustomWinAPIs, CustomWinSysCalls, stackCleanup, read_string, buildPtrString, getPointerVal, makeArgVals, art
from .DLLs.syscall_signatures import syscall_signature, syscallRS
from .helper.emuHelpers import (
    constConvert, set_register, boolFollowJump, push, bprint, signedNegHexTo, exitAPI, 
    giveRegs, giveStack, controlFlow, retEnding, getJmpFlag, tryDictLocate
)
from .helper.moduleHelpers import readDLLsAddsFromFile
from .helper.emuHelpers import findRetVal 
from .helper.sharemuDeob import binaryToStr, sharDeobf
from .helper.variable import Variables
from .sharem_debugger import debugger
from .DLLs.emu_helpers.sharem_artifacts import Artifacts_regex
import sharem.sharem.constants as constants

import json
import re
import os
import colorama
import traceback
import platform

finalAddress=0

class Coverage():
    def __init__(self, uc: Uc, address: int):
        self.address: int = address
        if em.arch == 32:
            self.regs = {'eax': 0x0, 'ebx': 0x0, 'ecx': 0x0, 'edx': 0x0, 'edi': 0x0, 'esi': 0x0, 'esp': 0x0, 'ebp': 0x0, 'eflags': 0x0}
        else:
            self.regs = {'rax': 0x0, 'rbx': 0x0, 'rcx': 0x0, 'rdx': 0x0, 'rdi': 0x0, 'rsi': 0x0, 'r8': 0x0, 'r9': 0x0, 'r10': 0x0, 'r11': 0x0, 'r12': 0x0, 'r13': 0x0, 'r14': 0x0, 'r15': 0x0, 'rsp': 0x0, 'rbp': 0x0, 'eflags': 0x0}
        self.stack = b''
        self.ebpStack=b''
        self.inProgress = False
        self.coverage_num=coverage_num

        # Save registers into dict
        for reg, val in self.regs.items():
            self.regs[reg] = int(constConvert(uc, reg))
        
        # Save memory
        if em.writeToTempFile:
            print ("writeToTempFile 1")
            with open ('coverage_mem_tmp.bin', 'wb') as f:
                f.write(uc.mem_read(0x10000000, 0x10050000))

        # Save stack bytes
        esp = uc.reg_read(UC_X86_REG_ESP)  # noqa: F405
        ebp = uc.reg_read(UC_X86_REG_EBP)  # noqa: F405
        amt=em.codeCoverageStackAmt
        if em.arch == 32:
            esp = self.regs['esp']
            ebp = self.regs['ebp']
            stack_bytes_len = ebp - esp
            if stack_bytes_len < 0:
                stack_bytes_len = STACK_ADDR - esp
            # print ("stack_bytes_len", stack_bytes_len, "esp", hex(esp), "ebp", hex(ebp))

            
            try:
                # print ("new_stack", hex(esp -amt), hex(esp+amt*2), "ebp", hex(esp -amt), hex(esp+amt*2))
                self.stack = bytes(uc.mem_read(esp-amt, amt*2))
                # print (binaryToStr(self.stack))
            except UcError:
                if em.showCCDebugInfo:
                    print (constants.RED +"\t[*] "+ constants.WHITE + "Code coverage: Could not capture memory pointed to by esp - memory not valid: " +constants.RESET, hex(esp))
            try:
                # print ("new_stack_ebp", hex(esp -amt), hex(esp+amt*2), "ebp", hex(esp -amt), hex(esp+amt*2))
                self.ebpStack = bytes(uc.mem_read(ebp-amt, amt*2))
                # print ("stack size", len(self.ebpStack))
            except UcError:
                if em.showCCDebugInfo:
                    print (constants.RED +"\t[*] "+constants.WHITE+ "Code coverage: Could not capture memory pointed to by ebp - memory not valid: "++constants.RESET, hex(ebp))
        if em.arch == 64:
            rsp = self.regs['rsp']
            rbp = self.regs['rbp']
            try:
                self.stack = bytes(uc.mem_read(rsp-amt, amt*2))
                # print (binaryToStr(self.stack))
            except UcError:
                if em.showCCDebugInfo:
                    print (constants.constants.RED +"\t[*] "+constants.WHITE+ "Code coverage: Could not capture memory pointed to by rsp - memory not valid: "++constants.RESET, hex(rsp))
            try:
                self.ebpStack = bytes(uc.mem_read(rbp-amt, amt*2))
                # print ("stack size", len(self.ebpStack))
            except UcError:
                if em.showCCDebugInfo:
                    print (constants.constants.RED +"\t[*] "+constants.WHITE+ "Code coverage: Could not capture memory pointed to by rbp - memory not valid: "++constants.RESET, hex(rbp))

        coverageAdds.add(address)

    def dump_saved_info(self, uc):
        # Dump registers
        for reg, val in self.regs.items():
            set_register(uc, reg, val)

        # Restore the memory
        if em.writeToTempFile:
            print ("writeToTempFile 2")
            with open("coverage_mem_tmp.bin", 'rb') as f:
                uc.mem_write(0x10000000, f.read())


        # Restore the stack
        amt =  em.codeCoverageStackAmt
        if em.arch == 32:
            stackStart=self.regs['esp']-amt
            stackStartEBP=self.regs['ebp']-amt
            try:
                uc.mem_write(stackStart, self.stack)
            except UcError:
                 print ("\tComplete code coverage: restoring memory pointed to by esp,", hex(self.regs['esp']), ", failed for coverage object", self.coverage_num, ".")
            try:
                uc.mem_write(stackStartEBP, self.ebpStack)
            except UcError:
                 print ("\tComplete code coverage: restoring memory pointed to by ebp,", hex(self.regs['ebp']), ", failed for coverage object", self.coverage_num, ". This may be correct behavior.")
        else:
            stackStart=self.regs['rsp']-amt
            stackStartEBP=self.regs['rbp']-amt
            try:
                uc.mem_write(stackStart, self.stack)
            except UcError:
                 print ("\tComplete code coverage: restoring memory pointed to by rsp,", hex(self.regs['rsp']), ", failed for coverage object", self.coverage_num, ".")
            try:
                uc.mem_write(stackStartEBP, self.ebpStack)
            except UcError:
                 print ("\tComplete code coverage: restoring memory pointed to by rbp,", hex(self.regs['rbp']), ", failed for coverage object", self.coverage_num, ". This may be correct behavior.")

    def print_saved_info(self):
        print(f"Address: {hex(self.address)}")
        for reg, val in self.regs.items():
            print(f"{reg}: {hex(val)}")
        print(f"Stack = {binaryToStr(self.stack)}")

    def delete(self, index):
        if em.showCCDebugInfo:
            print (constants.YELLOW +"\t[*] Deleting code coverage object:" + constants.RESET, coverage_objects[index].coverage_num, constants.GREEN+ "   Address:", constants.WHITE+hex(coverage_objects[index].address))

        del coverage_objects[index]

    def giveAddress(self,address):
        print (constants.CYAN+"Coverage - adding address", hex(address), "num"++constants.RESET, self.coverage_num)
        self.address=address
        coverageAdds.add(address)
        

coverage_objects = []
covObjs =  {}
programCounter = 0
verbose = True
WinAPI = CustomWinAPIs()
WinSysCall = CustomWinSysCalls()

CODE_ADDR = 0x12000000
ENTRY_ADDR = 0x1000
STACK_ADDR = 0x19000000
EXTRA_ADDR = 0x20000000
MOD_LOW = 0x14100000
MOD_HIGH = 0x14100000
codeLen = 0
with open(os.path.join(os.path.dirname(__file__), 'WinSysCalls.json'), 'r') as syscall_file:
    syscall_dict = json.load(syscall_file)

with open(os.path.join(os.path.dirname(__file__), 'skipAddressesCCC.json'), 'r') as jsonCCC:
    skipJmpCCC = json.load(jsonCCC)

export_dict = {}
loggedList = []
logged_syscalls = []
logged_dlls = []
paramValues = []
network_activity = {}
jmpInstructs = {}
address_range = []

traversedAdds = set()
coverageAdds = set()
skipForCoverage=set()
coverage_num = 1
loadModsFromFile = True
foundDLLAddresses32 = os.path.join(os.path.dirname(__file__), "foundDLLAddresses32.json")
foundDLLAddresses64 = os.path.join(os.path.dirname(__file__), "foundDLLAddresses64.json")
outFile = open(os.path.join(os.path.dirname(__file__), 'emulationLog.txt'), 'w')
stackFile = open(os.path.join(os.path.dirname(__file__), 'stackLog.txt'), 'w')
cleanStackFlag = False
stopProcess = False
stopProcessCC = False
cleanBytes = 0
bad_instruct_count = 0

if platform.uname()[0] == "Windows":
    expandedDLLsPath32 = os.path.join(os.path.dirname(__file__), "DLLs\\x86\\")
    expandedDLLsPath64 = os.path.join(os.path.dirname(__file__), "DLLs\\x64\\")
else:
    expandedDLLsPath32 = os.path.join(os.path.dirname(__file__), "DLLs/x86/")
    expandedDLLsPath64 = os.path.join(os.path.dirname(__file__), "DLLs/x64/")

bVerbose = True

colorama.init()

def loadDlls(mu):
    global export_dict
    global expandedDLLsPath
    global MOD_HIGH

    # Set 32 bit variables
    if em.arch == 32:
        foundDLLAddrs = foundDLLAddresses32
        source_path = 'C:\\Windows\\SysWOW64\\'
        save_path = expandedDLLsPath32

    # Set 64 bit variables
    else:
        foundDLLAddrs = foundDLLAddresses64
        source_path = 'C:\\Windows\\System32\\'
        save_path = expandedDLLsPath64
    export_dict0 = readDLLsAddsFromFile(foundDLLAddrs, export_dict)

    mods, export_dict, MOD_HIGH = initMods(mu, em, export_dict0, source_path, save_path)

    if len(export_dict) > 0:
        saveDLLAddsToFile(foundDLLAddrs, export_dict)
    # print ("export_dict size", len(export_dict))
    
    export_dict = readDLLsAddsFromFile(foundDLLAddrs, export_dict)
    # print ("export_dict size", len(export_dict))
    return mods


def coverage_branch(uc):
    # this function is deprecated per Jacob
    global coverage_objects

    if len(coverage_objects) > 0:
        uc.reg_write(UC_X86_REG_EIP, coverage_objects[0].address)  # noqa: F405
        coverage_objects[0].delete(0)
    else:
        uc.emu_stop()

def calculateAddressesSkipCCC():
    if em.excludeJmpCallCoverage:
        for address in skipJmpCCC:
            lim=skipJmpCCC[address]
            address = int(address,16)
            for x in range(lim):
                skipForCoverage.add(address)
                address=address+1

def breakLoop(uc, jmpFlag, jmpType, op_str, addr, size):
    eflags = uc.reg_read(UC_X86_REG_EFLAGS)  # noqa: F405
    jmpLoc=0
    if boolFollowJump(jmpFlag, jmpType, eflags):
        if "0x12" in op_str:
            try:
                jmpLoc=int(op_str,16)
            except ValueError:
                jmpLoc=int(op_str)

        else:
            if "0x" in op_str:
                jmpLoc = addr + signedNegHexTo(op_str)
                print ("jmpLoc", hex(jmpLoc))
            else:
                try:
                    jmpLoc = addr + int(op_str)
                except ValueError:
                    jmpLoc = addr + int(op_str,16)

        uc.reg_write(UC_X86_REG_EIP, jmpLoc)
    else:
        uc.reg_write(UC_X86_REG_EIP, addr + size)
        jmpLoc= addr + size
        

    print (
        constants.CYAN 
        + "\t[*] " 
        +constants.RESET 
        + "Breaking out of a loop at " 
        + constants.GREEN 
        +  hex(addr) 
        +constants.RESET 
        + " - going to " 
        + constants.RED 
        + hex(jmpLoc) 
        +constants.RESET 
        +  "."
    )
    if verbose:
        outFile.write("***** Breaking out of a loop at " + hex(addr) + " - going to " + hex(jmpLoc) + ".\n")

def catch_windows_api(uc, fRaw, addr, ret, size, funcAddress):
    global stopProcess
    global cleanBytes

    ret += size
    push(uc, em.arch, ret)
    eip = uc.reg_read(UC_X86_REG_EIP)
    esp = uc.reg_read(UC_X86_REG_ESP)

    try:
        funcName = export_dict[funcAddress][0]
        dll = export_dict[funcAddress][1]
        dll = dll[0:-4]

        # Log usage of DLL
        dllL=dll.lower()
        foundAlready=False
        for each in logged_dlls:
            if dll == each or dllL == each.lower():
                foundAlready=True
        if not foundAlready:
            logged_dlls.append(dll)


    except Exception:
        funcName = "funcname: DID NOT FIND address - " + funcAddress
        print ("finding funcname")
        print(traceback.format_exc())

    try:
        funcInfo, cleanBytes = getattr(WinAPI, funcName)(uc, eip, esp, export_dict, addr, em)
        logCall(funcName, funcInfo)
        # print ("funcName", funcName)
    except AttributeError:
        try:
            bprint("hook_default", funcAddress)
            hook_default(uc, eip, esp, funcAddress, export_dict[funcAddress][0], addr)
        except Exception as e:
            print(e)
            print(traceback.format_exc())
            print("\n\tHook failed at " + str(funcAddress) + ".")

    fRaw.add(int(funcAddress, 16), funcName)
    if exitAPI(funcName):
        stopProcess = True
    uc.reg_write(UC_X86_REG_EIP, EXTRA_ADDR)  # noqa: F405
    return ret


bAddRead=set()
bAddReadTwice=set()
bAddReadTwiceTuple=set()
bAddReadThrice=set()
bAddReadThriceTuple=set()

bAddWrite=set()

bAddReadTuple=set()
bAddWriteTuple=set()
bAddWriteTwiceTuple=set()
bAddWriteTwice=set()
bAddWriteThriceTuple=set()
bAddWriteThrice=set()

bReadListTuple=[]
bWriteListTuple=[]



def hook_mem_access2(uc, address, size, user_data):
    global stackFile
    stackFile.write( "[ mem_access2: bad " + hex(address) +"] ")


def hook_mem_access3(uc, access, address, size, value=0, user_data=None):
    global stackFile
    stackFile.write( "[ mem_access2: bad " + hex(address) +"] ")


def hook_mem_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:  # noqa: F405
        if address > 0x12000000 and address <0x12990070:
            if address in bAddWrite:
                bAddWriteTwice.add(address)
                bAddWriteTwiceTuple.add((address, size))
            elif address in bAddWriteTwice:
                bAddWriteThriceTuple.add(address)
                bAddWriteThrice.address((address, size))
            else:
                bAddWriteTuple.add((address, size))
                bAddWrite.add(address)
        if address < MOD_LOW or address > MOD_HIGH  and (address < STACK_ADDR-0x5000  or address > STACK_ADDR +0x5000 ) and address != ENTRY_ADDR and address != EXTRA_ADDR:
            bWriteListTuple.append((hex(address),size))

        
    else:   # READ
        if address > 0x12000000 and address <0x12990070:

            if address in bAddRead:
                bAddReadTwice.add(address)
                bAddReadTwiceTuple.add((address, size))
            elif address in bAddReadTwice:
                bAddReadThriceTuple.add(address)
                bAddReadThrice.address((address, size))
            else:
                bAddRead.add(address)
                bAddReadTuple.add((address, size))
        if address < MOD_LOW or address > MOD_HIGH  and (address < STACK_ADDR-0x5000  or address > STACK_ADDR +0x5000 ) and address != ENTRY_ADDR and address != EXTRA_ADDR:
            bReadListTuple.append((hex(address),size))

def hook_code(uc, address, size, user_data):
    global cleanBytes, verbose
    global outFile
    global stackFile
    global programCounter
    global cleanStackFlag
    global stopProcess
    global stopProcessCC
    global traversedAdds
    global coverage_objects
    global em
    global bad_instruct_count
    global coverage_num
    global finalAddress

    finalAddress=address
    fRaw=user_data

    if cleanStackFlag:
        cleanStack(uc, cleanBytes)
        cleanStackFlag = False

    addressF = address
    if stopProcess or stopProcessCC:
        uc.emu_stop()
        if em.showCCDebugInfo:
            print (constants.RED +"\t[!] Forced stop"++constants.RESET)

    programCounter += 1
    if programCounter > em.maxCounter and em.maxCounter > 0:
        print(constants.RED + "\t[*] " +constants.RESET +" Exiting emulation because max counter of "  + constants.GREEN +  str(em.maxCounter) +constants.RESET + " reached.\n")
        uc.emu_stop()

    instructLine = ""
    timelessStack= ""
    if verbose:
        instructLine += giveRegs(uc, em.arch)
        instructLine += str(programCounter) + ": 0x%x" % address + "\t"
    if em.timeless_debugging_stack:
        timelessStack+=giveStack(uc, em.arch)
        timelessStack += str(programCounter) + ": 0x%x" % address + "\t"
        stackFile.write(timelessStack )

    shells = b''
    try:
        shells = uc.mem_read(address, size)
    except UcError:
        print(f"Failed to read memory at {address}")
        print(traceback.format_exc())
        instructLine += " size: 0x%x" % size + '\t'  # size is overflow - why so big?
        outFile.write("abrupt end:  " + instructLine)
        print("abrupt end: error reading line of shellcode")
        stopProcess = True
        # return # terminate func early   --don't comment - we want to see the earlyrror
        
    ret = address
    # Print out the instruction
    mnemonic = ""
    op_str = ""
    t = 0
    bad_instruct = False

    fRaw.addBytes(shells, addressF - CODE_ADDR, size)
    try:
        finalOut = uc.mem_read(CODE_ADDR + em.entryOffset, codeLen)
    except UcError:
        print(f"[!] Failed to read at address {CODE_ADDR+em.entryOffset}")
    fRaw.giveEnd(finalOut)

    if shells == b'\x00\x00':
        bad_instruct_count += 1
        if bad_instruct_count > 5:
            bad_instruct = True

    valInstruction=""
    for i in cs.disasm(shells, address):
        valInstruction = i.mnemonic + " " + i.op_str  # + " " + shells.hex()
        instructLine += valInstruction + '\n'
        # shells = uc.mem_read(base, size)
        # Debugger Test
        if em.debug:
            em = debugger(uc, em)
        if verbose:
            outFile.write(instructLine)
        if em.timeless_debugging_stack:
            stackFile.write("  "+valInstruction)
            # giveStackClass(uc, em.arch,programCounter,val)
        if t == 0:
            mnemonic = i.mnemonic
            op_str = i.op_str
            # print ("mnemonic op_str", mnemonic, op_str)
            break
        t += 1

    # Jump to code coverage branch if shellcode is already done
    jumpAddr = controlFlow(uc, mnemonic, op_str)

    if (jumpAddr < CODE_ADDR or jumpAddr > MOD_HIGH) and jumpAddr != -1:
        for add in address_range:
            rangeLow = add[0]
            rangeHigh = add[1]
            if jumpAddr < rangeLow or jumpAddr > rangeHigh:
                # print("************************** WE DIPPING EARLY *****************************")
                uc.emu_stop()

    # If jmp instruction, increment jmp counter to track for infinite loop and track in code coverage
    jmpFlag = getJmpFlag(mnemonic)
    if jmpFlag != "":
        if address not in jmpInstructs:
            jmpInstructs[address] = 1
        else:
            jmpInstructs[address] += 1

        if jmpInstructs[address] >= em.maxLoop and em.breakOutOfLoops:
            breakLoop(uc, jmpFlag, mnemonic, op_str, address, len(shells))
            jmpInstructs[address] = 0

        # track for code coverage
        if address not in traversedAdds and em.codeCoverage:
            eflags = uc.reg_read(UC_X86_REG_EFLAGS)  # noqa: F405

            if jumpAddr not in coverageAdds:
                cvg1 = Coverage(uc, jumpAddr)
                coverage_num += 1
                coverage_objects.append(cvg1)
                if em.showCCDebugInfo:
                    print (constants.CYAN+"\t[*] "+constants.CYAN+ "Creating code coverage object:" +constants.RESET, cvg1.coverage_num, constants.GREEN+"   Address:"+constants.RESET, hex(jumpAddr))
            if address + size not in coverageAdds:
                cvg2 = Coverage(uc, address + size)
                coverage_num += 1
                coverage_objects.append(cvg2)
                if em.showCCDebugInfo:
                    print (constants.CYAN+"\t[*] "+constants.CYAN+ "Creating code coverage object:" +constants.RESET, cvg2.coverage_num, constants.GREEN+"   Address:"+constants.RESET, hex(address + size), )
    elif "call" in mnemonic and em.includeCallInCC and em.codeCoverage:    # we are adding CALL as well.
        if address + size not in coverageAdds and address + size not in skipForCoverage:
            cvg2 = Coverage(uc, address + size)
            coverage_num += 1
            coverage_objects.append(cvg2)
            if em.showCCDebugInfo:
                print (constants.YELLOW +"\t[*] "+constants.CYAN+ "Code Coverage CALL - adding address"+constants.RESET, hex(address + size), constants.CYAN+"- coverage object:"+constants.RESET, cvg2.coverage_num)
    elif "jmp" in mnemonic and em.codeCoverage and em.includeJmpInCC:    # we are adding CALL as well.
        if address + size not in coverageAdds and address + size not in skipForCoverage:
            if address + size == 0x12000005:
                print ("12..5")
            cvg2 = Coverage(uc, address + size)
            coverage_num += 1
            coverage_objects.append(cvg2)
            if em.showCCDebugInfo:
                print (constants.YELLOW +"\t[*] "+constants.CYAN+ "Code Coverage JMP - adding address"+constants.RESET, hex(address + size), constants.CYAN+"- coverage object:"+constants.RESET, cvg2.coverage_num)

    # Track addresses we've already visited
    if em.codeCoverage:
        if em.restartCCInProgress:
            if address in traversedAdds and address != EXTRA_ADDR:
                # print ("\tInstruction already traversed:", valInstruction)
                if em.showCCDebugInfo:
                    if stopProcessCC:
                        print(constants.RED +"\t[*]"+constants.RESET+" Complete code coverage: already traversed " + hex(address) + constants.RED + " -  stopping."+constants.RESET)
                    elif em.StopExecutingAfterTraversed:
                        print(constants.RED +"\t[*]"+constants.RESET+" Complete code coverage: already traversed " + hex(address) + constants.RED + " -  stopping after next instruction."+constants.RESET)

                if verbose:
                    if stopProcessCC:
                        outFile.write("\n***** Complete code coverage: already traversed " + hex(address) + " -  stopping.\n")
                    elif em.StopExecutingAfterTraversed:
                        outFile.write("\n***** Complete code coverage: already traversed " + hex(address) + " -  stopping after next instruction.\n")

                if em.timeless_debugging_stack:
                    if stopProcessCC:
                        stackFile.write("\n***** Complete code coverage: already traversed " + hex(address) + " - stopping.\n")
                    elif em.StopExecutingAfterTraversed:
                        stackFile.write("\n***** Complete code coverage: already traversed " + hex(address) + " - stopping after next instruction.\n")
                if em.StopExecutingAfterTraversed:
                    stopProcessCC = True
        traversedAdds.add(address)
        if address in coverageAdds:
            for i, obj in enumerate(coverage_objects):
                if obj.address == address:
                    coverage_objects[i].delete(i)

    # Hook usage of Windows API function
    if jumpAddr > MOD_LOW and jumpAddr < MOD_HIGH:
        funcAddress = hex(jumpAddr)
        ret = catch_windows_api(uc, fRaw, address, ret, size, funcAddress)

    # Hook usage of Windows Syscall
    if jumpAddr == 0x5000:
        hook_sysCall(uc, address, size)

    if retEnding(uc, mnemonic) or bad_instruct:
        stopProcess = True
        # print ("Stop: retEnding")

    # Begin code coverage if the shellcode is finished, and the option is enabled
    # if stopProcess and em.codeCoverage and not em.beginCoverage:
    #     stopProcess = False
    #     em.beginCoverage = True
    #     coverage_branch(uc, address, mnemonic, bad_instruct)

    # Prevent the emulation from stopping if code coverage still has objects left
    # if len(coverage_objects) > 0 and em.beginCoverage:
    #     stopProcess = False

    # If parameters were used in the function, we need to clean the stack
    if address == EXTRA_ADDR:
        cleanStackFlag = True


def hook_syscallBackup(uc, eip, esp, funcAddress, funcName, callLoc, syscallID):
    try:
        for dictionary_candidate in ((dict_kernel32, "kernel32"), (dict_ntdll, "ntdll"), (dict_user32, "user32")):  # noqa: F405
            try:
                dictionary_candidate[0][funcName]
                apiDict = dictionary_candidate[0]
            except KeyError:
                print(f"[!] {funcName} not found in {dictionary_candidate[1]}")

        paramVals = getParams(uc, esp, apiDict, 'dict1')

        paramTypes = ['DWORD'] * len(paramVals)
        paramNames = ['arg'] * len(paramVals)

        retVal, retValStr = findRetVal(funcName, syscallRS)

        uc.reg_write(UC_X86_REG_EAX, retVal)  # noqa: F405

        funcInfo = (funcName, hex(callLoc),retValStr, 'INT', paramVals, paramTypes, paramNames, False, syscallID)
        logSysCall(funcName, funcInfo)
    except Exception as e:
        print("Error!", e)
        print(traceback.format_exc())


def hook_syscallDefault(uc, eip, esp, funcAddress, funcName, sysCallID, callLoc):
    returnType, paramVals, paramTypes, paramNames, nt_tuple = '', '', '', '', ()
    dll = 'ntdll'

    try:
        nt_tuple = syscall_signature[funcName]
        paramVals = getParams(uc, esp, nt_tuple, 'ntdict')
        paramTypes = nt_tuple[1]

        paramNames = nt_tuple[2]
        returnType = nt_tuple[3]

        retVal, retValStr = findRetVal(funcName, syscallRS)


        funcInfo = (funcName, hex(callLoc), retValStr, returnType, paramVals, paramTypes, paramNames, False, sysCallID)
        logSysCall(funcName, funcInfo)
    except:
        hook_syscallBackup(uc, eip, esp, funcAddress, funcName, callLoc, sysCallID)


def hook_sysCall(uc, address, size):
    # print ("hook_sysCall")
    global logged_dlls
    global stopProcess

    ret = address + size
    push(uc, em.arch, ret)

    syscallID = uc.reg_read(UC_X86_REG_EAX)  # noqa: F405
    sysCallName = syscall_dict[em.winVersion][em.winSP][str(syscallID)]
    exportAddress = 0
    eip = uc.reg_read(UC_X86_REG_EIP)  # noqa: F405
    esp = uc.reg_read(UC_X86_REG_ESP)  # noqa: F405

    try:
        funcInfo = getattr(WinSysCall, sysCallName)(uc, eip, esp, address, em)
        funcInfo.append(syscallID)
        logSysCall(sysCallName, funcInfo)
    except AttributeError:
        try:
            hook_syscallDefault(uc, eip, esp, exportAddress, sysCallName, syscallID, address)
        except Exception as e:
            print("\n\tHook failed at " + str(hex(exportAddress)) + ".")
    if sysCallName == 'NtTerminateProcess':
        stopProcess = True
        # print ("Stop: NtTerminateProcess syscall")
    if 'LoadLibrary' in sysCallName and uc.reg_read(UC_X86_REG_EAX) == 0:  # noqa: F405
        print("\t[*] LoadLibrary failed. Emulation ceasing.")
        stopProcess = True
        # print ("Stop: LoadLibraryFailed")

    uc.reg_write(UC_X86_REG_EIP, EXTRA_ADDR)  # noqa: F405


# Most Windows APIs use stdcall, so we need to clean the stack.
def cleanStack(uc, numBytes):
    if numBytes > 0:
        esp = uc.reg_read(UC_X86_REG_ESP)  # noqa: F405
        uc.reg_write(UC_X86_REG_ESP, esp + numBytes)  # noqa: F405

    # reset cleanBytes
    global cleanBytes
    cleanBytes = 0


# Get the parameters off the stack
def findDict(funcAddress, funcName, dll=None):
    try:
        global cleanBytes
        if not dll:
            dll = export_dict[funcAddress][1]
            dll = dll[0:-4]

        # dll=dll.lower()
        dict4 = tryDictLocate('dict4', dll)
        dict2 = tryDictLocate('dict2', dll)
        dict5 = tryDictLocate('dict5', dll)
        dict1 = tryDictLocate('dict', dll)

        if ((len(dict4)==0) and (len(dict2)==0) and (len(dict1)==0) and (len(dict5) == 0)):
            dll=dll.lower()
            dict4 = tryDictLocate('dict4', dll)
            dict2 = tryDictLocate('dict2', dll)
            dict5 = tryDictLocate('dict5', dll)
            dict1 = tryDictLocate('dict', dll)
            if dll == "kernelbase":
                dict4 = tryDictLocate('dict2', 'kernel32')

        bprint("dll", dll)
        # Log usage of DLL
        dllL=dll.lower()
        foundAlready=False

        for each in logged_dlls:
            if dll == each or dllL == each.lower():
                foundAlready=True
        if not foundAlready:
            logged_dlls.append(dll)

        # Use dict three if we find a record for it
        if funcName in dict3_w32:
            return dict3_w32[funcName], 'dict3', dll

        # Use dict2 if we can't find the API in dict1
        elif funcName in dict2:
            return dict2[funcName], 'dict2', dll

        # Use dict four (WINE) if we find a record for it
        elif funcName in dict4:
            return dict4[funcName], 'dict4', dll

        elif funcName in dict5:
            return dict5[funcName], 'dict5', dll

        # If all else fails, use dict 1
        elif funcName in dict1:
            return dict1[funcName], 'dict1', dll

        else:
            print(funcName + " from "  + dll + " was not found in dictionaries.")
            return "none", "none", dll
    except Exception as e:
        bprint("Oh no!!!", e)
        bprint(traceback.format_exc())


def getParams(uc, esp, apiDict, dictName):
    global cleanBytes

    paramVals = []
    if dictName == 'dict1':
        numParams = apiDict[0]
        paramVals = makeArgVals(uc, em, esp, numParams)
        cleanBytes = apiDict[1]
    else:
        numParams = apiDict[0]
        paramVals = makeArgVals(uc, em, esp, numParams)
        for i in range(numParams):
            # Check if parameter is pointer, then convert
            if apiDict[1][i][0] == 'P':
                try:
                    pointer = paramVals[i]
                    pointerVal = getPointerVal(uc, pointer)
                    paramVals[i] = buildPtrString(pointer, pointerVal)
                except:
                    pass

            # Check if the type is a string
            elif "STR" in apiDict[1][i]:
                paramVals[i] = read_string(uc, paramVals[i])
            else:
                paramVals[i] = hex(paramVals[i])

        # Go through all parameters, and see if they can be interpreted as a string
        for i in range(0, len(paramVals)):
            if "STR" not in apiDict[1][i]:
                try:
                    p = int(paramVals[i], 16)
                except ValueError:
                    print("[!] paramVals[i] is not an int.")
                if (0x40000000 < p and p < 0x50010000):
                    string = read_string(uc, p)
                    if len(string) < 30:
                        paramVals[i] = string

    cleanBytes = stackCleanup(uc, em, esp, numParams)

    return paramVals


# If we haven't manually implemented the function, we send it to this function
# This function will simply find parameters, then log the call in our dictionary
def hook_default(uc, eip, esp, funcAddress, funcName, callLoc) -> None:
    try:
        dictName = apiDict = ""
        bprint(funcAddress, funcName)

        apiDict, dictName, dll = findDict(funcAddress, funcName)
        # bprint ("", apiDict, dictName, dll, funcName)
        if apiDict == "none" and dll == "wsock32":
            apiDict, dictName, dll = findDict(funcAddress, funcName, "ws2_32")
            bprint("", apiDict, dictName, dll)

        paramVals = getParams(uc, esp, apiDict, dictName)

        if dictName != 'dict1':
            paramTypes = apiDict[1]
            paramNames = apiDict[2]
        else:
            paramTypes = ['DWORD'] * len(paramVals)
            paramNames = ['arg'] * len(paramVals)

        try:
            dictR1 = globals()['dictRS_' + dll]
        except KeyError:
            print(f"[!]dictRS_{dll} is not a valid key.")
            dictR1 = {}
        retVal, retValStr = findRetVal(funcName, dictR1)
        bprint("returnVal", funcName, retVal)
        uc.reg_write(UC_X86_REG_EAX, retVal)  # noqa: F405

        if retValStr == 32:
            funcInfo = (funcName, hex(callLoc), hex(retValStr), 'INT', paramVals, paramTypes, paramNames, False)
        else:
            funcInfo = (funcName, hex(callLoc), (retValStr), '', paramVals, paramTypes, paramNames, False)

        logCall(funcName, funcInfo)
    except Exception as e:
        print("Error!", e)
        print(traceback.format_exc())


def logCall(funcName, funcInfo):
    global paramValues
    loggedList.append(funcInfo)
    paramValues += funcInfo[4]


def logSysCall(syscallName, syscallInfo):
    global paramValues
    var = Variables()
    var.logged_syscalls.append(syscallInfo)
    logged_syscalls.append(syscallInfo)
    paramValues += syscallInfo[4]


def findArtifacts():
    Regex = Artifacts_regex()
    Regex.initializeRegex()

    for p in paramValues:
        # -------------------------------------------
        #       Finding Paths
        # -------------------------------------------
        art.path_artifacts += re.findall(Regex.total_findPaths,str(p),re.IGNORECASE)

        # -------------------------------------------
        #       Finding Files
        # -------------------------------------------
        art.file_artifacts += re.findall(Regex.find_totalFiles,str(p))
        art.file_artifacts += re.findall(Regex.find_totalFilesBeginning,str(p),re.IGNORECASE)

        #-------------------------------------------
        #       Finding Command line
        # -------------------------------------------
        art.commandLine_artifacts += re.findall(Regex.total_commandLineArguments, str(p), re.IGNORECASE)

        # -------------------------------------------
        #       Finding WEB
        # -------------------------------------------
        art.web_artifacts += re.findall(Regex.total_webTraffic, str(p), re.IGNORECASE)

        # -------------------------------------------
        #       Finding Registry
        # -------------------------------------------
        art.registry_artifacts += re.findall(Regex.total_Registry, str(p), re.IGNORECASE)

        # -------------------------------------------
        #       Finding Exe / DLL
        # -------------------------------------------
        art.exe_dll_artifacts += re.findall(Regex.find_exe_dll, str(p), re.IGNORECASE)




    art.combineRegexEmuCMDline()
    art.exePathToCategory()
    art.regexIntoMisc()
    art.regTechniquesFind()
    art.hierarchyFind()

    art.removeDuplicates()
    art.removeStructures(Regex)


def getArtifacts():
    artifacts, net_artifacts, file_artifacts, exec_artifacts = findArtifacts()

def test_i386(mode, code, fRaw):
    global artifacts2
    global outFile
    global stackFile
    global cs
    global codeLen
    global address_range
    global finalAddress
    mu = Uc(UC_ARCH_X86, mode)

    startLoc=CODE_ADDR + em.entryOffset
    try:
        codeLen = len(code)

        # Initialize emulator
        try:
            mu.mem_map(0x00000000, 0x23050000)
        except UcError as uce:
            print(uce)
            print ("memory loading erorr")
        mods = loadDlls(mu)

        # write machine code to be emulated to memory
        mu.mem_write(CODE_ADDR, code)
        address_range.append([CODE_ADDR, len(code)])

        mu.mem_write(EXTRA_ADDR, b'\xC3')

        # initialize stack
        mu.reg_write(UC_X86_REG_ESP, STACK_ADDR-600)  # noqa: F405
        mu.reg_write(UC_X86_REG_EBP, STACK_ADDR)  # noqa: F405

        # Push entry point addr to top of stack. Represents calling of entry point.
        push(mu, em.arch, ENTRY_ADDR)
        mu.mem_write(ENTRY_ADDR, b'\x90\x90\x90\x90')

        if mode == UC_MODE_32:  
            print(constants.CYAN + "\n\t[*]" +constants.RESET + " Emulating x86 shellcode")
            cs = Cs(CS_ARCH_X86, CS_MODE_32)
            allocateWinStructs32(mu, mods)
        elif mode == UC_MODE_64:  
            print(constants.CYAN + "\n\t[*]" +constants.RESET + " Emulating x86_64 shellcode")
            cs = Cs(CS_ARCH_X86, CS_MODE_64)
            allocateWinStructs64(mu, mods)

        # tracing all instructions with customized callback

        mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_access)  
        mu.hook_add(UC_HOOK_MEM_READ, hook_mem_access)  
        mu.hook_add(UC_HOOK_CODE, hook_code, user_data=fRaw)  

        # mu.hook_add(UC_ERR_FETCH_UNMAPPED, hook_mem_access2)

        if len(coverage_objects) > 0:
            startLoc = coverage_objects[0].address
            coverage_objects[0].dump_saved_info(mu)
            coverage_objects[0].inProgress = True
        else:
            startLoc = CODE_ADDR + em.entryOffset

    except Exception as e:
        print(e)
        print(traceback.format_exc())

    try:
        # Start the emulation
        mu.emu_start(startLoc, (CODE_ADDR + em.entryOffset) + len(code))

    except Exception as e:
        print("Emulation error: ", e)
        print ("Last address:", hex(finalAddress))
        print(traceback.format_exc())

    findArtifacts()
    return mu


def showTravAdds():
    print ("TraversedAdds at restart:")
    myOut=""
    for each in traversedAdds:
        myOut+=hex(each) + constants.GREEN+", "+constants.WHITE
    print (myOut)

def restartEmu(mu, mode, code):
    global cs
    global codeLen
    global stopProcessCC
    global stopProcess

    stopProcessCC=False
    stopProcess=False
    codeLen = len(code)
    em.restartCCInProgress = True

    try:
        startLoc = coverage_objects[0].address
        coverage_objects[0].dump_saved_info(mu)
        old_num= coverage_objects[0].coverage_num
        coverage_objects[0].delete(0)

    except Exception as e:
        print(e)
        print(traceback.format_exc())

    try:
        if mode == UC_MODE_32:  
            print(constants.GREEN + "\t[!]"+constants.RESET+" Complete code coverage: "+constants.GREEN+"restarting emulation"+constants.RESET+" of x86 shellcode at " + constants.GREEN + hex(startLoc) + constants.RESET + ".")
            if verbose:
                outFile.write("***** Complete code coverage: restarting emulation of x86 shellcode at " + hex(startLoc) + ".\n")
            if em.timeless_debugging_stack:
                stackFile.write("\n***** Complete code coverage: restarting emulation of x86 shellcode at " + hex(startLoc) + ". " + str(old_num)+ "\n")
            # cs = Cs(CS_ARCH_X86, CS_MODE_32)

        elif mode == UC_MODE_64:  # noqa: F405
            print(constants.GREEN + "\t[!]"+constants.RESET+" Complete code coverage: "+constants.GREEN+"restarting emulation"+constants.RESET+" of x86_64 shellcode at " + constants.GREEN + hex(startLoc) + constants.RESET + ".")
            if verbose:
                outFile.write("\n***** Complete code coverage: restarting emulation of x86_64 shellcode at " + hex(startLoc) + ".\n")
            if em.timeless_debugging_stack:
                stackFile.write("\n***** Complete code coverage: restarting emulation of x86_64 shellcode at " + hex(startLoc) + ".\n")

            cs = Cs(CS_ARCH_X86, CS_MODE_64)
        # Start the emulation
        mu.emu_start(startLoc, (CODE_ADDR + em.entryOffset) + len(code))
        print("\n")
    except Exception as e:
        print(e)
        print(traceback.format_exc())

def startEmu(data, vb, fRaw):
    global verbose
    global programCounter
    programCounter=0
    verbose = vb
    calculateAddressesSkipCCC()


    if em.arch == 32:
        em.arch=32
        mu = test_i386(UC_MODE_32, data, fRaw)  
    elif em.arch == 64:
        em.arch=64
        mu2 = test_i386(UC_MODE_64, data, fRaw)  

    runs = 0
    while len(coverage_objects) > 0 and em.codeCoverage:
        if em.arch == 32:
            restartEmu(mu, UC_MODE_32, data)  
        elif em.arch == 64:
            restartEmu(mu2,UC_MODE_64, data)  

        if runs > 2:
            break
        runs += 1

    print(constants.CYAN + "\t[*]" +constants.RESET + " CPU counter: " + str(programCounter))
    print(constants.CYAN + "\t[*]" +constants.RESET + " Emulation complete")

    fRaw.merge2()
    fRaw.completed()
    fRaw.findAPIs()

vars = Variables()
em = vars.emu
