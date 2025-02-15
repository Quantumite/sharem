from struct import pack
from .sim_values import emuSimVals
from unicorn import Uc, UcError

HeapsDict: "dict[int,Heap]" = {}  # Dictionary of All Heaps

# Convert Heaps to Handles Some Day Shelby


# Heap Functions
class HeapAllocation:
    def __init__(self, uc: Uc, size: int):
        try:
            self.address = emuSimVals.availMem
            self.size = size
            uc.mem_map(self.address, self.size)
            emuSimVals.availMem += self.size
        except ImportError as ie:
            print("Heap Allocation failed because unicorn could not be imported.")
            print(ie)
        except Exception as e:
            print(
                "An unknown exception was raised during HeapAllocation initialization."
            )
            print(e)
            self.address = 0
            self.size = 0
            print("Heap Allocation Failed")


class Heap:
    realSize = 4096

    def __init__(self, uc: Uc, handle: int, size: int):
        """Initialize a Heap object."""
        try:
            self.baseAddress = emuSimVals.availMem
            uc.mem_map(self.baseAddress, self.realSize)
            emuSimVals.availMem += self.realSize
        except ImportError as ie:
            print("Heap Create Failed because unicorn could not be imported.")
            print(ie)
        except Exception as e:
            print("An unknown exception was raised during Heap initialization.")
            print(e)
        self.availableSize = size
        if not handle:
            self.handle = self.baseAddress
        else:
            self.handle = handle
        self.allocations: dict[int, HeapAllocation] = {}
        self.usedSize = 0
        HeapsDict.update({self.handle: self})

    def createAllocation(self, uc: Uc, size: int) -> HeapAllocation:
        """Create new HeapAllocation and update dictionary of allocations."""
        # Check avaible Memory Increase if Necessary
        while (self.usedSize + size) > self.availableSize:
            self.increaseSize()

        newAllocation = HeapAllocation(uc, size)
        self.usedSize = self.usedSize + size
        self.allocations.update({newAllocation.address: newAllocation})
        return newAllocation

    def reAlloc(self, uc: Uc, addr: int, size: int) -> HeapAllocation:
        """Reallocate old memory to new HeapAllocation."""
        # Check avaible Memory Increase if Necessary
        while (self.usedSize + size) > self.availableSize:
            self.increaseSize()

        newAllo = HeapAllocation(uc, size)
        oldAllo = self.allocations[addr]

        try:
            memory = uc.mem_read(oldAllo.address, oldAllo.size)
            fmt = "<" + str(oldAllo.size) + "s"
            uc.mem_write(newAllo.address, pack(fmt, memory))
        except UcError:
            print("[!] reAlloc failed. Returning old allocation.")
            return oldAllo

        self.usedSize = self.usedSize - oldAllo.size + size
        self.free(uc, oldAllo.address)
        self.allocations.update({newAllo.address: newAllo})
        return newAllo

    def increaseSize(self) -> None:
        """Increase size of heap by doubling."""
        self.availableSize = self.availableSize * 2

    def free(self, uc: Uc, addr: int):
        """Free memory using Unicorn's mem_unmap() and remove from allocations."""
        if addr in self.allocations:
            try:
                uc.mem_unmap(
                    self.allocations[addr].address, self.allocations[addr].size
                )
            except UcError:
                print(
                    f"[!] Underlying unicorn unmap failed to unmap {self.allocations[addr].address}"
                )
            self.usedSize -= self.allocations[addr].size
            self.allocations.pop(addr)

    def destroy(self, uc: Uc):
        """Destroy all allocations and current heap."""
        for i in self.allocations:
            self.usedSize -= self.allocations[i].size
            try:
                uc.mem_unmap(self.allocations[i].address, self.allocations[i].size)
            except UcError:
                print(
                    f"[!] Underlying unicorn unmap failed to unmap {self.allocations[i].address}."
                )
        self.allocations = {}
        try:
            uc.mem_unmap(self.baseAddress, self.realSize)
        except UcError:
            print(f"[!] Underlying unicorn unmap failed to unmap {self.baseAddress}.")
        HeapsDict.pop(self.baseAddress)

    def printInfo(self):
        print("Heap Info")
        print("Handle: ", hex(self.handle))
        print("BaseAddress: ", hex(self.baseAddress))
        print("Used Size: ", self.usedSize)
        print("Total Size: ", self.availableSize)
        print("Allocations: ", len(self.allocations))
        for i in self.allocations:
            print(
                " Address:",
                hex(self.allocations[i].address),
                "Size:",
                self.allocations[i].size,
            )
