from ctypes import sizeof

from sharem.sharem.helper.structHelpers import (
    BOOL,
    DWORD,
    INT,
    LONG,
    LONGLONG,
    QWORD,
    SHORT,
    UINT,
    ULONG,
    ULONGLONG,
    USHORT,
    WCHAR,
    WORD,
    CHAR,
)
from unicorn import Uc, UcError


class Memory:
    class Read:
        def CHAR(uc: Uc, address: int):
            try:
                return CHAR.from_buffer_copy(uc.mem_read(address, sizeof(CHAR))).value
            except UcError:
                print(f"[!] Failed to read memory at {address}")
                return 0

        def WCHAR(uc: Uc, address: int):
            try:
                return WCHAR.from_buffer_copy(uc.mem_read(address, sizeof(WCHAR))).value
            except UcError:
                print(f"[!] Failed to read memory at {address}")
                return 0

        def BOOL(uc: Uc, address: int):
            try:
                return BOOL.from_buffer_copy(uc.mem_read(address, sizeof(BOOL))).value
            except UcError:
                print(f"[!] Failed to read memory at {address}")
                return 0

        def WORD(uc: Uc, address: int):
            try:
                return WORD.from_buffer_copy(uc.mem_read(address, sizeof(WORD))).value
            except UcError:
                print(f"[!] Failed to read memory at {address}")
                return 0

        def DWORD(uc: Uc, address: int):
            try:
                return DWORD.from_buffer_copy(uc.mem_read(address, sizeof(DWORD))).value
            except UcError:
                print(f"[!] Failed to read memory at {address}")
                return 0

        def QWORD(uc: Uc, address: int):
            try:
                return QWORD.from_buffer_copy(uc.mem_read(address, sizeof(QWORD))).value
            except UcError:
                print(f"[!] Failed to read memory at {address}")
                return 0

        def SHORT(uc: Uc, address: int):
            try:
                return SHORT.from_buffer_copy(uc.mem_read(address, sizeof(SHORT))).value
            except UcError:
                print(f"[!] Failed to read memory at {address}")
                return 0

        def USHORT(uc: Uc, address: int):
            try:
                return USHORT.from_buffer_copy(
                    uc.mem_read(address, sizeof(USHORT))
                ).value
            except UcError:
                print(f"[!] Failed to read memory at {address}")
                return 0

        def INT(uc: Uc, address: int):
            try:
                return INT.from_buffer_copy(uc.mem_read(address, sizeof(INT))).value
            except UcError:
                print(f"[!] Failed to read memory at {address}")
                return 0

        def UINT(uc: Uc, address: int):
            try:
                return UINT.from_buffer_copy(uc.mem_read(address, sizeof(UINT))).value
            except UcError:
                print(f"[!] Failed to read memory at {address}")
                return 0

        def LONG(uc: Uc, address: int):
            try:
                return LONG.from_buffer_copy(uc.mem_read(address, sizeof(LONG))).value
            except UcError:
                print(f"[!] Failed to read memory at {address}")
                return 0

        def ULONG(uc: Uc, address: int):
            try:
                return ULONG.from_buffer_copy(uc.mem_read(address, sizeof(ULONG))).value
            except UcError:
                print(f"[!] Failed to read memory at {address}")
                return 0

        def LONGLONG(uc: Uc, address: int):
            try:
                return LONGLONG.from_buffer_copy(
                    uc.mem_read(address, sizeof(LONGLONG))
                ).value
            except UcError:
                print(f"[!] Failed to read memory at {address}")
                return 0

        def ULONGLONG(uc: Uc, address: int):
            try:
                return ULONGLONG.from_buffer_copy(
                    uc.mem_read(address, sizeof(ULONGLONG))
                ).value
            except UcError:
                print(f"[!] Failed to read memory at {address}")
                return 0

    class Write:
        def CHAR(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, CHAR(val))
            except UcError:
                print(f"[!] Failed to write memory at {address}")
                pass

        def WCHAR(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, WCHAR(val))
            except UcError:
                print(f"[!] Failed to write memory at {address}")
                pass

        def BOOL(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, BOOL(val))
            except UcError:
                print(f"[!] Failed to write memory at {address}")
                pass

        def WORD(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, WORD(val))
            except UcError:
                print(f"[!] Failed to write memory at {address}")
                pass

        def DWORD(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, DWORD(val))
            except UcError:
                print(f"[!] Failed to write memory at {address}")
                pass

        def QWORD(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, QWORD(val))
            except UcError:
                print(f"[!] Failed to write memory at {address}")
                pass

        def SHORT(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, SHORT(val))
            except UcError:
                print(f"[!] Failed to write memory at {address}")
                pass

        def USHORT(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, USHORT(val))
            except UcError:
                print(f"[!] Failed to write memory at {address}")
                pass

        def INT(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, INT(val))
            except UcError:
                print(f"[!] Failed to write memory at {address}")
                pass

        def UINT(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, bytes(UINT(val)))
            except UcError:
                print(f"[!] Failed to write memory at {address}")
                pass

        def LONG(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, LONG(val))
            except UcError:
                print(f"[!] Failed to write memory at {address}")
                pass

        def ULONG(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, ULONG(val))
            except UcError:
                print(f"[!] Failed to write memory at {address}")
                pass

        def LONGLONG(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, LONGLONG(val))
            except UcError:
                print(f"[!] Failed to write memory at {address}")
                pass

        def ULONGLONG(uc: Uc, address: int, val: int):
            try:
                if address != 0x0:
                    uc.mem_write(address, ULONGLONG(val))
            except UcError:
                print(f"[!] Failed to write memory at {address}")
                pass
