# 驱动样本分析（WDM · KMDF · minifilter · NDIS）

## 概览

```
范围：WDM / KMDF / minifilter / NDIS / legacy NT drivers
入口：DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)
隔离：必须使用带快照的 VM；内核崩溃=蓝屏；禁止在裸机加载未知 SYS
```

## IDA 分析 - DriverEntry 检查表

```
[ ] DriverEntry -> MajorFunction 表填充（IRP_MJ_CREATE/CLOSE/READ/WRITE/DEVICE_CONTROL）
[ ] IoCreateDevice / IoCreateDeviceSecure -> 设备对象 + 符号链接
[ ] IoCreateSymbolicLink -> 用户态可访问设备路径（如 \\DosDevices\\TargetDevice）
[ ] IOCTL 分发：IRP_MJ_DEVICE_CONTROL handler -> 根据 IoStackLocation->Parameters.DeviceIoControl.IoControlCode 分支
[ ] 解码 IOCTL：CTL_CODE(DeviceType, Function, Method, Access)
    Method: METHOD_BUFFERED=0, METHOD_IN_DIRECT=1, METHOD_OUT_DIRECT=2, METHOD_NEITHER=3
[ ] 内核回调：PsSetCreateProcessNotifyRoutine / PsSetLoadImageNotifyRoutine / ObRegisterCallbacks
[ ] DKOM 指标：PsGetCurrentProcess / PsLookupProcessByProcessId + 链表操作
[ ] Rootkit 指标：SSDT hooks / IDT hooks / IRP hooks / DKOM
[ ] 危险 IOCTL：METHOD_NEITHER 未校验导致任意读写 -> 本地提权
```

## WinDbg KD 命令参考

```
# Attach to kernel (local or remote)
windbg -k com:port=\\.\pipe\com_1,baud=115200,pipe  # QEMU serial pipe
windbg -k net:port=50000,key=a.b.c.d                # KDNET

# Driver basics
lm m target*           # verify driver loaded
!drvobj \Driver\Target 7   # show driver object + dispatch table
!devobj \Device\Target     # device object info
dt nt!_DRIVER_OBJECT <addr>

# IOCTL trace (x64: IRP.Tail.Overlay.CurrentStackLocation = IRP+0x70; IoControlCode = stack_loc+0x18)
# Verify offsets with: dt nt!_IRP; dt nt!_IO_STACK_LOCATION
bp target!DispatchDeviceControl "r rcx; .printf \"IoControlCode: %x\", poi(poi(@rcx+0x70)+0x18); g"
!irp @rcx              # dump IRP at entry

# Kernel callbacks
!for_each_module "!object \Driver\@#ModuleName"
# PsLoadedModuleList walk to find hidden drivers
dt nt!_LDR_DATA_TABLE_ENTRY <PsLoadedModuleList>

# Memory
!pool <addr>           # pool allocation info
!address <addr>        # memory region type
db/dw/dd/dq <addr> L<n>  # dump bytes/words/dwords/qwords

# Crash analysis
!analyze -v            # post-crash analysis
!thread                # current thread info
```

## IOCTL 探测模板（Python / ctypes）

```python
import ctypes, struct, os

GENERIC_READ  = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_SHARE_READ  = 0x00000001
FILE_SHARE_WRITE = 0x00000002

k32 = ctypes.windll.kernel32

def open_device(path):
    h = k32.CreateFileW(path, GENERIC_READ|GENERIC_WRITE,
                        FILE_SHARE_READ|FILE_SHARE_WRITE, None, OPEN_EXISTING, 0, None)
    if h == ctypes.c_void_p(-1).value:
        raise OSError("CreateFile failed: " + str(ctypes.GetLastError()))
    return h

def send_ioctl(handle, ioctl_code, in_buf=b'\x00'*64, out_len=256):
    out_buf = ctypes.create_string_buffer(out_len)
    bytes_ret = ctypes.c_ulong(0)
    ret = k32.DeviceIoControl(handle, ioctl_code,
                              ctypes.c_char_p(in_buf), len(in_buf),
                              out_buf, out_len, ctypes.byref(bytes_ret), None)
    return ret, bytes_ret.value, out_buf.raw[:bytes_ret.value]

# Example: fuzz IOCTL range for a target driver
h = open_device(r"\\.\TargetDevice")
for func_code in range(0x800, 0x900):
    ioctl = (0x0022 << 16) | (func_code << 2) | 0  # DeviceType=0x22, Method=BUFFERED
    ret, n, data = send_ioctl(h, ioctl)
    if ret or n > 0:
        print(f"[+] IOCTL 0x{ioctl:08X}: ret={ret} bytes={n} data={data.hex()}")
k32.CloseHandle(h)
```
