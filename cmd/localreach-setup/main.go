// Local-only setup preview. Not an installed background agent.
package main
import(
 "flag"
 "log"
 "os"

 "github.com/SanamRai001/localReach/internal/localsetup"
)
func main(){
 root:=flag.String("web","web/setup","path to static setup assets")
 flag.Parse()
 log.Printf("LocalReach setup preview on http://%s (mock only)",localsetup.Address)
 if err:=localsetup.Serve(os.DirFS(*root),nil);err!=nil{log.Fatal(err)}
}
