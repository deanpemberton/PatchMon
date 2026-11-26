package main
import "testing"
func TestBounded(t *testing.T){
 a:=Request{"11111111-1111-1111-1111-111111111111","example-id","0123456789abcdef01234567"}
 if !valid([]Request{a}){t.Fatal("valid request rejected")}
 if valid(nil)||valid([]Request{a,a})||valid([]Request{a,a,a,a,a,a}){t.Fatal("invalid batch accepted")}
 a.APIID="bad\nid";if valid([]Request{a}){t.Fatal("invalid identifier")}
}
