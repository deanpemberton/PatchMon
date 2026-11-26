package main

import (
	"strings"
	"testing"
)
func TestTargets(t *testing.T) {
	good := `[{"id":"11111111-1111-4111-8111-111111111111","api_id":"patchmon_0123456789abcdef"}]`
	if x,err := validatedTargets(strings.NewReader(good)); err != nil || len(x)!=1 { t.Fatal("valid target rejected") }
	for _,s := range []string{`[]`,`[{"id":"x","api_id":"patchmon_0123456789abcdef"}]`,`[{"id":"11111111-1111-4111-8111-111111111111","api_id":"patchmon_0123456789abcdef","type":"reboot_host"}]`,good+" {}"} {
		if _,err := validatedTargets(strings.NewReader(s));err==nil {t.Fatal("unsafe input accepted")}
	}
}
