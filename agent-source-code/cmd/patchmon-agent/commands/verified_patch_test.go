package commands

import (
	"testing"
)

func TestVerifiedAPTTransaction(t *testing.T) {
	targets := []verifiedTarget{{Name: "example-package", Installed: "1.0-1", Candidate: "1.0-2"}}
	valid := "1 upgraded, 0 newly installed, 0 to remove and 4 not upgraded.\nInst example-package [1.0-1] (1.0-2 Example:stable [amd64])\nConf example-package (1.0-2 Example:stable [amd64])\n"
	if err := verifyAPTTransaction(valid, targets); err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{
		"Inst example-package [1.0-1] (1.0-2 Example)\n",
		valid + "Remv another-package [1.0]\n",
		valid + "Inst unexpected (2.0 Example)\n",
		"1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nInst example-package [1.0-1] (1.0-3 Example)\n",
		"2 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nInst example-package [1.0-1] (1.0-2 Example)\nInst extra [1.0] (2.0 Example)\n",
	} {
		if verifyAPTTransaction(output, targets) == nil {
			t.Fatalf("unsafe transaction accepted: %q", output)
		}
	}
	if verifyTargetSyntax([]verifiedTarget{{Name: "-o", Installed: "1", Candidate: "2"}}) == nil {
		t.Fatal("unsafe package accepted")
	}
	if verifyTargetSyntax([]verifiedTarget{{Name: "example", Installed: "1", Candidate: "2 -o"}}) == nil {
		t.Fatal("unsafe version accepted")
	}
}

func TestVerifiedDigestStable(t *testing.T) {
	a := verifiedTarget{Name: "example-a", Installed: "1", Candidate: "2"}
	b := verifiedTarget{Name: "example-b", Installed: "1", Candidate: "2"}
	if verifiedDigest([]verifiedTarget{a, b}) != verifiedDigest([]verifiedTarget{b, a}) {
		t.Fatal("digest depends on ordering")
	}
	b.Candidate = "3"
	if verifiedDigest([]verifiedTarget{a, b}) == verifiedDigest([]verifiedTarget{a, {Name: "example-b", Installed: "1", Candidate: "2"}}) {
		t.Fatal("digest ignores candidate")
	}
}
