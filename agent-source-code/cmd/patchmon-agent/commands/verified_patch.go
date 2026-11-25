package commands

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const verifiedPatchType = "patch_package_verified"
const verifiedPlanMarker = "PATCHMON_VERIFIED_PLAN "

var (
	verifiedNamePattern = regexp.MustCompile("^[a-z0-9][a-z0-9+.-]{0,127}(:[a-z0-9][a-z0-9-]{0,31})?$")
	verifiedVersionPattern = regexp.MustCompile("^[0-9][A-Za-z0-9.+:~\\-]{0,255}$")
	verifiedInstallPattern = regexp.MustCompile(`^Inst ([^ ]+) \[([^]]+)\] \(([^ )]+)(?: |\))`)
	verifiedSummaryPattern = regexp.MustCompile(`^([0-9]+) upgraded, ([0-9]+) newly installed, ([0-9]+) to remove and [0-9]+ not upgraded\.?$`)
)

type verifiedTarget struct {
	Name string `json:"name"`
	Installed string `json:"installed"`
	Candidate string `json:"candidate"`
}

func verifyTargetSyntax(targets []verifiedTarget) error {
	if len(targets)==0||len(targets)>64{return errors.New("verified patch requires 1 to 64 exact targets")}
	seen:=map[string]bool{}
	for _,t:=range targets{
		if !verifiedNamePattern.MatchString(t.Name)||!verifiedVersionPattern.MatchString(t.Installed)||!verifiedVersionPattern.MatchString(t.Candidate)||t.Installed==t.Candidate||seen[t.Name]{return errors.New("invalid or duplicate verified package target")}
		seen[t.Name]=true
	}
	return nil
}

func verifiedDigest(targets []verifiedTarget) string {
	items:=append([]verifiedTarget(nil),targets...)
	sort.Slice(items,func(i,j int)bool{return items[i].Name<items[j].Name})
	raw,_:=json.Marshal(items)
	sum:=sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func readInstalledVersion(ctx context.Context,name string)(string,error) {
	cmd:=exec.CommandContext(ctx,"dpkg-query","-W","-f=${Version}\t${Status}\n",name)
	cmd.Env=append(os.Environ(),"LC_ALL=C")
	raw,err:=cmd.Output()
	if err!=nil{return "",err}
	fields:=strings.Split(strings.TrimSpace(string(raw)),"\t")
	if len(fields)!=2||fields[1]!="install ok installed"||!verifiedVersionPattern.MatchString(fields[0]){return "",errors.New("package is not uniquely installed")}
	return fields[0],nil
}

func readCandidateVersion(ctx context.Context,name string)(string,error) {
	cmd:=exec.CommandContext(ctx,"apt-cache","policy",name)
	cmd.Env=append(os.Environ(),"LC_ALL=C")
	raw,err:=cmd.Output();if err!=nil{return "",err}
	var candidate string
	for _,line:=range strings.Split(string(raw),"\n"){
		line=strings.TrimSpace(line)
		if strings.HasPrefix(line,"Candidate: "){
			if candidate!=""{return "",errors.New("ambiguous apt candidate")}
			candidate=strings.TrimSpace(strings.TrimPrefix(line,"Candidate: "))
		}
	}
	if !verifiedVersionPattern.MatchString(candidate){return "",errors.New("missing apt candidate")}
	return candidate,nil
}

// verifiedAPTArguments validates the installed and candidate versions after
// refreshing apt metadata. Downgrades and non-installed packages are refused.
func verifiedAPTArguments(ctx context.Context,targets []verifiedTarget,disableRetries bool)([]string,error) {
	if err:=verifyTargetSyntax(targets);err!=nil{return nil,err}
	args:=[]string{"--no-remove","--no-install-recommends","--only-upgrade"}
	if disableRetries{args=append(args,aptRetriesOff...)}
	args=append(args,"install","-y")
	for _,t:=range targets {
		installed,err:=readInstalledVersion(ctx,t.Name);if err!=nil||installed!=t.Installed{return nil,fmt.Errorf("installed version changed for %s",t.Name)}
		candidate,err:=readCandidateVersion(ctx,t.Name);if err!=nil||candidate!=t.Candidate{return nil,fmt.Errorf("candidate changed for %s",t.Name)}
		if err=exec.CommandContext(ctx,"dpkg","--compare-versions",t.Candidate,"gt",t.Installed).Run();err!=nil{return nil,fmt.Errorf("non-upgrade candidate for %s",t.Name)}
		args=append(args,t.Name+"="+t.Candidate)
	}
	return args,nil
}

// verifyAPTTransaction accepts only the complete expected upgrade transaction.
// Any extra dependency, removal, newly installed package, mismatch, or missing
// summary blocks execution. Parsing runs with LC_ALL=C.
func verifyAPTTransaction(output string,targets []verifiedTarget) error {
	if err:=verifyTargetSyntax(targets);err!=nil{return err}
	expected:=map[string]verifiedTarget{}
	for _,t:=range targets{expected[t.Name]=t}
	seen:=map[string]bool{}
	summary:=false
	for _,raw:=range strings.Split(output,"\n") {
		line:=strings.TrimSpace(raw)
		if strings.HasPrefix(line,"Remv ")||strings.HasPrefix(line,"Purg "){return errors.New("removal in apt simulation")}
		if strings.HasPrefix(line,"Inst "){
			m:=verifiedInstallPattern.FindStringSubmatch(line)
			if len(m)!=4{return errors.New("new or unrecognized package transaction")}
			t,ok:=expected[m[1]]
			if !ok||seen[m[1]]||t.Installed!=m[2]||t.Candidate!=m[3]{return errors.New("unexpected package or version in simulation")}
			seen[m[1]]=true
		}
		if m:=verifiedSummaryPattern.FindStringSubmatch(line);len(m)==4 {
			n,err:=strconv.Atoi(m[1]);if err!=nil||summary||n!=len(targets)||m[2]!="0"||m[3]!="0"{return errors.New("unexpected apt transaction summary")}
			summary=true
		}
	}
	if !summary||len(seen)!=len(targets){return errors.New("incomplete apt simulation")}
	return nil
}

func verifyInstalledTargets(ctx context.Context,targets []verifiedTarget)error {
	for _,t:=range targets {
		v,err:=readInstalledVersion(ctx,t.Name)
		if err!=nil||v!=t.Candidate{return fmt.Errorf("post-install version mismatch for %s",t.Name)}
	}
	return nil
}
