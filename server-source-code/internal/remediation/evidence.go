package remediation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	MaxEvidenceBytes = 8 * 1024 * 1024
	MaxEvidenceAge = 30*time.Minute
	EvidencePathEnv = "PATCHMON_REMEDIATION_EVIDENCE_FILE"
	PublicKeyEnv = "PATCHMON_REMEDIATION_PUBLIC_KEY"
	ExecutionEnv = "PATCHMON_REMEDIATION_EXECUTION"
)

type HostEvidence struct {
	HostID string `json:"host_id"`
	IdentityFingerprint string `json:"identity_fingerprint"`
	OS string `json:"os"`
	OSVersion string `json:"os_version"`
	PackagesHash string `json:"packages_hash"`
	ObservedAt time.Time `json:"observed_at"`
	BackupAt time.Time `json:"backup_at"`
	BackupComplete bool `json:"backup_complete"`
	RecoveryVerified bool `json:"recovery_verified"`
	ApplicationHealthy bool `json:"application_healthy"`
	Targets []Target `json:"targets"`
	ResolvedFindings []ResolvedFinding `json:"resolved_findings,omitempty"`
}

// ResolvedFinding is a positive vendor-specific reassessment, not an absent row.
type ResolvedFinding struct {
	Package string `json:"package"`
	Key string `json:"key"`
	Installed string `json:"installed"`
}

type Evidence struct {
	Schema int `json:"schema"`
	GeneratedAt time.Time `json:"generated_at"`
	Hosts []HostEvidence `json:"hosts"`
}

type envelope struct {
	Payload string `json:"payload"`
	Signature string `json:"signature"`
}

func decodeStrict(data []byte, v any) error {
	d:=json.NewDecoder(bytes.NewReader(data));d.DisallowUnknownFields()
	if err:=d.Decode(v);err!=nil{return err}
	if d.Decode(new(any))!=io.EOF{return errors.New("trailing JSON data")}
	return nil
}

func Fresh(t,now time.Time,max time.Duration) bool {
	return !t.IsZero() && !t.After(now) && now.Sub(t)<=max
}

// Verify authenticates the exact payload bytes before decoding. The signer is a
// trusted data producer, not an API credential or a patch authorization.
func Verify(raw []byte,key ed25519.PublicKey,now time.Time)(Evidence,error) {
	var result Evidence
	if len(raw)>MaxEvidenceBytes||len(key)!=ed25519.PublicKeySize{return result,errors.New("invalid evidence envelope or key")}
	var e envelope
	if err:=decodeStrict(raw,&e);err!=nil{return result,err}
	data,err:=base64.StdEncoding.Strict().DecodeString(e.Payload)
	if err!=nil{return result,errors.New("invalid evidence payload")}
	sig,err:=base64.StdEncoding.Strict().DecodeString(e.Signature)
	if err!=nil||!ed25519.Verify(key,data,sig){return result,errors.New("invalid evidence signature")}
	if err:=decodeStrict(data,&result);err!=nil{return result,err}
	if result.Schema!=1||!Fresh(result.GeneratedAt,now,MaxEvidenceAge)||len(result.Hosts)>10000{return result,errors.New("stale or invalid evidence")}
	seen:=map[string]bool{}
	for _,h:=range result.Hosts {
		if h.HostID==""||len(h.HostID)>128||seen[h.HostID]||len(h.Targets)>10000||len(h.ResolvedFindings)>10000{return Evidence{},errors.New("invalid or duplicate evidence host")}
		seen[h.HostID]=true
		keys:=map[string]bool{}
		for _,t:=range h.Targets {
			if err:=t.Validate();err!=nil{return Evidence{},fmt.Errorf("invalid evidence target: %w",err)}
			k:=t.CVE
			if k==""{k="routine:"+t.Installed+":"+t.Candidate}
			k=t.Package+"|"+k
			if keys[k]{return Evidence{},errors.New("duplicate finding")}
			keys[k]=true
		}
		for _,f:=range h.ResolvedFindings {
			k:=f.Package+"|"+f.Key
			if !packagePattern.MatchString(f.Package)||!versionPattern.MatchString(f.Installed)||!(cvePattern.MatchString(f.Key)||(len(f.Key)<600&&len(f.Key)>8&&f.Key[:8]=="routine:"))||keys[k]{return Evidence{},errors.New("invalid or contradictory resolved finding")}
			keys[k]=true
		}
	}
	return result,nil
}

func Read(now time.Time)(Evidence,error) {
	path:=os.Getenv(EvidencePathEnv)
	key,err:=base64.StdEncoding.Strict().DecodeString(os.Getenv(PublicKeyEnv))
	if path==""||err!=nil||len(key)!=ed25519.PublicKeySize{return Evidence{},errors.New("signed evidence is not configured")}
	info,err:=os.Lstat(path)
	if err!=nil||!info.Mode().IsRegular()||info.Mode().Perm()&0022!=0||info.Size()>MaxEvidenceBytes{return Evidence{},errors.New("evidence file missing or insecure")}
	f,err:=os.Open(path);if err!=nil{return Evidence{},err};defer f.Close()
	raw,err:=io.ReadAll(io.LimitReader(f,MaxEvidenceBytes+1));if err!=nil{return Evidence{},err}
	return Verify(raw,ed25519.PublicKey(key),now)
}

func ExecutionEnabled() bool {return os.Getenv(ExecutionEnv)=="true"}

func (h HostEvidence) Safe(now time.Time,p Policy) bool {
	return Fresh(h.ObservedAt,now,MaxEvidenceAge) && h.IdentityFingerprint!="" && h.PackagesHash!="" &&
		h.BackupComplete && h.RecoveryVerified && h.ApplicationHealthy &&
		Fresh(h.BackupAt,now,time.Duration(p.BackupMaxAgeHours)*time.Hour)
}

func (h HostEvidence) Digest() string {
	b,_:=json.Marshal(h.Targets)
	s:=sha256.Sum256(b);return hex.EncodeToString(s[:])
}
