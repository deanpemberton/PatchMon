package remediation

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestEvidenceSignatureExpiryAndBackup(t *testing.T) {
	now:=time.Date(2025,1,1,12,0,0,0,time.UTC)
	pub,priv,err:=ed25519.GenerateKey(nil);if err!=nil{t.Fatal(err)}
	h:=HostEvidence{HostID:"example-host",IdentityFingerprint:"fixture",PackagesHash:"fixture",ObservedAt:now,BackupAt:now.Add(-time.Hour),BackupComplete:true,RecoveryVerified:true,ApplicationHealthy:true}
	data,_:=json.Marshal(Evidence{Schema:1,GeneratedAt:now,Hosts:[]HostEvidence{h}})
	sig:=ed25519.Sign(priv,data)
	e:=envelope{Payload:base64.StdEncoding.EncodeToString(data),Signature:base64.StdEncoding.EncodeToString(sig)}
	raw,_:=json.Marshal(e)
	got,err:=Verify(raw,pub,now);if err!=nil||len(got.Hosts)!=1{t.Fatalf("valid evidence rejected: %v",err)}
	if !h.Safe(now,DefaultPolicy()){t.Fatal("backup rejected")}
	h.RecoveryVerified=false;if h.Safe(now,DefaultPolicy()){t.Fatal("unverified recovery accepted")}
	if _,err=Verify(raw,pub,now.Add(time.Hour));err==nil{t.Fatal("stale evidence accepted")}
	data[0]='[';e.Payload=base64.StdEncoding.EncodeToString(data);raw,_=json.Marshal(e)
	if _,err=Verify(raw,pub,now);err==nil{t.Fatal("tampered evidence accepted")}
}
