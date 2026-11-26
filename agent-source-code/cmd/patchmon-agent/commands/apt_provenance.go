package commands

import (
	"context"
	"encoding/json"
	"os/exec"
	"runtime"
	"time"
)

// Read only local distribution metadata. No server-supplied shell text, URLs,
// arguments or file paths; no package installation or cache mutation.
const aptProvenanceProgram = `
import json,pathlib,re
import apt
V=re.compile(r"^[0-9][A-Za-z0-9.+:~-]{0,255}$")
N=re.compile(r"^[a-z0-9][a-z0-9+.-]{0,127}(:[a-z0-9][a-z0-9-]{0,31})?$")
osr=dict((k,v.strip('"')) for k,v in (line.split("=",1) for line in pathlib.Path("/etc/os-release").read_text().splitlines() if "=" in line))
distro,release=osr.get("ID"),osr.get("VERSION_CODENAME")
if distro not in ("debian","ubuntu") or not re.fullmatch("[a-z0-9-]{1,32}",release or ""):raise SystemExit(1)
def origin(o):
    if not o.trusted:return False
    if distro=="debian" and o.origin=="Debian":
        return (o.label=="Debian-Security" and o.codename==release+"-security") or (o.label=="Debian" and o.codename in (release,release+"-updates"))
    if distro=="ubuntu" and o.origin=="Ubuntu" and o.label=="Ubuntu":
        return o.codename==release and o.archive in (release,release+"-security",release+"-updates")
    return False
rows=[]
for p in apt.Cache(memonly=True):
    if not p.is_installed or not p.is_upgradable:continue
    i,c=p.installed,p.candidate
    if not i or not c or i.source_name!=c.source_name or not N.fullmatch(i.source_name or "") or not N.fullmatch(p.fullname or ""):continue
    if not all(isinstance(v,str) and V.fullmatch(v) for v in (i.version,c.version,i.source_version,c.source_version)):continue
    origins=[o for o in c.origins if o.site]
    if not origins or not all(origin(o) for o in origins):continue
    rows.append(dict(binary=p.fullname,installed=i.version,candidate=c.version,source=i.source_name,installed_source=i.source_version,candidate_source=c.source_version))
    if len(rows)>2000:raise SystemExit(1)
data=json.dumps(dict(schema=1,distro=distro,release=release,candidates=rows),separators=(",",":"))
if len(data)>524288:raise SystemExit(1)
print(data)
`

func collectAPTProvenance() json.RawMessage {
	if runtime.GOOS != "linux" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "-c", aptProvenanceProgram).Output()
	if err != nil || len(raw) == 0 || len(raw) > 524288 || !json.Valid(raw) {
		return nil
	}
	return json.RawMessage(raw)
}
