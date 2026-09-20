package classify

const (
	CSValid                 = 0x00000001
	CSAdhoc                 = 0x00000002
	CSGetTaskAllow          = 0x00000004
	CSInstaller             = 0x00000008
	CSForcedLV              = 0x00000010
	CSInvalidAllowed        = 0x00000020
	CSHard                  = 0x00000100
	CSKill                  = 0x00000200
	CSCheckExpiration       = 0x00000400
	CSRestrict              = 0x00000800
	CSEnforcement           = 0x00001000
	CSRequireLV             = 0x00002000
	CSEntitlementsValidated = 0x00004000
	CSNvramUnrestricted     = 0x00008000
	CSRuntime               = 0x00010000
	CSLinkerSigned          = 0x00020000
	CSExecSetHard           = 0x00100000
	CSExecSetKill           = 0x00200000
	CSExecSetEnforcement    = 0x00400000
	CSExecInheritSIP        = 0x00800000
	CSKilled                = 0x01000000
	CSDyldPlatform          = 0x02000000
	CSPlatformBinary        = 0x04000000
	CSPlatformPath          = 0x08000000
	CSDebugged              = 0x10000000
	CSSigned                = 0x20000000
	CSDevCode               = 0x40000000
	CSDatavaultController   = 0x80000000

	ArchARM64  = "arm64"
	ArchX86_64 = "x86_64"
	ArchARM    = "arm"
	Arch386    = "i386"

	cpuABI64  = 0x01000000
	cpuX86    = 7
	cpuARM    = 12
	cpuX86_64 = cpuX86 | cpuABI64
	cpuARM64  = cpuARM | cpuABI64

	ModeSetUID = 0o4000
	ModeSetGID = 0o2000
	ModeSticky = 0o1000
	ModePerm   = 0o777

	UFNoDump     = 0x00000001
	UFImmutable  = 0x00000002
	UFAppend     = 0x00000004
	UFOpaque     = 0x00000008
	UFCompressed = 0x00000020
	UFTracked    = 0x00000040
	UFDataVault  = 0x00000080
	UFHidden     = 0x00008000
	SFArchived   = 0x00010000
	SFImmutable  = 0x00020000
	SFAppend     = 0x00040000
	SFRestricted = 0x00080000
	SFNoUnlink   = 0x00100000
	SFFirmlink   = 0x00800000
	SFDataless   = 0x40000000
)

var csNames = []struct {
	bit  uint32
	name string
}{
	{CSValid, "valid"},
	{CSAdhoc, "adhoc"},
	{CSGetTaskAllow, "get-task-allow"},
	{CSInstaller, "installer"},
	{CSForcedLV, "forced-lv"},
	{CSInvalidAllowed, "invalid-allowed"},
	{CSHard, "hard"},
	{CSKill, "kill"},
	{CSCheckExpiration, "check-expiration"},
	{CSRestrict, "restrict"},
	{CSEnforcement, "enforcement"},
	{CSRequireLV, "require-lv"},
	{CSEntitlementsValidated, "entitlements-validated"},
	{CSNvramUnrestricted, "nvram-unrestricted"},
	{CSRuntime, "runtime"},
	{CSLinkerSigned, "linker-signed"},
	{CSExecSetHard, "exec-set-hard"},
	{CSExecSetKill, "exec-set-kill"},
	{CSExecSetEnforcement, "exec-set-enforcement"},
	{CSExecInheritSIP, "exec-inherit-sip"},
	{CSKilled, "killed"},
	{CSDyldPlatform, "dyld-platform"},
	{CSPlatformBinary, "platform"},
	{CSPlatformPath, "platform-path"},
	{CSDebugged, "debugged"},
	{CSSigned, "signed"},
	{CSDevCode, "dev-code"},
	{CSDatavaultController, "datavault-controller"},
}

type Bit struct {
	Bit  uint32 `json:"bit"`
	Name string `json:"name"`
}

type Tables struct {
	CS        []Bit             `json:"cs"`
	FileFlags []Bit             `json:"fileFlags"`
	Mode      []Bit             `json:"mode"`
	Arch      map[string]string `json:"arch"`
	Signing   map[string]uint32 `json:"signing"`
}

func BitTables() Tables {
	bits := func(src []struct {
		bit  uint32
		name string
	}) []Bit {
		out := make([]Bit, 0, len(src))
		for _, b := range src {
			out = append(out, Bit{b.bit, b.name})
		}
		return out
	}
	return Tables{
		CS:        bits(csNames),
		FileFlags: bits(fileFlagNames),
		Mode: []Bit{
			{ModeSetUID, "setuid"},
			{ModeSetGID, "setgid"},
			{ModeSticky, "sticky"},
			{0o002, "world-writable"},
			{0o020, "group-writable"},
		},
		Signing: map[string]uint32{
			"platform":     CSPlatformBinary,
			"adhoc":        CSAdhoc,
			"hardened":     CSRuntime,
			"libraryValid": CSRequireLV | CSForcedLV,
			"debuggable":   CSGetTaskAllow,
			"linkerSigned": CSLinkerSigned,
		},
		Arch: map[string]string{
			"16777228": "arm64",
			"16777223": "x86_64",
			"12":       "arm",
			"7":        "i386",
		},
	}
}

// CSNames lists code signing flags, lowest bit first.
func CSNames(flags uint32) []string {
	out := []string{}
	for _, f := range csNames {
		if flags&f.bit != 0 {
			out = append(out, f.name)
		}
	}

	return out
}

type Signing struct {
	Platform     bool `json:"platform"`     // Apple binary
	Adhoc        bool `json:"adhoc"`        // no signing identity
	Hardened     bool `json:"hardened"`     // hardened runtime
	LibraryValid bool `json:"libraryValid"` // only own libraries may load
	Debuggable   bool `json:"debuggable"`   // anything can attach
	LinkerSigned bool `json:"linkerSigned"` // never went through codesign
}

// SigningOf reads the states out of the raw flags.
func SigningOf(flags uint32) Signing {
	return Signing{
		Platform:     flags&CSPlatformBinary != 0,
		Adhoc:        flags&CSAdhoc != 0,
		Hardened:     flags&CSRuntime != 0,
		LibraryValid: flags&(CSRequireLV|CSForcedLV) != 0,
		Debuggable:   flags&CSGetTaskAllow != 0,
		LinkerSigned: flags&CSLinkerSigned != 0,
	}
}

func Arch(cputype int) string {
	switch cputype {
	case cpuARM64:
		return ArchARM64
	case cpuX86_64:
		return ArchX86_64
	case cpuARM:
		return ArchARM
	case cpuX86:
		return Arch386
	case 0:
		return ""
	}

	return "unknown"
}

type Perm struct {
	SetUID        bool `json:"setuid"`
	SetGID        bool `json:"setgid"`
	WorldWritable bool `json:"worldWritable"`
	GroupWritable bool `json:"groupWritable"`
}

// PermOf bits out of st_mode.
func PermOf(mode uint32) Perm {
	return Perm{
		SetUID:        mode&ModeSetUID != 0,
		SetGID:        mode&ModeSetGID != 0,
		WorldWritable: mode&0o002 != 0,
		GroupWritable: mode&0o020 != 0,
	}
}

var fileFlagNames = []struct {
	bit  uint32
	name string
}{
	{SFAppend, "sappend"},
	{SFArchived, "archived"},
	{SFDataless, "dataless"},
	{SFFirmlink, "firmlink"},
	{SFImmutable, "simmutable"},
	{SFNoUnlink, "nounlink"},
	{SFRestricted, "restricted"},
	{UFAppend, "uappend"},
	{UFCompressed, "compressed"},
	{UFDataVault, "datavault"},
	{UFHidden, "hidden"},
	{UFImmutable, "uimmutable"},
	{UFNoDump, "nodump"},
	{UFOpaque, "opaque"},
	{UFTracked, "tracked"},
}

// FileFlagNames lists set st_flags.
func FileFlagNames(flags uint32) []string {
	out := []string{}
	for _, f := range fileFlagNames {
		if flags&f.bit != 0 {
			out = append(out, f.name)
		}
	}

	return out
}
