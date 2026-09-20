package classify

const (
	AccountRoot    = "root"
	AccountPerson  = "person"
	AccountService = "service"

	RoleInit        = "init"        // launchd - pid 1
	RoleStub        = "stub"        // execs on behalf of launchd
	RoleShell       = "shell"       // runs whatever it is handed
	RoleInterpreter = "interpreter" // runs code from a file or string
	RoleNetwork     = "network"     // moves network traffic
	RolePrivilege   = "privilege"   // changes policy or privileges
)

func Role(name string) string { return tags.RoleOf(name) }

func Labels() (byRole, byCategory map[string]string) {
	return tags.Labels()
}

func Account(uid uint32) string {
	switch {
	case uid == 0:
		return AccountRoot
	case uid >= 501:
		return AccountPerson
	case uid > 4000000000:
		return AccountService
	default:
		return AccountService
	}
}
