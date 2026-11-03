package classify

import (
	"strings"
	"testing"
)

func got(cmd ...string) string {
	return strings.Join(Concerns(cmd), ",")
}

func TestConcerns(t *testing.T) {
	hits := map[string][]string{
		FetchRun: {
			`/bin/bash -c curl https://x | python3 -`,
			`/bin/sh -c wget -qO- https://x/i.sh|bash`,
			`/bin/sh -c curl -fsSL https://x/i.sh | sh`,
		},
		Disarm: {
			`csrutil disable`,
			`spctl --master-disable`,
			`tccutil reset Accessibility`,
			`systemsetup -setremotelogin on`,
			`security authorizationdb reset`,
			`security authorizationdb write system.preferences allow`,
			`/usr/bin/security authorizationdb remove com.apple.trust-settings.admin`,
		},
		Unquarantine: {
			`xattr -c /tmp/thing`,
			`xattr -d com.apple.quarantine /Applications/X.app`,
			`xattr -rd com.apple.quarantine /Applications/X.app`,
		},
		Inject: {
			`/bin/sh -c LD_PRELOAD=/tmp/x.so ./prog`,
			`env DYLD_INSERT_LIBRARIES=/tmp/evil.dylib /usr/bin/id`,
		},
		Startup: {
			`launchctl bootout system/com.x.y`,
			`cp /tmp/x.plist /Library/LaunchDaemons/x.plist`,
			`launchctl load -w /Library/LaunchDaemons/x.plist`,
			`launchctl bootstrap gui/501 /Users/a/Library/LaunchAgents/y.plist`,
			`/bin/launchctl unload -w /System/Library/LaunchDaemons/com.apple.smbd.plist`,
		},
		CredentialAccess: {
			`/bin/cat /Users/a/.ssh/id_ed25519`,
			`/bin/cp /Users/a/.aws/credentials /tmp/`,
			`security find-generic-password -s github -w`,
		},
	}

	for want, lines := range hits {
		for _, line := range lines {
			cmd := strings.Fields(line)
			if !strings.Contains(got(cmd...), want) {
				t.Errorf("%q\n  = %q, want it to include %q", line, got(cmd...), want)
			}
		}
	}

	quiet := []string{
		`git status`,
		`crontab -l`,
		`spctl --status`,
		`csrutil status`,
		`launchctl list`,
		`launchctl print gui/501`,
		`/bin/sh -c ps aux | grep ssh`,
		`xattr -l /Applications/X.app`,
		`xattr -p com.apple.quarantine /tmp/f`,
		`curl -fsSL https://x/file.tar.gz -o /tmp/f.tgz`,
		`/bin/ls /Library/LaunchAgents`,
		`/bin/cat /Library/LaunchDaemons/com.apple.smbd.plist`,
		`jq -c {env: [$x.env[]? | select(test("^(DYLD_|LD_PRELOAD=|ELECTRON_RUN_AS_NODE=)"))]}`,
		`grep -r DYLD_INSERT_LIBRARIES /etc`,
		`launchctl print gui/501`,
		`security -h`,
		`profiles list`,
		`profiles status -type enrollment`,
		`security authorizationdb read system.preferences`,
		`/usr/bin/ssh -i /Users/a/.ssh/config host`,
		`/bin/ls /Users/a/.ssh`,
		`go build -o release/x .`,
	}

	for _, line := range quiet {
		if c := got(strings.Fields(line)...); c != "" {
			t.Errorf("%q should be quiet, got %q", line, c)
		}
	}
}

// Terminal session housekeeping vs history deletion.
func TestEvasionIsAnAct(t *testing.T) {
	quiet := [][]string{
		{"mkdir", "-m", "700", "-p", "/Users/u/.zsh_sessions"},
		{"/usr/bin/find", "/Users/u/.zsh_sessions/_expiration_check_timestamp", "-mtime", "-1d"},
		{"/bin/cat", "/Users/u/.zsh_sessions/0D42D997-AF07-2053-8516-B86671ABFD72.historynew"},
		{"tail", "-n", "20", "/Users/u/.zsh_history"},
	}

	for _, cmd := range quiet {
		for _, k := range Concerns(cmd) {
			if k == Evasion {
				t.Errorf("%v read as evasion", cmd)
			}
		}
	}

	loud := [][]string{
		{"rm", "/Users/u/.zsh_history"},
		{"sh", "-c", "unset HISTFILE"},
		{"chflags", "hidden", "/tmp/q"},
	}

	for _, cmd := range loud {
		found := false

		for _, k := range Concerns(cmd) {
			found = found || k == Evasion
		}

		if !found {
			t.Errorf("%v did not read as evasion", cmd)
		}
	}
}

// Every concern kind is in the table exactly once.
func TestEveryConcernHasOneRule(t *testing.T) {
	kinds := []string{
		FetchRun, Disarm, TrustChange, ConfigProfile,
		Unquarantine, Inject, Startup, CredentialAccess,
		AccountChange, Evasion, Encoded, Killed,
		MakeExec, ProfileChange, Mount,
	}

	seen := map[string]int{}

	for _, r := range concernRules {
		seen[r.kind]++
	}

	for _, k := range kinds {
		if seen[k] != 1 {
			t.Errorf("kind %q appears %d times in concernRules, want once",
				k, seen[k])
		}
	}

	if len(seen) != len(kinds) {
		t.Errorf("concernRules has %d kinds, the package names %d",
			len(seen), len(kinds))
	}

	for _, cmd := range [][]string{{"x"}, {""}, {"chmod"}, {"xattr"}} {
		Concerns(cmd)
	}
}

// Trust and routing changes fire, reads do not.
func TestTrustChange(t *testing.T) {
	has := func(cmd []string) bool {
		for _, k := range Concerns(cmd) {
			if k == TrustChange {
				return true
			}
		}

		return false
	}

	for _, cmd := range [][]string{
		{"security", "add-trusted-cert", "-d", "-r",
			"trustRoot", "-k", "/Library/Keychains/System.keychain", "ca.pem"},
		{"/usr/sbin/networksetup", "-setautoproxyurl",
			"Wi-Fi", "http://wpad.invalid/proxy.pac"},
		{"/usr/bin/security", "remove-trusted-cert", "-d", "old.pem"},
		{"security", "trust-settings-import", "-d", "settings.plist"},
		{"security", "user-trust-settings-enable", "-d"},
		{"networksetup", "-setwebproxy", "Wi-Fi", "127.0.0.1", "8080"},
		{"networksetup", "-setsecurewebproxystate", "Wi-Fi", "off"},
		{"networksetup", "-setproxybypassdomains", "Wi-Fi", "*.local"},
		{"networksetup", "-setdnsservers", "Wi-Fi", "203.0.113.10"},
		{"sh", "-c", "echo '203.0.113.9 login.example.com' >> /etc/hosts"},
		{"sudo", "sh", "-c", `echo x >"/private/etc/hosts"`},
		{"tee", "-a", "/private/etc/hosts"},
		{"vim", "/etc/hosts"},
		{"cp", "/tmp/hosts", "/etc/hosts"},
		{"sed", "-i", "", "s/a/b/", "/etc/hosts"},
		{"perl", "-pi", "-e", "s/x/y/", "/ETC/HOSTS"},
		{"tee", "/etc/resolver/test"},
	} {
		if !has(cmd) {
			t.Errorf("%q: not read as a trust or routing change", cmd)
		}
	}

	for _, cmd := range [][]string{
		{"security", "dump-trust-settings", "-d"},
		{"security", "trust-settings-export", "-d", "out.plist"},
		{"security", "user-trust-settings-enable"},
		{"security", "find-certificate", "-a", "-p"},
		{"networksetup", "-getwebproxy", "Wi-Fi"},
		{"networksetup", "-listallnetworkservices"},
		{"networksetup", "-setcomputername", "Mac"},
		{"sh", "-c", "networksetup -getdnsservers Wi-Fi > /tmp/dns.txt"},
		{"cat", "/etc/hosts"},
		{"sh", "-c", "grep example /etc/hosts > /dev/null 2>&1"},
		{"cp", "/etc/hosts", "/Users/a/hosts.bak"},
		{"sed", "-n", "p", "/etc/hosts"},
		{"mkdir", "-p", "/etc/resolver"},
	} {
		if has(cmd) {
			t.Errorf("%q: read as trust or routing change, should be read", cmd)
		}
	}
}

// profiles changes and opened .mobileconfig files fire, reads do not.
func TestConfigProfile(t *testing.T) {
	has := func(cmd []string) bool {
		for _, k := range Concerns(cmd) {
			if k == ConfigProfile {
				return true
			}
		}

		return false
	}

	for _, cmd := range [][]string{
		{"profiles", "install", "-type", "configuration",
			"-path", "/tmp/p.mobileconfig"},
		{"/usr/bin/profiles", "remove", "-identifier", "com.example.vpn"},
		{"profiles", "remove", "-all", "-forced"},
		{"profiles", "renew", "-type", "enrollment"},
		{"profiles", "sync", "-type", "configuration"},
		{"profiles", "-I", "-F", "/tmp/p.mobileconfig"},
		{"profiles", "-R", "-p", "com.example.vpn"},
		{"profiles", "-N"},
		{"profiles", "-F", "/tmp/p.mobileconfig", "-I"},
		{"open", "/Users/a/Downloads/Settings.MobileConfig"},
		{"open", "-a", "System Settings", "/tmp/p.mobileconfig"},
	} {
		if !has(cmd) {
			t.Errorf("%q: not read as profile change", cmd)
		}
	}

	for _, cmd := range [][]string{
		{"profiles", "list"},
		{"profiles", "show", "-type", "enrollment"},
		{"profiles", "status", "-type", "enrollment"},
		{"profiles", "validate", "-path", "/tmp/p.mobileconfig"},
		{"profiles", "help", "install"},
		{"cat", "/tmp/p.mobileconfig"},
		{"open", "/Users/a/Downloads/notes.txt"},
	} {
		if has(cmd) {
			t.Errorf("%q: read as profile change, should be read", cmd)
		}
	}
}
