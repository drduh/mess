package rules

import (
	"strings"

	"github.com/drduh/mess/internal/event"
	"github.com/drduh/mess/internal/signals"
)

const (
	curlValued = "AbcCdDeEFHKmoPQrtTuUwxXyYz"
	scpValued  = "cDFiJlMoPSX"
	sshValued  = "BbcDEeFIiJLlmOoPpQRSWw"
	wgetValued = "ABDIOPQRTUXYaeilnotw"
)

var (
	transferRules = sentOffSplit.rules()
	wgetrcName    = strings.NewReplacer("-", "", "_", "", " ", "", "\t", "")
	wgetLong      = setOf(`
		accept accept-regex adjust-extension append-output ask-password
		auth-no-challenge background backup-converted backups base bind-address
		bind-dns-address body-data body-file cache clobber compression config
		connect-timeout content-disposition content-on-error continue
		convert-file-only convert-links cookies cut-dirs debug default-page
		delete-after directories directory-prefix dns-cache dns-servers
		dns-timeout domains dont-remove-listing dot-style egd-file
		exclude-directories exclude-domains execute follow-ftp follow-tags
		force-directories force-html ftp-password ftp-stmlf ftp-user glob header
		help host-directories hsts hsts-file html-extension htmlify
		http-keep-alive http-passwd http-password http-user if-modified-since
		ignore-case ignore-length ignore-tags include-directories inet4-only
		inet6-only input-file input-metalink iri keep-badhash
		keep-session-cookies level limit-rate load-cookies local-encoding
		max-redirect metalink-index metalink-over-http method mirror netrc no
		no-adjust-extension no-ask-password no-auth-no-challenge no-background
		no-backup-converted no-backups no-cache no-clobber no-config
		no-content-disposition no-content-on-error no-continue
		no-convert-file-only no-convert-links no-cookies no-debug
		no-delete-after no-directories no-dns-cache no-follow-ftp
		no-force-directories no-force-html no-ftp-stmlf no-glob
		no-host-directories no-hsts no-html-extension no-htmlify
		no-http-keep-alive no-if-modified-since no-ignore-case no-ignore-length
		no-inet4-only no-inet6-only no-iri no-keep-badhash
		no-keep-session-cookies no-metalink-over-http no-mirror no-netrc
		no-no-clobber no-no-config no-no-parent no-page-requisites no-parent
		no-passive-ftp no-preserve-permissions no-protocol-directories no-proxy
		no-quiet no-random-wait no-recursive no-relative no-remove-listing
		no-report-speed no-restrict-file-names no-retr-symlinks
		no-retry-connrefused no-retry-on-host-error no-save-headers
		no-server-response no-show-progress no-span-hosts no-spider
		no-strict-comments no-timestamping no-trust-server-names no-unlink
		no-use-server-timestamps no-verbose no-warc-cdx no-warc-compression
		no-warc-digests no-warc-keep-log no-wdebug no-xattr output-document
		output-file page-requisites parent passive-ftp password post-data
		post-file prefer-family preferred-location preserve-permissions progress
		protocol-directories proxy proxy-passwd proxy-password proxy-user
		proxy__compat quiet quota random-file random-wait read-timeout recursive
		referer regex-type reject reject-regex rejected-log relative
		remote-encoding remove-listing report-speed restrict-file-names
		retr-symlinks retry-connrefused retry-on-host-error retry-on-http-error
		save-cookies save-headers server-response show-progress span-hosts
		spider start-pos strict-comments timeout timestamping tries
		trust-server-names unlink use-askpass use-server-timestamps user
		user-agent verbose version wait waitretry warc-cdx warc-compression
		warc-dedup warc-digests warc-file warc-header warc-keep-log
		warc-max-size warc-tempdir wdebug xattr`)
	wgetLongValued = setOf(`
		accept accept-regex append-output base bind-address bind-dns-address
		body-data body-file compression config connect-timeout cut-dirs
		default-page directory-prefix dns-servers dns-timeout domains dot-style
		egd-file exclude-directories exclude-domains execute follow-tags
		ftp-password ftp-user header hsts-file http-passwd http-password
		http-user ignore-tags include-directories input-file input-metalink
		level limit-rate load-cookies local-encoding max-redirect metalink-index
		method no output-document output-file password post-data post-file
		prefer-family preferred-location progress proxy-passwd proxy-password
		proxy-user proxy__compat quota random-file read-timeout referer
		regex-type reject reject-regex rejected-log remote-encoding
		retry-on-http-error save-cookies start-pos timeout tries use-askpass
		user user-agent wait waitretry warc-dedup warc-file warc-header
		warc-max-size warc-tempdir`)

	curlLongValued = map[string]bool{
		"abstract-unix-socket": true, "alt-svc": true, "aws-sigv4": true,
		"cacert": true, "capath": true, "cert": true, "cert-type": true,
		"ciphers": true, "config": true, "connect-timeout": true,
		"connect-to": true, "continue-at": true, "cookie": true, "cookie-jar": true,
		"create-file-mode": true, "crlfile": true, "curves": true, "data": true,
		"data-ascii": true, "data-binary": true, "data-raw": true,
		"data-urlencode": true, "delegation": true, "dns-interface": true,
		"dns-ipv4-addr": true, "dns-ipv6-addr": true, "dns-servers": true,
		"doh-url": true, "dump-header": true, "ech": true, "egd-file": true,
		"engine": true, "etag-compare": true, "etag-save": true,
		"expect100-timeout": true, "form": true, "form-string": true,
		"ftp-account": true, "ftp-alternative-to-user": true, "ftp-method": true,
		"ftp-port": true, "ftp-ssl-ccc-mode": true,
		"happy-eyeballs-timeout-ms": true, "haproxy-clientip": true, "header": true,
		"hostpubmd5": true, "hostpubsha256": true, "hsts": true,
		"httpsig-algo": true, "httpsig-headers": true, "httpsig-key": true,
		"httpsig-keyid": true, "interface": true, "ip-tos": true,
		"ipfs-gateway": true, "json": true, "keepalive-cnt": true,
		"keepalive-time": true, "key": true, "key-type": true, "knownhosts": true,
		"krb": true, "krb4": true, "libcurl": true, "limit-rate": true,
		"local-port": true, "login-options": true, "mail-auth": true,
		"mail-from": true, "mail-rcpt": true, "max-filesize": true,
		"max-redirs": true, "max-time": true, "netrc-file": true, "noproxy": true,
		"oauth2-bearer": true, "output": true, "output-dir": true,
		"parallel-max": true, "parallel-max-host": true, "pass": true,
		"pinnedpubkey": true, "preproxy": true, "proto": true,
		"proto-default": true, "proto-redir": true, "proxy": true,
		"proxy-cacert": true, "proxy-capath": true, "proxy-cert": true,
		"proxy-cert-type": true, "proxy-ciphers": true, "proxy-crlfile": true,
		"proxy-header": true, "proxy-key": true, "proxy-key-type": true,
		"proxy-pass": true, "proxy-pinnedpubkey": true, "proxy-service-name": true,
		"proxy-tls13-ciphers": true, "proxy-tlsauthtype": true,
		"proxy-tlspassword": true, "proxy-tlsuser": true, "proxy-user": true,
		"proxy1.0": true, "pubkey": true, "quote": true, "random-file": true,
		"range": true, "rate": true, "referer": true, "request": true,
		"request-target": true, "resolve": true, "retry": true, "retry-delay": true,
		"retry-max-time": true, "sasl-authzid": true, "service-name": true,
		"sigalgs": true, "socks4": true, "socks4a": true, "socks5": true,
		"socks5-gssapi-service": true, "socks5-hostname": true, "speed-limit": true,
		"speed-time": true, "ssl-sessions": true, "stderr": true,
		"telnet-option": true, "tftp-blksize": true, "time-cond": true,
		"tls-max": true, "tls13-ciphers": true, "tlsauthtype": true,
		"tlspassword": true, "tlsuser": true, "trace": true, "trace-ascii": true,
		"trace-config": true, "unix-socket": true, "upload-file": true,
		"upload-flags": true, "url": true, "url-query": true, "user": true,
		"user-agent": true, "variable": true, "vlan-priority": true,
		"write-out": true,
	}
)

// sentOffSplit is files sent elsewhere, cut on a terminal.
var sentOffSplit = split{
	key: func(e *signals.Seen) string { return sentTo(e.Event) },
	by:  untyped,
	yes: signals.Rule{
		ID:      "sent_off",
		Title:   "Files sent off this machine unattended",
		Tier:    signals.Notice,
		Scope:   "command",
		Summary: "rsync, scp, curl or wget sent files to another machine with no terminal attached.",
		Because: "Scheduled backups, deploys and upload jobs.",
		Find:    sentOffFind,
	},
	no: signals.Rule{
		ID:      "sent_off_typed",
		Title:   "Files sent off this machine from a terminal",
		Tier:    signals.Context,
		Scope:   "command",
		Summary: "rsync, scp, curl or wget sent files to another machine from a terminal session.",
		Because: "Someone at a keyboard did this.",
		Find:    sentOffFind,
	},
}

// sentTo is where an exec was sending files.
func sentTo(e *event.Event) string {
	if to := rsyncPushTo(e); to != "" {
		return to
	}

	if to := scpPushTo(e); to != "" {
		return to
	}

	if to := curlUploadTo(e); to != "" {
		return to
	}

	return wgetUploadTo(e)
}

// sentOffFind searches for a row by its destination.
func sentOffFind(key string) string {
	return strings.ReplaceAll(key, ":", " ")
}

// rsyncPushTo is where the ssh rsync started was sending files.
func rsyncPushTo(e *event.Event) string {
	if len(e.Cmd) < 3 || signals.ImageName(e) != "ssh" {
		return ""
	}

	i := 1
	for ; i < len(e.Cmd); i++ {
		a := e.Cmd[i]
		if a == "--" {
			i++
			break
		}

		if len(a) < 2 || a[0] != '-' {
			break
		}

		for j := 1; j < len(a); j++ {
			if strings.IndexByte(sshValued, a[j]) >= 0 {
				if j == len(a)-1 {
					i++
				}

				break
			}
		}
	}

	if i >= len(e.Cmd)-1 {
		return ""
	}

	host, far := e.Cmd[i], strings.Fields(strings.Join(e.Cmd[i+1:], " "))
	server := -1
	for k, w := range far {
		switch {
		case w == "--sender":
			return ""
		case w == "--server" && k > 0 && strings.HasSuffix(far[k-1], "rsync"):
			server = k
		}
	}

	if server < 0 || len(far) < server+3 {
		return ""
	}

	return host + ":" + far[len(far)-1]
}

// scpPushTo is where scp was copying to.
func scpPushTo(e *event.Event) string {
	if len(e.Cmd) < 3 || signals.ImageName(e) != "scp" {
		return ""
	}

	var operands []string

	options := true
	for i := 1; i < len(e.Cmd); i++ {
		a := e.Cmd[i]
		switch {
		case options && a == "--":
			options = false
		case options && len(a) > 1 && a[0] == '-':
			for j := 1; j < len(a); j++ {
				c := a[j]
				if c == 't' || c == 'f' {
					return ""
				}
				if strings.IndexByte(scpValued, c) >= 0 {
					if j == len(a)-1 {
						i++
					}
					break
				}
			}
		default:
			options = false
			operands = append(operands, a)
		}
	}

	if len(operands) < 2 {
		return ""
	}

	target := operands[len(operands)-1]
	if !scpRemote(target) {
		return ""
	}

	for _, source := range operands[:len(operands)-1] {
		if scpRemote(source) {
			return ""
		}
	}

	return target
}

// scpRemote reads an scp operand.
func scpRemote(a string) bool {
	if strings.HasPrefix(a, "scp://") {
		return true
	}

	if a == "" || a[0] == ':' {
		return false
	}

	bracket := a[0] == '['
	for i := 0; i < len(a); i++ {
		switch c := a[i]; {
		case c == '@' && i+1 < len(a) && a[i+1] == '[':
			bracket = true
		case c == ']' && bracket && i+1 < len(a) && a[i+1] == ':':
			return true
		case c == ':' && !bracket:
			return true
		case c == '/':
			return false
		}
	}

	return false
}

// curlUploadTo is where curl uploaded a file.
func curlUploadTo(e *event.Event) string {
	if len(e.Cmd) < 3 || signals.ImageName(e) != "curl" {
		return ""
	}

	sends := false

	var urls, words []string
	value := func(option, v string) {
		switch option {
		case "T", "upload-file":
			sends = true
		case "d", "data", "data-binary", "data-ascii", "json":
			sends = sends || strings.HasPrefix(v, "@")
		case "data-urlencode":
			at, eq := strings.IndexByte(v, '@'), strings.IndexByte(v, '=')
			sends = sends || (at >= 0 && (eq < 0 || at < eq))
		case "F", "form":
			if _, part, ok := strings.Cut(v, "="); ok {
				sends = sends || strings.HasPrefix(part, "@") || strings.HasPrefix(part, "<")
			}
		case "url":
			urls = append(urls, v)
		}
	}

	options := true
	for i := 1; i < len(e.Cmd); i++ {
		a := e.Cmd[i]

		switch {
		case !options:
			words = append(words, a)
		case a == "--":
			options = false
		case strings.HasPrefix(a, "--"):
			name := strings.TrimPrefix(a[2:], "expand-")
			if curlLongValued[name] && i+1 < len(e.Cmd) {
				i++
				value(name, e.Cmd[i])
			}
		case len(a) > 1 && a[0] == '-':
			for j := 1; j < len(a); j++ {
				if strings.IndexByte(curlValued, a[j]) < 0 {
					continue
				}

				v := a[j+1:]
				if v == "" && i+1 < len(e.Cmd) {
					i++
					v = e.Cmd[i]
				}

				value(string(a[j]), v)
				break
			}
		default:
			words = append(words, a)
		}
	}

	if !sends {
		return ""
	}

	for _, w := range words {
		if strings.Contains(w, "://") {
			urls = append(urls, w)
		}
	}

	if len(urls) == 0 && len(words) > 0 {
		urls = append(urls, words[len(words)-1])
	}

	if len(urls) == 0 {
		return ""
	}

	return destOf(urls[0])
}

// destOf is a URL as host[:port]/path.
func destOf(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}

	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}

	host, path, _ := strings.Cut(u, "/")
	if at := strings.LastIndexByte(host, '@'); at >= 0 {
		host = host[at+1:]
	}

	if path == "" {
		return host
	}

	return host + "/" + path
}

// wgetUploadTo is where wget uploaded a file.
func wgetUploadTo(e *event.Event) string {
	if len(e.Cmd) < 3 || signals.ImageName(e) != "wget" {
		return ""
	}

	sends := false
	value := func(option, v string) {
		switch option {
		case "post-file", "body-file":
			sends = true
		case "execute":
			name, _, _ := strings.Cut(v, "=")
			name = strings.ToLower(wgetrcName.Replace(name))
			sends = sends || name == "postfile" || name == "bodyfile"
		}
	}

	var operands []string
	options := true
	for i := 1; i < len(e.Cmd); i++ {
		a := e.Cmd[i]
		switch {
		case !options || len(a) < 2 || a[0] != '-':
			operands = append(operands, a)
		case a == "--":
			options = false
		case strings.HasPrefix(a, "--"):
			given, v, inline := strings.Cut(a[2:], "=")
			if name := wgetLongName(given); wgetLongValued[name] {
				if !inline && i+1 < len(e.Cmd) {
					i++
					v = e.Cmd[i]
				}

				value(name, v)
			}
		default:
			for j := 1; j < len(a); j++ {
				if strings.IndexByte(wgetValued, a[j]) < 0 {
					continue
				}

				v := a[j+1:]
				if v == "" && i+1 < len(e.Cmd) {
					i++
					v = e.Cmd[i]
				}

				if a[j] == 'e' {
					value("execute", v)
				}

				break
			}
		}
	}

	if !sends {
		return ""
	}

	for _, w := range operands {
		if strings.Contains(w, "://") {
			return destOf(w)
		}
	}

	if len(operands) > 0 {
		return destOf(operands[0])
	}

	return ""
}

// wgetLongName resolves a long option prefix as getopt_long does.
func wgetLongName(given string) string {
	if wgetLong[given] {
		return given
	}

	match := ""
	for name := range wgetLong {
		if strings.HasPrefix(name, given) {
			if match != "" {
				return ""
			}

			match = name
		}
	}

	return match
}

func setOf(words string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.Fields(words) {
		out[w] = true
	}

	return out
}
