# https://github.com/drduh/mess
#
# Endpoint Security exec projection
# for use with: `eslogger exec | jq -c -f exec.jq`

.event.exec as $x | .event.exec.target as $t | .process as $p |
{
  time: .time,
  seq:  .global_seq_num,

  # caller: the process calling exec
  pid:   $p.audit_token.pid,
  ppid:  $p.ppid,
  oppid: (if $p.original_ppid != $p.ppid then $p.original_ppid else null end),
  rpid:  $p.responsible_audit_token.pid,
  sid:   $p.session_id,
  uid:   $p.audit_token.euid,
  auid:  $p.audit_token.auid,
  sys:   $p.is_platform_binary,
  team:  $p.team_id,
  sign:  $p.signing_id,
  path:  $p.executable.path,

  # target: the image being started
  tgt: ({
    path: $t.executable.path,
    sys:  $t.is_platform_binary,
    team: $t.team_id,
    sign: $t.signing_id,
    uid:  $t.audit_token.euid,
    cs:   $t.codesigning_flags
  } + (if $t.is_platform_binary then {} else {
    cdhash: $t.cdhash,
    size:   $t.executable.stat.st_size,
    mtime:  ($t.executable.stat.st_mtimespec | .[:19] + "Z"),
    birth:  ($t.executable.stat.st_birthtimespec | .[:19] + "Z"),
    owner:  $t.executable.stat.st_uid,
    mode:   $t.executable.stat.st_mode,
    flags:  $t.executable.stat.st_flags
  } end)),

  # how and where it was run
  tty:    $t.tty.path,
  cwd:    $x.cwd.path,
  cpu:    $x.image_cputype,
  script: $x.script.path,
  cmd:    $x.args,

  # select relevant env vars
  env: [ $x.env[]
    | select(test("^(DYLD_|LD_|XPC_SERVICE_NAME=|SSH_CONNECTION=|SSH_CLIENT=|SUDO_|__CFBundleIdentifier=|PATH=|PYTHONPATH=|PYTHONSTARTUP=|NODE_OPTIONS=|PERL5OPT=|RUBYOPT=|BASH_ENV=|ENV=|ZDOTDIR=|PROMPT_COMMAND=|(http|https|all|no)_proxy=|(HTTP|HTTPS|ALL|NO)_PROXY=)"))
    | select(. != "XPC_SERVICE_NAME=0") ]
}

# drop nulls and empty lists
| del(.. | nulls) | del(.env | select(length == 0))

