// Package event defines events written by the eslogger pipeline.
package event

import "time"

type Event struct {
	Time time.Time `json:"time"`
	Seq  int64     `json:"seq,omitempty"` // global sequence number
	File string    `json:"-"`             // log file the events were read from

	PID   int `json:"pid"`
	PPID  int `json:"ppid"`
	OPPID int `json:"oppid,omitempty"` // original parent, present when it differs from ppid
	RPID  int `json:"rpid,omitempty"`  // responsible process
	SID   int `json:"sid,omitempty"`   // session id

	Sys  bool    `json:"sys"`            // caller is a platform binary
	UID  uint32  `json:"uid"`            // effective uid of the caller
	AUID *uint32 `json:"auid,omitempty"` // audit uid; nil when log predates it
	Path string  `json:"path"`           // executable that called exec
	Team string  `json:"team"`           // empty when absent or null in the log
	Sign string  `json:"sign"`

	TTY    string   `json:"tty,omitempty"`    // controlling terminal
	CWD    string   `json:"cwd,omitempty"`    // working directory of the exec
	CPU    int      `json:"cpu,omitempty"`    // mach cpu type of the image
	Script string   `json:"script,omitempty"` // shebang named an interpreter
	Cmd    []string `json:"cmd"`              // argv of the new image
	Env    []string `json:"env,omitempty"`    // environment, limited variables

	Target Target `json:"tgt,omitzero"`
}

// Target represents the image an exec started.
type Target struct {
	Path string `json:"path"`
	Sys  bool   `json:"sys"`
	Team string `json:"team,omitempty"`
	Sign string `json:"sign,omitempty"`
	UID  uint32 `json:"uid"` // effective uid the image starts with
	CS   uint32 `json:"cs"`  // raw code signing flags

	CDHash string    `json:"cdhash,omitempty"`
	Size   int64     `json:"size,omitempty"`
	MTime  time.Time `json:"mtime,omitzero"`
	Birth  time.Time `json:"birth,omitzero"`  // when the file appeared
	Owner  uint32    `json:"owner,omitempty"` // st_uid
	Mode   uint32    `json:"mode,omitempty"`  // st_mode
	Flags  uint32    `json:"flags,omitempty"` // st_flags
}
