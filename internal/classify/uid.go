package classify

import "strconv"

const uidKeyed = 1024

var uidKeys = func() [uidKeyed]string {
	var a [uidKeyed]string
	for i := range a {
		a[i] = "uid " + strconv.Itoa(i)
	}

	return a
}()

func UIDKey(uid uint32) string {
	if uid < uidKeyed {
		return uidKeys[uid]
	}

	return "uid " + strconv.FormatUint(uint64(uid), 10)
}
