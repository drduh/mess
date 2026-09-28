package classify

type Described struct {
	Kind     string
	Vendor   string
	Category string
}

type labelKey struct {
	name string
	path string
	sign string
}

type Memo struct {
	seen map[labelKey]Described
}

func NewMemo() *Memo {
	return &Memo{
		seen: map[labelKey]Described{},
	}
}

func (m *Memo) Of(name, path, sign string) Described {
	if m == nil {
		return describedBy(name, path, sign)
	}

	k := labelKey{name, path, sign}
	if l, ok := m.seen[k]; ok {
		return l
	}

	if m.seen == nil {
		m.seen = map[labelKey]Described{}
	}

	l := describedBy(name, path, sign)
	m.seen[k] = l

	return l
}

func describedBy(name, path, sign string) Described {
	return Described{
		Kind:     Kind(name, path),
		Vendor:   Vendor(path, sign),
		Category: Category(name, path, sign),
	}
}
