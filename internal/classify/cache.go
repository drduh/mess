package classify

type Cache struct {
	key     []byte
	seen    map[string]*answers
	cats    map[string]string // Category
	vendors map[string]string // Vendor
}

type answers struct {
	concerns []string
	template string
	hasCon   bool
	hasTmpl  bool
}

func NewCache() *Cache { return &Cache{} }

func (c *Cache) join(parts ...string) {
	c.key = c.key[:0]
	for i, a := range parts {
		if i > 0 {
			c.key = append(c.key, 0)
		}
		c.key = append(c.key, a...)
	}
}

// at finds or makes the entry for one argv.
func (c *Cache) at(cmd []string) *answers {
	c.join(cmd...)
	if got, ok := c.seen[string(c.key)]; ok {
		return got
	}

	if c.seen == nil {
		c.seen = map[string]*answers{}
	}

	a := &answers{}
	c.seen[string(c.key)] = a

	return a
}

func (c *Cache) Concerns(cmd []string) []string {
	if c == nil || len(cmd) == 0 {
		return Concerns(cmd)
	}

	a := c.at(cmd)
	if !a.hasCon {
		a.concerns, a.hasCon = Concerns(cmd), true
	}

	return a.concerns
}

func (c *Cache) Template(cmd []string) string {
	if c == nil || len(cmd) == 0 {
		return Template(cmd)
	}

	a := c.at(cmd)
	if !a.hasTmpl {
		a.template, a.hasTmpl = Template(cmd), true
	}

	return a.template
}

func (c *Cache) Category(name, path, sign string) string {
	if c == nil {
		return Category(name, path, sign)
	}

	c.join(name, path, sign)
	if got, ok := c.cats[string(c.key)]; ok {
		return got
	}

	out := Category(name, path, sign)
	if c.cats == nil {
		c.cats = map[string]string{}
	}

	c.cats[string(c.key)] = out

	return out
}

func (c *Cache) Vendor(path, sign string) string {
	if c == nil {
		return Vendor(path, sign)
	}
	c.join(path, sign)

	if got, ok := c.vendors[string(c.key)]; ok {
		return got
	}
	out := Vendor(path, sign)

	if c.vendors == nil {
		c.vendors = map[string]string{}
	}
	c.vendors[string(c.key)] = out

	return out
}
