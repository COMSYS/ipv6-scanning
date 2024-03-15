package iplist

// Handle the key-value pairs that hold our comments, i.e., information on the IP address.

type comment struct {
	key    interface{}
	values map[interface{}]bool
}

func newComment(key interface{}, value interface{}) *comment {
	c := &comment{
		key:    key,
		values: make(map[interface{}]bool, 0),
	}

	c.values[value] = true

	return c
}

func (c *comment) addValue(value interface{}) {
	c.values[value] = true
}

type comments struct {
	comments []*comment
}

func newComments() *comments {
	return &comments{
		comments: make([]*comment, 0),
	}
}

func (c *comments) getKeys() []string {
	res := make([]string, 0)

	for _, k := range c.comments {
		res = append(res, k.key.(string))
	}

	return res
}

func (c *comments) getComment(key string) *comment {
	for _, k := range c.comments {
		if k.key == key {
			return k
		}
	}
	return nil
}

func (c *comments) get(key string) map[interface{}]bool {
	comment := c.getComment(key)
	if comment != nil {
		return comment.values
	}

	return nil
}

func (c *comments) contain(key string, value interface{}) bool {
	values := c.get(key)
	_, ok := values[value]
	return ok
}

func (c *comments) add(key string, value interface{}) bool {
	if !c.contain(key, value) {
		if !c.keysContain(key) {
			c.comments = append(c.comments, newComment(key, value))
		} else {
			c.getComment(key).addValue(value)
		}
	}
	return false
}

func (c *comments) keysContain(key string) bool {
	for _, k := range c.comments {
		if k.key == key {
			return true
		}
	}
	return false
}

func (c *comments) merge(d *comments) {
	for _, k := range d.comments {
		key := k.key.(string)
		for val := range k.values {
			c.add(key, val)
		}
	}
}
