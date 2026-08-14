package ent

import "entgo.io/ent/dialect"

// Driver returns the underlying dialect.Driver configured on the ent.Client.
func (c *Client) Driver() dialect.Driver {
	return c.driver
}
