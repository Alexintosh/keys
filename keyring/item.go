package keyring

import (
	"time"
)

// Item is a keyring entry.
type Item struct {
	ID        string
	Type      string
	Data      []byte
	CreatedAt time.Time
}

// NewItem creates an Item with a secret.
func NewItem(id string, b []byte, typ string, createdAt time.Time) *Item {
	item := &Item{ID: id, Data: b, Type: typ, CreatedAt: createdAt}
	return item
}
