package keyring

import (
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v4"
)

// ItemEncoder decribes how to encode/decode items.
type ItemEncoder interface {
	Encode(item *Item, secretKey SecretKey) ([]byte, error)
	Decode(b []byte, secretKey SecretKey) (*Item, error)
}

type itemEncoder struct{}

func (e *itemEncoder) Encode(item *Item, secretKey SecretKey) ([]byte, error) {
	if secretKey == nil {
		return nil, errors.Errorf("no secret key specified")
	}
	b, err := msgpack.Marshal(item)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to marshal kerying item")
	}
	encrypted := secretBoxSeal(b, secretKey)
	return encrypted, nil
}

func (e *itemEncoder) Decode(b []byte, secretKey SecretKey) (*Item, error) {
	decrypted, ok := secretBoxOpen(b, secretKey)
	if !ok {
		return nil, ErrInvalidAuth
	}

	if decrypted == nil {
		return nil, errors.Errorf("no data")
	}
	var item Item
	if err := msgpack.Unmarshal(decrypted, &item); err != nil {
		return nil, errors.Wrapf(err, "keyring item data is invalid")
	}

	return &item, nil
}

// DefaultItemEncoder is the default ItemEncoder.
func DefaultItemEncoder() ItemEncoder {
	return &itemEncoder{}
}
