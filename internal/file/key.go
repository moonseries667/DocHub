package file

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// objectKey builds a storage key that belongs to exactly one row.
//
// The random segment is the whole point: an instant-upload row deliberately
// shares its source row's key, so a key derived from (tenant, dir, name) alone
// would be reused by a later upload at the same path — silently replacing the
// bytes a surviving reference still serves. The key therefore identifies the
// object, not the path; dir and name stay the row's own metadata.
//
// Length is checked here against the column width rather than failing at insert
// time with an opaque MySQL error.
func objectKey(tenantID int64, name string) (string, error) {
	suffix, err := randomKeySuffix()
	if err != nil {
		return "", err
	}
	key := fmt.Sprintf("%d/%s/%s", tenantID, suffix, name)
	if len(key) > maxStorageKeyLen {
		return "", fmt.Errorf("%w: storage key exceeds %d bytes", ErrInvalidPath, maxStorageKeyLen)
	}
	return key, nil
}

func randomKeySuffix() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate storage key: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
