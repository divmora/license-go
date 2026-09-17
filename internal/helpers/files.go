package helpers

import (
	"errors"
	"fmt"
	"os"
)

// ErrSymlinkDetected is returned when a requested file is a symbolic link.
var ErrSymlinkDetected = errors.New("symlinks are prohibited for security")

// CheckNotSymlink verifies that the specified path exists and is not a symbolic link.
func CheckNotSymlink(filePath string) error {
	fi, err := os.Lstat(filePath)
	if err != nil {
		return fmt.Errorf("failed to stat file %s: %w", filePath, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSymlinkDetected, filePath)
	}
	return nil
}

// SafeReadFile checks that filePath is not a symbolic link before reading its content.
func SafeReadFile(filePath string) ([]byte, error) {
	if err := CheckNotSymlink(filePath); err != nil {
		return nil, err
	}
	return os.ReadFile(filePath)
}
