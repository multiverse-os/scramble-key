package scramblekeys

import (
	"errors"
	"os"

	io "github.com/multiverse-os/scramblekeys/atomicio"
)

type KeyFormat int

const (
	JSON KeyFormat = iota
)

func (self Key) OverwriteFile(path string, format KeyFormat) error {
	switch format {
	case JSON:
		return io.WriteFile(path, self.JSON(), 0644)
	default:
		return errors.New("error: output key format not specified")
	}
}

func (self Key) WriteFile(path string, format KeyFormat) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		switch format {
		case JSON:
			return io.WriteFile(path, self.JSON(), 0644)
		default:
			return errors.New("error: output key format not specified")
		}
	} else {
		return errors.New("error: key file already exists")
	}
}
