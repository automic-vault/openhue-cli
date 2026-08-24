package openhue

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const (
	avMarker      = "@av"
	avPath        = "/usr/local/bin/av"
	avMaxKeyBytes = 64 * 1024
)

var (
	avTestEnabled bool
	avTestStore   = map[string]string{}
)

func enableAVCredentialTestStore() {
	avTestEnabled = true
	avTestStore = map[string]string{}
}

func (c *Config) hydrateAV() error {
	if c.Key == "" {
		return nil
	}
	if c.Key != avMarker {
		return errors.New("OpenHue config contains a plaintext application key; run `av harden openhue-cli`")
	}
	if err := validAVBridge(c.Bridge); err != nil {
		return err
	}
	key, err := runAV("get", c.Bridge, nil)
	if err != nil {
		return err
	}
	if err := validAVKey(string(key)); err != nil {
		return err
	}
	c.Key = string(key)
	return nil
}

func (c *Config) storeAV() error {
	if err := validAVBridge(c.Bridge); err != nil {
		return err
	}
	if err := validAVKey(c.Key); err != nil {
		return err
	}
	_, err := runAV("store", c.Bridge, []byte(c.Key))
	return err
}

func validAVBridge(bridge string) error {
	if bridge == "" || len(bridge) > 255 || strings.ContainsRune(bridge, '\x00') {
		return errors.New("invalid OpenHue bridge scope")
	}
	return nil
}

func validAVKey(key string) error {
	if key == "" || key == avMarker || len(key) > avMaxKeyBytes || strings.ContainsRune(key, '\x00') {
		return errors.New("invalid OpenHue application key")
	}
	return nil
}

func runAV(action, bridge string, input []byte) ([]byte, error) {
	if avTestEnabled {
		switch action {
		case "get":
			key, ok := avTestStore[bridge]
			if !ok {
				return nil, errors.New("test OpenHue credential store is empty")
			}
			return []byte(key), nil
		case "store":
			avTestStore[bridge] = string(input)
			return nil, nil
		default:
			return nil, errors.New("unsupported OpenHue credential helper action")
		}
	}
	cmd := exec.Command(avPath, "openhue-credential", action, bridge)
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Automic Vault OpenHue credential helper failed: %w", err)
	}
	if len(output) > avMaxKeyBytes {
		return nil, errors.New("OpenHue application key exceeds 64 KiB")
	}
	return bytes.TrimSuffix(output, []byte("\n")), nil
}
