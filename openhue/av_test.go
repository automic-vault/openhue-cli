package openhue

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestAVCredentialRoundTripAndPlaintextRejection(t *testing.T) {
	previousPath := configPath
	configPath = t.TempDir()
	t.Cleanup(func() {
		configPath = previousPath
		viper.Reset()
	})
	viper.Reset()
	enableAVCredentialTestStore()
	viper.SetConfigFile(filepath.Join(configPath, "config.yaml"))

	config := Config{Bridge: "192.0.2.10", Key: "application-key"}
	_, err := config.Save()
	require.NoError(t, err)
	onDisk, err := os.ReadFile(filepath.Join(configPath, "config.yaml"))
	require.NoError(t, err)
	require.Contains(t, strings.ToLower(string(onDisk)), "key: '@av'")
	require.NotContains(t, string(onDisk), "application-key")

	viper.Reset()
	loaded := Config{}
	loaded.Load()
	require.Equal(t, "application-key", loaded.Key)

	require.NoError(t, os.WriteFile(
		filepath.Join(configPath, "config.yaml"),
		[]byte("bridge: 192.0.2.10\nkey: plaintext\n"),
		0600,
	))
	viper.Reset()
	require.Panics(t, func() { (&Config{}).Load() })
}
