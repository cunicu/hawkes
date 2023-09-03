package tpm2_test

import (
	"crypto/rand"
	"testing"

	swtpm "github.com/foxboron/swtpm_test"
	"github.com/stretchr/testify/require"

	"cunicu.li/go-skes/providers/ecdh"
	tpm2x "cunicu.li/go-skes/providers/ecdh/tpm2"
)

func TestStandard(t *testing.T) {
	require := require.New(t)

	tpm, err := swtpm.OpenSwtpm(t.TempDir())
	require.NoError(err)
	defer tpm.Close()

	cfg := tpm2x.Config{
		TPM: tpm,
	}

	kpHW, err := tpm2x.GenerateKeypair(cfg)
	require.NoError(err)

	kp, err := kpHW.MarshalBinary()
	require.NoError(err)

	testKeypair(t, cfg, kp)
}

func TestWithPinEntry(t *testing.T) {
	require := require.New(t)

	tpm, err := swtpm.OpenSwtpm(t.TempDir())
	require.NoError(err)
	defer tpm.Close()

	cfg := tpm2x.Config{
		TPM:      tpm,
		PinEntry: func() ([]byte, error) { return []byte("1234"), nil },
	}

	kpHW, err := tpm2x.GenerateKeypair(cfg)
	require.NoError(err)

	kp, err := kpHW.MarshalBinary()
	require.NoError(err)

	testKeypair(t, cfg, kp)
}

func testKeypair(t *testing.T, cfg tpm2x.Config, kp []byte) {
	require := require.New(t)

	kpHW, err := tpm2x.LoadKeypair(cfg, kp)
	require.NoError(err)

	kpSW, err := ecdh.P256.GenerateKeypair(rand.Reader)
	require.NoError(err)

	ssSW, err := kpSW.DH(kpHW.Public())
	require.NoError(err)

	ssTPM, err := kpHW.DH(kpSW.Public())
	require.NoError(err)

	require.Equal(ssSW, ssTPM)
}
