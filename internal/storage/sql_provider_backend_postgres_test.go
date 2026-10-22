// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"database/sql/driver"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

func TestNewPostgreSQLProvider(t *testing.T) {
	address, err := schema.NewAddress("tcp://localhost:5432")
	require.NoError(t, err)

	testCases := []struct {
		name string
		have *schema.Configuration
	}{
		{
			"ShouldHandleSimple",
			&schema.Configuration{
				Storage: schema.Storage{
					EncryptionKey: "testing-key-only",
					PostgreSQL: &schema.StoragePostgreSQL{
						StorageSQL: schema.StorageSQL{
							Address: &schema.AddressTCP{Address: *address},
						},
					},
				},
			},
		},
		{
			"ShouldHandleTLS",
			&schema.Configuration{
				Storage: schema.Storage{
					EncryptionKey: "testing-key-only",
					PostgreSQL: &schema.StoragePostgreSQL{
						StorageSQL: schema.StorageSQL{
							Address: &schema.AddressTCP{Address: *address},
							TLS: &schema.TLS{
								MinimumVersion: schema.TLSVersion{Value: tls.VersionTLS12},
								MaximumVersion: schema.TLSVersion{Value: tls.VersionTLS13},
							},
						},
					},
				},
			},
		},
		{
			"ShouldHandleLegacyTLSVerifyFull",
			&schema.Configuration{
				Storage: schema.Storage{
					EncryptionKey: "testing-key-only",
					PostgreSQL: &schema.StoragePostgreSQL{
						StorageSQL: schema.StorageSQL{
							Address: &schema.AddressTCP{Address: *address},
						},
						SSL: &schema.StoragePostgreSQLSSL{ //nolint:staticcheck
							Mode: "verify-full",
						},
					},
				},
			},
		},
		{
			"ShouldHandleLegacyTLSVerifyCA",
			&schema.Configuration{
				Storage: schema.Storage{
					EncryptionKey: "testing-key-only",
					PostgreSQL: &schema.StoragePostgreSQL{
						StorageSQL: schema.StorageSQL{
							Address: &schema.AddressTCP{Address: *address},
						},
						SSL: &schema.StoragePostgreSQLSSL{ //nolint:staticcheck
							Mode: "verify-ca",
						},
					},
				},
			},
		},
		{
			"ShouldHandleLegacyTLSRequire",
			&schema.Configuration{
				Storage: schema.Storage{
					EncryptionKey: "testing-key-only",
					PostgreSQL: &schema.StoragePostgreSQL{
						StorageSQL: schema.StorageSQL{
							Address: &schema.AddressTCP{Address: *address},
						},
						SSL: &schema.StoragePostgreSQLSSL{ //nolint:staticcheck
							Mode: "require",
						},
					},
				},
			},
		},
		{
			"ShouldHandleLegacyTLSDisabled",
			&schema.Configuration{
				Storage: schema.Storage{
					EncryptionKey: "testing-key-only",
					PostgreSQL: &schema.StoragePostgreSQL{
						StorageSQL: schema.StorageSQL{
							Address: &schema.AddressTCP{Address: *address},
						},
						SSL: &schema.StoragePostgreSQLSSL{ //nolint:staticcheck
							Mode: "disable",
						},
					},
				},
			},
		},
		{
			"ShouldHandleLegacyTLSVerifyCARootCA",
			&schema.Configuration{
				Storage: schema.Storage{
					EncryptionKey: "testing-key-only",
					PostgreSQL: &schema.StoragePostgreSQL{
						StorageSQL: schema.StorageSQL{
							Address: &schema.AddressTCP{Address: *address},
						},
						SSL: &schema.StoragePostgreSQLSSL{ //nolint:staticcheck
							Mode:            "verify-ca",
							RootCertificate: "../configuration/test_resources/crypto/ca.rsa.2048.crt",
						},
					},
				},
			},
		},
		{
			"ShouldHandleLegacyTLSVerifyCAAllCertificates",
			&schema.Configuration{
				Storage: schema.Storage{
					EncryptionKey: "testing-key-only",
					PostgreSQL: &schema.StoragePostgreSQL{
						StorageSQL: schema.StorageSQL{
							Address: &schema.AddressTCP{Address: *address},
						},
						SSL: &schema.StoragePostgreSQLSSL{ //nolint:staticcheck
							Mode:            "verify-ca",
							RootCertificate: "../configuration/test_resources/crypto/ca.rsa.2048.crt",
							Certificate:     "../configuration/test_resources/crypto/rsa.2048.crt",
							Key:             "../configuration/test_resources/crypto/rsa.2048.pem",
						},
					},
				},
			},
		},
		{
			"ShouldHandleLegacyTLSVerifyCAAllCertificatesFailReadFileCA",
			&schema.Configuration{
				Storage: schema.Storage{
					EncryptionKey: "testing-key-only",
					PostgreSQL: &schema.StoragePostgreSQL{
						StorageSQL: schema.StorageSQL{
							Address: &schema.AddressTCP{Address: *address},
						},
						SSL: &schema.StoragePostgreSQLSSL{ //nolint:staticcheck
							Mode:            "verify-ca",
							RootCertificate: "../configuration/test_resources/crypto/ca.rsa.2048.cert",
							Certificate:     "../configuration/test_resources/crypto/rsa.2048.crt",
							Key:             "../configuration/test_resources/crypto/rsa.2048.pem",
						},
					},
				},
			},
		},
		{
			"ShouldHandleLegacyTLSVerifyCAAllCertificatesFailReadFileKey",
			&schema.Configuration{
				Storage: schema.Storage{
					EncryptionKey: "testing-key-only",
					PostgreSQL: &schema.StoragePostgreSQL{
						StorageSQL: schema.StorageSQL{
							Address: &schema.AddressTCP{Address: *address},
						},
						SSL: &schema.StoragePostgreSQLSSL{ //nolint:staticcheck
							Mode:            "verify-ca",
							RootCertificate: "../configuration/test_resources/crypto/ca.rsa.2048.crt",
							Certificate:     "../configuration/test_resources/crypto/rsa.2048.crt",
							Key:             "../configuration/test_resources/crypto/rsa.2048.key",
						},
					},
				},
			},
		},
		{
			"ShouldHandleLegacyTLSVerifyCAAllCertificatesFailReadFileCertificate",
			&schema.Configuration{
				Storage: schema.Storage{
					EncryptionKey: "testing-key-only",
					PostgreSQL: &schema.StoragePostgreSQL{
						StorageSQL: schema.StorageSQL{
							Address: &schema.AddressTCP{Address: *address},
						},
						SSL: &schema.StoragePostgreSQLSSL{ //nolint:staticcheck
							Mode:            "verify-ca",
							RootCertificate: "../configuration/test_resources/crypto/ca.rsa.2048.crt",
							Certificate:     "../configuration/test_resources/crypto/rsa.2048.cert",
							Key:             "../configuration/test_resources/crypto/rsa.2048.pem",
						},
					},
				},
			},
		},
		{
			"ShouldHandleLegacyTLSVerifyCAAllCertificatesFailPair",
			&schema.Configuration{
				Storage: schema.Storage{
					EncryptionKey: "testing-key-only",
					PostgreSQL: &schema.StoragePostgreSQL{
						StorageSQL: schema.StorageSQL{
							Address: &schema.AddressTCP{Address: *address},
						},
						SSL: &schema.StoragePostgreSQLSSL{ //nolint:staticcheck
							Mode:            "verify-ca",
							RootCertificate: "../configuration/test_resources/crypto/ca.rsa.2048.crt",
							Certificate:     "../configuration/test_resources/crypto/rsa.2048.crt",
							Key:             "../configuration/test_resources/crypto/rsa.4096.pem",
						},
					},
				},
			},
		},
		{
			"ShouldHandleLegacyTLSVerifyCAAllCertificatesFailReadCACertificateFromPrivateKey",
			&schema.Configuration{
				Storage: schema.Storage{
					EncryptionKey: "testing-key-only",
					PostgreSQL: &schema.StoragePostgreSQL{
						StorageSQL: schema.StorageSQL{
							Address: &schema.AddressTCP{Address: *address},
						},
						SSL: &schema.StoragePostgreSQLSSL{ //nolint:staticcheck
							Mode:            "verify-ca",
							RootCertificate: "../configuration/test_resources/crypto/ca.rsa.2048.pem",
							Certificate:     "../configuration/test_resources/crypto/rsa.2048.crt",
							Key:             "../configuration/test_resources/crypto/rsa.2048.pem",
						},
					},
				},
			},
		},
	}

	t.Parallel()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, _ := NewPostgreSQLProvider(tc.have, x509.NewCertPool())

			assert.NotNil(t, provider)
		})
	}
}

func TestLoadPostgreSQLLegacyTLSConfig(t *testing.T) {
	testCases := []struct {
		name             string
		mode             string
		rootCertificate  string
		globalCACertPool *x509.CertPool
		nilTLSConfig     bool
		assert           func(t *testing.T, tlsConfig *tls.Config)
	}{
		{
			name:             "ShouldReturnNilOnDisable",
			mode:             "disable",
			globalCACertPool: x509.NewCertPool(),
			nilTLSConfig:     true,
		},
		{
			name:             "ShouldHandleNilGlobalCACertPool",
			mode:             "require",
			globalCACertPool: nil,
		},
		{
			name:             "ShouldHandleNilGlobalCACertPoolWithRootCertificate",
			mode:             "verify-ca",
			rootCertificate:  "../configuration/test_resources/crypto/ca.rsa.2048.crt",
			globalCACertPool: nil,
		},
		{
			name:             "ShouldHandleGlobalCACertPool",
			mode:             "require",
			globalCACertPool: x509.NewCertPool(),
		},
		{
			name:             "ShouldHandleGlobalCACertPoolWithRootCertificate",
			mode:             "verify-ca",
			rootCertificate:  "../configuration/test_resources/crypto/ca.rsa.2048.crt",
			globalCACertPool: x509.NewCertPool(),
		},
		{
			name:             "ShouldHandleNilAddressOnVerifyFull",
			mode:             "verify-full",
			globalCACertPool: x509.NewCertPool(),
			assert: func(t *testing.T, tlsConfig *tls.Config) {
				assert.False(t, tlsConfig.InsecureSkipVerify)
				assert.Empty(t, tlsConfig.ServerName)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &schema.StoragePostgreSQL{
				SSL: &schema.StoragePostgreSQLSSL{ //nolint:staticcheck
					Mode:            tc.mode,
					RootCertificate: tc.rootCertificate,
				},
			}

			var tlsConfig *tls.Config

			require.NotPanics(t, func() {
				tlsConfig = loadPostgreSQLLegacyTLSConfig(config, tc.globalCACertPool)
			})

			if tc.nilTLSConfig {
				assert.Nil(t, tlsConfig)

				return
			}

			require.NotNil(t, tlsConfig)
			assert.NotNil(t, tlsConfig.RootCAs)

			if tc.assert != nil {
				tc.assert(t, tlsConfig)
			}
		})
	}
}

func TestLoadPostgreSQLLegacyTLSConfigShouldNotMutateGlobalCACertPool(t *testing.T) {
	dataGlobal, err := os.ReadFile("../configuration/test_resources/crypto/ca.rsa.4096.crt")
	require.NoError(t, err)

	dataRoot, err := os.ReadFile("../configuration/test_resources/crypto/ca.rsa.2048.crt")
	require.NoError(t, err)

	globalCACertPool := x509.NewCertPool()
	require.True(t, globalCACertPool.AppendCertsFromPEM(dataGlobal))

	expectedGlobal := x509.NewCertPool()
	require.True(t, expectedGlobal.AppendCertsFromPEM(dataGlobal))

	expectedRootCAs := x509.NewCertPool()
	require.True(t, expectedRootCAs.AppendCertsFromPEM(dataGlobal))
	require.True(t, expectedRootCAs.AppendCertsFromPEM(dataRoot))

	config := &schema.StoragePostgreSQL{
		SSL: &schema.StoragePostgreSQLSSL{ //nolint:staticcheck
			Mode:            "verify-ca",
			RootCertificate: "../configuration/test_resources/crypto/ca.rsa.2048.crt",
		},
	}

	tlsConfig := loadPostgreSQLLegacyTLSConfig(config, globalCACertPool)

	require.NotNil(t, tlsConfig)
	require.NotNil(t, tlsConfig.RootCAs)

	assert.True(t, tlsConfig.RootCAs.Equal(expectedRootCAs))
	assert.True(t, globalCACertPool.Equal(expectedGlobal))
	assert.False(t, globalCACertPool.Equal(tlsConfig.RootCAs))
}

func TestDSNPostgreSQLFallbacks(t *testing.T) {
	mkAddress := func(t *testing.T, raw string) *schema.AddressTCP {
		t.Helper()

		address, err := schema.NewAddress(raw)
		require.NoError(t, err)

		return &schema.AddressTCP{Address: *address}
	}

	testCases := []struct {
		name     string
		existing []*pgconn.FallbackConfig
		servers  []schema.StoragePostgreSQLServer
		assert   func(t *testing.T, dsnConfig *pgx.ConnConfig)
	}{
		{
			name:    "ShouldHandleEmptyServers",
			servers: []schema.StoragePostgreSQLServer{},
			assert: func(t *testing.T, dsnConfig *pgx.ConnConfig) {
				assert.NotNil(t, dsnConfig.Fallbacks)
				assert.Empty(t, dsnConfig.Fallbacks)
			},
		},
		{
			name: "ShouldHandleSingleTCPServer",
			servers: []schema.StoragePostgreSQLServer{
				{Address: mkAddress(t, "tcp://db1.example.com:5432")},
			},
			assert: func(t *testing.T, dsnConfig *pgx.ConnConfig) {
				require.Len(t, dsnConfig.Fallbacks, 1)
				assert.Equal(t, "db1.example.com", dsnConfig.Fallbacks[0].Host)
				assert.Equal(t, uint16(5432), dsnConfig.Fallbacks[0].Port)
				assert.Nil(t, dsnConfig.Fallbacks[0].TLSConfig)
			},
		},
		{
			name: "ShouldHandleMultipleTCPServers",
			servers: []schema.StoragePostgreSQLServer{
				{Address: mkAddress(t, "tcp://db1.example.com:5432")},
				{Address: mkAddress(t, "tcp://db2.example.com:6543")},
				{Address: mkAddress(t, "tcp://db3.example.com:7654")},
			},
			assert: func(t *testing.T, dsnConfig *pgx.ConnConfig) {
				require.Len(t, dsnConfig.Fallbacks, 3)
				assert.Equal(t, "db1.example.com", dsnConfig.Fallbacks[0].Host)
				assert.Equal(t, uint16(5432), dsnConfig.Fallbacks[0].Port)
				assert.Equal(t, "db2.example.com", dsnConfig.Fallbacks[1].Host)
				assert.Equal(t, uint16(6543), dsnConfig.Fallbacks[1].Port)
				assert.Equal(t, "db3.example.com", dsnConfig.Fallbacks[2].Host)
				assert.Equal(t, uint16(7654), dsnConfig.Fallbacks[2].Port)
			},
		},
		{
			name: "ShouldHandleTCPServerWithTLS",
			servers: []schema.StoragePostgreSQLServer{
				{
					Address: mkAddress(t, "tcp://db1.example.com:5432"),
					TLS: &schema.TLS{
						MinimumVersion: schema.TLSVersion{Value: tls.VersionTLS12},
						MaximumVersion: schema.TLSVersion{Value: tls.VersionTLS13},
					},
				},
			},
			assert: func(t *testing.T, dsnConfig *pgx.ConnConfig) {
				require.Len(t, dsnConfig.Fallbacks, 1)
				require.NotNil(t, dsnConfig.Fallbacks[0].TLSConfig)
				assert.Equal(t, uint16(tls.VersionTLS12), dsnConfig.Fallbacks[0].TLSConfig.MinVersion)
				assert.Equal(t, uint16(tls.VersionTLS13), dsnConfig.Fallbacks[0].TLSConfig.MaxVersion)
			},
		},
		{
			name: "ShouldDefaultPortToFiveFourThreeTwoWhenZeroAndTCP",
			servers: []schema.StoragePostgreSQLServer{
				{Address: mkAddress(t, "tcp://db.example.com")},
			},
			assert: func(t *testing.T, dsnConfig *pgx.ConnConfig) {
				require.Len(t, dsnConfig.Fallbacks, 1)
				assert.Equal(t, "db.example.com", dsnConfig.Fallbacks[0].Host)
				assert.Equal(t, uint16(5432), dsnConfig.Fallbacks[0].Port)
			},
		},
		{
			name: "ShouldHandleUnixSocketServer",
			servers: []schema.StoragePostgreSQLServer{
				{Address: mkAddress(t, "unix:///var/run/postgresql")},
			},
			assert: func(t *testing.T, dsnConfig *pgx.ConnConfig) {
				require.Len(t, dsnConfig.Fallbacks, 1)
				assert.Equal(t, "/var/run/postgresql", dsnConfig.Fallbacks[0].Host)
				assert.Equal(t, uint16(5432), dsnConfig.Fallbacks[0].Port)
			},
		},
		{
			name: "ShouldHandleUnixSocketServerWithAbsolutePort",
			servers: []schema.StoragePostgreSQLServer{
				{Address: mkAddress(t, "unix:///tmp/.s.PGSQL.25432")},
			},
			assert: func(t *testing.T, dsnConfig *pgx.ConnConfig) {
				require.Len(t, dsnConfig.Fallbacks, 1)
				assert.Equal(t, "/tmp", dsnConfig.Fallbacks[0].Host)
				assert.Equal(t, uint16(25432), dsnConfig.Fallbacks[0].Port)
			},
		},
		{
			name: "ShouldHandleMixedTCPAndUnixSocketServers",
			servers: []schema.StoragePostgreSQLServer{
				{Address: mkAddress(t, "tcp://db.example.com:6543")},
				{Address: mkAddress(t, "unix:///var/run/postgresql")},
			},
			assert: func(t *testing.T, dsnConfig *pgx.ConnConfig) {
				require.Len(t, dsnConfig.Fallbacks, 2)
				assert.Equal(t, "db.example.com", dsnConfig.Fallbacks[0].Host)
				assert.Equal(t, uint16(6543), dsnConfig.Fallbacks[0].Port)
				assert.Equal(t, "/var/run/postgresql", dsnConfig.Fallbacks[1].Host)
				assert.Equal(t, uint16(5432), dsnConfig.Fallbacks[1].Port)
			},
		},
		{
			name: "ShouldHandleServerWithoutTLS",
			servers: []schema.StoragePostgreSQLServer{
				{Address: mkAddress(t, "tcp://db.example.com:5432")},
			},
			assert: func(t *testing.T, dsnConfig *pgx.ConnConfig) {
				require.Len(t, dsnConfig.Fallbacks, 1)
				assert.Nil(t, dsnConfig.Fallbacks[0].TLSConfig)
			},
		},
		{
			name: "ShouldOverwriteExistingFallbacks",
			existing: []*pgconn.FallbackConfig{
				{Host: "old1.example.com", Port: 1111},
				{Host: "old2.example.com", Port: 2222},
			},
			servers: []schema.StoragePostgreSQLServer{
				{Address: mkAddress(t, "tcp://db.example.com:5432")},
			},
			assert: func(t *testing.T, dsnConfig *pgx.ConnConfig) {
				require.Len(t, dsnConfig.Fallbacks, 1)
				assert.Equal(t, "db.example.com", dsnConfig.Fallbacks[0].Host)
				assert.Equal(t, uint16(5432), dsnConfig.Fallbacks[0].Port)
			},
		},
	}

	t.Parallel()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dsnConfig, err := pgx.ParseConfig("")
			require.NoError(t, err)

			if tc.existing != nil {
				dsnConfig.Fallbacks = tc.existing
			}

			config := &schema.StoragePostgreSQL{
				Servers: tc.servers,
			}

			dsnPostgreSQLFallbacks(config, x509.NewCertPool(), dsnConfig)

			tc.assert(t, dsnConfig)
		})
	}
}

func TestDSNConfigPostgreSQLHostPort(t *testing.T) {
	testCases := []struct {
		name      string
		have      string
		hexpected string
		pexpected uint16
	}{
		{
			"ShouldParseDirectoryDefaultPort",
			"unix:///tmp",
			"/tmp",
			5432,
		},
		{
			"ShouldParseURLPort",
			"unix://:255/tmp",
			"/tmp",
			255,
		},
		{
			"ShouldParseAbsolutePort",
			"unix:///tmp/.s.PGSQL.25432",
			"/tmp",
			25432,
		},
		{
			"ShouldParseAbsolutePortWithURLPort",
			"unix://:2455/tmp/.s.PGSQL.25432",
			"/tmp",
			25432,
		},
		{
			"ShouldParseAbsolutePortInvalidWithURLPort",
			"unix://:2455/tmp/.s.PGSQL.233335432",
			"/tmp/.s.PGSQL.233335432",
			2455,
		},
		{
			"ShouldParseAbsolutePortInvalid",
			"unix:///tmp/.s.PGSQL.233335432",
			"/tmp/.s.PGSQL.233335432",
			5432,
		},
	}

	t.Parallel()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			address, err := schema.NewAddress(tc.have)
			require.NotNil(t, address)
			require.NoError(t, err)

			host, port := dsnPostgreSQLHostPort(&schema.AddressTCP{Address: *address})
			assert.Equal(t, tc.hexpected, host)
			assert.Equal(t, tc.pexpected, port)
		})
	}
}

func TestNewPostgreSQLProviderShouldRebindAllQueries(t *testing.T) {
	address, err := schema.NewAddress("tcp://localhost:5432")
	require.NoError(t, err)

	provider, err := NewPostgreSQLProvider(&schema.Configuration{
		Storage: schema.Storage{
			EncryptionKey: "testing-key-only",
			PostgreSQL: &schema.StoragePostgreSQL{
				StorageSQL: schema.StorageSQL{
					Address: &schema.AddressTCP{Address: *address},
				},
			},
		},
	}, x509.NewCertPool())

	require.NoError(t, err)
	require.NotNil(t, provider)

	value := reflect.ValueOf(provider.SQLProvider)
	typed := value.Type()

	for i := range typed.NumField() {
		field := typed.Field(i)

		if field.Type.Kind() != reflect.String || !strings.HasPrefix(field.Name, "sql") {
			continue
		}

		query := value.Field(i).String()

		assert.NotEmpty(t, query, "field %s does not have a query assigned to it", field.Name)
		assert.NotContains(t, query, "?", "field %s contains a '?' placeholder which PostgreSQL does not support, it must either be rebound via (*sqlx.DB).Rebind or assigned a PostgreSQL specific query", field.Name)
	}
}

func mustGenerateTestCA(t *testing.T, serial *big.Int) (certificate *x509.Certificate, pemBytes []byte, key *ecdsa.PrivateKey) {
	t.Helper()

	var err error

	if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	var der []byte

	if der, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key); err != nil {
		t.Fatal(err)
	}

	if certificate, err = x509.ParseCertificate(der); err != nil {
		t.Fatal(err)
	}

	return certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key
}

func mustGenerateTestCertificate(t *testing.T, serial *big.Int, name string, usage x509.ExtKeyUsage, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (certificate *x509.Certificate, certificatePEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}

	var der []byte

	if der, err = x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey); err != nil {
		t.Fatal(err)
	}

	if certificate, err = x509.ParseCertificate(der); err != nil {
		t.Fatal(err)
	}

	var keyDER []byte

	if keyDER, err = x509.MarshalPKCS8PrivateKey(key); err != nil {
		t.Fatal(err)
	}

	return certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func writeTestPair(t *testing.T, directory, name string, certificatePEM, keyPEM []byte) (certificatePath, keyPath string) {
	t.Helper()

	certificatePath, keyPath = filepath.Join(directory, name+".crt"), filepath.Join(directory, name+".key")

	require.NoError(t, os.WriteFile(certificatePath, certificatePEM, 0600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0600))

	return certificatePath, keyPath
}

func handshakeClientCertificateSerial(t *testing.T, clientConfig, serverConfig *tls.Config) (serial *big.Int) {
	t.Helper()

	clientConnection, serverConnection := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server := tls.Server(serverConnection, serverConfig)
	serverErr := make(chan error, 1)

	go func() { serverErr <- server.HandshakeContext(ctx) }()

	client := tls.Client(clientConnection, clientConfig)

	require.NoError(t, client.HandshakeContext(ctx))
	require.NoError(t, <-serverErr)

	require.Len(t, server.ConnectionState().PeerCertificates, 1)

	return server.ConnectionState().PeerCertificates[0].SerialNumber
}

func TestPostgreSQLBeforeConnectReloadsCertificate(t *testing.T) {
	directory := t.TempDir()

	caOne, caOnePEM, caOneKey := mustGenerateTestCA(t, big.NewInt(1))
	require.NoError(t, os.WriteFile(filepath.Join(directory, "ca.pem"), caOnePEM, 0600))

	_, certificateOnePEM, keyOnePEM := mustGenerateTestCertificate(t, big.NewInt(2), "client", x509.ExtKeyUsageClientAuth, caOne, caOneKey)
	certificatePath, keyPath := writeTestPair(t, directory, "client", certificateOnePEM, keyOnePEM)

	config := &schema.StoragePostgreSQL{
		TLS: &schema.TLS{CertificateChainPath: certificatePath, PrivateKeyPath: keyPath, SkipVerify: true},
	}

	hook := newPostgreSQLBeforeConnect(config, directory, x509.NewCertPool())

	_, serverOnePEM, serverOneKeyPEM := mustGenerateTestCertificate(t, big.NewInt(3), "postgres", x509.ExtKeyUsageServerAuth, caOne, caOneKey)

	serverOnePair, err := tls.X509KeyPair(serverOnePEM, serverOneKeyPEM)
	require.NoError(t, err)

	connConfig, err := pgx.ParseConfig("")
	require.NoError(t, err)
	require.NoError(t, hook(context.Background(), connConfig))

	assert.Equal(t, big.NewInt(2), handshakeClientCertificateSerial(t, connConfig.TLSConfig, &tls.Config{
		Certificates: []tls.Certificate{serverOnePair},
		ClientAuth:   tls.RequireAnyClientCert,
	}))

	// A connection made after the pair and the CA are replaced uses the new certificate and trusts the new CA.
	caTwo, caTwoPEM, caTwoKey := mustGenerateTestCA(t, big.NewInt(4))
	require.NoError(t, os.WriteFile(filepath.Join(directory, "ca.pem"), caTwoPEM, 0600))

	_, certificateTwoPEM, keyTwoPEM := mustGenerateTestCertificate(t, big.NewInt(5), "client", x509.ExtKeyUsageClientAuth, caTwo, caTwoKey)
	require.NoError(t, os.WriteFile(certificatePath, certificateTwoPEM, 0600))
	require.NoError(t, os.WriteFile(keyPath, keyTwoPEM, 0600))

	serverTwo, serverTwoPEM, serverTwoKeyPEM := mustGenerateTestCertificate(t, big.NewInt(6), "postgres", x509.ExtKeyUsageServerAuth, caTwo, caTwoKey)

	serverTwoPair, err := tls.X509KeyPair(serverTwoPEM, serverTwoKeyPEM)
	require.NoError(t, err)

	nextConfig, err := pgx.ParseConfig("")
	require.NoError(t, err)
	require.NoError(t, hook(context.Background(), nextConfig))

	assert.Equal(t, big.NewInt(5), handshakeClientCertificateSerial(t, nextConfig.TLSConfig, &tls.Config{
		Certificates: []tls.Certificate{serverTwoPair},
		ClientAuth:   tls.RequireAnyClientCert,
	}))

	_, err = serverTwo.Verify(x509.VerifyOptions{Roots: nextConfig.TLSConfig.RootCAs, DNSName: "postgres"})
	assert.NoError(t, err)
}

func TestPostgreSQLBeforeConnectPreservesServerName(t *testing.T) {
	directory := t.TempDir()

	ca, caPEM, caKey := mustGenerateTestCA(t, big.NewInt(1))
	require.NoError(t, os.WriteFile(filepath.Join(directory, "ca.pem"), caPEM, 0600))

	_, certificatePEM, keyPEM := mustGenerateTestCertificate(t, big.NewInt(2), "client", x509.ExtKeyUsageClientAuth, ca, caKey)
	certificatePath, keyPath := writeTestPair(t, directory, "client", certificatePEM, keyPEM)

	config := &schema.StoragePostgreSQL{
		TLS: &schema.TLS{CertificateChainPath: certificatePath, PrivateKeyPath: keyPath},
	}

	hook := newPostgreSQLBeforeConnect(config, "", x509.NewCertPool())

	connConfig, err := pgx.ParseConfig("")
	require.NoError(t, err)

	connConfig.TLSConfig = &tls.Config{ServerName: "postgres.example"}

	require.NoError(t, hook(context.Background(), connConfig))
	assert.Equal(t, "postgres.example", connConfig.TLSConfig.ServerName)
}

func TestDSNPostgreSQLHasNoFallbackWithoutServers(t *testing.T) {
	address, err := schema.NewAddress("tcp://postgres.example:5432")
	require.NoError(t, err)

	config := &schema.StoragePostgreSQL{
		Address:  &schema.AddressTCP{Address: *address},
		Database: "authelia",
		Username: "authelia",
		TLS:      &schema.TLS{ServerName: "postgres.example"},
	}

	assert.Empty(t, dsnPostgreSQL(config, x509.NewCertPool()).Fallbacks)
}

func TestPostgreSQLTLSNeverFallsBackToPlaintext(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer listener.Close()

	received := make(chan []byte, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			received <- nil

			return
		}

		defer conn.Close()

		request := make([]byte, 8)

		if _, err = io.ReadFull(conn, request); err != nil {
			received <- nil

			return
		}

		// Refuse TLS as a server without TLS support does.
		_, _ = conn.Write([]byte{'N'})

		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

		remainder := make([]byte, 1)

		if n, _ := conn.Read(remainder); n != 0 {
			request = append(request, remainder...)
		}

		received <- request
	}()

	host, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)

	portNumber, err := strconv.ParseUint(port, 10, 16)
	require.NoError(t, err)

	config := &schema.StoragePostgreSQL{TLS: &schema.TLS{SkipVerify: true}}

	hook := newPostgreSQLBeforeConnect(config, "", x509.NewCertPool())

	connConfig, err := pgx.ParseConfig("")
	require.NoError(t, err)

	connConfig.Host, connConfig.Port = host, uint16(portNumber)
	connConfig.ConnectTimeout = time.Second

	require.NoError(t, hook(context.Background(), connConfig))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = pgx.ConnectConfig(ctx, connConfig)
	require.Error(t, err)

	// Only the SSLRequest arrives: a fallback to plaintext would also send a StartupMessage.
	assert.Len(t, <-received, 8)
}

type testPoolConnector struct{}

func (testPoolConnector) Connect(context.Context) (driver.Conn, error) { return testPoolConn{}, nil }
func (testPoolConnector) Driver() driver.Driver                        { return nil }

type testPoolConn struct{}

func (testPoolConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (testPoolConn) Close() error                        { return nil }
func (testPoolConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }

func TestSetPostgreSQLPoolLimits(t *testing.T) {
	testCases := []struct {
		name         string
		have         *schema.StoragePostgreSQL
		lifetimeShut bool
		idleShut     bool
	}{
		{
			"ShouldApplyLifetime",
			&schema.StoragePostgreSQL{
				StorageSQL:                schema.StorageSQL{TLS: &schema.TLS{CertificateChainPath: "/c.pem"}},
				MaximumConnectionLifetime: 20 * time.Millisecond,
				MaximumConnectionIdleTime: time.Hour,
			},
			true, false,
		},
		{
			"ShouldApplyIdleTime",
			&schema.StoragePostgreSQL{
				StorageSQL:                schema.StorageSQL{TLS: &schema.TLS{CertificateChainPath: "/c.pem"}},
				MaximumConnectionLifetime: time.Hour,
				MaximumConnectionIdleTime: 20 * time.Millisecond,
			},
			false, true,
		},
		{
			"ShouldNotApplyWithoutFilePair",
			&schema.StoragePostgreSQL{
				StorageSQL:                schema.StorageSQL{TLS: &schema.TLS{}},
				MaximumConnectionLifetime: 20 * time.Millisecond,
				MaximumConnectionIdleTime: 20 * time.Millisecond,
			},
			false, false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := sql.OpenDB(testPoolConnector{})

			defer db.Close()

			setPostgreSQLPoolLimits(db, tc.have)

			conn, err := db.Conn(context.Background())
			require.NoError(t, err)
			require.NoError(t, conn.Close())

			time.Sleep(1500 * time.Millisecond)

			conn, err = db.Conn(context.Background())
			require.NoError(t, err)
			require.NoError(t, conn.Close())

			stats := db.Stats()

			assert.Equal(t, tc.lifetimeShut, stats.MaxLifetimeClosed > 0)
			assert.Equal(t, tc.idleShut, stats.MaxIdleTimeClosed > 0)
		})
	}
}
