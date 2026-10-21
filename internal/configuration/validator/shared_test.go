// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

func TestValidateTLSConfig(t *testing.T) {
	var (
		config, configDefault *schema.TLS
	)

	assert.EqualError(t, ValidateTLSConfig(config, configDefault), "must provide configDefault")

	configDefault = &schema.TLS{}

	assert.NoError(t, ValidateTLSConfig(config, configDefault))

	config = &schema.TLS{}

	assert.NoError(t, ValidateTLSConfig(config, configDefault))

	config.PrivateKey = keyRSA2048
	config.CertificateChain = certRSA4096

	assert.EqualError(t, ValidateTLSConfig(config, configDefault), "option 'certificate_chain' is invalid: provided certificate chain does not contain the public key for the private key provided")
}

func TestValidateTLSConfigFiles(t *testing.T) {
	configDefault := &schema.TLS{}

	assert.EqualError(t, ValidateTLSConfig(&schema.TLS{CertificateChainFile: "/a/cert.pem"}, configDefault),
		"option 'certificate_chain_file' is invalid: it must be used with 'private_key_file'")

	assert.NoError(t, ValidateTLSConfig(&schema.TLS{CertificateChainFile: "/a/cert.pem", PrivateKeyFile: "/a/key.pem"}, configDefault))

	assert.EqualError(t, ValidateTLSConfig(&schema.TLS{CertificateChain: certRSA4096, CertificateChainFile: "/a/cert.pem", PrivateKeyFile: "/a/key.pem"}, configDefault),
		"option 'certificate_chain_file' is invalid: it cannot be used in addition to 'certificate_chain'")

	assert.EqualError(t, ValidateTLSConfig(&schema.TLS{PrivateKey: keyRSA2048, CertificateChainFile: "/a/cert.pem", PrivateKeyFile: "/a/key.pem"}, configDefault),
		"option 'private_key_file' is invalid: it cannot be used in addition to 'private_key'")
}
