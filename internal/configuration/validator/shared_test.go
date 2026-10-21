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
	var (
		config, configDefault *schema.TLS
	)

	configDefault = &schema.TLS{}

	certificatePath, keyPath := "../test_resources/crypto/rsa.2048.crt", "../test_resources/crypto/rsa.2048.pem"

	config = &schema.TLS{CertificateChainFile: certificatePath}

	assert.EqualError(t, ValidateTLSConfig(config, configDefault),
		"option 'certificate_chain_file' is invalid: it must be used with 'private_key_file'")

	config = &schema.TLS{CertificateChainFile: certificatePath, PrivateKeyFile: keyPath}

	assert.NoError(t, ValidateTLSConfig(config, configDefault))

	config = &schema.TLS{CertificateChain: certRSA4096, CertificateChainFile: certificatePath, PrivateKeyFile: keyPath}

	assert.EqualError(t, ValidateTLSConfig(config, configDefault),
		"option 'certificate_chain_file' is invalid: it cannot be used in addition to 'certificate_chain'")

	config = &schema.TLS{PrivateKey: keyRSA2048, CertificateChainFile: certificatePath, PrivateKeyFile: keyPath}

	assert.EqualError(t, ValidateTLSConfig(config, configDefault),
		"option 'private_key_file' is invalid: it cannot be used in addition to 'private_key'")

	config = &schema.TLS{CertificateChainFile: "../test_resources/crypto/does.not.exist.crt", PrivateKeyFile: keyPath}

	assert.ErrorContains(t, ValidateTLSConfig(config, configDefault), "option 'certificate_chain_file' is invalid: the certificate pair could not be loaded")
}
