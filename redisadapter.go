// This file contains code used to interact with Redis in Fabriktor.
// It follows the port and adapter approach.
// Fabriktor has since discarded this code because mutual TLS is not required,
// but this adapter implements mutual TLS.
package redisadapter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"fmt"

	"github.com/redis/go-redis/v9"
	"gitlab.com/fabriktor/billable/config"
	"gitlab.com/fabriktor/billable/interface/util"
	"gitlab.com/fruitygo/gojuice/juice/logjuice"
)

type Adapter struct {
	logger    util.LoggerPort
	FS        embed.FS
	redisHost string
	cfg       RedisClientConfig
	client    *redis.Client
}

// RedisClientConfig represents the configuration for the Redis client.
type RedisClientConfig struct {
	Password string
	Socket   Socket
}

// Socket represents the configuration for the Redis socket.
//
// Fields:
// - Port: The port number for the Redis connection. This is required.
// - MutualTLS: A boolean flag indicating whether mutual TLS is required for the connection.
//   - To disable mutual TLS, set this to `false`. No certificates will be needed.
//   - If `true`, the Cert, Key, and CA fields must be set for mutual TLS.
//
// - Cert: Path to the client certificate file (only required when MutualTLS is `true`).
// - Key: Path to the client key file (only required when MutualTLS is `true`).
// - CA: Path to the certificate authority file (only required when MutualTLS is `true`).
//
// Example: To connect without mutual TLS, set MutualTLS to `false` and leave the Cert, Key, and CA fields empty.
type Socket struct {
	Port      int    // Redis port number (required)
	MutualTLS bool   // Enable mutual TLS (set to `false` if TLS is not required)
	Cert      string // Client certificate file path (required only if MutualTLS is `true`)
	Key       string // Client key file path (required only if MutualTLS is `true`)
	CA        string // CA file path (required only if MutualTLS is `true`)
}

// GetClient returns the Redis client.
func (a *Adapter) GetClient() *redis.Client {
	return a.client
}

// SetClient sets the Redis client in the adapter.
func (a *Adapter) SetClient(ctx context.Context) error {
	if a.client != nil {
		return nil
	}

	// Validate required config values.
	if a.redisHost == "" || a.cfg.Socket.Port == 0 {
		return fmt.Errorf("Redis host and port must be set")
	}

	// Build Redis options.
	options := &redis.Options{
		Addr:     a.redisHost + ":" + fmt.Sprint(a.cfg.Socket.Port),
		DB:       0,
		Password: a.cfg.Password,
		Username: config.RedisUsername,
	}

	// Retrieve mutual TLS config.
	if a.cfg.Socket.TLS {
		tlsConfig, err := a.getTLSConfig()
		if err != nil {
			return err
		}

		options.TLSConfig = tlsConfig
	}

	// Set the Redis client in the adapter.
	a.client = redis.NewClient(options)

	// Attempt to ping the Redis server.
	_, err := a.client.Ping(ctx).Result()
	if err != nil {
		return err
	}

	a.logger.SLog(ctx, logjuice.Info, "📌", "Connected to Redis")

	return nil
}

// getTLSConfig returns the TLS configuration.
func (a *Adapter) getTLSConfig() (*tls.Config, error) {
	// Read the certificate file from the embedded file system.
	certData, err := a.FS.ReadFile(a.cfg.Socket.Cert)
	if err != nil {
		return nil, err
	}

	// Read the key file from the embedded file system.
	keyData, err := a.FS.ReadFile(a.cfg.Socket.Key)
	if err != nil {
		return nil, err
	}

	// Create a certificate pair from the cert and key data.
	cert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return nil, err
	}

	// Load CA certificate.
	caCert, err := a.FS.ReadFile(a.cfg.Socket.CA)
	if err != nil {
		return nil, err
	}

	// Create a CertPool from the CA certificate.
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// Close closes the Redis client.
func (a *Adapter) Close(ctx context.Context) error {
	if a.client == nil {
		return nil
	}

	// Attempt to ping the Redis server before closing the client.
	_, err := a.client.Ping(ctx).Result()
	if err != nil {
		return err
	}

	// Close the client.
	if err := a.client.Close(); err != nil {
		return err
	}

	a.logger.SLog(ctx, logjuice.Info, "📌", "Disconnected from Redis")

	return nil
}
