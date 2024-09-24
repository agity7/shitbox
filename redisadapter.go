// This file contains code used to interact with Redis in Fabriktor.
// It follows the port and adapter approach.
package redis

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

// ------------------------------
// TYPES
// ------------------------------

type Adapter struct {
	logger    util.LoggerPort
	FS        embed.FS
	redisHost string
	client    *redis.Client
	cfg       RedisClientConfig
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
// - UseTLS: A boolean flag indicating whether TLS is required for the connection.
//   - Set this to `true` to enable TLS. This will configure the client to use TLS when connecting to Redis.
//   - If `false`, no TLS will be used.
//
// - MutualTLS: A boolean flag indicating whether mutual TLS is required for the connection.
//   - If `true`, both the client and server will authenticate each other using certificates.
//   - If `false`, only server-side TLS will be used (client will verify the server certificate but won't send its own).
//
// - Cert: Path to the client certificate file (only required when MutualTLS is `true`).
// - Key: Path to the client key file (only required when MutualTLS is `true`).
// - CA: Path to the certificate authority file (required if MutualTLS is `true`).
//
// Example:
// - To connect using TLS but without mutual authentication, set `UseTLS` to `true` and `MutualTLS` to `false`.
// - To connect without any TLS, set `UseTLS` to `false`.
type Socket struct {
	Cert      string
	Key       string
	CA        string
	Port      int
	UseTLS    bool
	MutualTLS bool
}

// ------------------------------
// FUNCS
// ------------------------------

func NewAdapter(l util.LoggerPort, FS embed.FS, host string, cfg RedisClientConfig) *Adapter {
	return &Adapter{
		logger:    l,
		FS:        FS,
		redisHost: host,
		cfg:       cfg,
		client:    nil,
	}
}

// ------------------------------
// METHODS
// ------------------------------

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
		return fmt.Errorf("redis host and port must be set")
	}

	// Build Redis options.
	options := &redis.Options{
		Addr:     a.redisHost + ":" + fmt.Sprint(a.cfg.Socket.Port),
		DB:       0,
		Password: a.cfg.Password,
		Username: config.RedisUsername,
	}

	// Configure TLS if UseTLS is enabled.
	if a.cfg.Socket.UseTLS {
		if a.cfg.Socket.MutualTLS {
			tlsConfig, err := a.getMutualTLSConfig()
			if err != nil {
				return err
			}

			options.TLSConfig = tlsConfig
		} else {
			// Use regular TLS without client certs (server cert only).
			options.TLSConfig = &tls.Config{
				InsecureSkipVerify: false,
				MinVersion:         tls.VersionTLS12,
			}
		}
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

// getMutualTLSConfig returns the TLS configuration for mutual TLS.
func (a *Adapter) getMutualTLSConfig() (*tls.Config, error) {
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

	// Close the client.
	if err := a.client.Close(); err != nil {
		return err
	}

	a.logger.SLog(ctx, logjuice.Info, "📌", "Disconnected from Redis")

	return nil
}
