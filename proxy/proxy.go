package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"go.opentelemetry.io/otel/attribute"
	"go.temporal.io/sdk/converter"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"os"
	"sync"
	"temporal-sa/temporal-cloud-proxy/auth"
	"temporal-sa/temporal-cloud-proxy/codec"
	"temporal-sa/temporal-cloud-proxy/config"
	"temporal-sa/temporal-cloud-proxy/metrics"
)

type (
	ProxyProvider interface {
		GetConnectionMux() grpc.ClientConnInterface
		Start() error
		Stop() error
	}

	MuxConnection interface {
		GetConnection() grpc.ClientConnInterface
		GetAuthenticator() auth.Authenticator
		Close() error
	}

	proxyServer struct {
		grpc.ClientConnInterface
		connectionMux map[string]MuxConnection
		mu            sync.RWMutex
		logger        *zap.Logger
	}

	namespaceConnection struct {
		conn *grpc.ClientConn
		auth *auth.Authenticator
	}
)

func newProxyProvider(configProvider config.ConfigProvider, logger *zap.Logger,
	authFactory auth.AuthenticatorFactory, codecFactory codec.EncryptionCodecFactory) ProxyProvider {
	proxy := &proxyServer{
		connectionMux: make(map[string]MuxConnection),
		logger:        logger,
	}

	for _, w := range configProvider.GetProxyConfig().Workloads {
		logger.Debug("adding namespace connection",
			zap.String("workload-id", w.WorkloadId),
			zap.String("namespace", w.TemporalCloud.Namespace),
		)
		proxy.mu.RLock()
		_, exists := proxy.connectionMux[w.WorkloadId]
		proxy.mu.RUnlock()
		if exists {
			// TODO: validation should be done in the config provider
			logger.Fatal("workload already exists", zap.String("workload-id", w.WorkloadId))
		}

		// only support one type of namespace auth
		// TODO: validation should be done in the config provider
		if w.TemporalCloud.Authentication.ApiKey != nil && w.TemporalCloud.Authentication.TLS != nil {
			logger.Fatal("cannot have both api key and mtls authentication configured on a single workload",
				zap.String("workload-id", w.WorkloadId))
		}

		nsConn := &namespaceConnection{}

		// configure worker auth
		if w.Authentication == nil {
			logger.Warn("workload configured without worker authentication",
				zap.String("workload-id", w.WorkloadId))
		}
		if w.Authentication != nil {
			authenticator, err := authFactory.NewAuthenticator(*w.Authentication)
			if err != nil {
				logger.Fatal("failed to create authenticator",
					zap.String("workload-id", w.WorkloadId), zap.Error(err))
			}
			nsConn.auth = &authenticator
		}

		var grpcInterceptors []grpc.UnaryClientInterceptor

		codecContext := map[string]string{
			"namespace": w.TemporalCloud.Namespace,
		}

		// configure encryption/decryption codec
		// configure encryption metrics handler
		metricsHandler := metrics.NewMetricsHandler(metrics.MetricsHandlerOptions{
			// Todo: do we need these many attributes?
			InitialAttributes: attribute.NewSet(
				attribute.String("workload_id", w.WorkloadId),
				attribute.String("namespace", w.TemporalCloud.Namespace),
				attribute.String("host_port", w.TemporalCloud.HostPort),
				//attribute.String("auth_type", w.Authentication.Type),
				//attribute.String("encryption_key", w.EncryptionKey),
			),
		})

		if w.Encryption == nil {
			logger.Warn("workload configured without payload encryption",
				zap.String("workload-id", w.WorkloadId))
		}
		if w.Encryption != nil {
			encryptionCodec, err := codecFactory.NewEncryptionCodec(codec.EncryptionCodecOptions{
				LocalEncryptionConfig: *w.Encryption,
				CodecContext:          codecContext,
				MetricsHandler:        &metricsHandler,
			})
			if err != nil {
				logger.Fatal("failed to create encryption codec",
					zap.String("workload-id", w.WorkloadId), zap.Error(err))
			}

			if encryptionCodec != nil {
				encryptionInterceptor, err := converter.NewPayloadCodecGRPCClientInterceptor(
					converter.PayloadCodecGRPCClientInterceptorOptions{
						Codecs: []converter.PayloadCodec{encryptionCodec},
					},
				)
				if err != nil {
					logger.Fatal("failed to create client interceptor",
						zap.String("workload-id", w.WorkloadId), zap.Error(err))
				}
				if encryptionInterceptor != nil {
					grpcInterceptors = append(grpcInterceptors, encryptionInterceptor)
				}
			}
		}

		// set api key or mTLS auth on the namesapce connection
		tlsConfig, authInterceptor, err := setNamespaceAuth(w, logger)
		if err != nil {
			logger.Fatal("failed to set namespace auth", zap.Error(err))
		}
		if authInterceptor != nil {
			grpcInterceptors = append(grpcInterceptors, authInterceptor)
		}

		conn, err := grpc.NewClient(
			w.TemporalCloud.HostPort,
			grpc.WithTransportCredentials(credentials.NewTLS(
				tlsConfig,
			)),
			grpc.WithChainUnaryInterceptor(grpcInterceptors...),
		)
		if err != nil {
			logger.Fatal("failed to create grpc client",
				zap.String("workload-id", w.WorkloadId), zap.Error(err))
		}

		nsConn.conn = conn

		proxy.mu.Lock()
		proxy.connectionMux[w.WorkloadId] = nsConn
		proxy.mu.Unlock()
	}

	return proxy
}

func (n *namespaceConnection) GetConnection() grpc.ClientConnInterface {
	return n.conn
}

func (n *namespaceConnection) GetAuthenticator() auth.Authenticator {
	if n.auth == nil {
		return nil
	}
	return *n.auth
}

func (n *namespaceConnection) Close() error {
	// TODO don't be lazy, close authenticator too if this fails
	if err := n.conn.Close(); err != nil {
		return err
	}
	if n.auth != nil {
		if err := n.GetAuthenticator().Close(); err != nil {
			return err
		}
	}

	return nil
}

func (p *proxyServer) GetConnectionMux() grpc.ClientConnInterface {
	return p
}

func (p *proxyServer) Start() error {
	return nil
}

func (p *proxyServer) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var errs []error

	for _, conn := range p.connectionMux {
		if err := conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func setNamespaceAuth(workloadConfig config.WorkloadConfig, logger *zap.Logger) (*tls.Config, grpc.UnaryClientInterceptor, error) {
	tlsConfig := &tls.Config{}
	var grpcInterceptor grpc.UnaryClientInterceptor

	if apiKeyConfig := workloadConfig.TemporalCloud.Authentication.ApiKey; apiKeyConfig != nil {
		//
		//	Configure API key auth
		//
		if apiKeyConfig.Value != "" && apiKeyConfig.EnvVar != "" {
			logger.Warn("multiple values provided for api key, using value",
				zap.String("workload-id", workloadConfig.WorkloadId))
		}

		apiKey := ""
		if apiKeyConfig.Value != "" {
			apiKey = apiKeyConfig.Value
		} else if apiKeyConfig.EnvVar != "" {
			apiKey = os.Getenv(apiKeyConfig.EnvVar)
		}

		if apiKey == "" {
			return nil, nil, fmt.Errorf("no api key provided")
		}

		grpcInterceptor =
			func(ctx context.Context, method string, req any, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
				md, ok := metadata.FromIncomingContext(ctx)

				if ok {
					md = md.Copy()
					md.Delete("authorization")
					md.Delete("temporal-namespace")

					ctx = metadata.NewOutgoingContext(ctx, md)
					ctx = metadata.AppendToOutgoingContext(ctx, "temporal-namespace", workloadConfig.TemporalCloud.Namespace)
					ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+apiKey)
				}

				return invoker(ctx, method, req, reply, cc, opts...)
			}
	} else if workloadConfig.TemporalCloud.Authentication.TLS != nil {
		//
		//	Configure mTLS auth
		//
		cert, err := tls.LoadX509KeyPair(workloadConfig.TemporalCloud.Authentication.TLS.CertFile,
			workloadConfig.TemporalCloud.Authentication.TLS.KeyFile)
		if err != nil {
			return nil, nil, err
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	} else {
		// Passthrough. Useful if the client/worker is setting the API. Note: will not work with
		// mTLS configured at the client/worker.
	}

	return tlsConfig, grpcInterceptor, nil
}

// Invoke implements the grpc.ClientConnInterface Invoke method
func (p *proxyServer) Invoke(ctx context.Context, method string, args interface{}, reply interface{}, opts ...grpc.CallOption) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Errorf(codes.InvalidArgument, "unable to read metadata")
	}

	workloadId := md.Get("workload-id")

	if len(workloadId) <= 0 {
		return status.Error(codes.InvalidArgument, "metadata missing workload-id")
	}
	if len(workloadId) != 1 {
		return status.Error(codes.InvalidArgument, "metadata contains multiple workload-id entries")
	}

	p.mu.RLock()
	namespace, exists := p.connectionMux[workloadId[0]]
	p.mu.RUnlock()

	if !exists {
		return status.Errorf(codes.InvalidArgument, "invalid workload-id: %s", workloadId[0])
	}

	if namespace.GetAuthenticator() != nil {
		authorization := md.Get("authorization")

		if len(authorization) < 1 {
			return status.Error(codes.InvalidArgument, "metadata is missing authorization")
		} else if len(authorization) > 1 {
			return status.Error(codes.InvalidArgument, "metadata contains multiple authorization entries")
		}

		result, err := namespace.GetAuthenticator().Authenticate(ctx, authorization[0])
		if err != nil {
			return status.Errorf(codes.Unknown, "failed to authenticate: %s", err)
		}
		if !result.Authenticated {
			return status.Errorf(codes.Unauthenticated, "invalid token")
		}
	}

	p.logger.Debug("invoking method",
		zap.String("workload-id", workloadId[0]),
		zap.String("method", method),
		zap.Any("args", args),
		zap.Any("md", md),
	)

	return namespace.GetConnection().Invoke(ctx, method, args, reply, opts...)
}

// NewStream implements the grpc.ClientConnInterface NewStream method
func (p *proxyServer) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, status.Error(codes.Unimplemented, "streams not supported")
}
