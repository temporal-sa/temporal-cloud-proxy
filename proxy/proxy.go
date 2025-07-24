package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
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
	"temporal-sa/temporal-cloud-proxy/crypto"
	"temporal-sa/temporal-cloud-proxy/metrics"
	"time"
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

func newProxyProvider(configProvider config.ConfigProvider, logger *zap.Logger, authFactory auth.AuthenticatorFactory) ProxyProvider {
	proxy := &proxyServer{
		connectionMux: make(map[string]MuxConnection),
		logger:        logger,
	}

	var cachingConfig *crypto.CachingConfig

	providerCacheCfg := configProvider.GetProxyConfig().Encryption.Caching
	if providerCacheCfg.MaxCache > 0 || providerCacheCfg.MaxAge != "" || providerCacheCfg.MaxUsage > 0 {
		cachingConfig = &crypto.CachingConfig{
			MaxCache:        providerCacheCfg.MaxCache,
			MaxMessagesUsed: providerCacheCfg.MaxUsage,
		}
		if providerCacheCfg.MaxAge != "" {
			if duration, err := time.ParseDuration(providerCacheCfg.MaxAge); err == nil {
				cachingConfig.MaxAge = duration
			}
		}
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
			logger.Fatal("workload already exists", zap.String("workload-id", w.WorkloadId))
		}

		// only support one type of namespace auth
		if w.TemporalCloud.Authentication.ApiKey != nil && w.TemporalCloud.Authentication.TLS != nil {
			logger.Fatal("cannot have both api key and mtls authentication configured on a single workload",
				zap.String("workload-id", w.WorkloadId))
		}

		nsConn := &namespaceConnection{}

		authenticator, err := authFactory.NewAuthenticator(*w.Authentication)
		if err != nil {
			logger.Fatal("failed to create authenticator", zap.Error(err))
		}
		nsConn.auth = &authenticator

		//
		// -----------------
		var grpcInterceptors []grpc.UnaryClientInterceptor

		// configure payload encryption
		kmsClient := createKMSClient()

		codecContext := map[string]string{
			"namespace": w.TemporalCloud.Namespace,
		}

		// configure metrics handler
		metricsHandler := metrics.NewMetricsHandler(metrics.MetricsHandlerOptions{
			// Todo: do we need these many attributes?
			InitialAttributes: attribute.NewSet(
				attribute.String("workload_id", w.WorkloadId),
				attribute.String("namespace", w.TemporalCloud.Namespace),
				attribute.String("host_port", w.TemporalCloud.HostPort),
				attribute.String("auth_type", w.Authentication.Type),
				attribute.String("encryption_key", w.EncryptionKey),
			),
		})

		clientInterceptor, err := converter.NewPayloadCodecGRPCClientInterceptor(
			converter.PayloadCodecGRPCClientInterceptorOptions{
				Codecs: []converter.PayloadCodec{codec.NewEncryptionCodecWithCaching(
					kmsClient,
					codecContext,
					w.EncryptionKey,
					metricsHandler,
					cachingConfig,
				)},
			},
		)
		if err != nil {
			logger.Fatal("failed to create client interceptor",
				zap.String("workload-id", w.WorkloadId), zap.Error(err))
		}
		grpcInterceptors = append(grpcInterceptors, clientInterceptor)

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

// createKMSClient creates an AWS KMS client
func createKMSClient() *kms.KMS {
	// Use the region from parameter or environment variable
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-west-2" // Default region
	}

	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(region),
	}))

	return kms.New(sess)
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
	} else {
		//
		//	Configure mTLS auth
		//
		cert, err := tls.LoadX509KeyPair(workloadConfig.TemporalCloud.Authentication.TLS.CertFile,
			workloadConfig.TemporalCloud.Authentication.TLS.KeyFile)
		if err != nil {
			return nil, nil, err
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
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
	)
	
	return namespace.GetConnection().Invoke(ctx, method, args, reply, opts...)
}

// NewStream implements the grpc.ClientConnInterface NewStream method
func (p *proxyServer) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, status.Error(codes.Unimplemented, "streams not supported")
}
