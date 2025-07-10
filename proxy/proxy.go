package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"go.temporal.io/sdk/converter"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"os"
	"sync"
	"temporal-sa/temporal-cloud-proxy/auth"
	"temporal-sa/temporal-cloud-proxy/codec"
	"temporal-sa/temporal-cloud-proxy/crypto"
	"temporal-sa/temporal-cloud-proxy/metrics"
	"temporal-sa/temporal-cloud-proxy/utils"
)

type Conn struct {
	mu        sync.RWMutex
	namespace map[string]NamespaceConn
}

type NamespaceConn struct {
	conn        *grpc.ClientConn
	authManager *auth.AuthManager
	authType    string
}

func NewConn() *Conn {
	return &Conn{
		namespace: make(map[string]NamespaceConn),
	}
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

// AddConnInput contains parameters for adding a new connection
type AddConnInput struct {
	Workload            *utils.WorkloadConfig
	AuthManager         *auth.AuthManager
	AuthType            string
	MetricsHandler      metrics.MetricsHandler
	CryptoCachingConfig *crypto.CachingConfig
}

// AddConn adds a new connection to the proxy
func (mc *Conn) AddConn(input AddConnInput) error {
	fmt.Printf("Adding connection id: %s namespace: %s hostport: %s\n",
		input.Workload.WorkloadId, input.Workload.TemporalCloud.Namespace, input.Workload.TemporalCloud.HostPort)

	mc.mu.RLock()
	_, exists := mc.namespace[input.Workload.WorkloadId]
	mc.mu.RUnlock()
	if exists {
		return fmt.Errorf("workload-id %s already exists", input.Workload.WorkloadId)
	}

	if input.Workload.TemporalCloud.Authentication.ApiKey != nil && input.Workload.TemporalCloud.Authentication.TLS != nil {
		return fmt.Errorf("%s: cannot have both api key and mtls authentication configured on a single workload",
			input.Workload.WorkloadId)
	}

	//Initialize AWS KMS client
	kmsClient := createKMSClient()

	codecContext := map[string]string{
		"namespace": input.Workload.TemporalCloud.Namespace,
	}

	clientInterceptor, err := converter.NewPayloadCodecGRPCClientInterceptor(
		converter.PayloadCodecGRPCClientInterceptorOptions{
			Codecs: []converter.PayloadCodec{codec.NewEncryptionCodecWithCaching(
				kmsClient,
				codecContext,
				input.Workload.EncryptionKey,
				input.MetricsHandler,
				input.CryptoCachingConfig,
			)},
		},
	)
	if err != nil {
		return err
	}

	tlsConfig := tls.Config{}

	grpcInterceptors := []grpc.UnaryClientInterceptor{
		clientInterceptor,
	}

	if apiKeyConfig := input.Workload.TemporalCloud.Authentication.ApiKey; apiKeyConfig != nil {
		if apiKeyConfig.Value != "" && apiKeyConfig.EnvVar != "" {
			// TODO proper logging
			fmt.Printf("WARN - multiple values provided for api key, using value. workload-id: %s\n", input.Workload.WorkloadId)
		}

		apiKey := ""
		if apiKeyConfig.Value != "" {
			apiKey = apiKeyConfig.Value
		} else if apiKeyConfig.EnvVar != "" {
			apiKey = os.Getenv(apiKeyConfig.EnvVar)
		}

		if apiKey == "" {
			return fmt.Errorf("%s: no api key provided", input.Workload.WorkloadId)
		}

		grpcInterceptors = append(grpcInterceptors,
			func(ctx context.Context, method string, req any, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
				md, ok := metadata.FromIncomingContext(ctx)

				if ok {
					md = md.Copy()
					md.Delete("authorization")
					md.Delete("temporal-namespace")

					ctx = metadata.NewOutgoingContext(ctx, md)
					ctx = metadata.AppendToOutgoingContext(ctx, "temporal-namespace", input.Workload.TemporalCloud.Namespace)
					ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+apiKey)
				}

				return invoker(ctx, method, req, reply, cc, opts...)
			})
	} else {
		cert, err := tls.LoadX509KeyPair(input.Workload.TemporalCloud.Authentication.TLS.CertFile,
			input.Workload.TemporalCloud.Authentication.TLS.KeyFile)
		if err != nil {
			return err
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	conn, err := grpc.NewClient(
		input.Workload.TemporalCloud.HostPort,
		grpc.WithTransportCredentials(credentials.NewTLS(
			&tlsConfig,
		)),
		grpc.WithChainUnaryInterceptor(grpcInterceptors...),
	)
	if err != nil {
		return err
	}

	mc.mu.Lock()
	mc.namespace[input.Workload.WorkloadId] = NamespaceConn{
		conn:        conn,
		authManager: input.AuthManager,
		authType:    input.AuthType,
	}
	mc.mu.Unlock()

	return nil
}

// CloseAll closes all connections
func (mc *Conn) CloseAll() error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	var errs []error

	for _, namespace := range mc.namespace {
		if err := namespace.conn.Close(); err != nil {
			errs = append(errs, err)
		}
		if namespace.authManager != nil {
			if err := namespace.authManager.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}

	return errors.Join(errs...)
}

// Invoke implements the grpc.ClientConnInterface Invoke method
func (mc *Conn) Invoke(ctx context.Context, method string, args interface{}, reply interface{}, opts ...grpc.CallOption) error {
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

	mc.mu.RLock()
	namespace, exists := mc.namespace[workloadId[0]]
	mc.mu.RUnlock()

	if !exists {
		return status.Errorf(codes.InvalidArgument, "invalid workload-id: %s", workloadId[0])
	}

	if namespace.authManager != nil {
		authorization := md.Get("authorization")

		if len(authorization) < 1 {
			return status.Error(codes.InvalidArgument, "metadata is missing authorization")
		} else if len(authorization) > 1 {
			return status.Error(codes.InvalidArgument, "metadata contains multiple authorization entries")
		}

		result, err := namespace.authManager.Authenticate(ctx, namespace.authType, authorization[0])
		if err != nil {
			return status.Errorf(codes.Unknown, "failed to authenticate: %s", err)
		}
		if !result.Authenticated {
			return status.Errorf(codes.Unauthenticated, "invalid token")
		}
	}

	return namespace.conn.Invoke(ctx, method, args, reply, opts...)
}

// NewStream implements the grpc.ClientConnInterface NewStream method
func (mc *Conn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, status.Error(codes.Unimplemented, "streams not supported")
}
