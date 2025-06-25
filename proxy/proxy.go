package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"

	"temporal-sa/temporal-cloud-proxy/codec"

	"go.temporal.io/sdk/converter"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type ProxyConn struct {
	mu    sync.RWMutex
	conns map[string]*grpc.ClientConn
}

func NewProxyConn() *ProxyConn {
	return &ProxyConn{
		conns: make(map[string]*grpc.ClientConn),
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
	Source          string
	Target          string
	TLSCertPath     string
	TLSKeyPath      string
	EncryptionKeyID string
	Namespace       string
}

// AddConn adds a new connection to the proxy
func (mc *ProxyConn) AddConn(input AddConnInput) error {
	fmt.Println("Adding connection from", input.Source, "to", input.Target)

	cert, err := tls.LoadX509KeyPair(input.TLSCertPath, input.TLSKeyPath)
	if err != nil {
		return err
	}

	// Initialize AWS KMS client
	kmsClient := createKMSClient()

	codecContext := map[string]string{
		"namespace": input.Namespace,
	}

	clientInterceptor, err := converter.NewPayloadCodecGRPCClientInterceptor(
		converter.PayloadCodecGRPCClientInterceptorOptions{
			Codecs: []converter.PayloadCodec{codec.NewEncryptionCodec(kmsClient, codecContext, input.EncryptionKeyID)},
		},
	)
	if err != nil {
		return err
	}

	conn, err := grpc.NewClient(
		input.Target,
		grpc.WithTransportCredentials(credentials.NewTLS(
			&tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		)),
		grpc.WithUnaryInterceptor(clientInterceptor),
	)
	if err != nil {
		return err
	}

	mc.mu.Lock()
	mc.conns[input.Source] = conn
	mc.mu.Unlock()

	return nil
}

// CloseAll closes all connections
func (mc *ProxyConn) CloseAll() error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	var errs []error

	for _, conn := range mc.conns {
		if err := conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// Invoke implements the grpc.ClientConnInterface Invoke method
func (mc *ProxyConn) Invoke(ctx context.Context, method string, args interface{}, reply interface{}, opts ...grpc.CallOption) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Errorf(codes.InvalidArgument, "unable to read metadata")
	}

	target := md.Get(":authority")

	if len(target) <= 0 {
		return status.Error(codes.InvalidArgument, "metadata missing :authority")
	}
	if len(target) != 1 {
		return status.Error(codes.InvalidArgument, "metadata contains multiple :authority entries")
	}

	mc.mu.RLock()
	conn, exists := mc.conns[target[0]]
	mc.mu.RUnlock()

	if !exists {
		return status.Errorf(codes.Unavailable, "invalid target: %s", target[0])
	}

	return conn.Invoke(ctx, method, args, reply, opts...)
}

// NewStream implements the grpc.ClientConnInterface NewStream method
func (mc *ProxyConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, status.Error(codes.Unimplemented, "streams not supported")
}
