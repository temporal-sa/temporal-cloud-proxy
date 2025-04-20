package main

import (
	"context"
	"crypto/tls"
	"errors"

	"go.temporal.io/sdk/converter"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type ProxyConn struct {
	conns map[string]*grpc.ClientConn
}

func NewProxyConn() *ProxyConn {
	return &ProxyConn{
		conns: make(map[string]*grpc.ClientConn),
	}
}

// TODO: thread safety
func (mc *ProxyConn) AddConn(source, target, tlsCertPath, tlsKeyPath, encrpytionKey string) error {
	cert, err := tls.LoadX509KeyPair(tlsCertPath, tlsKeyPath)
	if err != nil {
		return err
	}

	clientInterceptor, err := converter.NewPayloadCodecGRPCClientInterceptor(
		converter.PayloadCodecGRPCClientInterceptorOptions{
			Codecs: []converter.PayloadCodec{NewEncryptionCodec(encrpytionKey)},
		},
	)
	if err != nil {
		return err
	}

	conn, err := grpc.NewClient(
		target,
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

	mc.conns[source] = conn

	return nil
}

func (mc *ProxyConn) CloseAll() error {
	var errs []error

	for _, conn := range mc.conns {
		if err := conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// TODO: thread safety
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
	if mc.conns[target[0]] == nil {
		return status.Errorf(codes.Unavailable, "invalid target: %s", target[0])
	}

	conn := mc.conns[target[0]]

	return conn.Invoke(ctx, method, args, reply, opts...)
}

func (mc *ProxyConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, status.Error(codes.Unimplemented, "streams not supported")
}
