package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"

	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"google.golang.org/grpc"
)

var portFlag int

func init() {
	flag.IntVar(&portFlag, "port", 7233, "port to listen on")
}

// TODO: graceful shutdown
func main() {
	flag.Parse()

	proxyConns := NewProxyConn()
	defer proxyConns.CloseAll()

	// Create a set of connections to proxy.
	//
	// Note that first argument is the host:port the worker will
	// connect to; the DNS entry for this host must resolve to the proxy.

	// TODO: don't hardcode; have a config file / management
	//       api / something else.
	err := proxyConns.AddConn(
		"brendan-myers.a2dd6.internal:7233",              // source
		"brendan-myers.a2dd6.tmprl.cloud:7233",           // target
		"/Users/brendan/dev/brendan-myers.a2dd6/tls.crt", // tls certificate
		"/Users/brendan/dev/brendan-myers.a2dd6/tls.key", // tls key
		"brendan-myers",                                  // payload encryption key
	)
	if err != nil {
		log.Fatalln("failed to create client", err)
	}

	err = proxyConns.AddConn(
		"brendan-myers-aws.a2dd6.internal:7233",
		"brendan-myers-aws.a2dd6.tmprl.cloud:7233",
		"/Users/brendan/dev/brendan-myers-aws.a2dd6/tls.crt",
		"/Users/brendan/dev/brendan-myers-aws.a2dd6/tls.key",
		"brendan-myers-aws",
	)
	if err != nil {
		log.Fatalln("failed to create client", err)
	}

	workflowClient := workflowservice.NewWorkflowServiceClient(proxyConns)

	handler, err := client.NewWorkflowServiceProxyServer(
		client.WorkflowServiceProxyOptions{Client: workflowClient},
	)
	if err != nil {
		log.Fatalln("failed to create service proxy", err)
	}

	grpcServer := grpc.NewServer()
	workflowservice.RegisterWorkflowServiceServer(grpcServer, handler)

	lis, err := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(portFlag))
	if err != nil {
		log.Fatalln("failed to listen", err)
	}

	fmt.Printf("listening on :%d\n", portFlag)

	err = grpcServer.Serve(lis)
	if err != nil {
		log.Fatalln("failed to start server", err)
	}
}
