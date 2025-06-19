package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"temporal-sa/temporal-cloud-proxy/proxy"
	"temporal-sa/temporal-cloud-proxy/utils"

	"github.com/urfave/cli/v2"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"google.golang.org/grpc"
)

var configFilePath string

// TODO: graceful shutdown
func main() {
	app := &cli.App{
		Name:  "tclp",
		Usage: "Temporal Cloud Proxy",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "config",
				Usage:       "config file",
				Aliases:     []string{"c"},
				Value:       "config.yaml",
				Destination: &configFilePath,
			},
		},
		Action: func(*cli.Context) error {
			cfg, err := utils.LoadConfig(configFilePath)
			if err != nil {
				return err
			}

			proxyConns := proxy.NewProxyConn()
			defer proxyConns.CloseAll()

			// Create a set of connections to proxy.
			//
			// Note that first argument is the host:port the worker will
			// connect to; the DNS entry for this host must resolve to the proxy.
			for _, t := range cfg.Targets {
				fmt.Println(
					t.Source+":"+strconv.Itoa(cfg.Server.Port),
					t.Target,
					t.TLS.CertFile,
					t.TLS.KeyFile,
					t.EncryptionKey,
				)
				err := proxyConns.AddConn(
					t.Source+":"+strconv.Itoa(cfg.Server.Port),
					t.Target,
					t.TLS.CertFile,
					t.TLS.KeyFile,
					t.EncryptionKey,
				)
				if err != nil {
					return err
				}
			}

			workflowClient := workflowservice.NewWorkflowServiceClient(proxyConns)

			handler, err := client.NewWorkflowServiceProxyServer(
				client.WorkflowServiceProxyOptions{Client: workflowClient},
			)
			if err != nil {
				return err
			}

			grpcServer := grpc.NewServer()
			workflowservice.RegisterWorkflowServiceServer(grpcServer, handler)

			lis, err := net.Listen("tcp", cfg.Server.Host+":"+strconv.Itoa(cfg.Server.Port))
			if err != nil {
				return err
			}

			fmt.Printf("listening on %s:%d\n", cfg.Server.Host, cfg.Server.Port)

			err = grpcServer.Serve(lis)

			return err
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalln(err)
	}
}
