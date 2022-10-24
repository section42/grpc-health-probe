// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/golang/protobuf/proto"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

var (
	flAddr          string
	flService       string
	flUserAgent     string
	flConnTimeout   time.Duration
	flRPCTimeout    time.Duration
	flTLS           bool
	flTLSNoVerify   bool
	flTLSCACert     string
	flTLSClientCert string
	flTLSClientKey  string
	flTLSServerName string
	flVerbose       bool
	flGZIP          bool
	flWeb           bool
)

const (
	// StatusInvalidArguments indicates specified invalid arguments.
	StatusInvalidArguments = 1
	// StatusConnectionFailure indicates connection failed.
	StatusConnectionFailure = 2
	// StatusRPCFailure indicates rpc failed.
	StatusRPCFailure = 3
	// StatusUnhealthy indicates rpc succeeded but indicates unhealthy service.
	StatusUnhealthy = 4
)

func init() {
	flagSet := flag.NewFlagSet("", flag.ContinueOnError)
	log.SetFlags(0)
	flagSet.StringVar(&flAddr, "addr", "", "(required) tcp host:port to connect")
	flagSet.StringVar(&flService, "service", "", "service name to check (default: \"\")")
	flagSet.StringVar(&flUserAgent, "user-agent", "grpc_health_probe", "user-agent header value of health check requests")
	// timeouts
	flagSet.DurationVar(&flConnTimeout, "connect-timeout", time.Second, "timeout for establishing connection")
	flagSet.DurationVar(&flRPCTimeout, "rpc-timeout", time.Second, "timeout for health check rpc")
	// tls settings
	flagSet.BoolVar(&flTLS, "tls", false, "use TLS (default: false, INSECURE plaintext transport)")
	flagSet.BoolVar(&flTLSNoVerify, "tls-no-verify", false, "(with -tls) don't verify the certificate (INSECURE) presented by the server (default: false)")
	flagSet.StringVar(&flTLSCACert, "tls-ca-cert", "", "(with -tls, optional) file containing trusted certificates for verifying server")
	flagSet.StringVar(&flTLSClientCert, "tls-client-cert", "", "(with -tls, optional) client certificate for authenticating to the server (requires -tls-client-key)")
	flagSet.StringVar(&flTLSClientKey, "tls-client-key", "", "(with -tls) client private key for authenticating to the server (requires -tls-client-cert)")
	flagSet.StringVar(&flTLSServerName, "tls-server-name", "", "(with -tls) override the hostname used to verify the server certificate")
	flagSet.BoolVar(&flVerbose, "v", false, "verbose logs")
	flagSet.BoolVar(&flGZIP, "gzip", false, "use GZIPCompressor for requests and GZIPDecompressor for response (default: false)")
	flagSet.BoolVar(&flWeb, "web", false, "send a http1.1 grpc-web message instead of a http2 grpc message (default: false)")

	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		os.Exit(StatusInvalidArguments)
	}

	argError := func(s string, v ...interface{}) {
		log.Printf("error: "+s, v...)
		os.Exit(StatusInvalidArguments)
	}

	if flAddr == "" {
		argError("-addr not specified")
	}
	if flConnTimeout <= 0 {
		argError("-connect-timeout must be greater than zero (specified: %v)", flConnTimeout)
	}
	if flRPCTimeout <= 0 {
		argError("-rpc-timeout must be greater than zero (specified: %v)", flRPCTimeout)
	}
	if !flTLS && flTLSNoVerify {
		argError("specified -tls-no-verify without specifying -tls")
	}
	if !flTLS && flTLSCACert != "" {
		argError("specified -tls-ca-cert without specifying -tls")
	}
	if !flTLS && flTLSClientCert != "" {
		argError("specified -tls-client-cert without specifying -tls")
	}
	if !flTLS && flTLSServerName != "" {
		argError("specified -tls-server-name without specifying -tls")
	}
	if flTLSClientCert != "" && flTLSClientKey == "" {
		argError("specified -tls-client-cert without specifying -tls-client-key")
	}
	if flTLSClientCert == "" && flTLSClientKey != "" {
		argError("specified -tls-client-key without specifying -tls-client-cert")
	}
	if flTLSNoVerify && flTLSCACert != "" {
		argError("cannot specify -tls-ca-cert with -tls-no-verify (CA cert would not be used)")
	}
	if flTLSNoVerify && flTLSServerName != "" {
		argError("cannot specify -tls-server-name with -tls-no-verify (server name would not be used)")
	}

	if flVerbose {
		log.Printf("parsed options:")
		log.Printf("> addr=%s conn_timeout=%v rpc_timeout=%v", flAddr, flConnTimeout, flRPCTimeout)
		log.Printf("> tls=%v", flTLS)
		if flTLS {
			log.Printf("  > no-verify=%v ", flTLSNoVerify)
			log.Printf("  > ca-cert=%s", flTLSCACert)
			log.Printf("  > client-cert=%s", flTLSClientCert)
			log.Printf("  > client-key=%s", flTLSClientKey)
			log.Printf("  > server-name=%s", flTLSServerName)
		}
	}
}

func buildCredentials(skipVerify bool, caCerts, clientCert, clientKey, serverName string) (credentials.TransportCredentials, error) {
	var cfg tls.Config

	if clientCert != "" && clientKey != "" {
		keyPair, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load tls client cert/key pair. error=%v", err)
		}
		cfg.Certificates = []tls.Certificate{keyPair}
	}

	if skipVerify {
		cfg.InsecureSkipVerify = true
	} else if caCerts != "" {
		// override system roots
		rootCAs := x509.NewCertPool()
		pem, err := ioutil.ReadFile(caCerts)
		if err != nil {
			return nil, fmt.Errorf("failed to load root CA certificates from file (%s) error=%v", caCerts, err)
		}
		if !rootCAs.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no root CA certs parsed from file %s", caCerts)
		}
		cfg.RootCAs = rootCAs
	}
	if serverName != "" {
		cfg.ServerName = serverName
	}
	return credentials.NewTLS(&cfg), nil
}

func main() {
	retcode := 0
	defer func() { os.Exit(retcode) }()

	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		sig := <-c
		if sig == os.Interrupt {
			log.Printf("cancellation received")
			cancel()
			return
		}
	}()
	resp, connDuration, rpcDuration := doCall(&retcode, ctx)

	if resp == nil {
		return
	}

	if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		log.Printf("service unhealthy (responded with %q)", resp.GetStatus().String())
		retcode = StatusUnhealthy
		return
	}
	if flVerbose {
		log.Printf("time elapsed: connect=%v rpc=%v", connDuration, rpcDuration)
	}
	log.Printf("status: %v", resp.GetStatus().String())
	return

}

func doCall(retcode *int, ctx context.Context) (*healthpb.HealthCheckResponse, time.Duration, time.Duration) {
	if flWeb {
		return doWebCall(retcode, ctx)
	}
	return doGrpcCall(retcode, ctx)
}

func doWebCall(retcode *int, ctx context.Context) (*healthpb.HealthCheckResponse, time.Duration, time.Duration) {
	var url = "http://"
	if flTLS {
		url = "https://"
	}

	url += flAddr + "/grpc.health.v1.Health/Check"

	var contentType = "application/grpc-web-text+proto"

	requestMsg := &healthpb.HealthCheckRequest{
		Service: flService,
	}

	requestMsgBytes, err := proto.Marshal(requestMsg)
	if err != nil {
		log.Printf("failed building grpc web request message. error=%v", err)
		*retcode = StatusInvalidArguments
		return nil, 0, 0
	}

	headerBytes := append([]byte{0, 0, 0, 0}, byte(len(requestMsgBytes)))
	requestBytes := append(headerBytes, requestMsgBytes...)

	requestString := base64.StdEncoding.EncodeToString(requestBytes)

	client := http.Client{
		Timeout: flConnTimeout,
	}
	connStart := time.Now()
	res, err := client.Post(url, contentType, bytes.NewBuffer([]byte(requestString)))
	if err != nil {
		log.Printf("grpc web request failed. error=%v", err)
		*retcode = StatusConnectionFailure
		return nil, 0, 0
	}
	connDuration := time.Since(connStart)

	defer res.Body.Close()

	if res.StatusCode != 200 {
		log.Printf("got invalid grpc web result. status=%v", res.StatusCode)
		*retcode = StatusRPCFailure
		return nil, 0, 0
	}

	var resType = res.Header.Get("Content-Type")

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Printf("got invalid grpc web result. error=%v", err)
		*retcode = StatusRPCFailure
		return nil, 0, 0
	}

	var resultBytes = body
	if resType == "application/grpc-web-text" {
		var bodyString = string(body)
		// remove trailer message
		m1 := regexp.MustCompile(`(=+).+`)
		var result = m1.ReplaceAllString(bodyString, "$1")

		dedodedBytes, err := base64.StdEncoding.DecodeString(result)
		if err != nil {

			log.Printf("got invalid grpc web result. error=%v", err)
			*retcode = StatusRPCFailure
			return nil, 0, 0
		}
		resultBytes = dedodedBytes
	}

	// first byte is header
	// next 4 bytes give the length of the message
	len := binary.BigEndian.Uint32(resultBytes[1:5])

	resultBytes = resultBytes[5 : 5+len]

	protomsg := &healthpb.HealthCheckResponse{}

	err = proto.Unmarshal(resultBytes, protomsg)
	if err != nil {
		log.Printf("got invalid grpc web result, failed while parsing. error=%v", err)
		*retcode = StatusRPCFailure
		return nil, 0, 0
	}

	return protomsg, connDuration, 0
}

func doGrpcCall(retcode *int, ctx context.Context) (*healthpb.HealthCheckResponse, time.Duration, time.Duration) {

	opts := []grpc.DialOption{
		grpc.WithUserAgent(flUserAgent),
		grpc.WithBlock(),
	}
	if flTLS {
		creds, err := buildCredentials(flTLSNoVerify, flTLSCACert, flTLSClientCert, flTLSClientKey, flTLSServerName)
		if err != nil {
			log.Printf("failed to initialize tls credentials. error=%v", err)
			*retcode = StatusInvalidArguments
			return nil, 0, 0
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}

	if flGZIP {
		opts = append(opts,
			grpc.WithCompressor(grpc.NewGZIPCompressor()),
			grpc.WithDecompressor(grpc.NewGZIPDecompressor()),
		)
	}

	if flVerbose {
		log.Print("establishing connection")
	}
	connStart := time.Now()
	dialCtx, dialCancel := context.WithTimeout(ctx, flConnTimeout)
	defer dialCancel()
	conn, err := grpc.DialContext(dialCtx, flAddr, opts...)
	if err != nil {
		if err == context.DeadlineExceeded {
			log.Printf("timeout: failed to connect service %q within %v", flAddr, flConnTimeout)
		} else {
			log.Printf("error: failed to connect service at %q: %+v", flAddr, err)
		}
		*retcode = StatusConnectionFailure
		return nil, 0, 0
	}
	connDuration := time.Since(connStart)
	defer conn.Close()
	if flVerbose {
		log.Printf("connection established (took %v)", connDuration)
	}

	rpcStart := time.Now()
	rpcCtx, rpcCancel := context.WithTimeout(ctx, flRPCTimeout)
	defer rpcCancel()
	resp, err := healthpb.NewHealthClient(conn).Check(rpcCtx,
		&healthpb.HealthCheckRequest{
			Service: flService})
	if err != nil {
		if stat, ok := status.FromError(err); ok && stat.Code() == codes.Unimplemented {
			log.Printf("error: this server does not implement the grpc health protocol (grpc.health.v1.Health): %s", stat.Message())
		} else if stat, ok := status.FromError(err); ok && stat.Code() == codes.DeadlineExceeded {
			log.Printf("timeout: health rpc did not complete within %v", flRPCTimeout)
		} else {
			log.Printf("error: health rpc failed: %+v", err)
		}
		*retcode = StatusRPCFailure
		return nil, 0, 0
	}
	rpcDuration := time.Since(rpcStart)

	return resp, connDuration, rpcDuration
}
