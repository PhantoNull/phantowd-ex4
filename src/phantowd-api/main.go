// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	selfTest := flag.Bool("self-test", false, "test the fixed guest-loopback endpoint; QEMU only")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected arguments")
	}
	if *selfTest {
		if err := runSelfTest(); err != nil {
			fmt.Fprintf(os.Stderr, "PHANTOWD_API_ERROR %v\n", err)
			os.Exit(1)
		}
		return
	}
	if os.Geteuid() == 0 {
		log.Fatal("refusing to serve as root")
	}
	server := newServer(newHandler(func() (systemSnapshot, error) {
		return collectSystem(os.DirFS("/proc"), time.Now())
	}, func() (storageSnapshot, error) {
		return collectStorage(os.DirFS("/sys"))
	}))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdown, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("PhantoWD development diagnostics listening on %s", listenAddress)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("diagnostics server failed")
	}
	<-shutdownDone
}
