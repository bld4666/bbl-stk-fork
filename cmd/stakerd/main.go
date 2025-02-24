package main

import (
	"fmt"
	"net/http"
	"os"
	"runtime/pprof"

	"github.com/babylonlabs-io/btc-staker/metrics"
	staker "github.com/babylonlabs-io/btc-staker/staker"
	scfg "github.com/babylonlabs-io/btc-staker/stakercfg"
	service "github.com/babylonlabs-io/btc-staker/stakerservice"

	"github.com/jessevdk/go-flags"
	"github.com/lightningnetwork/lnd/signal"
)

func main() {
	// Hook interceptor for os signals.
	shutdownInterceptor, err := signal.Intercept()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	cfg, cfgLogger, zapLogger, err := scfg.LoadConfig()

	if err != nil {
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			// Print error if not due to help request.
			err = fmt.Errorf("failed to load config: %w", err)
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// Help was requested, exit normally.
		os.Exit(0)
	}

	// Enable http profiling server if requested.
	if cfg.Profile != "" {
		go func() {
			profileRedirect := http.RedirectHandler("/debug/pprof",
				http.StatusSeeOther)
			http.Handle("/", profileRedirect)
			cfgLogger.Infof("Pprof listening on %v", cfg.Profile)
			//nolint:gosec
			fmt.Println(http.ListenAndServe(cfg.Profile, nil))
		}()
	}

	// Write cpu profile if requested.
	if cfg.CPUProfile != "" {
		f, err := os.Create(cfg.CPUProfile)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_ = pprof.StartCPUProfile(f)
		defer f.Close()
		defer pprof.StopCPUProfile()
	}

	dbBackend, err := scfg.GetDbBackend(cfg.DBConfig)

	if err != nil {
		err = fmt.Errorf("failed to load db backend: %w", err)
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	stakerMetrics := metrics.NewStakerMetrics()

	// TODO: consider moving this to stakerservice
	staker, err := staker.NewStakerAppFromConfig(
		cfg,
		cfgLogger,
		zapLogger,
		dbBackend,
		stakerMetrics,
	)

	if err != nil {
		cfgLogger.Errorf("failed to create staker app: %v", err)
		os.Exit(1)
	}

	service := service.NewStakerService(
		cfg,
		staker,
		cfgLogger,
		shutdownInterceptor,
		dbBackend,
	)

	addr := fmt.Sprintf("%s:%d", cfg.MetricsConfig.Host, cfg.MetricsConfig.ServerPort)
	metrics.Start(cfgLogger, addr, stakerMetrics.Registry)

	err = service.RunUntilShutdown()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
