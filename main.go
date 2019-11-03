package main

import (
	"github.com/pkg/errors"
	"github.com/sevlyar/go-daemon"
	"github.com/spf13/cobra"
	"golang.org/x/net/proxy"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

var (
	buildDate     = "<unknown>"
	buildCommitID = "<wip>"
)

var (
	configPath = ""
	daemonize  = false
	logPath    = "-"
)

var rootCmd = &cobra.Command{
	Use:           "tls-proxy",
	Short:         "TLS proxy",
	RunE:          run,
	SilenceErrors: true,
	SilenceUsage:  true,
}

type ProxyFunc func(net.Conn, ProxyConfigs)

type ProxyType int

const (
	// ProxyTypeHTTP declares a HTTP proxy
	ProxyTypeHTTP = ProxyType(1)

	// ProxyTypeHTTP declares a TLS proxy
	ProxyTypeTLS = ProxyType(2)
)

type ProxyConfig struct {
	Type            ProxyType
	MatchHost       string
	MatchPort       int
	MatchPathRegexp *regexp.Regexp
	TargetHost      string
	TargetPort      int
	RewritePath     string
	Dialer          proxy.Dialer
}

type ProxyConfigs []*ProxyConfig

func (pc *ProxyConfigs) GetHostConfig(hostname string) *ProxyConfig {
	for _, c := range *pc {
		if strings.EqualFold(c.MatchHost, hostname) {
			return c
		}
	}
	return nil
}

func (pc *ProxyConfigs) GetHostPathConfig(hostname, path string) *ProxyConfig {
	for _, c := range *pc {
		if strings.EqualFold(c.MatchHost, hostname) {
			if c.MatchPathRegexp == nil || c.MatchPathRegexp.MatchString(path) {
				return c
			}
		}
	}
	return nil
}

func listen(errCh chan error, addressPort string, proxyConfigs ProxyConfigs) {
	listener, err := net.Listen("tcp", addressPort)
	if err != nil {
		errCh <- err
		return
	}
	log.Printf("listening on tcp:%s", addressPort)

	for {
		connection, err := listener.Accept()
		if err != nil {

			return
		}

		switch proxyConfigs[0].Type {
		case ProxyTypeHTTP:
			go proxyHTTPConnection(connection, proxyConfigs)
		case ProxyTypeTLS:
			go proxyTLSConnection(connection, proxyConfigs)
		}
	}
}

// GetOutboundIP returns the default outbound IP address
func GetOutboundIP() (net.IP, error) {
	// UDP is connectionless, so there is no actual network activity
	conn, err := net.Dial("udp", "1.2.3.4:5678")
	if err != nil {
		return nil, errors.New("cannot determine outbound IP address")
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP, nil
}

// GetOutboundIPString returns the default outbound IP address as string, or an empty string on failure
func GetOutboundIPString() string {
	addr, err := GetOutboundIP()
	if err != nil {
		return ""
	}
	return addr.String()
}

func dialerForProxy(targetProxy string) (proxy.Dialer, error) {
	if targetProxy != "" {
		return proxy.SOCKS5("tcp", targetProxy, nil, proxy.Direct)
	}
	return nil, nil
}

func run(cmd *cobra.Command, args []string) error {
	if logPath != "" && logPath != "-" {
		f, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0664)
		if err != nil {
			panic(err)
		}

		defer f.Close()
		log.SetOutput(f)
	}

	if daemonize {
		ctx := &daemon.Context{}

		d, err := ctx.Reborn()
		if err != nil {
			log.Panic(err)
		}
		if d != nil {
			return nil
		}
		defer ctx.Release()

		// re-open the logfile in child process
		if logPath != "" && logPath != "-" {
			f, err := os.OpenFile(logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0664)
			if err != nil {
				panic(err)
			}

			defer f.Close()
			log.SetOutput(f)
		}

		log.Println("daemonized")
	}

	config, err := ReadConfigFile(configPath)
	if err != nil {
		return err
	}

	if config.OwnAddress == "" {
		config.OwnAddress = GetOutboundIPString()
	}

	// prepare DNS config
	ownIP := net.ParseIP(config.OwnAddress)
	if ownIP == nil {
		return errors.New("invalid own address")
	}

	hosts := make(map[string]net.IP)
	reverse := NewDNSReverse()

	// setup proxy
	proxyConfigsByPort := make(map[int]ProxyConfigs)
	for _, cHTTP := range config.ProxyHTTP {
		port := cHTTP.MatchPort
		if port == 0 {
			port = 80
		}
		targetPort := cHTTP.TargetPort
		if targetPort == 0 {
			targetPort = port
		}

		var matchPathRegexp *regexp.Regexp
		if cHTTP.MatchPathRegexp != "" {
			matchPathRegexp, err = regexp.Compile(cHTTP.MatchPathRegexp)
			if err != nil {
				return errors.Wrapf(err, "invalid match-path '%s'", cHTTP.MatchPathRegexp)
			}
		}

		dialer, err := dialerForProxy(cHTTP.Proxy)
		if err != nil {
			return errors.Errorf("invalid proxy %s", cHTTP.Proxy)
		}

		proxyConfigsByPort[port] = append(proxyConfigsByPort[port], &ProxyConfig{
			Type:            ProxyTypeHTTP,
			MatchHost:       cHTTP.MatchHost,
			MatchPort:       port,
			MatchPathRegexp: matchPathRegexp,
			TargetHost:      cHTTP.TargetHost,
			TargetPort:      targetPort,
			RewritePath:     cHTTP.RewritePath,
			Dialer:          dialer,
		})

		// respond to DNS queries for the hostname we handle with our IP address
		hosts[cHTTP.MatchHost] = ownIP
		_ = reverse.Add(ownIP, cHTTP.MatchHost)
	}

	for _, cTLS := range config.ProxyTLS {
		port := cTLS.MatchPort
		if port == 0 {
			port = 443
		}
		targetPort := cTLS.TargetPort
		if targetPort == 0 {
			targetPort = port
		}

		if len(proxyConfigsByPort[port]) > 0 && proxyConfigsByPort[port][0].Type != ProxyTypeTLS {
			return errors.Errorf("Cannot mix HTTP and TLS proxy on port %d", port)
		}

		dialer, err := dialerForProxy(cTLS.Proxy)
		if err != nil {
			return errors.Errorf("invalid proxy %s", cTLS.Proxy)
		}

		proxyConfigsByPort[port] = append(proxyConfigsByPort[port], &ProxyConfig{
			Type:       ProxyTypeTLS,
			MatchHost:  cTLS.MatchHost,
			MatchPort:  port,
			TargetHost: cTLS.TargetHost,
			TargetPort: targetPort,
			Dialer:     dialer,
		})

		// respond to DNS queries for the hostname we handle with our IP address
		hosts[cTLS.MatchHost] = ownIP
		_ = reverse.Add(ownIP, cTLS.MatchHost)
	}

	listenErr := make(chan error)
	for port, proxyConfigs := range proxyConfigsByPort {
		go listen(listenErr, config.OwnAddress+":"+strconv.Itoa(port), proxyConfigs)
	}

	// setup DNS server
	if config.DNS.Listen == "" {
		config.DNS.Listen = config.OwnAddress + ":53"
	}
	if config.DNS.ServerTimeout == 0 {
		config.DNS.ServerTimeout = 10
	}
	if config.DNS.UpstreamTimeout == 0 {
		config.DNS.UpstreamTimeout = 6
	}
	if config.DNS.TTL == 0 {
		config.DNS.TTL = 60
	}

	// start DNS server
	dnsServer := &DNSServer{
		serverTimeout:       config.DNS.ServerTimeout,
		upstreamTimeout:     config.DNS.UpstreamTimeout,
		upstreamNameservers: config.DNS.UpstreamNameservers,
		ttl:                 config.DNS.TTL,
		hosts:               hosts,
		reverse:             reverse,
		nxDomains:           []string{},
	}

	dnsTcpErr := make(chan error)
	go func() {
		tcpAddr, err := net.ResolveTCPAddr("tcp", config.DNS.Listen)
		if err != nil {
			dnsTcpErr <- errors.Wrap(err, "DNS: cannot resolve TCP listen address")
			return
		}

		log.Printf("listening on tcp:%s", config.DNS.Listen)
		err = dnsServer.ListenAndServeTCP(*tcpAddr)
		if err != nil {
			dnsTcpErr <- errors.Wrap(err, "DNS: starting DNS TCP server failed")
		}
	}()

	dnsUdpErr := make(chan error)
	go func() {
		udpAddr, err := net.ResolveUDPAddr("udp", config.DNS.Listen)
		if err != nil {
			dnsUdpErr <- errors.Wrap(err, "DNS: cannot resolve UDP listen address")
			return
		}

		log.Printf("listening on udp:%s", config.DNS.Listen)
		err = dnsServer.ListenAndServeUDP(*udpAddr)
		if err != nil {
			dnsUdpErr <- errors.Wrap(err, "DNS: starting DNS UDP server failed")
		}
	}()

	// install signal handler
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// wait for terminating condition
	select {
	case err := <-listenErr:
		return errors.Wrap(err, "proxy failed")
	case err := <-dnsTcpErr:
		return err
	case err := <-dnsUdpErr:
		return err
	case sig := <-sigs:
		log.Printf("received signal %s, shutting down\n", sig)
		//shutdown()
		return nil
	}
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	rootCmd.Version = "1 (commit " + buildCommitID + " built on " + buildDate + ")"
	rootCmd.Flags().StringVarP(&configPath, "config", "c", "tls-proxy.yaml", "configuration file path")
	rootCmd.Flags().BoolVar(&daemonize, "daemon", false, "daemonize process")
	rootCmd.Flags().StringVar(&logPath, "log", "-", "log file path ('-' = stdout)")

	if err := rootCmd.Execute(); err != nil {
		log.Printf("Process ends abnormally. Reason: %v", err)
		os.Exit(1)
	} else {
		log.Println("Process ends normally. Goodbye.")
		os.Exit(0)
	}
}
