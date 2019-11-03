package main

import (
	"io"
	"os"

	"github.com/pkg/errors"
	yaml "gopkg.in/yaml.v3"
)

type ConfigProxyHTTP struct {
	MatchHost       string `yaml:"match-host"`
	MatchPort       int    `yaml:"match-port"`
	MatchPathRegexp string `yaml:"match-path"`
	TargetHost      string `yaml:"target-host"`
	TargetPort      int    `yaml:"target-port"`
	RewritePath     string `yaml:"rewrite-path"`
	Proxy           string `yaml:"proxy"`
}

type ConfigProxyTLS struct {
	MatchHost  string `yaml:"match-host"`
	MatchPort  int    `yaml:"match-port"`
	TargetHost string `yaml:"target-host"`
	TargetPort int    `yaml:"target-port"`
	Proxy      string `yaml:"proxy"`
}

type ConfigDNS struct {
	Listen              string   `yaml:"listen"`
	ServerTimeout       int      `yaml:"timeout"`
	UpstreamNameservers []string `yaml:"nameserver"`
	UpstreamTimeout     int      `yaml:"upstream-timeout"`
	TTL                 uint32   `yaml:"ttl"`
}

type Config struct {
	OwnAddress string             `yaml:"host-address"`
	ProxyHTTP  []*ConfigProxyHTTP `yaml:"http"`
	ProxyTLS   []*ConfigProxyTLS  `yaml:"tls"`
	DNS        *ConfigDNS         `yaml:"dns"`
}

// ParseConfig parses a YAML configuration file
func ParseConfig(r io.Reader) (*Config, error) {
	d := yaml.NewDecoder(r)
	d.KnownFields(true)
	conf := &Config{}
	if err := d.Decode(conf); err != nil {
		return nil, err
	}
	return conf, nil
}

// ReadConfigFile reads and parses a YAML configuration file
func ReadConfigFile(path string) (*Config, error) {
	r, err := os.Open(path)
	if err != nil {
		return nil, errors.Wrapf(err, "%s: open failed", path)
	}
	defer r.Close()

	config, err := ParseConfig(r)
	if err != nil {
		return nil, errors.Wrapf(err, "%s: reading config failed", path)
	}
	_ = r.Close()

	return config, nil
}
