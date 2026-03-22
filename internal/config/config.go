package config

import (
    //"io"
    "os"
    "fmt"
    //"path"
    //"errors"
    "regexp"
    //"strings"
    //"strconv"
    "net"
    //"net/url"
    "net/http"
    "io/ioutil"
    "gopkg.in/yaml.v2"
    "time"
    //"crypto/aes"
    "crypto/tls"
    "crypto/x509"
    "github.com/ltkh/mtproxy/internal/cryptor"
    //"github.com/ltkh/montools/internal/monitor"
    //"github.com/prometheus/client_golang/prometheus"
)

type Config struct {
    HttpClient             *HttpClient             `yaml:"http_client"`
    Upstreams              []*Upstream             `yaml:"upstreams"`
}

type HttpClient struct {
    Timeout                time.Duration           `yaml:"timeout"`
    HttpTransport          *HttpTransport          `yaml:"transport"`
}

type HttpTransport struct {
    DialContext            *DialContext            `yaml:"dial_context"`
    MaxIdleConnsPerHost    int                     `yaml:"max_idle_conns_per_host"`
    ExpectContinueTimeout  time.Duration           `yaml:"expect_continue_timeout"`
    TLSHandshakeTimeout    time.Duration           `yaml:"tls_handshake_timeout"`
    ResponseHeaderTimeout  time.Duration           `yaml:"response_header_timeout"`
}

type DialContext struct {
    Timeout                time.Duration           `yaml:"timeout"`
    KeepAlive              time.Duration           `yaml:"keep_alive"`
}

type Upstream struct {
    ListenAddr             string                  `yaml:"listen_addr"`
    ObjectHeader           string                  `yaml:"object_header"`
    //SizeLimit              float64                 `yaml:"size_limit"`
    UpdateStat             time.Duration           `yaml:"update_stat"`
    ErrorCode              int                     `yaml:"error_code"`
    CertFile               string                  `yaml:"tls_cert"`
    KeyFile                string                  `yaml:"tls_key"`
    URLMap                 []*URLMap               `yaml:"url_map"`
    MapPaths               []SrcPath               `yaml:"-"`
    SizeLimit              []SizeLimit             `yaml:"size_limit"`
}

// URLMap is a mapping from source paths to target urls.
type URLMap struct {
    SrcPaths               []string                `yaml:"src_paths"`
    URLPrefix              []*URLPrefix            `yaml:"url_prefix"`
    Users                  []*UserInfo             `yaml:"users"`
    MapUsers               map[string]string       `yaml:"-"`
    HealthCheck            string                  `yaml:"health_check"`
    ErrorCode              int                     `yaml:"error_code"`
    RequestsLimit          int                     `yaml:"requests_limit"`
    IgnoreAnswer           bool                    `yaml:"ignore_answer"`
    Client                 *http.Client            `yaml:"-"`
    ClientSettings         ClientSettings          `yaml:"client"`
}

// URLPrefix represents passed `url_prefix`
type URLPrefix struct {
    Requests               chan int
    Health                 chan int
    Latency                time.Duration
    URL                    string
}

// SrcPath represents an src path
type SrcPath struct {
    sOriginal              string
    RE                     *regexp.Regexp
    Index                  int
}

type SizeLimit struct {
    Object                 string                  `yaml:"object"`
    RE                     *regexp.Regexp
    Bytes                  float64                 `yaml:"bytes"`
}

// UserInfo is user information
type UserInfo struct {
    Username               string                  `yaml:"username"`
    Password               string                  `yaml:"password"`
}

// ClientSettings
type ClientSettings struct {
    Username               string                  `yaml:"username"`
    Password               string                  `yaml:"password"`
    //tlsSkipVerify          bool                    `yaml:"tls_skip_verify"`
    tlsCAFile              string                  `yaml:"tls_ca"`
    tlsCertFile            string                  `yaml:"tls_cert"`
    tlsKeyFile             string                  `yaml:"tls_key"`
}

// UnmarshalYAML unmarshals up from yaml.
func (up *URLPrefix) UnmarshalYAML(f func(interface{}) error) error {
    var s string
    if err := f(&s); err != nil {
        return err
    }
    //up.Check = true
    up.URL = s
    up.Requests = make(chan int, 1000000)
    up.Health = make(chan int, 5)
    return nil
}

func NewConfig(filename, key string, encrypted bool) (*Config, error) {

    cfg := &Config{}

    content, err := ioutil.ReadFile(filename)
    if err != nil {
       return cfg, err
    }

    if err := yaml.UnmarshalStrict(content, cfg); err != nil {
        return cfg, err
    }

    for u, stream := range cfg.Upstreams {
        if stream.ObjectHeader == "" { 
            stream.ObjectHeader = "X-Custom-Object"
        }
        for i, urlMap := range stream.URLMap {
            if urlMap.ClientSettings.Password != "" && encrypted {
                urlMap.ClientSettings.Password = cryptor.Decrypt(urlMap.ClientSettings.Password, key)
            }

            for _, srcPaths := range urlMap.SrcPaths {
                var mp SrcPath
                mp.sOriginal = srcPaths
                mp.Index = i

                re, err := regexp.Compile("^(?:" + srcPaths + ")$")
                if err != nil {
                    return cfg, fmt.Errorf("cannot build regexp from %q: %w", srcPaths, err)
                }
                mp.RE = re

                stream.MapPaths = append(stream.MapPaths, mp)
            }

            mu := make(map[string]string)
            for _, user := range urlMap.Users {
                mu[user.Username] = user.Password
            }
            urlMap.MapUsers = mu

            tlsConfig := &tls.Config{InsecureSkipVerify: true}

            // 1. Загружаем корневой сертификат (CA) для проверки сервера
            if urlMap.ClientSettings.tlsCAFile != "" {
                caCert, _ := os.ReadFile(urlMap.ClientSettings.tlsCAFile)
                caCertPool := x509.NewCertPool()
                caCertPool.AppendCertsFromPEM(caCert)

                tlsConfig.RootCAs = caCertPool
            }

            // 2. Загружаем пару сертификат + ключ клиента для авторизации на сервере
            if urlMap.ClientSettings.tlsCertFile != "" && urlMap.ClientSettings.tlsKeyFile != "" {
                clientCert, err := tls.LoadX509KeyPair(urlMap.ClientSettings.tlsCertFile, urlMap.ClientSettings.tlsKeyFile)
                if err != nil {
                    return cfg, err
                }
                tlsConfig.Certificates = []tls.Certificate{clientCert}
                tlsConfig.InsecureSkipVerify = false
            }

            urlMap.Client = &http.Client{
                Timeout: cfg.HttpClient.Timeout,
                Transport: &http.Transport{
                    MaxIdleConnsPerHost: cfg.HttpClient.HttpTransport.MaxIdleConnsPerHost,
                    DialContext: (&net.Dialer{
                        Timeout:   cfg.HttpClient.HttpTransport.DialContext.Timeout,
                        KeepAlive: cfg.HttpClient.HttpTransport.DialContext.KeepAlive,
                    }).DialContext,
                    ExpectContinueTimeout: cfg.HttpClient.HttpTransport.ExpectContinueTimeout,
                    TLSHandshakeTimeout:   cfg.HttpClient.HttpTransport.TLSHandshakeTimeout,
                    ResponseHeaderTimeout: cfg.HttpClient.HttpTransport.ResponseHeaderTimeout,
                    TLSClientConfig: tlsConfig,
                },
            }
        }
        for s, sizeLimit := range stream.SizeLimit {
            re, err := regexp.Compile("^(?:" + sizeLimit.Object + ")$")
            if err != nil {
                return cfg, fmt.Errorf("cannot build regexp from %q: %w", sizeLimit.Object, err)
            }
            cfg.Upstreams[u].SizeLimit[s].RE = re
        }
    }
    
    return cfg, nil
}
