package main

import (
	"errors"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type DNSServer struct {
	upstreamNameservers []string
	serverTimeout       int
	upstreamTimeout     int
	ttl                 uint32
	hosts               map[string]net.IP
	reverse             *DNSReverse
	nxDomains           []string
}

type DNSReverse struct {
	reverse map[string]string
}

func (this *DNSServer) ListenAndServeTCP(address net.TCPAddr) error {
	tcpHandler := dns.NewServeMux()
	tcpHandler.HandleFunc(".", this.tcpRequest)

	tcpServer := &dns.Server{Addr: address.String(),
		Net:          "tcp",
		Handler:      tcpHandler,
		ReadTimeout:  time.Duration(this.serverTimeout) * time.Second,
		WriteTimeout: time.Duration(this.serverTimeout) * time.Second,
	}

	err := tcpServer.ListenAndServe()
	if err != nil {
		return err
	}

	return nil
}

func (this *DNSServer) ListenAndServeUDP(address net.UDPAddr) error {
	udpHandler := dns.NewServeMux()
	udpHandler.HandleFunc(".", this.udpRequest)

	udpServer := &dns.Server{Addr: address.String(),
		Net:          "udp",
		Handler:      udpHandler,
		UDPSize:      65535,
		ReadTimeout:  time.Duration(this.serverTimeout) * time.Second,
		WriteTimeout: time.Duration(this.serverTimeout) * time.Second,
	}

	err := udpServer.ListenAndServe()
	if err != nil {
		return err
	}

	return nil
}

func (this *DNSServer) tcpRequest(response dns.ResponseWriter, message *dns.Msg) {
	this.request("tcp", response, message)
}

func (this *DNSServer) udpRequest(response dns.ResponseWriter, message *dns.Msg) {
	this.request("udp", response, message)
}

func (this *DNSServer) request(method string, response dns.ResponseWriter, message *dns.Msg) {
	hostname := strings.TrimSuffix(message.Question[0].Name, ".")
	localIP, found := this.hosts[hostname]
	if found {
		localResponse := new(dns.Msg)
		localResponse.SetReply(message)
		rrHeader := dns.RR_Header{
			Name:   message.Question[0].Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    this.ttl,
		}
		a := &dns.A{Hdr: rrHeader, A: localIP}
		localResponse.Answer = append(localResponse.Answer, a)
		err := response.WriteMsg(localResponse)
		if err != nil {
			log.Printf("DNS: writing local response %s failed: %v\n", localResponse, err)
		}
		return
	}

	reverse, found := this.reverse.Get(message.Question[0].Name)
	if found {
		localResponse := new(dns.Msg)
		localResponse.SetReply(message)
		rrHeader := dns.RR_Header{
			Name:   message.Question[0].Name,
			Rrtype: dns.TypePTR,
			Class:  dns.ClassINET,
			Ttl:    this.ttl,
		}
		ptr := &dns.PTR{Hdr: rrHeader, Ptr: reverse}
		localResponse.Answer = append(localResponse.Answer, ptr)
		localResponse.Authoritative = true
		err := response.WriteMsg(localResponse)
		if err != nil {
			log.Printf("DNS: writing local response %s failed: %v\n", localResponse, err)
		}
		return
	}

	// if we don't have a host entry, and it is on the nxDomain list, we answer directly
	for _, nxDomain := range this.nxDomains {
		if strings.HasSuffix(hostname, nxDomain) {
			localResponse := new(dns.Msg)
			localResponse.SetReply(message)
			localResponse.Authoritative = true
			localResponse.SetRcode(message, dns.RcodeNameError)
			err := response.WriteMsg(localResponse)
			if err != nil {
				log.Printf("DNS: writing local response %s failed: %v\n", localResponse, err)
			}
			return
		}
	}

	result, err := this.remoteDNSLookup(method, message)
	if err != nil {
		dns.HandleFailed(response, message)
		return
	}

	err = response.WriteMsg(result)
	if err != nil {
		log.Printf("DNS: writing response %s failed: %v\n", result, err)
	}
}

func (this *DNSServer) remoteDNSLookup(protocol string, request *dns.Msg) (*dns.Msg, error) {
	dnsClient := &dns.Client{
		Net:          protocol,
		ReadTimeout:  time.Duration(this.upstreamTimeout) * time.Second,
		WriteTimeout: time.Duration(this.upstreamTimeout) * time.Second,
	}

	var err error

	for _, nameserver := range this.upstreamNameservers {
		host, port, err := net.SplitHostPort(nameserver)
		if err != nil {
			host, port, err = net.SplitHostPort(nameserver + ":53")
			if err != nil {
				log.Printf("DNS: invalid upstream %s: %v\n", nameserver, err)
				continue
			}
		}

		result, _, err := dnsClient.Exchange(request, net.JoinHostPort(host, port))
		if err != nil {
			log.Printf("DNS: resolving %s via upstream %s failed: %v\n", request, nameserver, err)
			continue
		}

		if result != nil && result.Rcode != dns.RcodeSuccess {
			if result.Rcode == dns.RcodeNameError {
				log.Printf("DNS: resolving %s via upstream %s returned NXDOMAIN\n", request.Question[0].Name, nameserver)
			} else {
				log.Printf("DNS: resolving %s via upstream %s returned unsuccessful response: %s\n", request, nameserver, result)
			}
			continue
		}

		return result, nil
	}

	if err != nil {
		return nil, err
	} else {
		return nil, errors.New("DNS: Unknown DNS error")
	}
}

func NewDNSReverse() *DNSReverse {
	return &DNSReverse{
		reverse: make(map[string]string),
	}
}

func (rd *DNSReverse) Add(ip net.IP, hostname string) error {
	ipString := ip.String()

	arpa, err := dns.ReverseAddr(ipString)
	if err != nil {
		return err
	}

	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	rd.reverse[arpa] = hostname
	return nil
}

func (rd *DNSReverse) Get(arpa string) (string, bool) {
	hostname, exists := rd.reverse[arpa]
	return hostname, exists
}
