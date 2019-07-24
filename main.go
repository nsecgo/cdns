package main

import (
	"flag"
	"github.com/miekg/dns"
	"github.com/nsecgo/cdns/googleDOH"
	"github.com/oschwald/maxminddb-golang"
	"github.com/patrickmn/go-cache"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"
)

type geoIpRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

var (
	geoIpReader *maxminddb.Reader
	Client      = dns.Client{SingleInflight: true}
	httpClient  = &http.Client{}
	mc          = cache.New(5*time.Minute, 10*time.Minute)
	localDNS    = flag.String("ld", "192.168.1.1:53", "local dns")
	ecs         = flag.String("ecs", "0.0.0.0/0", "local ip addr")
	x           = flag.String("x", "socks5://localhost:1080", "proxy url")
	addr        = flag.String("l", ":5300", "listen address")
	geoip       = flag.String("geoip", "GeoLite2-Country.mmdb", "geoip-database(https://dev.maxmind.com/geoip/geoip2/geolite2/)")
	//remoteDNS   = flag.String("rd", "1.1.1.1:53", "remote dns")
	//network     = *flag.String("net", "tcp", "if 'tcp' or 'tcp-tls' (DNS over TLS) a TCP query will be initiated, otherwise an UDP one")
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()
	var err error

	geoIpReader, err = maxminddb.Open(*geoip)
	if err != nil {
		log.Fatal(err)
	}

	proxyUrl, err := url.Parse(*x)
	if err != nil {
		log.Fatal(err)
	}

	httpClient.Transport = http.DefaultTransport
	httpClient.Transport.(*http.Transport).MaxIdleConnsPerHost = 20
	httpClient.Transport.(*http.Transport).Proxy = http.ProxyURL(proxyUrl)

	dns.HandleFunc(".", handleDnsRequest)
	log.Fatal(dns.ListenAndServe(*addr, "udp", nil))
}
func handleDnsRequest(w dns.ResponseWriter, req *dns.Msg) {
	var resp *dns.Msg
	var err error
	if req.Question[0].Qtype == dns.TypeA || req.Question[0].Qtype == dns.TypeAAAA {
		r, ok := mc.Get(req.Question[0].String())
		if ok {
			resp = r.(*dns.Msg)
			resp.Id = req.Id
			resp.Truncated = false
		} else {
			resp, err = deliverAny(req)
			if err == nil {
				mc.Set(req.Question[0].String(), resp, cache.DefaultExpiration)
			}
		}
	} else {
		resp, _, err = Client.Exchange(req, *localDNS)
	}
	if err != nil {
		log.Println(err, "===========>", req.Question[0].String())
		return
	}
	w.WriteMsg(resp)
}
func deliverAny(req *dns.Msg) (resp *dns.Msg, err error) {
	resp, _, err = Client.Exchange(req, *localDNS)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return resp, nil
	}
	var ip net.IP
	for _, a := range resp.Answer {
		if a.Header().Rrtype == dns.TypeA {
			ip = a.(*dns.A).A
			break
		}
		if a.Header().Rrtype == dns.TypeAAAA {
			ip = a.(*dns.AAAA).AAAA
			break
		}
	}
	var record geoIpRecord
	if ip == nil || (geoIpReader.Lookup(ip, &record) == nil && record.Country.ISOCode != "CN") {
		resp, err = googleDOH.ExchangeDOH(httpClient, req, *ecs)
		if err != nil {
			return nil, err
		}

	}
	return resp, nil
}
