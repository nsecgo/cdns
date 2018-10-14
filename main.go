package main

import (
	"flag"
	"github.com/miekg/dns"
	"github.com/nsecgo/cdns/googleDOH"
	"github.com/nsecgo/cdns/util"
	"github.com/patrickmn/go-cache"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"
)

var (
	client      dns.Client
	httpClient  = &http.Client{}
	chinaIPList []*net.IPNet
	mc          = cache.New(5*time.Minute, 10*time.Minute)
	localDNS    = flag.String("ld", "119.29.29.29:53", "local dns")
	remoteDNS   = flag.String("rd", "8.8.8.8:53", "remote dns")
	ecs         = flag.String("ecs", "0.0.0.0/0", "local ip addr")
	proxy       = flag.String("proxy", "socks5://127.0.0.1:1080", "http,https,socks5 are supported")
	addr        = flag.String("l", ":53", "listen address")
	ips         = flag.String("ip", "./china_ip_list.txt", "china ip list")
	network     = flag.String("net", "tcp", "if 'tcp' or 'tcp-tls' (DNS over TLS) a TCP query will be initiated, otherwise an UDP one")
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()
	var err error
	chinaIPList, err = util.GetIPList(*ips)
	if err != nil {
		log.Fatal(err)
	}
	proxyUrl, err := url.Parse(*proxy)
	if err != nil {
		log.Fatal(err)
	}
	client.SingleInflight = true
	client.Net = *network
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
		resp, _, err = client.Exchange(req, *localDNS)
	}
	if err != nil {
		log.Println(err, "===========>", req.Question[0].String())
		return
	}
	w.WriteMsg(resp)
}
func deliverAny(req *dns.Msg) (resp *dns.Msg, err error) {
	resp, err = googleDOH.ExchangeDOH(httpClient, req, *ecs)
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
	if ip == nil {
		return resp, nil
	}
	if util.IPListMatch(ip, chinaIPList) {
		resp, _, err = client.Exchange(req, *localDNS)
	} else {
		resp, _, err = client.Exchange(req, *remoteDNS)
	}
	if err != nil {
		return nil, err
	}
	return resp, nil
}
