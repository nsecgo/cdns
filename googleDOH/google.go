package googleDOH

import (
	"encoding/json"
	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
	"net"
	"net/http"
	"net/url"
	"strconv"
)

type Msg struct {
	Status           int32
	TC               bool
	RD               bool
	RA               bool
	AD               bool
	CD               bool
	Question         []Question
	Answer           []RR
	Authority        []RR
	Additional       []RR
	EDNSClientSubnet string `json:"edns_client_subnet"`
	Comment          string
}

type Question struct {
	Name string
	Type int
}

type RR struct {
	Name string
	Type uint16
	TTL  uint32
	Data string
}

var (
	u     *url.URL
	group singleflight.Group
)

func init() {
	u, _ = url.Parse("https://dns.google.com/resolve")
}
func ExchangeDOH(hc *http.Client, req *dns.Msg, ecs string) (*dns.Msg, error) {
	r, err, shared := group.Do(req.Question[0].String(), func() (interface{}, error) {
		//var ecs string
		//opt := req.IsEdns0()
		//if opt != nil {
		//	for _, val := range opt.Option {
		//		if v, ok := val.(*dns.EDNS0_SUBNET); ok {
		//			ecs = v.Address.String()
		//			break
		//		}
		//	}
		//}
		var v = make(url.Values, 3)
		v.Set("name", req.Question[0].Name)
		v.Set("type", strconv.Itoa(int(req.Question[0].Qtype)))
		v.Set("edns_client_subnet", ecs)
		u.RawQuery = v.Encode()
		r, err := hc.Get(u.String())
		if err != nil {
			return nil, err
		}
		defer r.Body.Close()
		var m = new(Msg)
		err = json.NewDecoder(r.Body).Decode(m)
		if err != nil {
			return nil, err
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		for _, a := range m.Answer {
			resp.Answer = append(resp.Answer, convertRR(a))
		}
		resp.MsgHdr.Truncated = m.TC
		resp.MsgHdr.RecursionDesired = m.RD
		resp.MsgHdr.RecursionAvailable = m.RA
		resp.MsgHdr.AuthenticatedData = m.AD
		resp.MsgHdr.CheckingDisabled = m.CD
		resp.MsgHdr.Rcode = int(m.Status)
		return resp, nil
	})
	if err != nil {
		return nil, err
	}
	resp := r.(*dns.Msg)
	if shared {
		resp = resp.Copy()
	}
	return resp, nil
}
func convertRR(grr RR) dns.RR {
	rrHeader := dns.RR_Header{
		Name:   grr.Name,
		Rrtype: grr.Type,
		Class:  dns.ClassINET,
		Ttl:    grr.TTL,
	}
	var rr dns.RR
	newRR, ok := dns.TypeToRR[grr.Type]
	if ok {
		rr = newRR()
		*rr.Header() = rrHeader
		switch v := rr.(type) {
		case *dns.A:
			v.A = net.ParseIP(grr.Data)
		case *dns.AAAA:
			v.AAAA = net.ParseIP(grr.Data)
		}
	} else {
		rr = dns.RR(&dns.RFC3597{
			Hdr:   rrHeader,
			Rdata: grr.Data,
		})
	}
	return rr
}
