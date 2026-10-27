package main

import (
	"net/netip"

	"golang.org/x/net/dns/dnsmessage"
)

const mdnsName = "7a1f6e3c-0b2d-4c5e-9f10-aabbccddeeff.local."

// mdnsQuery is pion/mdns's `sendQuestion` for one record type: a message holding one question,
// packed.
func mdnsQuery() []byte {
	packedName, err := dnsmessage.NewName(mdnsName)
	if err != nil {
		panic(err)
	}
	msg := dnsmessage.Message{
		Questions: []dnsmessage.Question{{
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			Name:  packedName,
		}},
	}
	raw, err := msg.Pack()
	if err != nil {
		panic(err)
	}
	return raw
}

// mdnsAnswer is pion/mdns's server path: unpack the query, find the question for a local name,
// and pack the A record that answers it.
func mdnsAnswer(query []byte, addr netip.Addr) []byte {
	var p dnsmessage.Parser
	if _, err := p.Start(query); err != nil {
		panic(err)
	}
	q, err := p.Question()
	if err != nil {
		panic(err)
	}
	if q.Name.String() != mdnsName || q.Type != dnsmessage.TypeA {
		panic("unexpected question")
	}
	name, err := dnsmessage.NewName(mdnsName)
	if err != nil {
		panic(err)
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120},
			Body:   &dnsmessage.AResource{A: addr.As4()},
		}},
	}
	raw, err := msg.Pack()
	if err != nil {
		panic(err)
	}
	return raw
}
