// Package gandiv5 implements a DNS provider for solving the DNS-01 challenge using Gandi LiveDNS api.
package gandiv5

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

// Gandi API reference:       http://doc.livedns.gandi.net/

const (
	// defaultBaseURL endpoint is the Gandi API endpoint used by Present and CleanUp.
	defaultBaseURL = "https://dns.api.gandi.net/api/v5"
	minTTL         = 300
)

// DNSProvider is an implementation of the
// acme.ChallengeProviderTimeout interface that uses Gandi's LiveDNS
// API to manage TXT records for a domain.
type DNSProvider struct {
	dns01Nameservers []string
	APIUrl           string
	APIKey           string
	TTL              int
	inProgressMu     sync.Mutex
}

// NewDNSProvider returns a DNSProvider instance configured for Gandi.
// Credentials must be passed in the environment variable: GANDIV5_API_KEY.
func NewDNSProvider(dns01Nameservers []string) (*DNSProvider, error) {
	key := os.Getenv("GANDIV5_API_KEY")
	return NewDNSProviderKey(key, dns01Nameservers)
}

// NewDNSProviderKey uses the supplied key to return a
// DNSProvider instance configured for gandi.
func NewDNSProviderKey(key string, dns01Nameservers []string) (*DNSProvider, error) {
	if key == "" {
		return nil, fmt.Errorf("gandiv5: no API Key given")
	}

	apiurl := os.Getenv("GANDIV5_API_URL")
	if apiurl == "" {
		apiurl = defaultBaseURL
	}

	ttl, err := strconv.Atoi(os.Getenv("GANDIV5_TTL"))
	if (err == nil) || (ttl < minTTL) {
		ttl = minTTL
	}

	return &DNSProvider{
		dns01Nameservers: dns01Nameservers,
		APIUrl:           apiurl,
		APIKey:           key,
		TTL:              ttl,
	}, nil
}

// Present creates a TXT record using the specified parameters.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	fqdn, _, _, err := util.DNS01Record(domain, keyAuth, d.dns01Nameservers)
	if err != nil {
		return err
	}

	authZone, name, err := getDomainAndName(fqdn)
	if err != nil {
		return err
	}

	// acquire lock and check there is not a challenge already in
	// progress for this value of authZone
	d.inProgressMu.Lock()
	defer d.inProgressMu.Unlock()

	// add TXT record into authZone
	err = d.setRecord(util.UnFqdn(authZone), "TXT", name, keyAuth, d.TTL)
	if err != nil {
		return err
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, _, _, err := util.DNS01Record(domain, keyAuth, d.dns01Nameservers)
	if err != nil {
		return err
	}

	authZone, name, err := getDomainAndName(fqdn)
	if err != nil {
		return err
	}

	// acquire lock and retrieve authZone
	d.inProgressMu.Lock()
	defer d.inProgressMu.Unlock()

	// delete TXT record from authZone
	err = d.deleteRecord(util.UnFqdn(authZone), "TXT", name)
	if err != nil {
		return fmt.Errorf("gandiv5: %v", err)
	}
	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS
// propagation. Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 120 * time.Second, 2 * time.Second
}

func getDomainAndName(fqdn string) (string, string, error) {
	// find authZone
	authZone, err := util.FindZoneByFqdn(fqdn, util.RecursiveNameservers)
	if err != nil {
		return "", "", fmt.Errorf("gandiv5: findZoneByFqdn failure: %v", err)
	}

	// determine name of TXT record
	if !strings.HasSuffix(
		strings.ToLower(fqdn), strings.ToLower("."+authZone)) {
		return "", "", fmt.Errorf("gandiv5: unexpected authZone %s for fqdn %s", authZone, fqdn)
	}
	name := fqdn[:len(fqdn)-len("."+authZone)]
	return authZone, name, nil
}
