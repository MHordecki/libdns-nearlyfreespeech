package nearlyfreespeech

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/schema"
	"github.com/libdns/libdns"
)

type (
	clock  = func() time.Time
	salter = func() (string, error)
)

const authHeaderName = "X-NFSN-Authentication"

type Provider struct {
	Username string
	APIKey   string

	clock  clock
	salter salter
	apiURL string
}

func NewProvider(username, apiKey string) *Provider {
	return &Provider{
		clock:    time.Now,
		salter:   generateSalt,
		apiURL:   "https://api.nearlyfreespeech.net",
		Username: username,
		APIKey:   apiKey,
	}
}

func (p *Provider) prepareRequest(ctx context.Context, method, path string, content []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, p.apiURL+path, bytes.NewReader(content))
	if err != nil {
		return nil, fmt.Errorf("failed to prepare HTTP request: %v", err)
	}
	authHeader, err := generateAuthHeader(p.clock, p.salter, p.Username, p.APIKey, path, content)
	if err != nil {
		return nil, fmt.Errorf("failed to generate auth header: %v", err)
	}
	req.Header.Add(authHeaderName, authHeader)
	return req, nil
}

func (p *Provider) finishRequest(req *http.Request) ([]byte, error) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call %v: %v", req.URL.Path, err)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response: %v", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%v response from server for %v: %v", resp.StatusCode, req.URL.Path, string(b))
	}

	return b, nil
}

func (p *Provider) doGet(ctx context.Context, path string) ([]byte, error) {
	req, err := p.prepareRequest(ctx, "GET", path, nil)
	if err != nil {
		return nil, err
	}
	return p.finishRequest(req)
}

func (p *Provider) doPost(ctx context.Context, path string, value any) ([]byte, error) {
	vals := url.Values{}
	if value != nil {
		if err := schema.NewEncoder().Encode(value, vals); err != nil {
			return nil, fmt.Errorf("failed to encode POST values: %v", err)
		}
	}

	req, err := p.prepareRequest(ctx, "POST", path, []byte(vals.Encode()))
	if err != nil {
		return nil, err
	}

	if value != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return p.finishRequest(req)
}

func (p *Provider) doDNS(ctx context.Context, zone, command string, record *nfsRecord) ([]byte, error) {
	path := fmt.Sprintf("/dns/%v/%v", strings.TrimSuffix(zone, "."), command)
	if record == nil {
		return p.doPost(ctx, path, nil)
	}
	return p.doPost(ctx, path, *record)
}

func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	b, err := p.doDNS(ctx, zone, "listRRs", nil)
	if err != nil {
		return nil, err
	}
	var records []nfsRecord
	if err := json.Unmarshal(b, &records); err != nil {
		return nil, fmt.Errorf("failed to deserialize DNS server response: %v", err)
	}

	var result []libdns.Record
	for _, r := range records {
		record := libdns.Record{
			ID:       "",
			Type:     r.Type,
			Name:     r.Name,
			Value:    r.Data,
			TTL:      time.Duration(r.TTL) * time.Second,
			Priority: r.Aux,
		}
		result = append(result, record)
	}
	return result, nil
}

func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if len(records) == 0 {
		return nil, nil
	}
	if len(records) > 1 {
		// There is no way to avoid partial state updates in case of an error.
		return nil, fmt.Errorf("this DNS provider can only alter one record at a time")
	}

	r := records[0]
	_, err := p.doDNS(ctx, zone, "replaceRR", &nfsRecord{
		Name: r.Name,
		Type: r.Type,
		Data: r.Value,
		TTL:  int(r.TTL.Seconds()),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update DNS record: %v", err)
	}

	newRecords, err := p.GetRecords(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("failed to get new records after a successful update: %v", err)
	}

	for _, nr := range newRecords {
		if nr.Name == r.Name && nr.Type == r.Type && nr.Value == r.Value {
			return []libdns.Record{nr}, nil
		}
	}

	return nil, fmt.Errorf("after the update, could not find the new record")
}

func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if len(records) == 0 {
		return nil, nil
	}
	if len(records) > 1 {
		// There is no way to avoid partial state updates in case of an error.
		return nil, fmt.Errorf("this DNS provider can only alter one record at a time")
	}
	r := records[0]

	_, err := p.doDNS(ctx, zone, "addRR", &nfsRecord{
		Name: r.Name,
		Type: r.Type,
		Data: r.Value,
		TTL:  int(r.TTL.Seconds()),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to add DNS record: %v", err)
	}

	newRecords, err := p.GetRecords(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("failed to get new records after a successful update: %v", err)
	}

	for _, nr := range newRecords {
		if nr.Name == r.Name && nr.Type == r.Type && nr.Value == r.Value {
			return []libdns.Record{nr}, nil
		}
	}

	return nil, fmt.Errorf("after the update, could not find the new record")
}

func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if len(records) == 0 {
		return nil, nil
	}
	if len(records) > 1 {
		// There is no way to avoid partial state updates in case of an error.
		return nil, fmt.Errorf("this DNS provider can only alter one record at a time")
	}
	r := records[0]

	_, err := p.doDNS(ctx, zone, "removeRR", &nfsRecord{
		Name: r.Name,
		Type: r.Type,
		Data: r.Value,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to remove DNS record: %v", err)
	}

	return records, nil
}

type nfsRecord struct {
	Name string `json:"name" schema:"name"`
	Type string `json:"type" schema:"type"`
	Data string `json:"data" schema:"data"`
	TTL  int    `json:"ttl" schema:"ttl,omitempty"`
	Aux  int    `json:"aux,omitempty" schema:"aux,omitempty"`
}

func generateSalt() (string, error) {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func sha1Hash(b []byte) string {
	hash := sha1.Sum(b)
	slice := hash[:]
	return hex.EncodeToString(slice)
}

func generateAuthHeader(clock clock, salter salter, username, apiKey, requestPath string, body []byte) (string, error) {
	salt, err := salter()
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %v", err)
	}
	timestamp := clock().Unix()

	hashInput := fmt.Sprintf("%v;%v;%v;%v;%v;%v", username, timestamp, salt, apiKey, requestPath, sha1Hash(body))
	hash := sha1Hash([]byte(hashInput))
	return fmt.Sprintf("%v;%v;%v;%v", username, timestamp, salt, hash), nil
}
