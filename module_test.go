package nearlyfreespeech

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/gorilla/mux"
	"github.com/libdns/libdns"
)

type fakeNFSServer struct {
	records map[string][]nfsRecord
}

func validateRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validating the header value is a real PITA.
		// There's a dedicated test for this in TestDoRequest.
		if r.Header.Get("X-NFSN-Authentication") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Missing auth header"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (f *fakeNFSServer) handleListRRs(w http.ResponseWriter, r *http.Request) {
	records := f.records[mux.Vars(r)["zone"]]
	b, err := json.Marshal(records)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("failed to marshal response: %v", err)))
		return
	}
	w.Write(b)
}

// func (f *fakeNFSServer) handle

func (f *fakeNFSServer) handler() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/dns/{zone}/listRRs", f.handleListRRs).Methods("POST")
	r.Use(validateRequest)
	return r
}

func TestGetRecords(t *testing.T) {
	f := &fakeNFSServer{
		records: map[string][]nfsRecord{
			"example.com": {
				{
					Name: "foo",
					Type: "A",
					Data: "127.0.0.1",
					TTL:  3600,
					Aux:  0,
				},
				{
					Name: "",
					Type: "MX",
					Data: "foo.com.",
					TTL:  5,
					Aux:  20,
				},
			},
		},
	}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	p := NewProvider("test-user", "test-key")
	p.apiURL = srv.URL

	tests := []struct {
		name string
		zone string
		want []libdns.Record
	}{
		{
			name: "Empty",
			zone: "foo.com",
			want: nil,
		},
		{
			name: "TwoRecords",
			zone: "example.com",
			want: []libdns.Record{
				{
					ID:       "",
					Type:     "A",
					Name:     "foo",
					Value:    "127.0.0.1",
					TTL:      time.Duration(1) * time.Hour,
					Priority: 0,
				},
				{
					ID:       "",
					Type:     "MX",
					Name:     "",
					Value:    "foo.com.",
					TTL:      time.Duration(5) * time.Second,
					Priority: 20,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := p.GetRecords(context.Background(), tt.zone)
			if err != nil {
				t.Fatalf("GetRecords: %v", err)
			}
			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Fatalf("GetRecords: diff (-want +got)\n%v", diff)
			}
		})
	}
}

func TestDoRequest(t *testing.T) {
	// Example taken from https://members.nearlyfreespeech.net/wiki/API/Introduction

	wantAuthHeader := "testuser;1012121212;dkwo28Sile4jdXkw;0fa8932e122d56e2f6d1550f9aab39c4aef8bfc4"
	wantPath := "/site/example/getInfo"
	handlerCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path != wantPath {
			t.Errorf("Path: want %q, got %q", wantPath, req.URL.Path)
		}
		got := req.Header.Get("X-NFSN-Authentication")
		if got != wantAuthHeader {
			t.Errorf("Auth header: invalid value\n  want: %q\n   got: %q\n", wantAuthHeader, got)
		}
		rw.Write(nil)
		handlerCalled = true
	}))
	defer srv.Close()

	p := NewProvider("testuser", "p3kxmRKf9dk3l6ls")
	p.apiURL = srv.URL
	p.clock = func() time.Time { return time.Unix(1012121212, 0) }
	p.salter = func() (string, error) { return "dkwo28Sile4jdXkw", nil }

	_, err := p.doGet(context.Background(), "/site/example/getInfo")
	if err != nil {
		t.Fatalf("doRequest: %v", err)
	}
	if !handlerCalled {
		t.Fatalf("test HTTP handler was not called")
	}
}
