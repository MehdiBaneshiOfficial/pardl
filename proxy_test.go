package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestProxyAccelerates(t *testing.T) {
	data := make([]byte, 25<<20+777)
	_, _ = rand.Read(data)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "f.bin", time.Now(), bytes.NewReader(data))
	}))
	defer origin.Close()

	hub := newHub()
	ps := httptest.NewServer(newProxy(proxyOpts{Conns: 8, ChunkMB: 1, MinMB: 8}, hub))
	defer ps.Close()
	pu, _ := url.Parse(ps.URL)
	cl := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}, Timeout: 60 * time.Second}

	resp, err := cl.Get(origin.URL + "/f.bin")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("محتوا با اصل یکی نیست")
	}
	found := false
	for _, e := range hub.snapshot() {
		if e.Kind == "accel" && e.State == "done" {
			found = true
		}
	}
	if !found {
		t.Fatal("دانلود شتاب نگرفته (accel ثبت نشد)")
	}
}
