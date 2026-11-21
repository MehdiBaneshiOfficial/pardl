package main

import (
	"bytes"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParallelDownload(t *testing.T) {
	data := make([]byte, 20<<20+12345)
	_, _ = rand.Read(data)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "t.bin", time.Now(), bytes.NewReader(data))
	}))
	defer srv.Close()

	dir := t.TempDir()
	d := &Downloader{}
	if err := d.Start(Config{URLs: []string{srv.URL + "/t.bin"}, Dir: dir, Conns: 8, ChunkMB: 1}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		s := d.Status()
		if s.State == "done" {
			break
		}
		if s.State == "error" || s.State == "cancelled" {
			t.Fatal(s.State, s.Err)
		}
		if time.Now().After(deadline) {
			t.Fatal("timeout")
		}
		time.Sleep(50 * time.Millisecond)
	}
	got, err := os.ReadFile(filepath.Join(dir, "t.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("محتوای فایل با اصل یکی نیست")
	}
}
