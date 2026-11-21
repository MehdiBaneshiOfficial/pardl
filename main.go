package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed ui.html
var uiHTML string

const (
	ua    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ParDL/1.0"
	stall = 20 * time.Second // اگر این مدت هیچ داده‌ای نیامد، اتصال قطع و دوباره تلاش می‌شود
)

type Config struct {
	URLs    []string `json:"urls"`
	Dir     string   `json:"dir"`
	Conns   int      `json:"conns"`
	ChunkMB int      `json:"chunkMB"`
	Ifaces  []string `json:"ifaces"` // IPهای محلی؛ هر اتصال به‌صورت چرخشی از یکی‌شان خارج می‌شود
}

type Status struct {
	State   string  `json:"state"` // idle | probing | downloading | done | error | cancelled
	Err     string  `json:"err"`
	File    string  `json:"file"`
	Path    string  `json:"path"`
	Size    int64   `json:"size"`
	Done    int64   `json:"done"`
	Speed   float64 `json:"speed"`
	Avg     float64 `json:"avg"`
	Elapsed float64 `json:"elapsed"`
	ETA     float64 `json:"eta"`
	Workers int     `json:"workers"`
	RangeOK bool    `json:"rangeOK"`
	Mirrors int     `json:"mirrors"`
}

type saved struct {
	URL   string `json:"url"`
	Size  int64  `json:"size"`
	Chunk int64  `json:"chunk"`
	Done  []bool `json:"done"`
}

type fatalErr struct{ err error }

func (f fatalErr) Error() string { return f.err.Error() }
func (f fatalErr) Unwrap() error { return f.err }

type Downloader struct {
	mu      sync.Mutex
	st      Status
	running bool
	cancel  context.CancelFunc
	done    int64
	base    int64
	startT  time.Time
	endT    time.Time
}

func (c *Config) normalize() error {
	var urls []string
	for _, u := range c.URLs {
		u = strings.TrimSpace(u)
		if u != "" {
			urls = append(urls, u)
		}
	}
	if len(urls) == 0 {
		return errors.New("لینکی وارد نشده")
	}
	c.URLs = urls
	if c.Conns < 1 {
		c.Conns = 16
	}
	if c.Conns > 64 {
		c.Conns = 64
	}
	if c.ChunkMB < 1 {
		c.ChunkMB = 2
	}
	if c.Dir == "" {
		home, _ := os.UserHomeDir()
		c.Dir = filepath.Join(home, "Downloads")
	}
	return os.MkdirAll(c.Dir, 0o755)
}

func (d *Downloader) Start(cfg Config) error {
	if err := cfg.normalize(); err != nil {
		return err
	}
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return errors.New("یک دانلود در حال انجام است")
	}
	d.running = true
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel
	d.st = Status{State: "probing"}
	atomic.StoreInt64(&d.done, 0)
	d.base = 0
	d.startT = time.Now()
	d.endT = time.Time{}
	d.mu.Unlock()

	go func() {
		err := d.run(ctx, cfg)
		d.mu.Lock()
		d.running = false
		d.endT = time.Now()
		d.st.Speed = 0
		switch {
		case err == nil:
			d.st.State = "done"
		case ctx.Err() != nil:
			d.st.State = "cancelled"
		default:
			d.st.State = "error"
			d.st.Err = err.Error()
		}
		d.mu.Unlock()
		cancel()
	}()
	return nil
}

func (d *Downloader) Cancel() {
	d.mu.Lock()
	c := d.cancel
	d.mu.Unlock()
	if c != nil {
		c()
	}
}

func (d *Downloader) Status() Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.st
	s.Done = atomic.LoadInt64(&d.done)
	if !d.startT.IsZero() {
		end := d.endT
		if end.IsZero() {
			end = time.Now()
		}
		s.Elapsed = end.Sub(d.startT).Seconds()
		if s.Elapsed > 0 {
			s.Avg = float64(s.Done-d.base) / s.Elapsed
		}
	}
	if s.Speed > 1 && s.Size > s.Done {
		s.ETA = float64(s.Size-s.Done) / s.Speed
	}
	return s
}

func (d *Downloader) setInfo(p string, size int64, workers int, rangeOK bool, mirrors int) {
	d.mu.Lock()
	d.st.Path = p
	d.st.File = filepath.Base(p)
	d.st.Size = size
	d.st.Workers = workers
	d.st.RangeOK = rangeOK
	d.st.Mirrors = mirrors
	d.st.State = "downloading"
	d.mu.Unlock()
}

func newClient(ip string) *http.Client {
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	if ip != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(ip)}
	}
	tr := &http.Transport{
		Proxy:       http.ProxyFromEnvironment,
		DialContext: dialer.DialContext,
		// HTTP/2 را خاموش می‌کنیم تا هر worker واقعاً یک اتصال TCP جدا داشته باشد
		TLSClientConfig:       &tls.Config{},
		TLSNextProto:          map[string]func(string, *tls.Conn) http.RoundTripper{},
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConnsPerHost:   4,
	}
	return &http.Client{Transport: tr}
}

func sanitize(n string) string {
	n = filepath.Base(strings.ReplaceAll(n, "\\", "/"))
	n = strings.NewReplacer("<", "_", ">", "_", ":", "_", "\"", "_", "|", "_", "?", "_", "*", "_").Replace(n)
	n = strings.TrimSpace(n)
	if n == "" || n == "." || n == ".." {
		return "download.bin"
	}
	return n
}

func fileName(resp *http.Response, raw string) string {
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if _, p, err := mime.ParseMediaType(cd); err == nil && p["filename"] != "" {
			return sanitize(p["filename"])
		}
	}
	if u, err := url.Parse(raw); err == nil {
		b := path.Base(u.Path)
		if b != "" && b != "/" && b != "." {
			if dec, err := url.PathUnescape(b); err == nil {
				b = dec
			}
			return sanitize(b)
		}
	}
	return "download.bin"
}

func uniquePath(p string) string {
	if _, err := os.Stat(p); err != nil {
		return p
	}
	ext := filepath.Ext(p)
	base := strings.TrimSuffix(p, ext)
	for i := 1; ; i++ {
		q := fmt.Sprintf("%s (%d)%s", base, i, ext)
		if _, err := os.Stat(q); err != nil {
			return q
		}
	}
}

func probe(ctx context.Context, c *http.Client, u string) (size int64, rangeOK bool, name string, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return
	}
	req.Header.Set("Range", "bytes=0-0")
	req.Header.Set("User-Agent", ua)
	resp, err := c.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	name = fileName(resp, u)
	switch resp.StatusCode {
	case 206:
		cr := resp.Header.Get("Content-Range") // bytes 0-0/12345
		if i := strings.LastIndex(cr, "/"); i > 0 {
			size, _ = strconv.ParseInt(strings.TrimSpace(cr[i+1:]), 10, 64)
		}
		rangeOK = size > 0
	case 200:
		size = resp.ContentLength
	default:
		err = fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return
}

func (d *Downloader) run(ctx context.Context, cfg Config) error {
	chunk := int64(cfg.ChunkMB) << 20
	ips := cfg.Ifaces
	if len(ips) == 0 {
		ips = []string{""}
	}

	// ۱) بررسی لینک‌ها (لینک‌های اضافه = میرور همان فایل)
	var urls []string
	var size int64
	var name string
	var rangeOK bool
	var lastErr error
	for _, u := range cfg.URLs {
		s, r, n, err := probe(ctx, newClient(ips[0]), u)
		if err != nil {
			lastErr = err
			continue
		}
		if len(urls) == 0 {
			size, rangeOK, name = s, r, n
			urls = append(urls, u)
		} else if s == size && r == rangeOK {
			urls = append(urls, u)
		}
	}
	if len(urls) == 0 {
		return fmt.Errorf("اتصال به لینک ناموفق بود: %v", lastErr)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !rangeOK || size <= 0 {
		return d.single(ctx, cfg, urls[0], name, size)
	}

	// ۲) آماده‌سازی فایل و ادامه از جای قبلی
	p := filepath.Join(cfg.Dir, name)
	n := int((size + chunk - 1) / chunk)
	var doneChunks []bool
	resumed := false
	if b, err := os.ReadFile(p + ".pdstate"); err == nil {
		var s saved
		if json.Unmarshal(b, &s) == nil && s.Size == size && s.Chunk == chunk && len(s.Done) == n {
			if _, err := os.Stat(p); err == nil {
				doneChunks, resumed = s.Done, true
			}
		}
	}
	if !resumed {
		p = uniquePath(p)
		doneChunks = make([]bool, n)
	}
	stPath := p + ".pdstate"

	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if !resumed {
		if err := f.Truncate(size); err != nil {
			return err
		}
	}

	chunkLen := func(i int) int64 {
		l := size - int64(i)*chunk
		if l > chunk {
			l = chunk
		}
		return l
	}
	var pending []int
	var already int64
	for i := 0; i < n; i++ {
		if doneChunks[i] {
			already += chunkLen(i)
		} else {
			pending = append(pending, i)
		}
	}
	atomic.StoreInt64(&d.done, already)
	d.mu.Lock()
	d.base = already
	d.mu.Unlock()

	workers := cfg.Conns
	if workers > len(pending) {
		workers = len(pending)
	}
	d.setInfo(p, size, workers, true, len(urls))

	queue := make(chan int, len(pending))
	for _, i := range pending {
		queue <- i
	}
	close(queue)

	var cm sync.Mutex
	save := func() {
		cm.Lock()
		b, _ := json.Marshal(saved{URL: urls[0], Size: size, Chunk: chunk, Done: doneChunks})
		cm.Unlock()
		_ = os.WriteFile(stPath, b, 0o644)
	}

	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		last := atomic.LoadInt64(&d.done)
		lastT := time.Now()
		ticks := 0
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				cur := atomic.LoadInt64(&d.done)
				now := time.Now()
				inst := float64(cur-last) / now.Sub(lastT).Seconds()
				last, lastT = cur, now
				d.mu.Lock()
				d.st.Speed = d.st.Speed*0.6 + inst*0.4
				d.mu.Unlock()
				ticks++
				if ticks%4 == 0 {
					save()
				}
			}
		}
	}()

	// ۳) دانلود موازی
	wctx, wcancel := context.WithCancel(ctx)
	defer wcancel()
	var once sync.Once
	var firstErr error
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			client := newClient(ips[w%len(ips)])
			for i := range queue {
				if wctx.Err() != nil {
					return
				}
				s := int64(i) * chunk
				e := s + chunkLen(i) - 1
				if err := d.fetchChunk(wctx, client, urls, w, f, s, e); err != nil {
					once.Do(func() { firstErr = err; wcancel() })
					return
				}
				cm.Lock()
				doneChunks[i] = true
				cm.Unlock()
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	save()

	if err := ctx.Err(); err != nil {
		return err
	}
	if firstErr != nil {
		return firstErr
	}
	_ = f.Sync()
	_ = os.Remove(stPath)
	return nil
}

func (d *Downloader) fetchChunk(ctx context.Context, c *http.Client, urls []string, pref int, f *os.File, s, e int64) error {
	length := e - s + 1
	var off int64
	fails, rot := 0, 0
	for off < length {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := d.fetchRange(ctx, c, urls[(pref+rot)%len(urls)], s+off, e, f)
		off += n
		if off >= length {
			return nil
		}
		var fe fatalErr
		if errors.As(err, &fe) {
			return err
		}
		if n > 0 {
			fails = 0
		} else {
			fails++
		}
		rot++ // اگر میرور داریم، بعد از خطا میرور بعدی را امتحان کن
		if fails > 6 {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return fmt.Errorf("دانلود یک تکه بعد از چند تلاش ناموفق بود: %w", err)
		}
		wait := fails
		if wait > 5 {
			wait = 5
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(wait) * time.Second):
		}
	}
	return nil
}

func (d *Downloader) fetchRange(ctx context.Context, c *http.Client, u string, a, b int64, f *os.File) (int64, error) {
	rctx, rcancel := context.WithCancel(ctx)
	defer rcancel()
	timer := time.AfterFunc(stall, rcancel)
	defer timer.Stop()

	req, err := http.NewRequestWithContext(rctx, "GET", u, nil)
	if err != nil {
		return 0, fatalErr{err}
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", a, b))
	req.Header.Set("User-Agent", ua)
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 206 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	buf := make([]byte, 128<<10)
	var n int64
	remaining := b - a + 1
	for remaining > 0 {
		timer.Reset(stall)
		want := int64(len(buf))
		if remaining < want {
			want = remaining
		}
		m, rerr := resp.Body.Read(buf[:want])
		if m > 0 {
			if _, werr := f.WriteAt(buf[:m], a+n); werr != nil {
				return n, fatalErr{werr}
			}
			n += int64(m)
			remaining -= int64(m)
			atomic.AddInt64(&d.done, int64(m))
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				if remaining > 0 {
					return n, io.ErrUnexpectedEOF
				}
				break
			}
			return n, rerr
		}
	}
	return n, nil
}

// سرور از Range پشتیبانی نمی‌کند: دانلود تک‌اتصالی
func (d *Downloader) single(ctx context.Context, cfg Config, u, name string, size int64) error {
	p := uniquePath(filepath.Join(cfg.Dir, name))
	d.setInfo(p, size, 1, false, 1)
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", ua)
	resp, err := newClient("").Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if size <= 0 && resp.ContentLength > 0 {
		d.mu.Lock()
		d.st.Size = resp.ContentLength
		d.mu.Unlock()
	}
	f, err := os.Create(p)
	if err != nil {
		return err
	}
	buf := make([]byte, 128<<10)
	for {
		m, rerr := resp.Body.Read(buf)
		if m > 0 {
			if _, werr := f.Write(buf[:m]); werr != nil {
				f.Close()
				return werr
			}
			atomic.AddInt64(&d.done, int64(m))
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			return rerr
		}
	}
	return f.Close()
}

// ---------- شبکه‌ها ----------

type IfaceInfo struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}

func listIfaces() []IfaceInfo {
	out := []IfaceInfo{}
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipn.IP.To4()
			if ip4 == nil || ip4.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, IfaceInfo{Name: i.Name, IP: ip4.String()})
		}
	}
	return out
}

// ---------- سرور محلی و رابط ----------

func openBrowser(u string) {
	switch runtime.GOOS {
	case "windows":
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	case "darwin":
		_ = exec.Command("open", u).Start()
	default:
		_ = exec.Command("xdg-open", u).Start()
	}
}

func main() {
	cliURL := flag.String("url", "", "حالت خط فرمان: لینک (چند میرور با ویرگول)")
	conns := flag.Int("n", 16, "تعداد اتصال همزمان")
	chunk := flag.Int("chunk", 2, "اندازه هر تکه (مگابایت)")
	dir := flag.String("dir", "", "پوشه ذخیره")
	allIf := flag.Bool("all-ifaces", false, "استفاده از همه شبکه‌های فعال (سیم‌کارت/وای‌فای)")
	noOpen := flag.Bool("no-browser", false, "مرورگر خودکار باز نشود")
	flag.Parse()

	d := &Downloader{}

	if *cliURL != "" {
		cfg := Config{URLs: strings.Split(*cliURL, ","), Dir: *dir, Conns: *conns, ChunkMB: *chunk}
		if *allIf {
			for _, i := range listIfaces() {
				cfg.Ifaces = append(cfg.Ifaces, i.IP)
			}
		}
		if err := d.Start(cfg); err != nil {
			fmt.Println("خطا:", err)
			os.Exit(1)
		}
		for {
			time.Sleep(time.Second)
			s := d.Status()
			fmt.Printf("\r%s  %.1f/%.1f MB  %.2f MB/s   ", s.State, float64(s.Done)/1e6, float64(s.Size)/1e6, s.Speed/1e6)
			if s.State != "probing" && s.State != "downloading" {
				fmt.Println()
				if s.State == "error" {
					fmt.Println("خطا:", s.Err)
					os.Exit(1)
				}
				fmt.Println("ذخیره شد:", s.Path)
				return
			}
		}
	}

	tb := make([]byte, 16)
	_, _ = rand.Read(tb)
	token := hex.EncodeToString(tb)
	page := strings.Replace(uiHTML, "__TOKEN__", token, 1)

	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Token") != token {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			h(w, r)
		}
	}
	writeJSON := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	})
	mux.HandleFunc("/api/ifaces", auth(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, listIfaces()) }))
	mux.HandleFunc("/api/status", auth(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, d.Status()) }))
	mux.HandleFunc("/api/cancel", auth(func(w http.ResponseWriter, r *http.Request) { d.Cancel(); writeJSON(w, map[string]bool{"ok": true}) }))
	mux.HandleFunc("/api/start", auth(func(w http.ResponseWriter, r *http.Request) {
		var cfg Config
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&cfg); err != nil {
			writeJSON(w, map[string]string{"error": "درخواست نامعتبر"})
			return
		}
		if err := d.Start(cfg); err != nil {
			writeJSON(w, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))

	ln, err := net.Listen("tcp", "127.0.0.1:8765")
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Println("خطا:", err)
			os.Exit(1)
		}
	}
	addr := "http://" + ln.Addr().String()
	fmt.Println("ParDL اجرا شد:", addr)
	fmt.Println("(این پنجره را نبند؛ با بستنش برنامه بسته می‌شود)")
	if !*noOpen {
		openBrowser(addr)
	}
	_ = http.Serve(ln, mux)
}
