package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// پراکسی بالادستی (اگر کاربر قبلاً پراکسی/VPN سیستمی داشته)؛ روی newClient هم اعمال می‌شود
var proxyFunc = http.ProxyFromEnvironment

type proxyOpts struct {
	Port      int
	SysProxy  bool
	NoBrowser bool
	Conns     int
	ChunkMB   int
	MinMB     int
	AllIfaces bool
}

// ---------- رویدادها (برای داشبورد) ----------

type Event struct {
	ID    int64   `json:"id"`
	Time  string  `json:"time"`
	Kind  string  `json:"kind"` // accel | pass | tunnel
	Host  string  `json:"host"`
	Path  string  `json:"path"`
	Size  int64   `json:"size"`
	Done  int64   `json:"done"`
	Speed float64 `json:"speed"`
	State string  `json:"state"` // running | done | error
	Note  string  `json:"note"`
	Conns   int    `json:"conns"`
	ChunkKB int    `json:"chunkKB"`
	Mode    string `json:"mode"`
}

type Hub struct {
	mu    sync.Mutex
	list  []*Event
	hosts map[string]*Event
	next  int64
}

func newHub() *Hub { return &Hub{hosts: map[string]*Event{}} }

func (h *Hub) add(e *Event) *Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next++
	e.ID = h.next
	e.Time = time.Now().Format("15:04:05")
	h.list = append(h.list, e)
	if len(h.list) > 300 {
		h.list = h.list[len(h.list)-300:]
	}
	return e
}

func (h *Hub) update(e *Event, f func(*Event)) {
	h.mu.Lock()
	f(e)
	h.mu.Unlock()
}

// یک ردیف برای هر هاست (تعداد اتصال و حجم کل)
func (h *Hub) hostEvent(kind, host string) *Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := kind + "|" + host
	if e, ok := h.hosts[key]; ok {
		e.Done++
		e.Time = time.Now().Format("15:04:05")
		return e
	}
	h.next++
	e := &Event{ID: h.next, Time: time.Now().Format("15:04:05"), Kind: kind, Host: host, Done: 1, State: "running"}
	h.hosts[key] = e
	h.list = append(h.list, e)
	return e
}

func (h *Hub) addBytes(e *Event, n int64) {
	h.mu.Lock()
	e.Size += n
	h.mu.Unlock()
}

func (h *Hub) snapshot() []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := []Event{}
	for i := len(h.list) - 1; i >= 0 && len(out) < 80; i-- {
		out = append(out, *h.list[i])
	}
	return out
}

// ---------- پراکسی ----------

type proxy struct {
	hub      *Hub
	opts     proxyOpts
	tr       *http.Transport
	clients  []*http.Client
	upstream *url.URL
	noRange  sync.Map
	smu      sync.Mutex
	stats    map[string]*hostStat
}

type hostStat struct {
	bestL     int
	noGain    int
	skipUntil time.Time
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (p *proxy) learn(host string, L int) {
	p.smu.Lock()
	defer p.smu.Unlock()
	st := p.stats[host]
	if st == nil {
		st = &hostStat{}
		p.stats[host] = st
	}
	if L <= 1 {
		st.bestL = 0
		st.noGain++
		if st.noGain >= 2 { // دو بار پشت هم موازی‌سازی فایده نداشت: برای این سرور خاموش شو
			st.skipUntil = time.Now().Add(15 * time.Minute)
			st.noGain = 0
		}
	} else {
		st.noGain = 0
		st.bestL = L
	}
}

var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func delHop(h http.Header) {
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

func newProxy(o proxyOpts, hub *Hub) *proxy {
	if o.Conns < 1 {
		o.Conns = 32
	}
	if o.ChunkMB < 1 {
		o.ChunkMB = 2
	}
	if o.MinMB < 1 {
		o.MinMB = 8
	}
	ips := []string{""}
	if o.AllIfaces {
		ips = nil
		for _, i := range listIfaces() {
			ips = append(ips, i.IP)
		}
		if len(ips) == 0 {
			ips = []string{""}
		}
	}
	p := &proxy{hub: hub, opts: o, stats: map[string]*hostStat{}}
	for _, ip := range ips {
		p.clients = append(p.clients, newClient(ip))
	}
	p.tr = &http.Transport{
		Proxy:                 proxyFunc,
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConnsPerHost:   16,
	}
	if u, err := proxyFunc(&http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}}); err == nil {
		p.upstream = u
	}
	return p
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.tunnel(w, r)
		return
	}
	if !r.URL.IsAbs() {
		http.Error(w, "ParDL proxy", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodGet && r.Header.Get("Range") == "" && r.Header.Get("Upgrade") == "" {
		if p.tryAccelerate(w, r) {
			return
		}
	}
	p.passthrough(w, r)
}

func (p *proxy) passthrough(w http.ResponseWriter, r *http.Request) {
	ev := p.hub.hostEvent("pass", r.URL.Host)
	out := r.Clone(r.Context())
	out.RequestURI = ""
	delHop(out.Header)
	resp, err := p.tr.RoundTrip(out)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	delHop(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)
	p.hub.addBytes(ev, n)
}

func (p *proxy) dialTunnel(host string) (net.Conn, error) {
	if p.upstream == nil {
		return net.DialTimeout("tcp", host, 15*time.Second)
	}
	c, err := net.DialTimeout("tcp", p.upstream.Host, 15*time.Second)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil {
		c.Close()
		return nil, err
	}
	if resp.StatusCode != 200 {
		c.Close()
		return nil, fmt.Errorf("upstream HTTP %d", resp.StatusCode)
	}
	return c, nil
}

func (p *proxy) tunnel(w http.ResponseWriter, r *http.Request) {
	dst, err := p.dialTunnel(r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		dst.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	src, _, err := hj.Hijack()
	if err != nil {
		dst.Close()
		return
	}
	_, _ = src.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	ev := p.hub.hostEvent("tunnel", r.Host)
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(a, b net.Conn) {
		defer wg.Done()
		n, _ := io.Copy(a, b)
		p.hub.addBytes(ev, n)
		if tc, ok := a.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}
	go cp(dst, src)
	go cp(src, dst)
	wg.Wait()
	src.Close()
	dst.Close()
}

func (p *proxy) newReq(ctx context.Context, hdr http.Header, u, rng string) *http.Request {
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	delHop(req.Header)
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Range", rng)
	return req
}

type accel struct {
	ctx    context.Context
	cancel context.CancelFunc
	size   int64
	final  string
	hdr    http.Header
	errc   chan error
	order  chan chan []byte

	received int64 // بایت‌هایی که از سرور رسیده (atomic)

	mu         sync.Mutex
	cond       *sync.Cond
	limit      int // تعداد اتصال هم‌زمان مطلوب (توسط کنترلر هر لحظه تغییر می‌کند)
	chunk      int64
	active     int
	unconsumed int
	phase      string
}

func (a *accel) getLimit() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.limit
}

func (a *accel) setLimit(n int) {
	a.mu.Lock()
	a.limit = n
	a.cond.Broadcast()
	a.mu.Unlock()
}

func (a *accel) launch(p *proxy) {
	defer close(a.order)
	var off int64
	for i := 0; off < a.size; i++ {
		a.mu.Lock()
		for a.ctx.Err() == nil && !(a.active < a.limit && a.unconsumed < 2*a.limit+2) {
			a.cond.Wait()
		}
		if a.ctx.Err() != nil {
			a.mu.Unlock()
			return
		}
		a.active++
		a.unconsumed++
		cs := a.chunk
		a.mu.Unlock()

		start := off
		end := start + cs - 1
		if end > a.size-1 {
			end = a.size - 1
		}
		res := make(chan []byte, 1)
		a.order <- res
		go func(c *http.Client) {
			buf, err := p.fetchBuf(a.ctx, c, a.final, a.hdr, start, end, &a.received)
			a.mu.Lock()
			a.active--
			a.cond.Broadcast()
			a.mu.Unlock()
			if err != nil {
				select {
				case a.errc <- err:
				default:
				}
				a.cancel()
				return
			}
			res <- buf
		}(p.clients[i%len(p.clients)])
		off = end + 1
	}
}

// کنترلر: هر ۱٫۵ ثانیه سرعت واقعی را می‌سنجد و تعداد اتصال و اندازه تکه را تنظیم می‌کند
func (a *accel) control(max int, warm bool) {
	t := time.NewTicker(1500 * time.Millisecond)
	defer t.Stop()
	lastR := atomic.LoadInt64(&a.received)
	lastT := time.Now()
	phase := "ramp"
	if warm {
		phase = "hold"
	}
	a.mu.Lock()
	a.phase = phase
	a.mu.Unlock()
	var bestS, holdS float64
	bestL := a.getLimit()
	probing := false
	prevL := bestL
	dir := 1
	ticks := 0
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-t.C:
		}
		r := atomic.LoadInt64(&a.received)
		now := time.Now()
		s := float64(r-lastR) / now.Sub(lastT).Seconds()
		lastR, lastT = r, now
		L := a.getLimit()

		if phase == "ramp" {
			// فاز یافتن: تا وقتی اضافه کردن اتصال ≥۱۰٪ سرعت می‌دهد، دو برابر کن
			if bestS == 0 || s > bestS*1.10 {
				bestS, bestL = s, L
				if L >= max {
					phase, holdS = "hold", s
				} else {
					next := L * 2
					if next > max {
						next = max
					}
					a.setLimit(next)
				}
			} else {
				a.setLimit(bestL)
				phase, holdS = "hold", bestS
			}
		} else if probing {
			// نتیجه‌ی آزمایشِ دور قبل: اگر بهتر بود نگه دار، وگرنه برگرد
			ok := false
			if dir > 0 {
				ok = s > holdS*1.08
			} else {
				ok = s >= holdS*0.97
			}
			if ok {
				holdS = s
			} else {
				a.setLimit(prevL)
			}
			probing = false
			dir = -dir
			ticks = 0
		} else {
			if holdS == 0 {
				holdS = s
			} else {
				holdS = holdS*0.5 + s*0.5
			}
			ticks++
			if ticks >= 3 { // هر چند ثانیه یک آزمایش: یک بار بیشتر، یک بار کمتر
				prevL = L
				nl := L
				if dir > 0 {
					nl = L + maxInt(1, L/4)
					if nl > max {
						nl = max
					}
				} else {
					nl = L - maxInt(1, L/4)
					if nl < 1 {
						nl = 1
					}
				}
				if nl == L {
					dir = -dir
					ticks = 0
				} else {
					a.setLimit(nl)
					probing = true
				}
			}
		}

		// اندازه تکه: حدود ۱٫۵ ثانیه کار برای هر اتصال
		L = a.getLimit()
		c := int64(s / float64(maxInt(L, 1)) * 1.5)
		if c < 512<<10 {
			c = 512 << 10
		}
		if c > 8<<20 {
			c = 8 << 20
		}
		c -= c % (256 << 10)
		if lim := int64(256<<20) / int64(2*L+2); c > lim {
			c = lim
		}
		a.mu.Lock()
		a.chunk = c
		a.phase = phase
		a.mu.Unlock()
	}
}

func (p *proxy) tryAccelerate(w http.ResponseWriter, r *http.Request) bool {
	host := r.URL.Host
	key := host + r.URL.Path
	if v, ok := p.noRange.Load(key); ok && time.Since(v.(time.Time)) < 10*time.Minute {
		return false
	}
	p.smu.Lock()
	var skip bool
	var warmL int
	if st := p.stats[host]; st != nil {
		skip = time.Now().Before(st.skipUntil)
		warmL = st.bestL
	}
	p.smu.Unlock()
	if skip { // قبلاً معلوم شده موازی‌سازی روی این سرور فایده ندارد → خاموش
		return false
	}

	hdr := r.Header.Clone()
	resp, err := p.clients[0].Do(p.newReq(r.Context(), hdr, r.URL.String(), "bytes=0-0"))
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	resp.Body.Close()

	var size int64
	if resp.StatusCode == 206 {
		cr := resp.Header.Get("Content-Range")
		if i := strings.LastIndex(cr, "/"); i > 0 {
			size, _ = strconv.ParseInt(strings.TrimSpace(cr[i+1:]), 10, 64)
		}
	}
	if size < int64(p.opts.MinMB)<<20 || resp.Header.Get("Content-Encoding") != "" {
		p.noRange.Store(key, time.Now())
		return false
	}

	path := r.URL.Path
	if len(path) > 70 {
		path = "…" + path[len(path)-70:]
	}
	ev := p.hub.add(&Event{Kind: "accel", Host: host, Path: path, Size: size, State: "running"})

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	h := w.Header()
	for _, k := range []string{"Content-Type", "Last-Modified", "ETag", "Content-Disposition", "Cache-Control"} {
		if v := resp.Header.Get(k); v != "" {
			h.Set(k, v)
		}
	}
	h.Set("Content-Length", strconv.FormatInt(size, 10))
	w.WriteHeader(http.StatusOK)

	startL := 1
	warm := false
	if warmL > 1 {
		startL, warm = warmL, true
	}
	if startL > p.opts.Conns {
		startL = p.opts.Conns
	}
	a := &accel{
		ctx: ctx, cancel: cancel, size: size, final: resp.Request.URL.String(), hdr: hdr,
		errc:  make(chan error, 1),
		order: make(chan chan []byte, 2*p.opts.Conns+8),
		limit: startL, chunk: 1 << 20, phase: "ramp",
	}
	a.cond = sync.NewCond(&a.mu)
	stopWake := context.AfterFunc(ctx, func() {
		a.mu.Lock()
		a.cond.Broadcast()
		a.mu.Unlock()
	})
	defer stopWake()
	go a.launch(p)
	go a.control(p.opts.Conns, warm)

	begin := time.Now()
	fail := func(note string) bool {
		select {
		case err := <-a.errc:
			note = err.Error()
		default:
		}
		p.hub.update(ev, func(e *Event) { e.State = "error"; e.Note = note; e.Speed = 0 })
		if r.Context().Err() == nil {
			panic(http.ErrAbortHandler) // اتصال را قطع کن تا برنامه دوباره تلاش کند
		}
		return true
	}

	var sent, lastN int64
	lastT := time.Now()
	for res := range a.order {
		select {
		case buf := <-res:
			if _, err := w.Write(buf); err != nil {
				cancel()
				p.hub.update(ev, func(e *Event) { e.State = "error"; e.Note = "برنامه دانلود را قطع کرد"; e.Speed = 0 })
				return true
			}
			sent += int64(len(buf))
			a.mu.Lock()
			a.unconsumed--
			a.cond.Broadcast()
			lim, ck, ph := a.limit, a.chunk, a.phase
			a.mu.Unlock()
			dt := time.Since(lastT)
			var sp float64
			if dt >= 500*time.Millisecond {
				sp = float64(sent-lastN) / dt.Seconds()
				lastN, lastT = sent, time.Now()
			}
			p.hub.update(ev, func(e *Event) {
				e.Done = sent
				if sp > 0 {
					e.Speed = e.Speed*0.5 + sp*0.5
				}
				e.Conns, e.ChunkKB, e.Mode = lim, int(ck>>10), ph
			})
		case <-ctx.Done():
			return fail("قطع شد")
		}
	}
	if sent != size {
		return fail("قطع شد")
	}

	finalL := a.getLimit()
	note := ""
	if finalL <= 1 {
		note = "موازی‌سازی کمکی نکرد؛ تک‌اتصال"
	}
	p.hub.update(ev, func(e *Event) { e.Done = size; e.State = "done"; e.Speed = 0; e.Note = note; e.Conns = finalL })
	if time.Since(begin) >= 6*time.Second {
		p.learn(host, finalL)
	}
	return true
}

func (p *proxy) fetchBuf(ctx context.Context, c *http.Client, u string, hdr http.Header, a, b int64, cnt *int64) ([]byte, error) {
	var last error
	for try := 0; try < 6; try++ {
		if try > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(try) * time.Second):
			}
		}
		buf, err := p.fetchOnce(ctx, c, u, hdr, a, b, cnt)
		if err == nil {
			return buf, nil
		}
		last = err
	}
	return nil, last
}

func (p *proxy) fetchOnce(ctx context.Context, c *http.Client, u string, hdr http.Header, a, b int64, cnt *int64) ([]byte, error) {
	rctx, rcancel := context.WithCancel(ctx)
	defer rcancel()
	timer := time.AfterFunc(stall, rcancel)
	defer timer.Stop()

	resp, err := c.Do(p.newReq(rctx, hdr, u, fmt.Sprintf("bytes=%d-%d", a, b)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 206 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	want := b - a + 1
	buf := make([]byte, want)
	var read int64
	for read < want {
		timer.Reset(stall)
		m, err := resp.Body.Read(buf[read:])
		read += int64(m)
		if cnt != nil && m > 0 {
			atomic.AddInt64(cnt, int64(m))
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if read < want {
					return nil, io.ErrUnexpectedEOF
				}
				break
			}
			return nil, err
		}
	}
	return buf, nil
}

// ---------- پراکسی سیستم ویندوز ----------

const inetKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

type sysBackup struct {
	Enable string `json:"enable"`
	Server string `json:"server"`
}

func backupPath() string { return filepath.Join(os.TempDir(), "pardl-sysproxy-backup.json") }

func regGet(name string) string {
	out, err := exec.Command("reg", "query", inetKey, "/v", name).Output()
	if err != nil {
		return ""
	}
	for _, ln := range strings.Split(string(out), "\n") {
		f := strings.Fields(ln)
		if len(f) >= 3 && f[0] == name {
			return strings.Join(f[2:], " ")
		}
	}
	return ""
}

func regSet(name, typ, val string) {
	_ = exec.Command("reg", "add", inetKey, "/v", name, "/t", typ, "/d", val, "/f").Run()
}

func readSysProxy() sysBackup {
	if runtime.GOOS != "windows" {
		return sysBackup{}
	}
	return sysBackup{Enable: regGet("ProxyEnable"), Server: regGet("ProxyServer")}
}

func applySysProxy(prev sysBackup, addr string) {
	b, _ := json.Marshal(prev)
	_ = os.WriteFile(backupPath(), b, 0o644)
	regSet("ProxyServer", "REG_SZ", addr)
	regSet("ProxyEnable", "REG_DWORD", "1")
}

func restoreSysProxy() {
	if runtime.GOOS != "windows" {
		return
	}
	b, err := os.ReadFile(backupPath())
	if err != nil {
		regSet("ProxyEnable", "REG_DWORD", "0")
		return
	}
	var prev sysBackup
	_ = json.Unmarshal(b, &prev)
	if prev.Server != "" {
		regSet("ProxyServer", "REG_SZ", prev.Server)
	}
	if prev.Enable == "" {
		regSet("ProxyEnable", "REG_DWORD", "0")
	} else {
		regSet("ProxyEnable", "REG_DWORD", prev.Enable)
	}
	_ = os.Remove(backupPath())
}

func parseUpstream(s string) *url.URL {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if strings.ContainsAny(s, "=;") {
		found := ""
		for _, part := range strings.Split(s, ";") {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 && (kv[0] == "http" || kv[0] == "https") {
				found = kv[1]
				break
			}
		}
		if found == "" {
			return nil
		}
		s = found
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil
	}
	return u
}

// ---------- اجرای حالت پراکسی + داشبورد ----------

func runProxyMode(o proxyOpts) {
	if o.Port == 0 {
		o.Port = 8899
	}
	addr := fmt.Sprintf("127.0.0.1:%d", o.Port)

	// اگر دفعه قبل برنامه ناگهانی بسته شده، اول تنظیمات قبلی را برگردان
	if _, err := os.Stat(backupPath()); err == nil {
		restoreSysProxy()
	}

	prev := readSysProxy()
	upstreamNote := ""
	if o.SysProxy && prev.Enable == "0x1" && prev.Server != "" && prev.Server != addr {
		if u := parseUpstream(prev.Server); u != nil {
			proxyFunc = http.ProxyURL(u)
			upstreamNote = "پراکسی قبلی سیستم حفظ شد و به‌عنوان بالادست استفاده می‌شود: " + u.Host
		} else {
			upstreamNote = "⚠️ پراکسی قبلی سیستم از نوع پشتیبانی‌نشده است (مثلاً SOCKS) و ممکن است قطع شود"
		}
	}

	hub := newHub()
	px := newProxy(o, hub)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Println("پورت پراکسی باز نشد:", err)
		os.Exit(1)
	}
	go func() {
		_ = (&http.Server{Handler: px, ReadHeaderTimeout: 30 * time.Second}).Serve(ln)
	}()

	sysOn := false
	if o.SysProxy && runtime.GOOS == "windows" {
		applySysProxy(prev, addr)
		sysOn = true
	}
	cleanup := func() {
		if sysOn {
			restoreSysProxy()
			sysOn = false
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		cleanup()
		os.Exit(0)
	}()

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

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	})
	mux.HandleFunc("/api/events", auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"events":   hub.snapshot(),
			"sysProxy": sysOn,
			"addr":     addr,
			"note":     upstreamNote,
			"max":      o.Conns,
			"minMB":    o.MinMB,
		})
	}))
	mux.HandleFunc("/api/stop", auth(func(w http.ResponseWriter, r *http.Request) {
		cleanup()
		_, _ = io.WriteString(w, `{"ok":true}`)
		go func() { time.Sleep(300 * time.Millisecond); os.Exit(0) }()
	}))

	dl, err := net.Listen("tcp", "127.0.0.1:8765")
	if err != nil {
		dl, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			cleanup()
			fmt.Println("خطا:", err)
			os.Exit(1)
		}
	}
	durl := "http://" + dl.Addr().String()
	fmt.Println("ParDL فعال شد.")
	fmt.Println("  پراکسی:  ", addr, map[bool]string{true: "(روی پراکسی ویندوز تنظیم شد)", false: "(پراکسی ویندوز تنظیم نشد؛ دستی ست کن)"}[sysOn])
	fmt.Println("  داشبورد: ", durl)
	if upstreamNote != "" {
		fmt.Println("  ", upstreamNote)
	}
	fmt.Println("این پنجره را با Ctrl+C ببند تا تنظیمات پراکسی ویندوز برگردد.")
	if !o.NoBrowser {
		openBrowser(durl)
	}
	_ = http.Serve(dl, mux)
}
