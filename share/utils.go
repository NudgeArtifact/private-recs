package share

import (
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"runtime"
	"runtime/pprof"
	"sync/atomic"
)

var DebugMode = os.Getenv("DEBUG") == "1"
var MovielensMode = os.Getenv("MOVIELENS") == "1"
var Sketch = os.Getenv("SKETCH") == "1"

const NUM_VCPUS = 384

func PrintMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	fmt.Printf("Alloc = %v GiB", m.Alloc/1024/1024/1024)
	fmt.Printf("   TotalAlloc = %v GiB", m.TotalAlloc/1024/1024/1024)
	fmt.Printf("   Sys = %v GiB", m.Sys/1024/1024/1024)
	fmt.Printf("   NumGC = %v\n", m.NumGC)
}

func ProfileMemory(filename string) {
	f, err := os.Create(filename)
	if err != nil {
		fmt.Println(filename)
		panic("Could not create mem profile")
	}

	defer f.Close()

	runtime.GC()

	if err := pprof.Lookup("allocs").WriteTo(f, 0); err != nil {
		panic("Could not write to memory profile")
	}
}

func ProfileCPU(filename string) *os.File {
	f, err := os.Create(filename)
	if err != nil {
		fmt.Println(filename)
		panic("Could not create CPU profile")
	}

	if err := pprof.StartCPUProfile(f); err != nil {
		panic("Could not start CPU profile")
	}

	return f
}

// progressWriterAt wraps an io.WriterAt, adding atomic progress tracking.
type progressWriterAt struct {
	inner io.WriterAt  // real destination (file, mem‑buffer, pipe, …)
	total int64        // object size in bytes
	done  atomic.Int64 // bytes written so far
	next  int64        // next byte‑count checkpoint for logging
}

func newProgressWriterAt(inner io.WriterAt, total int64) *progressWriterAt {
	return &progressWriterAt{
		inner: inner,
		total: total,
		next:  total / 100,
	}
}

func (p *progressWriterAt) WriteAt(b []byte, off int64) (int, error) {
	n, err := p.inner.WriteAt(b, off)
	done := p.done.Add(int64(n))

	if done >= p.next {
		pct := float64(done) * 100 / float64(p.total)
		fmt.Printf("\rDownload %.1f %%  (%d /%d MiB)",
			pct,
			done>>20, p.total>>20)
		p.next += p.total / 100
	}
	return n, err
}

// openMemFile returns an *os.File whose pages live only in RAM.
func openMemFile(name string) (*os.File, error) {
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("memfd_create: %w", err)
	}
	return os.NewFile(uintptr(fd), name), nil
}
