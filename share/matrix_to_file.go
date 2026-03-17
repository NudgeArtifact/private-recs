package share

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"

	. "github.com/NudgeArtifact/private-recs/uint128"
	"github.com/NudgeArtifact/private-recs/utils"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func ReadMatrixFromFile(filename string) *Matrix[uint64] {
	f := utils.OpenFile(filename)
	defer f.Close()
	return ReadMatrixCSV(f)
}

func ReadMatrixFromS3(key string) *Matrix[uint64] {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		panic(err)
	}

	client := s3.NewFromConfig(cfg)
	dl := manager.NewDownloader(client, func(d *manager.Downloader) {
		d.PartSize, d.Concurrency = 100<<20, 200
	})

	buf := manager.NewWriteAtBuffer(nil) // in‑memory, io.WriterAt
	if _, err = dl.Download(context.TODO(), buf, &s3.GetObjectInput{
		Bucket: aws.String("mit-recs"),
		Key:    aws.String(key),
	}); err != nil {
		panic(err)
	}

	r := bytes.NewReader(buf.Bytes()) // slice points at the same backing array
	return ReadMatrixCSV(r)
}

func ReadMatrixCSV(r io.Reader) *Matrix[uint64] {
	reader := csv.NewReader(r)

	records := make([][]string, 0)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println(record)
			fmt.Println("CSV read error:", err)
			panic("Error reading csv")
		}
		if len(record) == 0 {
			continue // skip empty lines
		}
		records = append(records, record)
	}

	fmt.Println("Read all")

	nRows := uint64(len(records))
	nCols := uint64(len(records[0]))
	matrix := MatrixZeros[uint64](uint64(nRows), uint64(nCols))
	fmt.Printf("%d rows, %d cols\n", nRows, nCols)

	var wg sync.WaitGroup
	var mutex sync.Mutex

	for i, row := range records {
		if i%1000 == 0 {
			fmt.Printf("  on rows %d of %d...\n", i, nRows)
		}

		wg.Add(1)

		go func(m *Matrix[uint64], i int, row []string) {
			defer wg.Done()

			var rowInts []uint64
			for _, value := range row {
				num, err := strconv.Atoi(value)
				if err != nil {
					fmt.Println(err)
					panic("Error parsing csv")
				}
				rowInts = append(rowInts, uint64(num))
			}
			mutex.Lock()
			matrix.SetRowFromSlice(uint64(i), rowInts)
			mutex.Unlock()
		}(matrix, i, row)
	}

	wg.Wait()

	return matrix
}

func ReadMatrixShareFromFile(filename string) *Matrix[Share128] {
	f := utils.OpenFile(filename)
	defer f.Close()

	size, _ := f.Seek(0, io.SeekEnd)
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		panic(err)
	}

	fmt.Println("File size: ", size)
	return ReadMatrixShareCSVWithSize(f, int(float64(size)/8))
}

func ReadMatrixShareFromS3(key string) *Matrix[Share128] {
	return ReadMatrixShareFromS3WithSize(key, 0)
}

func ReadMatrixShareFromS3WithSize(key string, size int) *Matrix[Share128] {
	f, err := openMemFile("matrix.csv")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	httpClient := awshttp.NewBuildableClient().
		WithTransportOptions(func(tr *http.Transport) {
			tr.MaxIdleConns = 500        // pool size across hosts
			tr.MaxIdleConnsPerHost = 500 // keep‑alives for s3.amazonaws.com
			tr.MaxConnsPerHost = 500     // hard cap on simult. dials
		})

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithHTTPClient(httpClient),
		config.WithClientLogMode(aws.LogRetries))
	if err != nil {
		panic(err)
	}

	client := s3.NewFromConfig(cfg)
	dl := manager.NewDownloader(client, func(d *manager.Downloader) {
		d.PartSize = 100 << 20
		d.Concurrency = 200
	})

	head, _ := s3.NewFromConfig(cfg).HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: aws.String("mit-recs"), Key: aws.String(key),
	})

	pwrap := newProgressWriterAt(f, int64(*head.ContentLength))

	if _, err := dl.Download(context.TODO(), pwrap, &s3.GetObjectInput{
		Bucket: aws.String("mit-recs"), Key: aws.String(key),
	}); err != nil {
		panic(err)
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		panic(err)
	}
	if size != 0 {
		return ReadMatrixShareCSVWithSize(f, size)
	} else {
		fmt.Println("Launching with size: ", int(*head.ContentLength)/8)
		return ReadMatrixShareCSVWithSize(f, int(*head.ContentLength)/8)
	}
}

func ReadMatrixShareCSVWithSize(r io.Reader, maxSize int) *Matrix[Share128] {
	bufr := bufio.NewReaderSize(r, 64<<20)
	cr := csv.NewReader(bufr)
	cr.ReuseRecord = true // one backing slice reused every row
	cr.FieldsPerRecord = -1

	data := make([]Share128, maxSize) // don't know nRows yet, shrink later
	rowAt := 0
	nCols := 0
	length := 0

	var wg sync.WaitGroup
	var mutex sync.Mutex

	for i := uint64(0); i < 2000; i++ {
		wg.Add(1)

		go func(i uint64) {
			defer wg.Done()

			var rowVals []Share128
			var lastInt uint64
			var lastBig *Uint128
			var row []string
			for {
				if len(rowVals) != 0 {
					panic("should not happen")
				}

				mutex.Lock()
				curRow := rowAt
				rowAt += 1
				rowTmp, err := cr.Read()

				if err == nil {
					if len(row) < len(rowTmp) {
						row = make([]string, len(rowTmp))
					}

					copy(row, rowTmp) // deep copy, because of concurrency
					length += len(rowTmp) / 4

					if nCols == 0 {
						nCols = len(rowTmp) / 4
					}
				}

				mutex.Unlock()

				if err == io.EOF {
					break
				} else if err != nil {
					panic(err)
				}

				if curRow%100 == 0 {
					fmt.Println(" processing row: ", curRow, nCols)
				}

				for j, value := range row {
					num, err := strconv.ParseUint(value, 10, 64)
					if err != nil {
						fmt.Println(err)
						fmt.Println("Row was: ", row)
						panic("Error parsing csv")
					}
					if j%2 == 0 {
						lastInt = uint64(num)
					} else if (j/2)%2 == 0 {
						lastBig = MakeUint128(lastInt, uint64(num))
					} else {
						newBig := MakeUint128(lastInt, uint64(num))
						newShare := Share128{First: *lastBig, Second: *newBig}
						rowVals = append(rowVals, newShare)
					}
				}

				rowLen := len(rowVals)
				lenNeeded := rowLen * (curRow + 1)
				copy(data[rowLen*curRow:lenNeeded], rowVals)
				rowVals = rowVals[:0]
			}
		}(i)
	}

	wg.Wait()
	PrintMemUsage()

	data = data[:length]
	rows := length / nCols

	m := new(Matrix[Share128])
	m.Rows = uint64(rows)
	m.Cols = uint64(nCols)
	m.Data = data
	fmt.Printf(" %d rows, %d cols\n", rows, nCols)
	PrintMemUsage()

	return m
}

func WriteMatrixToFile(m *Matrix[uint64], filename string) {
	f := utils.OpenFileTrunc(filename)
	defer f.Close()
	WriteMatrixCSV(m, f)
}

func WriteMatrixToS3(m *Matrix[uint64], key string) {
	// Pipe CSV -> uploader so nothing hits disk
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		WriteMatrixCSV(m, pw)
	}()

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		panic(err)
	}

	s3Client := s3.NewFromConfig(cfg)
	uploader := manager.NewUploader(s3Client)

	_, err = uploader.Upload(context.TODO(),
		&s3.PutObjectInput{
			Bucket: aws.String("mit-recs"),
			Key:    aws.String(key),
			Body:   pr,
		})
}

func WriteMatrixCSV(m *Matrix[uint64], w io.Writer) {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	for i := uint64(0); i < m.NRows(); i++ {
		var strRow []string
		for j := uint64(0); j < m.NCols(); j++ {
			v := *m.Get(i, j)
			strRow = append(strRow, strconv.Itoa(int(v)))
		}
		if err := writer.Write(strRow); err != nil {
			fmt.Println(err)
			panic("Error writing file")
		}
	}
}

func WriteMatrixShareToFile(m *Matrix[Share128], filename string) {
	f := utils.OpenFileTrunc(filename)
	defer f.Close()
	WriteMatrixShareCSV(m, f)
}

func WriteMatrixShareToS3(m *Matrix[Share128], key string) {
	fmt.Println("Writing to S3: ", key)

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		panic(err)
	}
	uploader := manager.NewUploader(s3.NewFromConfig(cfg), func(u *manager.Uploader) {
		u.PartSize = 100 << 20
		u.Concurrency = 4
	})

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		WriteMatrixShareCSV(m, pw)
	}()

	_, err = uploader.Upload(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String("mit-recs"),
		Key:    aws.String(key),
		Body:   pr,
	})
}

func WriteMatrixShareCSV(m *Matrix[Share128], w io.Writer) {
	bw := bufio.NewWriterSize(w, 64<<10)
	defer bw.Flush()

	var buf []byte

	for i := uint64(0); i < m.NRows(); i++ {
		buf = buf[:0] // reuse underlying capacity
		for j := uint64(0); j < m.NCols(); j++ {
			v := m.Get(i, j)
			first_hi, first_lo := Uint128ToLimbs(&v.First)
			second_hi, second_lo := Uint128ToLimbs(&v.Second)
			buf = strconv.AppendUint(buf, first_hi, 10) // write digits
			buf = append(buf, ',')
			buf = strconv.AppendUint(buf, first_lo, 10) // write digits
			buf = append(buf, ',')
			buf = strconv.AppendUint(buf, second_hi, 10) // write digits
			buf = append(buf, ',')
			buf = strconv.AppendUint(buf, second_lo, 10) // write digits
			if j < m.NCols()-1 {
				buf = append(buf, ',')
			}
		}
		buf = append(buf, '\n')
		if _, err := bw.Write(buf); err != nil {
			panic(err)
		}
	}
}
