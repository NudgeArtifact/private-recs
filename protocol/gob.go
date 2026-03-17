package protocol

import (
	"bytes"
	"encoding/gob"
)

func (s *Submission) GobEncode() ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(s.ClientId)
	if err != nil {
		return buf.Bytes(), err
	}

	err = enc.Encode(s.Key)
	return buf.Bytes(), err
}

func (s *Submission) GobDecode(buf []byte) error {
	b := bytes.NewBuffer(buf)
	dec := gob.NewDecoder(b)
	err := dec.Decode(&s.ClientId)
	if err != nil {
		return err
	}

	err = dec.Decode(&s.Key)
	return err
}

func (q *RecQuery) GobEncode() ([]byte, error) {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(q.ClientId)
	if err != nil {
		return buf.Bytes(), err
	}

	err = enc.Encode(q.Keys)
	return buf.Bytes(), err
}

func (q *RecQuery) GobDecode(buf []byte) error {
	b := bytes.NewBuffer(buf)
	dec := gob.NewDecoder(b)
	err := dec.Decode(&q.ClientId)
	if err != nil {
		return err
	}

	err = dec.Decode(&q.Keys)
	return err
}
