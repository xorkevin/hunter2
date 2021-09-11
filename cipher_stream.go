package hunter2

import (
	"crypto/cipher"
	"hash"
	"io"
)

type (
	StreamHash interface {
		io.Writer
		Sum(b []byte) []byte
	}
)

type (
	EncStreamReader struct {
		S     cipher.Stream
		H     StreamHash
		R     io.Reader
		Count uint64
	}
)

func (r *EncStreamReader) Read(dst []byte) (int, error) {
	n, err := r.R.Read(dst)
	if n > 0 {
		r.S.XORKeyStream(dst[:n], dst[:n])
		r.Count += uint64(n)
		k, err := r.H.Write(dst[:n])
		if k != n && err == nil {
			// should never happen
			err = io.ErrShortWrite
		}
		if err != nil {
			// should not happen as specified by hash.Hash
			return n, err
		}
	}
	return n, err
}

type (
	EncStreamWriter struct {
		S     cipher.Stream
		H     hash.Hash
		W     io.Writer
		Count uint64
	}
)

func (w *EncStreamWriter) Write(src []byte) (int, error) {
	c := make([]byte, len(src))
	w.S.XORKeyStream(c, src)
	n, err := w.W.Write(c)
	if n != len(src) && err == nil {
		// should never happen
		err = io.ErrShortWrite
	}
	if err != nil {
		return n, err
	}
	w.Count += uint64(len(src))
	k, err := w.H.Write(c)
	if k != n && err == nil {
		// should never happen
		err = io.ErrShortWrite
	}
	if err != nil {
		// should not happen as specified by hash.Hash
		return n, err
	}
	return n, nil
}

func (w *EncStreamWriter) Close() error {
	if c, ok := w.W.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

type (
	DecStreamReader struct {
		S     cipher.Stream
		H     hash.Hash
		R     io.Reader
		Count uint64
	}
)

func (r *DecStreamReader) Read(dst []byte) (int, error) {
	n, err := r.R.Read(dst)
	if n > 0 {
		r.Count += uint64(n)
		k, err := r.H.Write(dst[:n])
		if k != n && err == nil {
			// should never happen
			err = io.ErrShortWrite
		}
		if err != nil {
			// should not happen as specified by hash.Hash
			return n, err
		}
		r.S.XORKeyStream(dst[:n], dst[:n])
	}
	return n, err
}

type (
	DecStreamWriter struct {
		S     cipher.Stream
		H     hash.Hash
		W     io.Writer
		Count uint64
	}
)

func (w *DecStreamWriter) Write(src []byte) (int, error) {
	w.Count += uint64(len(src))
	k, err := w.H.Write(src)
	if k != len(src) && err == nil {
		// should never happen
		err = io.ErrShortWrite
	}
	if err != nil {
		// should not happen as specified by hash.Hash
		return 0, err
	}
	c := make([]byte, len(src))
	w.S.XORKeyStream(c, src)
	n, err := w.W.Write(c)
	if n != len(src) && err == nil {
		// should never happen
		err = io.ErrShortWrite
	}
	if err != nil {
		return n, err
	}
	return n, nil
}

func (w *DecStreamWriter) Close() error {
	if c, ok := w.W.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// Cipher Stream algorithms
const (
	CipherStreamAlgChaCha20 = "cc20"
)

// Cipher Auth algorithms
const (
	CipherAuthAlgPoly1305 = "p1305"
)
