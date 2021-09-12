package hunter2

import (
	"crypto/cipher"
	"errors"
	"io"
)

var (
	// ErrCipherAuthInvalid is returned when the cipher auth tag is invalid
	ErrCipherAuthInvalid = errors.New("Cipher invalid auth tag")
)

type (
	EncStreamReader struct {
		S cipher.Stream
		H io.Writer
		R io.Reader
	}
)

func NewEncStreamReader(s cipher.Stream, h io.Writer, r io.Reader) *EncStreamReader {
	return &EncStreamReader{
		S: s,
		H: h,
		R: r,
	}
}

func (r *EncStreamReader) Read(dst []byte) (int, error) {
	n, err := r.R.Read(dst)
	if n > 0 {
		r.S.XORKeyStream(dst[:n], dst[:n])
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
		S cipher.Stream
		H io.Writer
		W io.Writer
	}
)

func NewEncStreamWriter(s cipher.Stream, h io.Writer, w io.Writer) *EncStreamWriter {
	return &EncStreamWriter{
		S: s,
		H: h,
		W: w,
	}
}

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
		S cipher.Stream
		H io.Writer
		R io.Reader
	}
)

func NewDecStreamReader(s cipher.Stream, h io.Writer, r io.Reader) *DecStreamReader {
	return &DecStreamReader{
		S: s,
		H: h,
		R: r,
	}
}

func (r *DecStreamReader) Read(dst []byte) (int, error) {
	n, err := r.R.Read(dst)
	if n > 0 {
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
		S cipher.Stream
		H io.Writer
		W io.Writer
	}
)

func NewDecStreamWriter(s cipher.Stream, h io.Writer, w io.Writer) *DecStreamWriter {
	return &DecStreamWriter{
		S: s,
		H: h,
		W: w,
	}
}

func (w *DecStreamWriter) Write(src []byte) (int, error) {
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
