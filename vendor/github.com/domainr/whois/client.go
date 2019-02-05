package whois

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"
)

const (
	// DefaultTimeout sets the maximum lifetime of whois requests.
	DefaultTimeout = 30 * time.Second

	// DefaultReadLimit sets the maximum bytes a client will attempt to read from a connection.
	DefaultReadLimit = 1 << 20 // 1 MB
)

// Client represents a whois client. It contains an http.Client, for executing
// some whois Requests.
type Client struct {
	Dial       func(string, string) (net.Conn, error)
	HTTPClient *http.Client
}

// DefaultClient represents a shared whois client with a default timeout, HTTP
// transport, and dialer.
var DefaultClient = NewClient(DefaultTimeout)

// NewClient creates and initializes a new Client with the specified timeout.
func NewClient(timeout time.Duration) *Client {
	dial := func(network, address string) (net.Conn, error) {
		deadline := time.Now().Add(timeout)
		conn, err := net.DialTimeout(network, address, timeout)
		if err != nil {
			return nil, err
		}
		conn.SetDeadline(deadline)
		return conn, nil
	}
	c := &Client{
		Dial:       dial,
		HTTPClient: &http.Client{},
	}
	c.HTTPClient.Transport = &http.Transport{
		Dial:                  c.dial,
		Proxy:                 http.ProxyFromEnvironment,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}
	return c
}

func (c *Client) dial(network, address string) (net.Conn, error) {
	return c.Dial(network, address)
}

// FetchError reports the underlying error and includes the target host of the fetch operation.
type FetchError struct {
	Err  error
	Host string
}

// Error implements the error interface.
func (f *FetchError) Error() string {
	return f.Err.Error()
}

// Fetch sends the Request to a whois server.
func (c *Client) Fetch(req *Request) (*Response, error) {
	if req.URL != "" {
		return c.fetchHTTP(req)
	}
	return c.fetchWhois(req)
}

func (c *Client) fetchWhois(req *Request) (*Response, error) {
	if req.Host == "" {
		return nil, &FetchError{fmt.Errorf("no request host for %s", req.Query), "unknown"}
	}
	conn, err := c.Dial("tcp", req.Host+":43")
	if err != nil {
		return nil, &FetchError{err, req.Host}
	}
	defer conn.Close()
	if _, err = conn.Write(req.Body); err != nil {
		logError(err)
		return nil, &FetchError{err, req.Host}
	}
	res := NewResponse(req.Query, req.Host)
	if res.Body, err = ioutil.ReadAll(io.LimitReader(conn, DefaultReadLimit)); err != nil {
		logError(err)
		return nil, &FetchError{err, req.Host}
	}
	res.DetectContentType("")
	return res, nil
}

func (c *Client) fetchHTTP(req *Request) (*Response, error) {
	hreq, err := httpRequest(req)
	if err != nil {
		return nil, &FetchError{err, req.Host}
	}
	hres, err := c.HTTPClient.Do(hreq)
	if err != nil {
		return nil, &FetchError{err, req.Host}
	}
	res := NewResponse(req.Query, req.Host)
	if res.Body, err = ioutil.ReadAll(io.LimitReader(hres.Body, DefaultReadLimit)); err != nil {
		logError(err)
		return nil, &FetchError{err, req.Host}
	}
	res.DetectContentType(hres.Header.Get("Content-Type"))
	return res, nil
}

func httpRequest(req *Request) (*http.Request, error) {
	var hreq *http.Request
	var err error
	// POST if non-zero Request.Body
	if len(req.Body) > 0 {
		hreq, err = http.NewRequest("POST", req.URL, bytes.NewReader(req.Body))
	} else {
		hreq, err = http.NewRequest("GET", req.URL, nil)
	}
	if err != nil {
		return nil, err
	}
	// Some web whois servers require a Referer header
	hreq.Header.Add("Referer", req.URL)
	return hreq, nil
}

func logError(err error) {
	switch t := err.(type) {
	case net.Error:
		fmt.Fprintf(os.Stderr, "net.Error timeout=%t, temp=%t: %s\n", t.Timeout(), t.Temporary(), err.Error())
	default:
		fmt.Fprintf(os.Stderr, "Unknown error %v: %s\n", t, err.Error())
	}
}
