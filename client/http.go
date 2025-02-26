package client

import (
	"io"
	"net/http"
)

type Response struct {
	Status     string
	StatusCode int
	Body       []byte
}

func toResponse(r *http.Response) (*Response, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	return &Response{
		Status:     r.Status,
		StatusCode: r.StatusCode,
		Body:       body,
	}, nil
}
