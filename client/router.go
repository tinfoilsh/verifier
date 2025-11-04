package client

import (
	"encoding/json"
	"errors"
	"math/rand"
	"net/http"
)

var (
	defaultRouterRepo = "tinfoilsh/confidential-model-router"
	defaultRouterURL  = "https://atc.tinfoil.sh/routers"
)

type Router struct {
	repo    string
	routers []string
}

func NewRouter() *Router {
	return &Router{
		repo:    defaultRouterRepo,
		routers: []string{},
	}
}

func (r *Router) GetRouter() (string, error) {
	resp, err := http.Get(defaultRouterURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var routers []string
	if err := json.NewDecoder(resp.Body).Decode(&routers); err != nil {
		return "", err
	}

	if len(routers) == 0 {
		return "", errors.New("no routers found")
	}
	return routers[rand.Intn(len(routers))], nil
}

func (r *Router) Client() (*SecureClient, error) {
	router, err := r.GetRouter()
	if err != nil {
		return nil, err
	}
	return NewSecureClient(router, r.repo), nil
}
