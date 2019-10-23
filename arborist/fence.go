package arborist

import (
	"net/http"
	"time"
)

type FenceServer struct {
	url		string
}

func (fenceServer *FenceServer) request(r *http.Request, url string, method string) (*http.Response, error) {
	var netClient = &http.Client{
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequest(method, fenceServer.url + url, nil)
	if err != nil {
		return nil, err
	}
	req.Header = r.Header
	response, err := netClient.Do(req)
	return response, err
}
