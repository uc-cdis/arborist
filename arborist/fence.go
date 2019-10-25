package arborist

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

type FenceServer struct {
	url		string
}

func (fenceServer *FenceServer) request(r *http.Request, url string, method string, values map[string]interface{}) (*http.Response, error) {
	var netClient = &http.Client{
		Timeout: 10 * time.Second,
	}

	jsonValue, _ := json.Marshal(values)
	req, err := http.NewRequest(method, fenceServer.url + url, bytes.NewBuffer(jsonValue))
	if err != nil {
		return nil, err
	}
	req.Header = r.Header
	response, err := netClient.Do(req)
	return response, err
}
