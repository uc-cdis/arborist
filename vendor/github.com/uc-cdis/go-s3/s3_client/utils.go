package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	//"os"
	//"strconv"
	//"reflect"
)

//https://michaelheap.com/golang-encodedecode-arbitrary-json/
func readFile(path string) ([]byte, error) {
	buff, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	return buff, nil
}

func printCredentials(creds []byte) {
	fmt.Println(string(creds))
}

func getValue(buff []byte, keys []string) (interface{}, error) {
	if len(keys) == 0 {
		return nil, errors.New("KeyValue")
	}

	var m map[string]interface{}
	json.Unmarshal(buff, &m)

	result := m[keys[0]]
	err := false

	for _, key := range keys[1:] {
		result, err = result.(map[string]interface{})[key]
		if err == false {
			return nil, errors.New("KeyValue")
		}

	}

	return result, nil

}

func test() {
	jsonBytes, _ := readFile("credentials.json")
	printCredentials(jsonBytes)
	fmt.Println(getValue(jsonBytes, []string{"AWS", "region"}))
	//fmt.Println(getValue(jsonBytes, []string{"AWS", "age"}))

}
