package converter

import (
	"encoding/json"
	"net"

	log "github.com/sirupsen/logrus"
)

func handleZdns(in chan string, out chan ConvertResult) {
	var unmarshalled_result map[string]interface{}

	for i := range in {
		json.Unmarshal([]byte(i), &unmarshalled_result)

		name := unmarshalled_result["name"].(string)

		data := getFieldFromMapIfAvailable(unmarshalled_result, "data")
		if data == nil {
			log.Warnf("data field unavailable: %s", i)
			continue
		}

		answers := getFieldFromMapIfAvailable(data.(map[string]interface{}), "answers")
		if answers == nil {
			continue
		}

		for _, a := range answers.([]interface{}) {
			nest_a := a.(map[string]interface{})

			t := getFieldFromMapIfAvailable(nest_a, "type")
			if t == nil || t.(string) != "AAAA" {
				continue
			}

			ipbyte := getFieldFromMapIfAvailable(nest_a, "answer")
			if ipbyte == nil {
				continue
			}

			ip := net.ParseIP(ipbyte.(string))
			if ip.To4() != nil {
				continue
			}

			out <- ConvertResult{name, ip.String()}
		}
	}
}

func getFieldFromMapIfAvailable(m map[string]interface{}, field string) interface{} {
	if data, ok := m[field]; ok {
		return data
	} else {
		return nil
	}
}
