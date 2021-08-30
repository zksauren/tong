package common

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/vugu/vjson"
	"reflect"
	"wasm/internal"
)

func  Log(waflog internal.Waflog)  {
	//proxy各个过程中均禁止使用log函数，考虑使用httpcall 直接向ES写日志
	if Rules == nil {
		return
	}
	bases := Rules["base"].(map[string]interface{})
	if len(bases) == 0 {
		return
	}
	logc := bases["logc"].(map[string]interface{})
	if len(logc) == 0 {
		return
	}
	state  := logc["state"].(string)
	if state != "on"{
		return
	}
	address := logc["address"].(string)

	hs := [][2]string{
		{":method", "POST"}, {":authority", address}, {":path", "/waf/_doc?pretty"}, {"Content-Type", "application/json"},
		{":host", address},
	}
	waf_inter := Struct2Map(waflog)
	logmsg , err  := vjson.Marshal(waf_inter)
	if err != nil {
		proxywasm.LogErrorf("日志保存错误:"+err.Error())
		return
	}

	proxywasm.DispatchHttpCall("waf-es", hs, logmsg, nil,
		5000, func(numHeaders, bodySize, numTrailers int) {})
}


func Struct2Map(obj interface{}) map[string]interface{} {
	t := reflect.TypeOf(obj)
	v := reflect.ValueOf(obj)

	var data = make(map[string]interface{})
	for i := 0; i < t.NumField(); i++ {
		data[t.Field(i).Name] = v.Field(i).Interface()
	}
	return data
}