package common

var ApiHost = "127.0.0.1:80"  //不要加http:// 会报400
var ApiUri = "/api/public/waf/rules"
var TickTime uint32 = 1000*60
var Rules = make(map[string]interface{})


