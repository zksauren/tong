package internal

import "github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"

type PluginContext struct {
	// Embed the default plugin context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultPluginContext
	types.DefaultHttpContext
	Rules map[string]interface{}
	ServerBody
	CallBack  func(numHeaders, bodySize, numTrailers int)
	TotalRequestBodySize int
	RealIP string
	XEnvoyInternal string
	Domain string
	Flag string

}

type  ServerBody struct {
	Bodydata string
	Headers string
	Uri string
	Cookies string
	User_agent string
	Postdata string
}


type Waflog struct {
	Domain string
	Method string
	XEnvoyInternal string //是否内网流量
	RealIP string
	Ruleid string
	Destined string //命中的字符
	Create_time int64 // 攻击时间
	EventId string //事件ID
	Logflag  string  //日志类别：rule 触发规则阻断 、 deny 黑名单阻断、 log 灰名单记录日志
	Body string
}