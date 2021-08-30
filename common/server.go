package common

import (
	"github.com/go-basic/uuid"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"strconv"
	"strings"
	"time"
	"wasm/internal"
)

//组成标准http header文本,header头均为小写
func GetRequestHeaders()  string{
	var headers string
	hs, err := proxywasm.GetHttpRequestHeaders()
	if err != nil {
		proxywasm.LogErrorf("failed to get request headers: %v", err)
		return ""
	}
	authority,_ := proxywasm.GetHttpRequestHeader(":authority")
	path,_ := proxywasm.GetHttpRequestHeader(":path")
	method,_ := proxywasm.GetHttpRequestHeader(":method")
	scheme,_ := proxywasm.GetHttpRequestHeader(":scheme")
	headers = method + " "+path  +" "+scheme +"\n"
	headers += "host: " + authority + "\n"
	for _, h := range hs {
		if h[0] != ":authority" &&  h[0] != ":path" &&  h[0] != ":method" && h[0] != ":scheme"{
			headers  +=  h[0]  +": "+  h[1] +"\n"
		}
	}
	return headers
}

//获取请求uri
func GetRequestUri() string{
	path ,err := proxywasm.GetHttpRequestHeader(":path")
	if err != nil {
		proxywasm.LogErrorf("failed to get request uri: %v", err)
		return ""
	}
	return path

}

//获取请求cookie
func GetRequestCookies()  string {
	cookies ,_ := proxywasm.GetHttpRequestHeader("cookie")
	return cookies
}

//获取请求 UA
func  GetRequestUA() string{
	UA ,err := proxywasm.GetHttpRequestHeader("user-agent")
	if err != nil {
		proxywasm.LogErrorf("failed to get request user-agent: %v", err)
		return ""
	}
	return UA
}

// 获取请求post 数据
func GetRequestPost(bodySize int) string {
	data ,err := proxywasm.GetHttpRequestBody(0,bodySize)
	if err != nil {
		proxywasm.LogErrorf("failed to get request post: %v", err)
		return ""
	}
	return string(data)
}



// 获取请求method
func GetRequestMethod()  string{
	method ,err := proxywasm.GetHttpRequestHeader(":method")
	if err != nil {
		proxywasm.LogErrorf("failed to get request post: %v", err)
		return ""
	}
	return method
}
//获取请求真实IP
func GetRealIP() string {
	var realip  string
	XEnvoyInternal := GetInternal()
	//Envoy设置的外部请求可信地址
	XEnvoyExternalAddress ,_ := proxywasm.GetHttpRequestHeader("x-envoy-external-address")
	//获取xff头 x-forwarded-for
	XForwardedFor ,_ := proxywasm.GetHttpRequestHeader("x-forwarded-for")
	//内部  IP 返回XFF最左面一个
	if XEnvoyInternal == "true"{
		return FilterXFF(XForwardedFor)
	}else{
		return XEnvoyExternalAddress
	}
	return realip
}

func GetInternal() string {
	//是否为内部请求
	XEnvoyInternal ,_ := proxywasm.GetHttpRequestHeader("x-envoy-internal")
	return XEnvoyInternal
}
func FilterXFF(xff string) string{
	countSplit := strings.Split(xff, ",")
	return countSplit[0]

}

//获取  请求域名
func GetDomain() string{
	domain,_ := proxywasm.GetHttpRequestHeader(":authority")
	domainSplit := strings.Split(domain, ":")
	return domainSplit[0]
}

//阻断请求 并记录日志
func BlockLog(ctx internal.PluginContext,destined string,ruleid string) {
	if Rules == nil {
		return
	}
	bases := Rules["base"].(map[string]interface{})
	if len(bases) == 0 {
		return
	}
	denyMsg := bases["denyMsg"].(map[string]interface{})
	if len(denyMsg) == 0 {
		return
	}
	state   := denyMsg["state"].(string)
	if state != "on"{
		return
	}
	httpcode   := denyMsg["http_code"].(string)
	httpcodeint, _ := strconv.Atoi(httpcode)
	TempMsg :=  denyMsg["msg"].(string)
	hs := [][2]string{{"content-type", "text/html; charset=utf-8"}}
	uuid := uuid.New()

	TempMsg = strings.Replace(TempMsg, "$event-id$", uuid, -1)
	body := ctx.Headers + "\n" +ctx.Postdata
	waflog := internal.Waflog{
		Domain:ctx.Domain,
		Method : GetRequestMethod(),
		XEnvoyInternal : ctx.XEnvoyInternal,
		RealIP :ctx.RealIP,
		Ruleid :ruleid,
		Destined:destined,
		Create_time : time.Now().UnixNano() / 1e6,
		EventId :uuid,
		Logflag : ctx.Flag,
		Body : body,
	}
	Log(waflog)
	
	proxywasm.SendHttpResponse(uint32(httpcodeint),hs,[]byte(TempMsg))

}

//灰名单记录日志
func NBlockLog(ctx internal.PluginContext,destined string,ruleid string) {
	uuid := uuid.New()

	body := ctx.Headers + "\n" +ctx.Postdata
	waflog := internal.Waflog{
		Domain:ctx.Domain,
		Method : GetRequestMethod(),
		XEnvoyInternal : ctx.XEnvoyInternal,
		RealIP :ctx.RealIP,
		Ruleid :ruleid,
		Destined:destined,
		Create_time : time.Now().UnixNano() / 1e6,
		EventId :uuid,
		Logflag : ctx.Flag,
		Body : body,
	}
	Log(waflog)

}

//获取域名下所需加载的规则集和
func GetRules() map[string]interface{} {
	grules := Rules
	if grules["rule"] != nil && grules["app"] != nil {
		host := GetDomain()
		temprules := make(map[string]interface{})
		if grules["app"].(map[string]interface{})[host] != nil {
			hostapp :=grules["app"].(map[string]interface{})[host].(map[string]interface{})
			if hostapp["rules"] != nil {
				for _,y := range hostapp["rules"].([]interface{}) {
					temprules[y.(string)] = grules["rule"].(map[string]interface{})[y.(string)]
				}
				grules["rule"] = temprules
				return grules
			}
		}
		if grules["app"].(map[string]interface{})["default"] != nil {
			hostapp :=grules["app"].(map[string]interface{})["default"].(map[string]interface{})
			if hostapp["rules"] != nil {
				for _,y := range hostapp["rules"].([]interface{}) {
					temprules[y.(string)] = grules["rule"].(map[string]interface{})[y.(string)]
				}
				grules["rule"] = temprules
				return grules
			}

		}
		grules["rule"] = temprules
	}
	return grules
}