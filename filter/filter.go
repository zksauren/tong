package filter

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"regexp"
	"time"
	"wasm/common"
	"wasm/internal"
)
//主过滤函数
func filter(ctx internal.PluginContext,body string,rule map[string]interface{}){
	ct := rule["ct"].(string)
	var ctmodel string
	if ct != "" {
		ctmodel= "(?" + ct + ")"
	}else{
		ctmodel= "(?im)"
	}
	rulestr := ctmodel+rule["rule"].(string)
	flysnowRegexp ,err:= regexp.Compile(rulestr)
	if err != nil {
		proxywasm.LogError("正则规则错误: "+ rule["ruleid"].(string)+err.Error())
	}
	params := flysnowRegexp.FindStringSubmatch(body)
	for _,destined :=range params {
		ctx.Flag = "rule"
		common.BlockLog(ctx,destined,rule["ruleid"].(string))
	}

}
func FilterHeader(ctx internal.PluginContext){
	//检查IP黑白名单控制
	if  ctx.Flag  ==  "allow"{
		return
	}else  if  ctx.Flag == "deny"{
		common.BlockLog(ctx,"","")
	}else if  ctx.Flag == "log"{
		common.NBlockLog(ctx,"","")
		return
	}
	rules :=common.GetRules()

	if rules["rule"] != nil {
		for _,v :=  range  rules["rule"].(map[string]interface{}){
			ruleobj :=  v.(map[string]interface{})
			body := ""
			if   ruleobj["key"]  == "uri"{
				body = ctx.Uri
			}
			if   ruleobj["key"]  == "cookie"{
				body = ctx.Cookies
			}
			if   ruleobj["key"]  == "useragent"{
				body = ctx.User_agent
			}
			if   ruleobj["key"]  == "header"{
				body = ctx.Headers
			}
			if ruleobj["key"]  == "all" && common.GetRequestMethod() == "GET"{
				body = ctx.Headers
			}

			filter(ctx,body,ruleobj)
		}
	}

}

func FilterBodyData(ctx internal.PluginContext){
	rules :=common.GetRules()

	if rules["rule"] != nil {
		for _,v :=  range  rules["rule"].(map[string]interface{}){
			ruleobj :=  v.(map[string]interface{})
			body := ""
			if   ruleobj["key"]  == "post"{
				body = ctx.Postdata
			}

			if ruleobj["key"]  == "all"{
				body = ctx.Headers + "\n" +ctx.Postdata
			}
			filter(ctx,body,ruleobj)
		}
	}
}


func FilterIp(ctx internal.PluginContext) string{
	rules :=common.Rules

	if ctx.RealIP == "" || len(rules) == 0 || len(rules["iplist"].(map[string]interface{})) == 0{
		return ""
	}
	iplist := rules["iplist"].(map[string]interface{})
	nowtime := time.Now().Unix()

	if iplist[ctx.RealIP] != nil  && len(iplist[ctx.RealIP].(map[string]interface{})) >  0   {
		realiplist := iplist[ctx.RealIP].(map[string]interface{})

		if  realiplist[ctx.Domain] != nil &&  len(realiplist[ctx.Domain].(map[string]interface{})) > 0 {
			domains  := realiplist[ctx.Domain]
			action  :=  domains.(map[string]interface{})["action"].(string)
			expire_time  :=  domains.(map[string]interface{})["expire_time"].(float64)
			if nowtime < int64(expire_time) || expire_time == 0 {
				return    action
			}

		}else if realiplist["default"] != nil &&  len(realiplist["default"].(map[string]interface{})) > 0 {

			domains  := realiplist["default"]
			action  :=  domains.(map[string]interface{})["action"].(string)
			expire_time  :=  domains.(map[string]interface{})["expire_time"].(float64)
			if nowtime < int64(expire_time) || expire_time == 0 {
				return   action
			}
		}

	}
	return  ""
}