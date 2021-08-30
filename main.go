package main

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"wasm/common"
	"wasm/filter"
	"wasm/internal"
	"wasm/updater"
)

func main() {

	proxywasm.SetVMContext(&vmContext{})

}

type vmContext struct {
	// Embed the default VM context here,
	// so that we don't need to reimplement all the methods.
	types.DefaultVMContext
}


type waf struct {
	// Embed the default plugin context here,
	// so that we don't need to reimplement all the methods.

	internal.PluginContext
	contextID uint32


}


// Override types.DefaultVMContext.
func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {

	return &waf{}
}




// Override types.DefaultPluginContext.
func (ctx *waf) NewHttpContext(contextID uint32) types.HttpContext {

	return &waf{contextID:contextID}

}
// Override types.DefaultPluginContext.
func (ctx *waf) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	//规则请求回调函数定义
	ctx.CallBack = func(numHeaders, bodySize, numTrailers int) {
		result ,err:= proxywasm.GetHttpCallResponseBody(0,bodySize)
		if err != nil {
			proxywasm.LogError(err.Error())
			return
		}

		temprules := updater.HandleRules(result)
		if len(temprules) != 0{
			common.Rules = temprules
		}

	}

	if err := proxywasm.SetTickPeriodMilliSeconds(common.TickTime); err != nil {
		proxywasm.LogCriticalf("failed to set tick period: %v", err)
		return types.OnPluginStartStatusFailed
	}
	proxywasm.LogInfof("set tick period milliseconds: %d", common.TickTime)
	return types.OnPluginStartStatusOK
}

// Override types.DefaultPluginContext.
func (ctx *waf) OnTick() {

	updater.Update(ctx.PluginContext)
}



// Override types.DefaultHttpContext.
func (ctx *waf) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	ctx.Headers = common.GetRequestHeaders()
	ctx.Uri = common.GetRequestUri()
	ctx.Cookies =  common.GetRequestCookies()
	ctx.User_agent = common.GetRequestUA()
	ctx.RealIP = common.GetRealIP()
	ctx.XEnvoyInternal =common.GetInternal()
	ctx.Domain = common.GetDomain()
	ctx.Flag = filter.FilterIp(ctx.PluginContext)

	filter.FilterHeader(ctx.PluginContext)
	return types.ActionContinue
}


// Override types.DefaultHttpContext.
func (ctx *waf) OnHttpRequestBody(bodySize int, endOfStream bool) types.Action {
	ctx.Postdata = common.GetRequestPost(bodySize)
	ctx.TotalRequestBodySize += bodySize
	if !endOfStream {
		// Wait until we see the entire body to replace.
		return types.ActionPause
	}
	wafP := ctx.PluginContext
	filter.FilterBodyData(wafP)
	return types.ActionContinue
}

// Override types.DefaultHttpContext.
func (ctx *waf) OnHttpResponseHeaders(numHeaders int, endOfStream bool) types.Action {

	return types.ActionContinue
}

// Override types.DefaultHttpContext.
func (ctx *waf) OnHttpStreamDone() {

}

func (ctx *waf) OnHttpRequestTrailers(int) types.Action       {

	return types.ActionContinue
}

func (ctx *waf) OnPluginDone() bool         {

	return true
}