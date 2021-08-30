package updater

import (
	"fmt"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/vugu/vjson"
	"wasm/common"
	"wasm/internal"
)


func Update(ctx internal.PluginContext){

	hs := [][2]string{
		{":method", "POST"}, {":authority", common.ApiHost}, {":path", common.ApiUri}, {"accept", "*/*"},
		{":host", common.ApiHost},
	}
	proxywasm.DispatchHttpCall("waf-rules", hs, []byte(""), nil,
		5000, ctx.CallBack)



}

func HandleRules(rules []byte) map[string]interface{} {

	var rule map[string]interface{}
	err := vjson.Unmarshal(rules, &rule)
	if  err != nil {
		fmt.Println(err)
	}
	vjson.Marshal(rules)
	return rule

}