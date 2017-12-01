local data=require"data"
local host=ngx.var.host
local ip=ngx.var.remote_addr
local waf_conf=data.get_conf()
local handle={}

handle["slow_attack_anti"] =function()
	local slow_attack_conf=waf_conf["slow_attack_conf"]
	if not slow_attack_conf then
		ngx.log(ngx.WARN,"waflog:No slow_attack_conf!")
		return 
	end
	local flag=slow_attack_conf["status"]
	if flag~="on" then
		ngx.log(ngx.WARN,"waflog:slow_attack_anti module off!")
		return
	end
	local dict=ngx.shared.slow_attack_cache
	local req_time=ngx.var.request_time
	local upstream_time=ngx.var.upstream_response_time or 0
	local cost_time=req_time-upstream_time
	local max_req_time=slow_attack_conf["max_req_time"]
	local threshold=slow_attack_conf["threshold"]
	local forbidden_time=slow_attack_conf["forbidden_time"]
	local period=slow_attack_conf["period"]
	local slow_count_key="slow_count:"..ip..host
	local slow_attack_key="slow_attack:"..ip..host
	local count=dict:get(slow_count_key)
	if count then
		if count >=threshold then
			dict:set(slow_attack_key,1,forbidden_time)
		else
			dict:incr(slow_count_key,1)
		end
	else
		dict:set(slow_count_key,1,period)
	end
	
end

handle.slow_attack_anti()

