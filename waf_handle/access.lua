local data=require"data"
local ip=ngx.var.remote_addr
local host=ngx.var.host
local waf_conf=data.get_conf()
local handle={}

handle["slow_check"]=function()
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
	local slow_attack_key="slow_attack:"..ip..host
	local flag=dict:get(slow_attack_key)
	if flag then
		ngx.log(ngx.WARN,"waflog:Slow attack IP=>"..ip)
		return ngx.exit(403)
	end
end

handle["cc_anti"]=function()
	local dict=ngx.shared.cc_cache
	local cc_conf=waf_conf["cc_conf"]
	if not cc_conf then
		ngx.log(ngx.WARN,"waflog:No cc_conf!")
		return 
	end
	local flag=cc_conf["status"]
	if flag~="on" then
		ngx.log(ngx.WARN,"waflog:CC anti module off!")
		return 
	end
	local threshold=cc_conf.threshold
	local period=cc_conf.period
	local forbidden_time=cc_conf.forbidden_time
	local access_id=host..ip
	
	local black_key="forbidden ip:"..ip
	local count_key="count:"..ip
	
	local black_flag=dict:get(black_key)
	if black_flag then
		ngx.log(ngx.WARN,"waflog:IP Forbidden=>"..ip)
		return ngx.exit(403)
	end
	local count=dict:get(count_key)
	if count then
		if count>=threshold then
			dict:set(black_key,1,forbidden_time)
			ngx.log(ngx.WARN,"waflog:Set IP forbidden=>"..ip)
			return ngx.exit(403)
		else
			dict:incr(count_key,1)
		end
	else
		dict:set(count_key,1,period)
	end
end

--hanle
handle.slow_check()
handle.cc_anti()
