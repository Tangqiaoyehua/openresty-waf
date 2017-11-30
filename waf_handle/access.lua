local data=require"data"
local ip=ngx.var.remote_addr
local host=ngx.var.host
local waf_conf=data.get_conf()
local handle={}

handle["cc_anti"]=function()
	local dict=ngx.shared.cc_cache
	local cc_conf=waf_conf["cc_conf"]
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

handle.cc_anti()
