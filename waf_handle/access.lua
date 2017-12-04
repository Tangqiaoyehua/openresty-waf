local data=require"data"
local check_args=require"rule"
local check_func=require"check_func"
local ip=ngx.var.remote_addr
local host=ngx.var.host
local waf_conf=data.get_conf()
local sql_check_dict=check_args["sql_check_dict"]
local xss_check_dict=check_args["xss_check_dict"]
local handle={}

handle["slow_check"]=function()
	local conf=waf_conf["slow_attack_conf"]
	if not conf or conf["status"]~="on" then
		ngx.log(ngx.WARN,"waflog:No slow_attack conf or module was off!")
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
	local conf=waf_conf["cc_conf"]
	if not conf or conf["status"]~="on" then
		ngx.log(ngx.WARN,"waflog:No cc_conf or module was off!")
		return 
	end
	local dict=ngx.shared.cc_cache
	local threshold=conf.threshold
	local period=conf.period
	local forbidden_time=conf.forbidden_time
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

handle["url_check"]=function()
	local conf=waf_conf["url_check_conf"]
	if not conf or conf["status"]~="on" then
		ngx.log(ngx.WARN,"waflog:No url_check conf or module was off!")
		return
	end
	
	local url=ngx.var.request_uri
	if conf["sql_check"]=="on" then
		local sta,content=check_func.sql_check_func(string.lower(url),sql_check_dict,"sql")
		if sta==0 then
			return
		elseif sta==1 then
			ngx.log(ngx.ERR,"WAF:attack=sql&info="..content)
			ngx.exit(403)
		else
			ngx.log(ngx.WARN,"waflog:sql check "..content)
		end
	end
	
	if conf["xss_check"]=="on" then
		local sta,content=check_func.sql_check_func(string.lower(url),sql_check_dict,"xss")
		if sta==0 then
			return
		elseif sta==1 then
			ngx.log(ngx.ERR,"WAF:attack=xss&info="..content)
			ngx.exit(403)
		else
			ngx.log(ngx.WARN,"waflog:xss check "..content)
		end
	end
	
end

handle["header_check"]=function()
	local conf=waf_conf["header_check_conf"]
	if not conf or conf["status"]~="on" then
		ngx.log(ngx.WARN,"waflog:No header_check conf or module was off!")
		return 
	end
	
end

handle["body_check"]=function()
	local conf=waf_conf["body_check_conf"]
	if not conf or conf["status"]~="on" then
		ngx.log(ngx.WARN,"waflog:No header_check conf or module was off!")
		return 
	end
	
end

--hanle
handle.slow_check()
handle.cc_anti()
