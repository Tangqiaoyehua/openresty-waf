local data=require"data"
local check_args=require"check_args"
local check_func=require"check_func"
local ip=ngx.var.remote_addr
local host=ngx.var.host
local waf_conf=data.get_conf()
local handle={}

local special_list=waf_conf["special_ip_list"]
local access_status
if special_list then
	access_status=special_list[ip]
	if access_status==1 then
		ngx.ctx.access_status=true
		return
	elseif access_status==-1 then
		return ngx.exit(403)
	end
end

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

handle["uri_check"]=function()
	local flag=waf_conf["uri_check"]
	if not flag or flag~="on" then
		ngx.log(ngx.WARN,"waflog:No uri_check conf or module was off!")
		return
	end
	
	local uri=ngx.var.request_uri
	uri=ngx.unescape_uri(uri)
	uri=string.lower(uri)
	local mz="uri"
	local res,err=check_func.handle(uri,mz)
	if res~=0 then
		ngx.log(ngx.ERR,"WAF:"..err)
		return ngx.exit(403)
	end
end

handle["args_check"]=function()
	local flag=waf_conf["args_check"]
	if not flag or flag~="on" then
		ngx.log(ngx.WARN,"waflog:No args_check conf or module was off!")
		return
	end
	
	local args=ngx.req.get_uri_args()
	local mz="args"
	for k,v in pairs(args) do
		local res,err=check_func.handle(v,mz)
		if res~=0 then
			ngx.log(ngx.ERR,"WAF:"..err)
			return ngx.exit(403)
		end
	end
end



handle["header_cookie_check"]=function()
	local flag=waf_conf["header_cookie_check"]
	if not flag or flag~="on" then
		ngx.log(ngx.WARN,"waflog:No header_cookie_check conf or module was off!")
		return
	end
	local cookie=require"resty.cookie"
	local mz="header_cookie"
	local ck,err=cookie:new()
	local ck_dict=ck:get_all()
	if ck_dict then
		for _,v in pairs(ck_dict) do
			local res,err=check_func.handle(v,mz)
			if res~=0 then
				ngx.log(ngx.ERR,"WAF:"..err)
				return ngx.exit(403)
			end
		end
	end
	
	
end

handle["body_check"]=function()
	local flag=waf_conf["body_check"]
	if not flag or flag~="on" then
		ngx.log(ngx.WARN,"waflog:No body_check conf or module was off!")
		return 
	end
	local mz="body"
	ngx.req.read_body()
	local content=ngx.req.get_body_data()
	--ngx.log(ngx.ERR,"dingding==>",content)
	if content then
		local res,err=check_func.handle(content,mz)
		if res~=0 then
			ngx.log(ngx.ERR,"WAF:",err)
			return ngx.exit(403)
		end
	
	end
end

handle["crawler_check"]=function()
	local flag=waf_conf["crawler_check"]
	if not flag or flag~="on" then
		ngx.log(ngx.WARN,"waflog:No crawler_check conf or module was off!")
		return 
	end
	local mz="user_agent"
	local ua=ngx.var.http_user_agent
	if ua then
		local res,err=check_func.handle(ua,mz)
		if res~=0 then
			ngx.log(ngx.ERR,"WAF:"..err)
			return ngx.exit(403)
		end
	else
		ngx.log(ngx.ERR,"WAF:no user-agent")
		return ngx.exit(403)
	end
end


--hanle
handle.slow_check()
handle.cc_anti()
handle.uri_check()
handle.args_check()
handle.header_cookie_check()
handle.body_check()
handle.crawler_check()






