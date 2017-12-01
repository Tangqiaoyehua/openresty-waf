local cjson=require"cjson.safe"
local data=require"data"
local handle={}
local delay=5
local conf_file_path="/usr/local/openresty/nginx/conf/conf.json"


local function conf_file_handle(file_path)
	local f=io.open(file_path)
	local json_str=f:read("a*")
	f:close()
	local sta,conf=pcall(cjson.decode,json_str)
	if not sta then
		ngx.log(ngx.WARN,"waflog:json decode failed.","sta:",sta,"reason:",conf)
		return nil
	end
	return conf
end

local function set_conf()
	local conf=conf_file_handle(conf_file_path)
	if conf then
		data.set_conf(conf)
	end
	local ok,err=ngx.timer.at(delay,set_conf)
	if not ok then
		ngx.log(ngx.WARN,"waflog:failed create a timer!")
	end
end

handle["timer_set_conf"]=function()
	local ok,err=ngx.timer.at(delay,set_conf)
	if not ok then
		ngx.log(ngx.WARN,"waflog:failed create a timer in handle!")
	end
end

handle["timer_flush_dict"]=function()
	
end

handle.timer_set_conf()
