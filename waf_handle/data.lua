local _M={}
local data={}

_M.set_conf=function(conf)
	data=conf
end

_M.get_conf=function()
	return data
end

return _M
