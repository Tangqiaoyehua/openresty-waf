local _M={}

function _M.sql_check_func(content,dict,check_type)
	local config_err=-1
	local attack_match=1
	local normal_req=0

	for _,v in pairs(dict) do
		local id=v["id"]
		local mz=v["match_dict"]
		if not mz then
			return config_err,"No mz!"
		end
		for _,word in pairs(mz) do
			local sta=string.find(content,word)
			if sta then
				return attack_match,check_type.." inject&matchword="..word
			end
		end	
	end
	return normal_req
end


return _M