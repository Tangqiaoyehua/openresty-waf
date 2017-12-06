local check_args=require"check_args"
local _M={}

function _M.handle(content,mz)
	local config_err=-1
	local attack_match=1
	local normal_req=0
	local dict=check_args
	for dict_n,dict in pairs(check_args) do
		for k,v in pairs(dict) do
			--ngx.log(ngx.ERR,"dingdingding:",v.id)
			local flag=string.find(v["mz"],mz)
			if flag then
				local args_dict=v["match_dict"]
				for _,arg in pairs(args_dict) do
					local m_flag=string.find(content,arg,1,true)
					if m_flag then
						return attack_match,"match_zone:"..mz.."&&match_dict:"..dict_n.."&&match_arg:"..arg
					end
				end
			end
		end
	end
	return normal_req

end





return _M
