-- The imported profile and its private key belong to the official WireGuard app.
on run
	set profileName to "RackNerd2"
	set expectedIP to paragraph 1 of (read (path to resource "endpoint.txt") as «class utf8»)
	repeat
		try
			set currentStatus to paragraph 1 of (do shell script "/usr/sbin/scutil --nc status " & quoted form of profileName)
		on error
			set currentStatus to "无法读取"
		end try
		if currentStatus is "Connected" then set currentStatus to "已连接"
		if currentStatus is "Disconnected" then set currentStatus to "已断开"
		set actionName to button returned of (display dialog (profileName & "　" & currentStatus) with title "RackNerd" buttons {"关闭", "验证公网出口", "连接 / 断开…"} default button "连接 / 断开…")
		if actionName is "关闭" then return
		if actionName is "连接 / 断开…" then
			do shell script "/usr/bin/open -b com.wireguard.macos"
			return
		end if
		set results to {}
		set matches to 0
		repeat with hostName in {"api.ipify.org", "ipv4.icanhazip.com"}
			try
				set observedIP to do shell script "/usr/bin/curl --disable --noproxy '*' -4fsS --connect-timeout 4 --max-time 8 " & quoted form of ("https://" & hostName)
				if observedIP is expectedIP then set matches to matches + 1
				-- Only display a short numeric response from the external service.
				if (length of observedIP) > 15 or observedIP is "" then error "Invalid response"
				repeat with ch in characters of observedIP
					if "0123456789." does not contain (ch as text) then error "Invalid response"
				end repeat
				set end of results to (hostName as text) & "　" & observedIP
			on error
				set end of results to (hostName as text) & "　查询失败"
			end try
		end repeat
		set headline to "未确认 RackNerd 出口"
		if matches is 2 then set headline to "已确认 RackNerd 公网 IPv4"
		display dialog (headline & return & item 1 of results & return & item 2 of results) with title "RackNerd" buttons {"返回"} default button "返回"
	end repeat
end run
