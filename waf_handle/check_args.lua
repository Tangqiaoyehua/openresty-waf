local _M={}

_M.sql_check_dict={
	{
		id=100,
		mz="url|header_cookie|body",
		match_dict={"select","union","update","delete","insert","table","from","ascii","hex","unhex","drop"}
	},
	{
		id=101,
		msg="sql special symbol",
		mz="url|header_cookie"
		match_dict={[[/]], [[/*]], [[*/]], [[|]], [[,]], "=", [[#]], [[0x]], [[(]], [[)]], [[']], [[@@]], [[&&]], [[;]],"=="}
	}
}

_M.xss_check_dict={
	id=200,
	msg="xss found",
	mz="url|header_cookie|body",
	match_dict={"<",">","[","]","~","`"}

}

_M.crawler_check_dict={
	id=300,
	msg="crawler identified",
	mz="header_user-agent",
	match_dict={
		"python",
		"apachebench",
		"FeedDemon",
		"Indy Library",
		"Alexa Toolbar",
		"AskTbFXTV",
		"AhrefsBot",
		"CrawlDaddy",
		"CoolpadWebkit",
		"Java",
		"Feedly",
		"UniversalFeedParser",
		"ApacheBench",
		"Microsoft URL Control",
		"Swiftbot",
		"ZmEu",
		"oBot",
		"jaunty",
		"lightDeckReports Bot",
		"YYSpider",
		"DigExt",
		"HttpClient",
		"MJ12bot",
		"heritrix",
		"EasouSpider",
		"Ezooms"
	}
}