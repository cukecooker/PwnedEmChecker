Red [ 
	Title: "RED-Pwned?"
    Purpose: "https://haveibeenpwned.com/API/v2 searched via a RESTful service"
    Author:  [
        "YU XIAODONG"
		"Gregg Irwin" {
			Ported from %json.r by Romano Paolo Tenca, Douglas Crockford, 
			and Gregg Irwin.
			Further research: json libs by Chris Ross-Gill, Kaj de Vos, and
			@WiseGenius.
		}
	]
	license: [
		http://www.apache.org/licenses/LICENSE-2.0 
		and "The Software shall be used for Good, not Evil."
	]
	References: [
		http://www.json.org/
		https://www.ietf.org/rfc/rfc4627.txt
		http://www.rfc-editor.org/rfc/rfc7159.txt
		http://www.ecma-international.org/publications/files/ECMA-ST/ECMA-404.pdf
		https://github.com/rebolek/red-tools/blob/master/json.red
	]
	Needs: [
		View
	]
	Version: 1.0.0
	icon: %snowman.ico
]
;#include %json.red
;do %json2.red
json2red: read %json.red
do json2red
url: "https://haveibeenpwned.com/api/v2/breachedaccount/"
breach_result: [
		View/flags [
			title "Breach searched"
		][popup]
	]
Get_data: function [email] [
	uurl: copy url
	append uurl email
	uurl: to url! uurl
	urlcheck: error? try[src: read uurl]
	if not urlcheck [
		if src ==""[
			result-src: ""
		]
		if src <>""[
			result-src: do [load-json src] 
			;result-src: load-json src
		]
	]
	if urlcheck[
		result-src: ""
	] 
	return result-src
]
item_tmp: ""
New_face: function [res][
	Data: "泄露信息:"
	clear breach_result_tmp
	breach_result_tmp: copy/deep breach_result
	if res ==""[
		append breach_result_tmp/2 [ backdrop #1e5621 below h3 "Good news — no pwnage found!" font-color #d3d3d3 text "No breached accounts and no pastes (subscribe to search sensitive breaches)" font-color #d3d3d3]
	]
	if res <>""[
		append breach_result_tmp/2 [ backdrop #6a2424 below h3 "Oh no — pwned!" font-color #d3d3d3 text "Breaches you were pwned in(信息泄露于)" font-color #d3d3d3]
		foreach item res [
			Data_tmp: copy Data
			title: select item "Title"
			insert title "Name:"
			Domain: select item "Domain"
			insert Domain "来源域名:"
			BreachDate: select item "BreachDate"
			insert BreachDate "泄露日期:"
			DataClasses: select item "DataClasses"
			append breach_result_tmp/2 'h4 'font-color #d3d3d3
			append breach_result_tmp/2 title
			append breach_result_tmp/2 'text 'font-color #d3d3d3
			append breach_result_tmp/2 Domain
			append breach_result_tmp/2 'text 'font-color #d3d3d3
			append breach_result_tmp/2 BreachDate
			append breach_result_tmp/2 'text 'font-color #d3d3d3
			foreach Classes DataClasses [
				append Data_tmp Classes
				append Data_tmp " "
			]
			append breach_result_tmp/2 Data_tmp
		]
	]
	do breach_result_tmp
]
Total: [
View/flags [
	title "haveibeenpwned by RED"
	below ;below row
	;origin 20x20
	title: h3 ";--have i been pwned?" #286786
	across
	src-email: field 230x25 "输入要检测的邮箱" font-size 10 font-color #286786 [ print src-email/text ] on-down [src-email/text: ""]
	button: button 70x25 "pwned?" [
		email: copy src-email/text
		check_at: find email @
		check_doc: find email '.
		if (none? check_at) and (none? check_doc) [
			src-email/text: "Not an Email addresses"
		]
		if (not none? check_at) and (not none? check_doc) [
			src-email/text: "watting....."
			New_face Get_data email
			src-email/text: "输入要检测的邮箱"
		]
	]
] [ no-min ]
]
do Total