function include_js(path) 
{     
      var sobj = document.createElement('script'); 
      sobj.type = "text/javascript"; 
      sobj.src = path; 
      var headobj = document.getElementsByTagName('head')[0]; 
      headobj.appendChild(sobj); 
} 
/* end of NYB */

include_js("jquery-3.2.1.min.js"); 
/* script about including "menu.js" is write in html file. NYB hate this */
/* change will happen in every html file. I don't have that much time. */

var authEntries = new Array();


function init()
{
	getAuthEntries();
	showAuthTable('authTable');
}

function getAuthEntries()
{
	var form0 = document.forms[0];
	if(form0.h_auth_table.value == "")
	{
		authEntries = undefined;
		return false;
	}
	authEntries = form0.h_auth_table.value.split('\n');
	alert(authEntries.length);
}

function showAuthTable(tableId)
{
	clearAuthTable(tableId);
	if(authEntries == undefined)
		return false;
	for(var i = 0; i < authEntries.length; i++)
	{
		addAuthTableRow(tableId, authEntries[i]);
	}
}


function clearAuthTable(tableId)
{

	var table = document.getElementById(tableId);
	var id_table = "table#" + tableId;
	$(id_table).empty();
	var newRow = '';
	newRow += '<tr align="center" id="auth_tr_0">'
  	newRow += 	'<th>'
  	newRow += 		'<input type="checkbox" id="checkbox_0" onclick="selectAllAuthTableRows()">'
  	newRow += 	'</th>'
  	newRow += 	'<th width="25%">索引</th>'
  	newRow += 	'<th  width="25%" id="auth_state_0">认证状态</th>'
	newRow += 	'<th  width="25%" id="ip_0">IP</th>'
	newRow += 	'<th  width="25%" id="mac_0">MAC</th>'
	newRow += '</tr>'
	$(id_table).append(newRow);
}

function addAuthTableRow(tableId, entry)
{
	var table = document.getElementById(tableId);
	var info = new Array();
	info = entry.split('#');
	
	var id_table = "table#" + tableId;
	var rowLen = $(id_table).find("tr").length;
	var newRow = '';
	newRow += '<tr align="center" id="auth_tr_' + rowLen + '">'
	newRow += '<td>'
  	newRow +=		'<input type="checkbox" id="checkbox_' + rowLen + '">'
  	newRow +=	'</td>'
	newRow += '<td>' + rowLen + '</td>'
	newRow +=	'<td>'
	if(info[0] == "0")
	{
		newRow +=		'<input type="radio" name="auth_state_' + rowLen + '" value="1">yes'
		newRow +=		'<input type="radio" name="auth_state_' + rowLen + '" value="0" checked="checked">no'
	}
	else
	{
		newRow +=		'<input type="radio" name="auth_state_' + rowLen + '" value="1" checked="checked">yes'
		newRow +=		'<input type="radio" name="auth_state_' + rowLen + '" value="0">no'
	}
	newRow +=	'</td>'
	newRow +=	'<td id="ip_' + rowLen + '">'+ info[1] + '</td>'
	newRow +=	'<td id="mac_' + rowLen + '">' + info[2] + '</td>'
	newRow += '</tr>'
	$("table#authTable").append(newRow);
}

function delAuthTableRowSelect(tableId)
{
	var id_table = "table#" + tableId;
	var rowLen = $(id_table).find("tr").length;
	for(var i = (rowLen - 1); i >= 1; i--)
	{
		var tr = $(id_table).find("tr");
		var td = $(tr[i]).find("td");
		var id_auth_tr  = "#auth_tr_" + $(td[1]).text();
		var id_checkbox = "#checkbox_" + $(td[1]).text();
		//alert($(td[1]).text());
		if($(id_checkbox).is(":checked"))
		{
			
			$(id_auth_tr).remove();
		}
	}
}

function update_h_auth_table(tableId)
{
	var form0 = document.forms[0];
	var table = document.getElementById(tableId);
	var id_table = "table#" + tableId;
	var rowLen = $(id_table).find("tr").length;
	var colLen = $(id_table).find("tr").find("td").length;
	form0.h_auth_table.value = "";
	if(rowLen == 1)
		return true;
	for(var i = 1; i < rowLen-1 ; i++)
	{
		var tr = $(id_table).find("tr");
		var td = $(tr[i]).find("td");
		var name_auth_state = "input:radio[name=auth_state_" + $(td[1]).text() +"]:checked";
		
		
		form0.h_auth_table.value += $(name_auth_state).val() + '#';
		form0.h_auth_table.value += $(td[3]).text() + '#';
		form0.h_auth_table.value += $(td[4]).text() + '#' + '\n';
		
		/*
		var name_auth_state = "input:radio[name=auth_state_" + i +"]:checked";
		var id_ip         = "#ip_" + i;
		var id_mac        = "#mac_" + i;
		form0.h_auth_table.value += $(name_auth_state).val() + '#';
		form0.h_auth_table.value += $(id_ip).text() + '#';
		form0.h_auth_table.value += $(id_mac).text() + '#' + '\n';
		*/
	}
	var tr = $(id_table).find("tr");
	var td = $(tr[rowLen-1]).find("td");
	var name_auth_state = "input:radio[name=auth_state_" + $(td[1]).text() +"]:checked";
	
	
	form0.h_auth_table.value += $(name_auth_state).val() + '#';
	form0.h_auth_table.value += $(td[3]).text() + '#';
	form0.h_auth_table.value += $(td[4]).text() + '#';
}

function delUpdateRefresh(tableId)
{
	delAuthTableRowSelect(tableId);
	update_h_auth_table(tableId);
	getAuthEntries();
	showAuthTable(tableId);
}


function selectAllAuthTableRows()
{
	var id_checkbox_all = "#checkbox_0";
	var rowLen = $("#authTable").find("tr").length;
	var is_checked;
	if($(id_checkbox_all).is(":checked"))
		is_checked = true;
	else
		is_checked = false;
	
	for(var i = 1; i < rowLen; i++)
	{
		var id_checkbox = "#checkbox_" + i;
		$(id_checkbox).attr("checked", is_checked);
	}
}
