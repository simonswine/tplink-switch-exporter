package switches

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

const portStatus = `<!DOCTYPE html>
<script>
var max_port_num = 8;
var port_middle_num  = 16;
var all_info = {
state:[0,1,1,1,1,1,1,1,0,0],
link_status:[0,6,0,0,0,5,6,6,0,0],
pkts:[11,0,0,0,208626,0,59405,0,0,0,0,0,0,0,0,0,26977,0,7514,0,52850,0,14235,0,3178723,0,2274174,0,2362493,0,3327460,0,0,0]
};
var tip = "";
</script>
 <head> <meta charset=gb2312> <script>document.write(top.Abbrev)</script> <script type=text/javascript>incCss("main.css"),incCss("help.css"),incJs("ui.js"),incJs("help.js"),incJs("tips.js");var state_info=new Array("Disabled","Enabled"),link_info=new Array("Link Down","Auto","10Half","10Full","100Half","100Full","1000Full","");function dosubmitClear(){return document.port_statistics.submit(),!0}function dosubmitRefresh(){document.location.href="PortStatisticsRpm.htm"}</script> </head> <body> <div id=div_tip_mask class=TIP_MASK> <div id=div_tip_svr class=TIP><span id=sp_tip_svr class=TIP_CONTENT></span></div> </div> <form name=port_statistics action=port_statistics_set.cgi enctype=multipart/form-data> <fieldset> <legend> <span id=portStatisticsInformation class=PAIN_TITLE>Port Statistics Info</span> </legend> <div id=div_sec_title> <table class=BORDER> <script>var index,tmp_info2,all_info2,port_id,state,link_status,tx_good,tx_bad,rx_good,rx_bad,LineTd="<td class=TABLE_HEAD_BOTTOM align=center width=78px>";for(docW("<tr class=TD_FIRST_ROW>"),docW(LineTd+"Port"),docW("</td>"),docW(LineTd+"Status"),docW("</td>"),docW(LineTd+"Link Status"),docW("</td>"),docW(LineTd+"TxGoodPkt"),docW("</td>"),docW(LineTd+"TxBadPkt"),docW("</td>"),docW(LineTd+"RxGoodPkt"),docW("</td>"),docW(LineTd+"RxBadPkt"),docW("</td>"),docW("</tr>"),index=0;index<max_port_num;index++)port="Port "+(port_id=index+1),state=state_info[all_info.state[index]],link_status=link_info[all_info.link_status[index]],tx_good=all_info.pkts[4*index],tx_bad=all_info.pkts[4*index+1],rx_good=all_info.pkts[4*index+2],rx_bad=all_info.pkts[4*index+3],docW("<tr>"),docW(LineTd+port),docW("</td>"),docW(LineTd+state),docW("</td>"),docW(LineTd+link_status),docW("</td>"),docW(LineTd+tx_good),docW("</td>"),docW(LineTd+tx_bad),docW("</td>"),docW(LineTd+rx_good),docW("</td>"),docW(LineTd+rx_bad),docW("</td>"),docW("</tr>")</script> </table> <table class=BTN_WRAPPER align=center> <tr> <td class=BTN_WRAPPER><a class=BTN> <input type=button value=Refresh name=refresh onclick=dosubmitRefresh() class=BTN_NORMAL_BTN> </a> </td> <td class=BTN_WRAPPER><a class=BTN> <input type=submit value=Clear id=btn_slt_clear name=clear onclick=dosubmitClear() class=BTN_NORMAL_BTN> </a> </td> <td class=BTN_WRAPPER> <a class=BTN> <input type=button class=BTN_NORMAL_BTN value=Help name=help onclick='doShowHelp("div_sec_title","div_help_lan_svr","PortStatisticsHelpRpm.htm")'> </a> </td> </tr> </table> </div> </fieldset> </form> <script>ShowHelp('<span class="HELP_TITLE" id="t_help_title">Port Statistics Info</span> ')</script>   <script>window.onload=function(){new Drag("div_help_lan_svr","div_help_lan_svr")}</script> <script>""!=tip&&(ShowTips("sp_tip_svr",tip),startDownScroll("div_tip_svr"))</script>`

func TestParse(t *testing.T) {
	client := &TPLINKSwitch{
		log: zerolog.Nop(),
	}

	x, err := client.parsePortStatus([]byte(portStatus))
	require.NoError(t, err)

	require.ElementsMatch(
		t,
		[]PortStats{
			{
				AdminStatus:  2,
				OperStatus:   2,
				OutUcastPkts: 11,
			},
			{
				AdminStatus:  1,
				OperStatus:   1,
				Speed:        1000000000,
				InUcastPkts:  59405,
				OutUcastPkts: 208626,
			},
			{
				AdminStatus: 1,
				OperStatus:  2,
			},
			{
				AdminStatus: 1,
				OperStatus:  2,
			},
			{
				AdminStatus:  1,
				OperStatus:   2,
				InUcastPkts:  7514,
				OutUcastPkts: 26977,
			},
			{
				AdminStatus:  1,
				OperStatus:   1,
				Speed:        100000000,
				InUcastPkts:  14235,
				OutUcastPkts: 52850,
			},
			{
				AdminStatus:  1,
				OperStatus:   1,
				Speed:        1000000000,
				InUcastPkts:  2.274174e+06,
				OutUcastPkts: 3.178723e+06,
			},
			{
				AdminStatus:  1,
				OperStatus:   1,
				Speed:        1000000000,
				InUcastPkts:  3.32746e+06,
				OutUcastPkts: 2.362493e+06,
			},
		},
		x,
	)

}
