PCI DSS Assessment / Technical Audit

Customer：Canlead International Co., Ltd.

Date: 2025-05-12

v1.0

1.  環境檢視

<u>掃描使用主機 (共 2 台)</u>

> Server 1 IP: 210.71.170.246
>
> Server 1 User: securevectors
>
> Server 2 IP: 54.178.41.188
>
> Server 2 User: pcidss

<u>主機規格:</u>

> OS: Ubuntu 24
>
> Spec: 2 core, 8G RAM, 50G Disk

<u>防火牆規則：</u>

<table>
<colgroup>
<col style="width: 24%" />
<col style="width: 25%" />
<col style="width: 25%" />
<col style="width: 24%" />
</colgroup>
<thead>
<tr>
<th style="text-align: left;">From</th>
<th style="text-align: left;">To</th>
<th style="text-align: left;">Service ports</th>
<th style="text-align: left;">用途</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: left;">安律辦公室</td>
<td style="text-align: left;">掃描使用主機</td>
<td style="text-align: left;">port 22/ssh</td>
<td style="text-align: left;">For 機器連線使用</td>
</tr>
<tr>
<td style="text-align: left;">掃描使用主機</td>
<td style="text-align: left;">internet</td>
<td style="text-align: left;">port 80, 443</td>
<td style="text-align: left;">For 機器設定安裝使用</td>
</tr>
<tr>
<td style="text-align: left;">所有內部網段</td>
<td style="text-align: left;">掃描使用主機</td>
<td style="text-align: left;">port 22/sftp</td>
<td style="text-align: left;">For收集主機檢查結果使用</td>
</tr>
<tr>
<td style="text-align: left;">掃描使用主機</td>
<td style="text-align: left;">所有內部網段</td>
<td style="text-align: left;">port ALL</td>
<td style="text-align: left;">For執行掃描使用</td>
</tr>
</tbody>
</table>

> \*\*\* 連線白名單 IP (安律辦公室): 122.116.225.155, 60.250.130.225,
> 13.228.126.249

1.  參考資料

現行主機資訊參考「機器\_網段清單.xlsx」<img src="media/image1.png" style="width:0.7372in;height:0.79765in"
alt="一張含有 文字, 字型, 螢幕擷取畫面, Rectangle 的圖片 AI 產生的內容可能不正確。" />以及下述各主機掃描結果進行比對。

<table>
<colgroup>
<col style="width: 30%" />
<col style="width: 30%" />
<col style="width: 39%" />
</colgroup>
<thead>
<tr>
<th style="text-align: center;">掃描 Server 1</th>
<th style="text-align: center;">掃描 Server 2</th>
<th style="text-align: center;">手動回傳 Report.zip</th>
</tr>
</thead>
<tbody>
<tr>
<td><img src="media/image2.png" style="width:2.26966in;height:2.43036in"
alt="一張含有 文字, 螢幕擷取畫面, 字型, 數字 的圖片 AI 產生的內容可能不正確。" /></td>
<td><img src="media/image3.png" style="width:2.3607in;height:2.41235in"
alt="一張含有 文字, 螢幕擷取畫面, 字型, 數字 的圖片 AI 產生的內容可能不正確。" /></td>
<td><img src="media/image4.png" style="width:3.70018in;height:2.45969in"
alt="一張含有 文字, 螢幕擷取畫面, 功能表, 文件 的圖片 AI 產生的內容可能不正確。" /></td>
</tr>
</tbody>
</table>

主機掃描摘要參考「consolidated\_system\_check\_report\_20250425\_121411.html」。<img src="media/image5.png" style="width:0.63115in;height:0.93939in"
alt="一張含有 文字, 字型, 螢幕擷取畫面, 圖形 的圖片 AI 產生的內容可能不正確。" />

1.  掃描結果

3.1 雲端主機 (AWS)

<table>
<colgroup>
<col style="width: 24%" />
<col style="width: 24%" />
<col style="width: 25%" />
<col style="width: 25%" />
</colgroup>
<thead>
<tr>
<th colspan="4" style="text-align: center;">雲端 (AWS)</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: center;">10.0.0.0/24</td>
<td style="text-align: center;">10.0.9.0/24</td>
<td style="text-align: center;">10.0.3.0/24</td>
<td style="text-align: center;">10.0.1.0/24</td>
</tr>
</tbody>
</table>

<table>
<colgroup>
<col style="width: 26%" />
<col style="width: 12%" />
<col style="width: 12%" />
<col style="width: 23%" />
<col style="width: 23%" />
</colgroup>
<thead>
<tr>
<th style="text-align: center;">項目名稱</th>
<th style="text-align: center;">IP</th>
<th style="text-align: center;">所屬機房</th>
<th style="text-align: center;">網段/Zone</th>
<th style="text-align: center;">狀態</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: center;">Web Server</td>
<td style="text-align: center;">10.0.0.111</td>
<td style="text-align: center;">AWS</td>
<td style="text-align: center;">10.0.0.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">Web Server</td>
<td style="text-align: center;">10.0.0.112</td>
<td style="text-align: center;">AWS</td>
<td style="text-align: center;">10.0.0.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">Web Server</td>
<td style="text-align: center;">10.0.0.113</td>
<td style="text-align: center;">AWS</td>
<td style="text-align: center;">10.0.0.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">Web Server</td>
<td style="text-align: center;">10.0.0.114</td>
<td style="text-align: center;">AWS</td>
<td style="text-align: center;">10.0.0.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">Active Directory</td>
<td style="text-align: center;">10.0.0.100</td>
<td style="text-align: center;">AWS</td>
<td style="text-align: center;">10.0.0.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">2FA Server</td>
<td style="text-align: center;">10.0.0.10</td>
<td style="text-align: center;">AWS</td>
<td style="text-align: center;">10.0.0.0/24</td>
<td style="text-align: center;">排除檢查 (OS 不可控)</td>
</tr>
<tr>
<td style="text-align: center;">JUMP Server</td>
<td style="text-align: center;">10.0.9.100</td>
<td style="text-align: center;">AWS</td>
<td style="text-align: center;">10.0.9.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">FTP Server</td>
<td style="text-align: center;">10.0.0.200</td>
<td style="text-align: center;">AWS</td>
<td style="text-align: center;">10.0.0.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">FTP Server</td>
<td style="text-align: center;">10.0.0.4</td>
<td style="text-align: center;">AWS</td>
<td style="text-align: center;">10.0.0.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">Mail Server</td>
<td style="text-align: center;">10.0.0.6</td>
<td style="text-align: center;">AWS</td>
<td style="text-align: center;">10.0.0.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">FIM Server (ip-10-0-0-12)</td>
<td style="text-align: center;">10.0.0.12</td>
<td style="text-align: center;">AWS</td>
<td style="text-align: center;">10.0.0.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">API Server</td>
<td style="text-align: center;">10.0.3.120</td>
<td style="text-align: center;">AWS</td>
<td style="text-align: center;">10.0.0.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">API Server</td>
<td style="text-align: center;">10.0.3.121</td>
<td style="text-align: center;">AWS</td>
<td style="text-align: center;">10.0.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">API Server</td>
<td style="text-align: center;">10.0.3.122</td>
<td style="text-align: center;">AWS</td>
<td style="text-align: center;">10.0.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">MS SQL Server</td>
<td style="text-align: center;">10.0.1.204</td>
<td style="text-align: center;">AWS</td>
<td style="text-align: center;">10.0.1.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">EIP Server</td>
<td style="text-align: center;">10.0.0.98</td>
<td style="text-align: center;">AWS</td>
<td style="text-align: center;">10.0.0.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
</tbody>
</table>

<table>
<colgroup>
<col style="width: 49%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr>
<th colspan="2"
style="text-align: center;"><strong>合規調整相關</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: center;"><p><strong>符合密碼原則</strong></p>
<p>未密碼原則(長度需為十二碼以上且英數字混合、新密碼不得與前四次密碼相同、最長使用時間90天)</p></td>
<td style="text-align: center;"><p>AWS-DB1</p>
<p>EC2AMAZ-3CUKPHR</p>
<p>EC2AMAZ-3CUKPHR_121</p>
<p>EC2AMAZ-5RNE6MK</p>
<p>EC2AMAZ-C87353G</p>
<p>EC2AMAZ-FO9SBK8</p>
<p>EC2AMAZ-L5S1NDE</p>
<p>(ip-10-0-0-12)</p>
<p>WEB1</p>
<p>WEB2</p>
<p>WEB3</p>
<p>WEB4</p></td>
</tr>
<tr>
<td
style="text-align: center;"><p><strong>符合帳戶的鎖定原則</strong></p>
<p>未符合帳戶的鎖定原則(錯誤不可超過 10 次、帳戶鎖定解除不少於 30 分鐘
或是手動解除)</p></td>
<td style="text-align: center;"><p>EC2AMAZ-3CUKPHR</p>
<p>EC2AMAZ-3CUKPHR_121</p>
<p>EC2AMAZ-5RNE6MK</p>
<p>EC2AMAZ-C87353G</p>
<p>EC2AMAZ-FO9SBK8</p>
<p>EC2AMAZ-L5S1NDE</p>
<p>EC2AMAZ-Q3KNMMR</p>
<p>(ip-10-0-0-12)</p>
<p>WEB1</p>
<p>WEB2</p>
<p>WEB3</p>
<p>WEB4</p></td>
</tr>
<tr>
<td
style="text-align: center;"><p><strong>符合帳戶閒置自動登出</strong></p>
<p>未符合帳戶閒置自動登出或超過15分鐘</p></td>
<td style="text-align: center;">EC2AMAZ-BEI6GLN</td>
</tr>
</tbody>
</table>

<table>
<colgroup>
<col style="width: 49%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr>
<th colspan="2"
style="text-align: center;"><strong>建議確認事項</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: center;"><p><strong>預設帳號關閉</strong></p>
<p>如無使用, 建議可關閉預設帳號如 (Guest, DefaultAccount, etc.)</p></td>
<td style="text-align: center;">ADServer01</td>
</tr>
<tr>
<td style="text-align: center;"><p><strong>Windows Update
紀錄</strong></p>
<p>偵測到大於 90 天未更新，建議可定期檢視微軟 Windows Update 是否有
Critical Patch 可更新。</p></td>
<td style="text-align: center;"><p>AWS-DB1</p>
<p>EC2AMAZ-5RNE6MK</p>
<p>EC2AMAZ-BEI6GLN</p>
<p>EC2AMAZ-L5S1NDE</p>
<p>WEB1</p>
<p>WEB2</p>
<p>WEB3</p>
<p>WEB4</p></td>
</tr>
</tbody>
</table>

3.2 地端主機

<table>
<colgroup>
<col style="width: 24%" />
<col style="width: 24%" />
<col style="width: 25%" />
<col style="width: 25%" />
</colgroup>
<thead>
<tr>
<th colspan="4" style="text-align: center;">地端</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: center;">192.168.4.0/24</td>
<td style="text-align: center;">192.168.9.0/24</td>
<td style="text-align: center;">192.168.8.0/24</td>
<td style="text-align: center;"></td>
</tr>
</tbody>
</table>

<table>
<colgroup>
<col style="width: 26%" />
<col style="width: 12%" />
<col style="width: 12%" />
<col style="width: 23%" />
<col style="width: 23%" />
</colgroup>
<thead>
<tr>
<th style="text-align: center;">項目名稱</th>
<th style="text-align: center;">IP</th>
<th style="text-align: center;">所屬機房</th>
<th style="text-align: center;">網段/Zone</th>
<th style="text-align: center;">狀態</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: center;">Batch Server</td>
<td style="text-align: center;">192.168.9.195</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.9.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">Firewall</td>
<td style="text-align: center;">192.168.0.254</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.0.0/24</td>
<td style="text-align: center;">排除檢查 (OS 不可控)</td>
</tr>
<tr>
<td style="text-align: center;">Firewall</td>
<td style="text-align: center;">192.168.3.254</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">排除檢查 (OS 不可控)</td>
</tr>
<tr>
<td style="text-align: center;">Firewall</td>
<td style="text-align: center;">192.168.6.254</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.6.0/24</td>
<td style="text-align: center;">排除檢查 (OS 不可控)</td>
</tr>
<tr>
<td style="text-align: center;">Log Server</td>
<td style="text-align: center;">192.168.9.190</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.9.0/24</td>
<td style="text-align: center;">排除檢查 (OS 不可控)</td>
</tr>
<tr>
<td style="text-align: center;">Accountant</td>
<td style="text-align: center;">192.168.8.74</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.8.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">Accountant</td>
<td style="text-align: center;">192.168.8.78</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.8.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">Accountant</td>
<td style="text-align: center;">192.168.8.79</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.8.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">Accountant</td>
<td style="text-align: center;">192.168.8.80</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.8.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">Accountant</td>
<td style="text-align: center;">192.168.8.81</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.8.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">Accountant</td>
<td style="text-align: center;">192.168.8.88</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.8.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">語音交換機主機</td>
<td style="text-align: center;">192.168.4.10</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.4.0/24</td>
<td style="text-align: center;">排除檢查 (OS 不可控)</td>
</tr>
<tr>
<td style="text-align: center;">語音交換機主機(主)</td>
<td style="text-align: center;">192.168.4.11</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.4.0/24</td>
<td style="text-align: center;">排除檢查 (OS 不可控)</td>
</tr>
<tr>
<td style="text-align: center;">語音交換機主機(備)</td>
<td style="text-align: center;">192.168.4.12</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.4.0/24</td>
<td style="text-align: center;">排除檢查 (OS 不可控)</td>
</tr>
<tr>
<td style="text-align: center;">語音客服系統(主)</td>
<td style="text-align: center;">192.168.4.13</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.4.0/24</td>
<td style="text-align: center;">排除檢查 (OS 不可控)</td>
</tr>
<tr>
<td style="text-align: center;">語音客服系統(備)</td>
<td style="text-align: center;">192.168.4.14</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.4.0/24</td>
<td style="text-align: center;">排除檢查 (OS 不可控)</td>
</tr>
<tr>
<td style="text-align: center;">WebCall</td>
<td style="text-align: center;">192.168.4.15</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.4.0/24</td>
<td style="text-align: center;">排除檢查 (OS 不可控)</td>
</tr>
</tbody>
</table>

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr>
<th style="text-align: center;"><strong>合規調整相關</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: center;"><strong>N/A</strong></td>
</tr>
</tbody>
</table>

<table>
<colgroup>
<col style="width: 49%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr>
<th colspan="2"
style="text-align: center;"><strong>建議確認事項</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: center;"><strong>USER8088
(192.168.8.88)</strong></td>
<td><ul>
<li><p>SMBv1狀態為 '已啟用' (應為 '停用')</p></li>
<li><p>發現風險接聽埠: 445</p></li>
<li><p>安全開機狀態為 '已停用' (應為 '啟用')</p></li>
</ul>
<p>TPM狀態異常: 'False' (應為存在且運作正常)</p></td>
</tr>
</tbody>
</table>

3.3 地端主機 (CS)

<table>
<colgroup>
<col style="width: 24%" />
<col style="width: 24%" />
<col style="width: 25%" />
<col style="width: 25%" />
</colgroup>
<thead>
<tr>
<th colspan="4" style="text-align: center;">地端</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;"></td>
<td style="text-align: center;"></td>
<td style="text-align: center;"></td>
</tr>
</tbody>
</table>

<table>
<colgroup>
<col style="width: 26%" />
<col style="width: 12%" />
<col style="width: 12%" />
<col style="width: 23%" />
<col style="width: 23%" />
</colgroup>
<thead>
<tr>
<th style="text-align: center;">項目名稱</th>
<th style="text-align: center;">IP</th>
<th style="text-align: center;">所屬機房</th>
<th style="text-align: center;">網段/Zone</th>
<th style="text-align: center;">狀態</th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.100</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.101</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.102</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.103</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.104</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.105</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.106</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.137</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.174</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.176</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.178</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.179</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.181</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.183</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.186</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.187</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.189</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.193</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.201</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.21</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.22</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.221</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.223</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.24</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.25</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.26</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.27</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.29</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.30</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.32</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.34</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.35</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.36</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.37</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.39</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.40</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.41</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.42</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.43</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.44</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.45</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.46</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.47</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.48</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.49</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.51</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.54</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.55</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.56</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.57</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.58</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.59</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.6</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.60</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.62</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.63</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.64</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.65</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.66</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.68</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.69</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.70</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.71</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.72</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.73</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.74</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.75</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.76</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.77</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.78</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.79</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.82</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.84</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.85</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.88</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.89</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.92</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.93</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.94</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.96</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
<tr>
<td style="text-align: center;">CustomerService</td>
<td style="text-align: center;">192.168.3.98</td>
<td style="text-align: center;">Local</td>
<td style="text-align: center;">192.168.3.0/24</td>
<td style="text-align: center;">已檢查設置</td>
</tr>
</tbody>
</table>

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr>
<th style="text-align: center;"><strong>合規調整相關</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: center;"><strong>N/A</strong></td>
</tr>
</tbody>
</table>

<table>
<colgroup>
<col style="width: 49%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr>
<th colspan="2"
style="text-align: center;"><strong>建議確認事項</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: center;">UAC 已停用</td>
<td style="text-align: center;">USER3055 (192.168.3.55)</td>
</tr>
<tr>
<td style="text-align: center;">防火牆未完全啟用</td>
<td style="text-align: center;">USER3028 (192.168.3.28)</td>
</tr>
<tr>
<td style="text-align: center;">Windows更新不活躍</td>
<td style="text-align: center;">USER3095 (192.168.3.95)</td>
</tr>
<tr>
<td style="text-align: center;">SMBv1協議未停用</td>
<td style="text-align: center;"><p>USER3021 (192.168.3.21)</p>
<p>USER3022 (192.168.3.22)</p>
<p>USER3025 (192.168.3.25)</p>
<p>USER3027 (192.168.3.27)</p>
<p>USER3028 (192.168.3.28)</p>
<p>USER3029-2 (192.168.3.29)</p>
<p>USER3032 (192.168.3.32)</p>
<p>USER3035 (192.168.3.35)</p>
<p>USER3036 (192.168.3.36)</p>
<p>USER3038 (192.168.3.38)</p>
<p>USER3041 (192.168.3.41)</p>
<p>USER3043 (192.168.3.43)</p>
<p>USER3048 (192.168.3.48)</p>
<p>USER3058 (192.168.3.58)</p>
<p>USER3060 (192.168.3.60)</p>
<p>USER3063 (192.168.3.63)</p>
<p>USER3065 (192.168.3.65)</p>
<p>USER3066 (192.168.3.66)</p>
<p>USER3070 (192.168.3.70)</p>
<p>USER3072 (192.168.3.72)</p>
<p>USER3077 (192.168.3.77)</p>
<p>USER3082 (192.168.3.82)</p>
<p>USER3084 (192.168.3.84)</p>
<p>USER3089 (192.168.3.89)</p>
<p>USER309 (192.168.3.137)</p>
<p>USER3095 (192.168.3.95)</p>
<p>USER3098 (192.168.3.98)</p>
<p>USER3101 (192.168.3.101)</p></td>
</tr>
</tbody>
</table>

1.  雲端環境

**AWS Account:** 366205796862

**Report Generated:** 2025-05-08 09:36:30

**Regions Checked:** Current region (ap-northeast-1 only). Use
--all-regions for a complete scan.

<img src="media/image6.png" style="width:8.51021in;height:4.37948in"
alt="一張含有 文字, 螢幕擷取畫面, 字型, 數字 的圖片 AI 產生的內容可能不正確。" />

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr>
<th style="text-align: center;"><strong>合規調整相關</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td><p><strong>Requirement 1: Install and maintain network security
controls</strong></p>
<p><strong>1.i Firewall Rules - Unrestricted Access</strong></p>
<p>✗ FAIL: Found <strong>64 non-compliant</strong> security groups with
unrestricted access</p>
<p><strong>1.ii Publicly Exposed Protocols</strong></p>
<p>✗ FAIL: Found <strong>51 non-compliant</strong> security groups with
publicly exposed protocols</p>
<p><strong>Requirement 4: Protect cardholder data with strong
cryptography</strong></p>
<p><strong>4.ii Weak Ciphers</strong></p>
<p>✗ FAIL: Found <strong>1 non-compliant</strong> load balancers using
weak ciphers</p>
<p><strong>Requirement 8: Identify users and authenticate
access</strong></p>
<p><strong>8.i Password Policy</strong></p>
<p>✗ FAIL: Found <strong>Some non-compliant</strong> IAM password
policies</p>
<p><strong>8.ii MFA Enforcement</strong></p>
<p>✗ FAIL: Found <strong>11 non-compliant</strong> IAM users without
MFA</p>
<p><strong>Requirement 10: Log and monitor all access</strong></p>
<p><strong>10.i Log Retention</strong></p>
<p>✗ FAIL: Found <strong>4 non-compliant</strong> log buckets without
1-year retention</p></td>
</tr>
</tbody>
</table>

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr>
<th style="text-align: center;"><strong>建議確認事項</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="text-align: center;">N/A</td>
</tr>
</tbody>
</table>

雲端掃描摘要參考「pci\_dss\_v4\_compliance\_report.html」。<img src="media/image7.png" style="width:0.95402in;height:1.32095in"
alt="一張含有 文字, 字型, 螢幕擷取畫面, 圖形 的圖片 AI 產生的內容可能不正確。" />

1.  總結摘要

<table>
<colgroup>
<col style="width: 34%" />
<col style="width: 65%" />
</colgroup>
<thead>
<tr>
<th
style="text-align: left;"><strong>目前範圍內是否有範圍外的主機出現</strong></th>
<th style="text-align: left;"><p><strong>通過</strong></p>
<p>尚未發現未授權主機。</p></th>
</tr>
</thead>
<tbody>
<tr>
<td
style="text-align: left;"><strong>是否有「合規調整相關」內容須修正</strong></td>
<td style="text-align: left;"><p><strong>需要修正/或確認</strong></p>
<blockquote>
<p><u>雲端環境</u></p>
<p>部分Firewall Rules, Weak Ciphers, Password Policy, MFA Enforcement,
Log Retention 需確認。</p>
<p><u>主機環境</u></p>
<p>部分主機可能不滿足以下需求。</p>
<p>未密碼原則(長度需為十二碼以上且英數字混合、新密碼不得與前四次密碼相同、最長使用時間90天)</p>
<p>未符合帳戶的鎖定原則(錯誤不可超過 10 次、帳戶鎖定解除不少於 30 分鐘
或是手動解除)</p>
<p>未符合帳戶閒置自動登出或超過15分鐘</p>
</blockquote></td>
</tr>
<tr>
<td
style="text-align: left;"><strong>是否有「建議確認事項」內容須確認</strong></td>
<td style="text-align: left;"><p><strong>需要修正/或確認</strong></p>
<p>部分主機可能需確認以下事項。</p>
<blockquote>
<p>SMBv1狀態為 '已啟用' (應為 '停用')</p>
<p>發現風險接聽埠: 445</p>
<p>UAC 已停用</p>
<p>防火牆未完全啟用</p>
<p>Windows更新不活躍</p>
</blockquote>
<p>其他建議確認事項。</p>
<blockquote>
<p>預設帳號關閉, 如無使用, 建議可關閉預設帳號如 (Guest, DefaultAccount,
etc.)</p>
<p>Windows Update 紀錄, 偵測到大於 90 天未更新，建議可定期檢視微軟
Windows Update 是否有 Critical Patch 可更新。</p>
</blockquote></td>
</tr>
<tr>
<td style="text-align: left;"></td>
<td style="text-align: left;"></td>
</tr>
<tr>
<td style="text-align: left;"></td>
<td style="text-align: left;"></td>
</tr>
</tbody>
</table>
