# AD_HealthCheck
Script to check health of your Active Directory Environment

**This Script was originally written by Nicolas Nerson. You can find it on https://adhealthcheck.codeplex.com/**
**The latest version that I found on Internet was 1.14**


# Main Modifications in my versions

[1] v1.15, 2019-11-22 - Adjust Hash Tables to Powershell v3 and superior, and change gpotool to latest version

[2] v1.16, 2019-11-26 - Add Parameter to choose between verify Forest or Domain and option to sendmail

[3] v1.17, 2020-08-18 - Adjust to run GpoTool in mode Forest or Domain 

[4] v1.18, 2020-12-10 - Adjust embedded images to be sent by e-mail and put a boolean variable to choose if you want to send e-mail or not 



# How to Use the Script

*_PUT the following files in same folder: AD_Configuration.xsd, AD_Configuration.xml, gpotool.exe and AD_Health_Check_v1.18_Git.ps1*

*_YOU SHOULD CREATE AN SERVICE ACCOUNT WITH DOMAIN ADMINS PERMISSIONS TO RUN THIS SCRIPT PROPERLY_"

[x] AD_Health_Check_v1.18_GIT.ps1 - This is the main script

[x] AD_Configuration.xml - file where you put your PDC, SCHEMA MASTER, RID MASTER, INTRASTRUCTURE MASTER, NAMING MASTER and yours Sites, Subnets and Links 

[x] gpotool.exe - This tool is explained in https://www.windowstechno.com/group-policy-verification-tool-gpotool-exe/

[x]ADHC_Auxiliar_XML.xlsx - worksheet to help to fill the XML after you run the script for the first time

[x] Button-Blank-Gray-icon.png ,Button-Blank-Green-icon.png, Button-Blank-Red-icon.png and Button-Blank-Yellow-icon.png  - Images must stay in subfolder Images. One level where you put the main script. 

[x]When you run this script for the first time, the HTML output will bring information about Sites, Subnets, Adjacent Sites and Site Links (with yellow collor). You have to insert all information in Ad_Configuration.xml for the next time these informations will become in green colour and any change will be noted. To help I created a worksheet called ADHC_Auxiliar_XML.xlsx where you put the information and paste to the XML. 
