# sccmsqlclient

A dedicated MSSQL client for SCCM database exploration and exploitation.
- Recon queries
- Run PowerShell scripts on managed clients
- Extract secrets

## Installation
You can install by cloning the repository and installing the dependencies.

```sh
$ git clone --recurse-submodules https://github.com/synacktiv/sccmsqlclient
$ cd sccmsqlclient
$ python3 -m venv .venv && source .venv/bin/activate
$ python3 -m pip install -r requirements.txt
```

## Usage 

### Authentication / Login

`sccmsqlclient.py` uses the same authentication model and syntax as Impacket’s `mssqlclient.py`, since it is based on the same TDS (Tabular Data Stream) MSSQL protocol implementation.  
If you are already familiar with Impacket tools, the usage and login format is identical.


```bash
$ python3 sccmsqlclient.py -windows-auth 'DOMAIN/USER:password'@mp.local
```

### SCCM Recon


#### List Sites and servers

List SCCM sites and servers in a multi-site hierarchy.

```
> sccm_sites
> sccm_servers
```

#### List Servers and their Roles

Enumerate SCCM infrastructure servers and their assigned roles within the hierarchy.

```
> sccm_sysreslist [ROLE_NAME]
> sccm_mp
> sccm_dp
```

This set of commands queries SCCM system resource and role assignment data in order to map infrastructure components and their responsibilities.

- `sccm_sysreslist` → lists all registered SCCM system resources and their roles  
- `sccm_sysreslist [ROLE_NAME]` → filters results by role name (e.g., Management Point, Distribution Point)  
- `sccm_mp` → shortcut for listing all Management Points  
- `sccm_dp` → shortcut for listing all Distribution Points 

#### List Managed Devices


List known devices, with partial filtering by name or IP address

```
> sccm_devices [FILTER]
```

List clients with their BGB / Notification channel status (*OnlineStatus=0|1*)

```
> sccm_devices_bgbstatus [FILTER]
```

---

## SCCM Run Scripts

Exploit the Run Scripts feature to execute powershell script on managed devices

#### Set PowerShell Script

Define a PowerShell script directly from a string.

```
> set_ps1_script "<string>"
```

**Example:** 

```
> set_ps1_script "Get-Process | Select-Object -First 10"
```


---

#### Load PowerShell Script from File

Load a script from a local `.ps1` file.

**Example:** 

```
> load_ps1_script ./script.ps1
```

#### Execute SCCM Run Script

Execute a previously defined script against a target SCCM resource.

```
> sccm_run_script <RESOURCE_ID>
```

**Example:**

```
> sccm_run_script 16777219
```

When executed, this command generates two GUIDs:
- a **TASK_GUID** (execution task identifier)
- a **SCRIPT_GUID** (SCCM Run Script object identifier)

These identifiers are automatically stored in memory and reused by the following commands:
- `last_task_output`
- `llast_task_output_print`
- `last_task_clean`

This allows you to operate on the most recent execution without manually specifying GUIDs.


---

#### Retrieve Last Execution Output

Show the results of the most recent task launched via `sccm_run_script`.


```
> last_task_output
```

This retrieves the raw execution output stored in memory from the last SCCM Run Script execution.

---

#### Pretty Print Last Execution Output

Display the execution output of the last task in a human-readable format.


```
> last_task_output_print
```

This formats and cleans the raw output from the last SCCM Run Script execution for easier reading and interpretation.

---

#### Check Script Execution Status

Retrieve execution status for a task or script.

```
> sccm_ScriptsExecutionStatus [TASK_GUID|SCRIPT_GUID]
```

**Examples:**


```
> sccm_ScriptsExecutionStatus
> sccm_ScriptsExecutionStatus 4F3A1B2C-AAAA-BBBB-CCCC-1234567890AB
```

---

#### Cleanup Last Task

Remove the most recently tracked SCCM task.


```
> last_task_clean
```

---

#### Cleanup Specific BGB Task

Remove a specific Background Group (BGB) task.


```
> sccm_BGB_Tasks_clean <TASK_GUID>
```

**Example:**

```
> sccm_BGB_Tasks_clean 4F3A1B2C-AAAA-BBBB-CCCC-1234567890AB
```

---

#### Delete SCCM Script

Delete a Run Script object from SCCM.

```
> sccm_script_delete <SCRIPT_GUID>
```

**Example:**
```
> sccm_script_delete 7F2C9D11-1111-2222-3333-ABCDEF987654
```

---

## SCCM Secret Extraction

These commands allow enumeration and extraction of sensitive SCCM-related secrets such as Network Access Accounts, Client Push credentials, and Azure AD application configurations. Decryption relies on executing a remote script through SCCM Run Scripts.

---

#### List User Accounts (NAA / Client Push)

Retrieve SCCM user accounts configured for privileged operations such as Network Access Accounts (NAA) or Client Push installation accounts.

```
> sccm_useraccounts
```

---

#### List Azure AD Applications

Enumerate Azure AD application configurations stored within SCCM.

```
> sccm_add_apps
```

---

#### Decrypt Secret Blob via Management Point Execution

Execute a remote script on a SCCM Management Point or managed client in order to decrypt stored secret blobs.

```
> sccm_decrypt_blob [RESOURCE_ID] [HEXBLOB]
```

This command:

- Executes a decryption routine on the target system via SCCM Run Scripts  
- Requires a valid `RESOURCE_ID` of a Site Server or managed client with a healthy agent status (see `sccm_devices_bgbstatus`)  
- Decrypts a hex encoded blob retrieved from `sccm_add_apps` or `sccm_useraccounts`  

The execution is performed remotely, and the decrypted result is returned through the SCCM Run Script execution channel.



# References
- https://www.synacktiv.com/sites/default/files/2025-06/x33fcon2025_owning_sccm_a_journey_from_research_to_critical_discovery.pdf#page=38
- https://www.synacktiv.com/sites/default/files/2025-08/def-con-33-mehdi-elyassa-sccm-the-tree-that-always-bears-bad-fruits.pdf#page=35