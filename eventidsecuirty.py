#windows secuirty event id database


EVENT_IDS ={
    #authentication events
    "4624": {
        "name": "Successful Logon",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Authentication",
        "subcategory": "Logon",
        "default_level": "Information",
        "severity": "Information",
        "description": "An account was successfully logged on."
    },

    "4625": {
        "name": "Failed Logon",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Authentication",
        "subcategory": "Logon",
        "default_level": "Audit Failure",
        "severity": "Warning",
        "description": "An account failed to log on."
    },

    "4634": {
        "name": "Logoff",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Logon/Logoff",
        "subcategory": "Logoff",
        "default_level": "Information",
        "severity": "Information",
        "description": "An account was logged off."
    },

    "4647": {
        "name": "User Initiated Logoff",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Logon/Logoff",
        "subcategory": "Logoff",
        "default_level": "Information",
        "severity": "Information",
        "description": "User initiated logoff."
    },

    "4648": {
        "name": "Explicit Credentials Used",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Authentication",
        "subcategory": "Credential Use",
        "default_level": "Information",
        "severity": "Information",
        "description": "A logon attempt was made using explicit credentials."
    },

    "4675": {
        "name": "SID Filtering",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Authentication",
        "subcategory": "Authentication",
        "default_level": "Information",
        "severity": "Information",
        "description": "SID filtering was applied to an account."
    },

    "4776": {
        "name": "Credential Validation",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Authentication",
        "subcategory": "NTLM",
        "default_level": "Information",
        "severity": "Information",
        "description": "The domain controller attempted to validate account credentials."
    },

    "4778": {
        "name": "Session Reconnected",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Logon/Logoff",
        "subcategory": "Remote Desktop",
        "default_level": "Information",
        "severity": "Information",
        "description": "A Remote Desktop session was reconnected."
    },

    "4779": {
        "name": "Session Disconnected",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Logon/Logoff",
        "subcategory": "Remote Desktop",
        "default_level": "Information",
        "severity": "Information",
        "description": "A Remote Desktop session was disconnected."
    },

    "4800": {
        "name": "Workstation Locked",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Logon/Logoff",
        "subcategory": "Workstation",
        "default_level": "Information",
        "severity": "Information",
        "description": "The workstation was locked."
    },

    "4801": {
        "name": "Workstation Unlocked",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Logon/Logoff",
        "subcategory": "Workstation",
        "default_level": "Information",
        "severity": "Information",
        "description": "The workstation was unlocked."
    },

    "4802": {
        "name": "Screen Saver Invoked",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Logon/Logoff",
        "subcategory": "Workstation",
        "default_level": "Information",
        "severity": "Information",
        "description": "The screen saver was invoked."
    },

    "4803": {
        "name": "Screen Saver Dismissed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Logon/Logoff",
        "subcategory": "Workstation",
        "default_level": "Information",
        "severity": "Information",
        "description": "The screen saver was dismissed."
    },
    #account management ids
        "4720": {
        "name": "User Account Created",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Account Management",
        "subcategory": "User Account",
        "default_level": "Information",
        "severity": "Information",
        "description": "A user account was created."
    },
    "4722": {
        "name": "User Account Enabled",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Account Management",
        "subcategory": "User Account",
        "default_level": "Information",
        "severity": "Information",
        "description": "A user account was enabled."
    },

    "4723": {
        "name": "Password Change Attempt",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Account Management",
        "subcategory": "Password",
        "default_level": "Information",
        "severity": "Information",
        "description": "An attempt was made to change an account's password."
    },

    "4724": {
        "name": "Password Reset Attempt",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Account Management",
        "subcategory": "Password",
        "default_level": "Information",
        "severity": "Warning",
        "description": "An attempt was made to reset an account's password."
    },

    "4725": {
        "name": "User Account Disabled",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Account Management",
        "subcategory": "User Account",
        "default_level": "Information",
        "severity": "Information",
        "description": "A user account was disabled."
    },

    "4726": {
        "name": "User Account Deleted",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Account Management",
        "subcategory": "User Account",
        "default_level": "Information",
        "severity": "Warning",
        "description": "A user account was deleted."
    },

    "4738": {
        "name": "User Account Changed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Account Management",
        "subcategory": "User Account",
        "default_level": "Information",
        "severity": "Information",
        "description": "A user account was changed."
    },

    "4740": {
        "name": "User Account Locked Out",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Account Management",
        "subcategory": "Account Lockout",
        "default_level": "Information",
        "severity": "Warning",
        "description": "A user account was locked out."
    },

    "4767": {
        "name": "User Account Unlocked",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Account Management",
        "subcategory": "Account Lockout",
        "default_level": "Information",
        "severity": "Information",
        "description": "A user account was unlocked."
    },

    "4781": {
        "name": "Account Renamed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Account Management",
        "subcategory": "User Account",
        "default_level": "Information",
        "severity": "Information",
        "description": "The name of an account was changed."
    },
    #group management ids
        "4727": {
        "name": "Security-Enabled Global Group Created",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Group Management",
        "subcategory": "Global Security Group",
        "default_level": "Information",
        "severity": "Information",
        "description": "A security-enabled global group was created."
    },

    "4728": {
        "name": "Member Added to Security-Enabled Global Group",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Group Management",
        "subcategory": "Global Security Group",
        "default_level": "Information",
        "severity": "Warning",
        "description": "A member was added to a security-enabled global group."
    },

    "4729": {
        "name": "Member Removed from Security-Enabled Global Group",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Group Management",
        "subcategory": "Global Security Group",
        "default_level": "Information",
        "severity": "Information",
        "description": "A member was removed from a security-enabled global group."
    },

    "4730": {
        "name": "Security-Enabled Global Group Deleted",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Group Management",
        "subcategory": "Global Security Group",
        "default_level": "Information",
        "severity": "Warning",
        "description": "A security-enabled global group was deleted."
    },

    "4731": {
        "name": "Security-Enabled Local Group Created",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Group Management",
        "subcategory": "Local Security Group",
        "default_level": "Information",
        "severity": "Information",
        "description": "A security-enabled local group was created."
    },

    "4732": {
        "name": "Member Added to Security-Enabled Local Group",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Group Management",
        "subcategory": "Local Security Group",
        "default_level": "Information",
        "severity": "Warning",
        "description": "A member was added to a security-enabled local group."
    },

    "4733": {
        "name": "Member Removed from Security-Enabled Local Group",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Group Management",
        "subcategory": "Local Security Group",
        "default_level": "Information",
        "severity": "Information",
        "description": "A member was removed from a security-enabled local group."
    },

    "4734": {
        "name": "Security-Enabled Local Group Deleted",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Group Management",
        "subcategory": "Local Security Group",
        "default_level": "Information",
        "severity": "Warning",
        "description": "A security-enabled local group was deleted."
    },

    "4735": {
        "name": "Security-Enabled Local Group Changed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Group Management",
        "subcategory": "Local Security Group",
        "default_level": "Information",
        "severity": "Information",
        "description": "A security-enabled local group was changed."
    },

    "4737": {
        "name": "Security-Enabled Global Group Changed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Group Management",
        "subcategory": "Global Security Group",
        "default_level": "Information",
        "severity": "Information",
        "description": "A security-enabled global group was changed."
    },

    "4754": {
        "name": "Security-Enabled Universal Group Created",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Group Management",
        "subcategory": "Universal Security Group",
        "default_level": "Information",
        "severity": "Information",
        "description": "A security-enabled universal group was created."
    },

    "4755": {
        "name": "Security-Enabled Universal Group Changed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Group Management",
        "subcategory": "Universal Security Group",
        "default_level": "Information",
        "severity": "Information",
        "description": "A security-enabled universal group was changed."
    },

    "4756": {
        "name": "Member Added to Security-Enabled Universal Group",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Group Management",
        "subcategory": "Universal Security Group",
        "default_level": "Information",
        "severity": "Warning",
        "description": "A member was added to a security-enabled universal group."
    },

    "4757": {
        "name": "Member Removed from Security-Enabled Universal Group",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Group Management",
        "subcategory": "Universal Security Group",
        "default_level": "Information",
        "severity": "Information",
        "description": "A member was removed from a security-enabled universal group."
    },

    "4758": {
        "name": "Security-Enabled Universal Group Deleted",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Group Management",
        "subcategory": "Universal Security Group",
        "default_level": "Information",
        "severity": "Warning",
        "description": "A security-enabled universal group was deleted."
    },

    "4764": {
        "name": "Group Type Changed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Group Management",
        "subcategory": "Group Properties",
        "default_level": "Information",
        "severity": "Information",
        "description": "A group's type was changed."
    },

    "4799": {
        "name": "Group Membership Enumerated",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Group Management",
        "subcategory": "Enumeration",
        "default_level": "Information",
        "severity": "Information",
        "description": "A security-enabled local group membership was enumerated."
    },
    #privlage use event ids
        "4670": {
        "name": "Permissions on an Object Changed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Privilege Use",
        "subcategory": "Permissions",
        "default_level": "Information",
        "severity": "Information",
        "description": "Permissions on an object were changed."
    },

    "4671": {
        "name": "Application Requested Access to Blocked Ordinal",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Privilege Use",
        "subcategory": "Privilege",
        "default_level": "Information",
        "severity": "Information",
        "description": "An application attempted to access a blocked service."
    },

    "4672": {
        "name": "Special Privileges Assigned",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Privilege Use",
        "subcategory": "Logon Privileges",
        "default_level": "Information",
        "severity": "High",
        "description": "Special privileges were assigned to a new logon."
    },

    "4673": {
        "name": "Privileged Service Called",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Privilege Use",
        "subcategory": "Sensitive Privilege Use",
        "default_level": "Information",
        "severity": "Medium",
        "description": "A privileged service was called."
    },

    "4674": {
        "name": "Privileged Object Operation",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Privilege Use",
        "subcategory": "Sensitive Privilege Use",
        "default_level": "Information",
        "severity": "Medium",
        "description": "An operation was attempted on a privileged object."
    },

    "4964": {
        "name": "Special Groups Assigned",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Privilege Use",
        "subcategory": "Special Groups",
        "default_level": "Information",
        "severity": "Medium",
        "description": "Special groups have been assigned to a new logon."
    },
    #process creation and detauled tracking 
        "4688": {
        "name": "Process Created",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Process Creation",
        "subcategory": "Process Execution",
        "default_level": "Information",
        "severity": "High",
        "description": "A new process has been created."
    },

    "4689": {
        "name": "Process Exited",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Process Creation",
        "subcategory": "Process Execution",
        "default_level": "Information",
        "severity": "Information",
        "description": "A process has exited."
    },

    "4690": {
        "name": "Handle Duplicated",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Process Creation",
        "subcategory": "Handle Management",
        "default_level": "Information",
        "severity": "Low",
        "description": "An attempt was made to duplicate a handle to an object."
    },

    "4691": {
        "name": "Indirect Access to Object",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Object Access",
        "subcategory": "Indirect Object Access",
        "default_level": "Information",
        "severity": "Low",
        "description": "Indirect access to an object was requested."
    },

    "4695": {
        "name": "Unprotected Audit Policy Changed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Policy Change",
        "subcategory": "Audit Policy",
        "default_level": "Information",
        "severity": "High",
        "description": "Unprotected audit policy information was modified."
    },

    "4696": {
        "name": "Primary Token Assigned",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Process Creation",
        "subcategory": "Token Management",
        "default_level": "Information",
        "severity": "Medium",
        "description": "A primary token was assigned to a process."
    },

    "4697": {
        "name": "Service Installed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Service Control",
        "subcategory": "Service Installation",
        "default_level": "Information",
        "severity": "High",
        "description": "A service was installed on the system."
    },
    #object access event ids
        "4656": {
        "name": "Handle Requested",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Object Access",
        "subcategory": "Handle",
        "default_level": "Information",
        "severity": "Information",
        "description": "A handle to an object was requested."
    },

    "4657": {
        "name": "Registry Value Modified",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Object Access",
        "subcategory": "Registry",
        "default_level": "Information",
        "severity": "Medium",
        "description": "A registry value was modified."
    },

    "4658": {
        "name": "Handle Closed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Object Access",
        "subcategory": "Handle",
        "default_level": "Information",
        "severity": "Low",
        "description": "The handle to an object was closed."
    },

    "4659": {
        "name": "Handle Requested with Intent to Delete",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Object Access",
        "subcategory": "Deletion",
        "default_level": "Information",
        "severity": "Medium",
        "description": "A handle to an object was requested with intent to delete."
    },

    "4660": {
        "name": "Object Deleted",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Object Access",
        "subcategory": "Deletion",
        "default_level": "Information",
        "severity": "High",
        "description": "An object was deleted."
    },

    "4661": {
        "name": "Handle Requested",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Object Access",
        "subcategory": "Handle",
        "default_level": "Information",
        "severity": "Information",
        "description": "A handle to an object was requested."
    },

    "4662": {
        "name": "Operation Performed on an Object",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Object Access",
        "subcategory": "Directory Service",
        "default_level": "Information",
        "severity": "High",
        "description": "An operation was performed on an object."
    },

    "4663": {
        "name": "Object Accessed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Object Access",
        "subcategory": "File System",
        "default_level": "Information",
        "severity": "High",
        "description": "An attempt was made to access an object."
    },

    "4664": {
        "name": "Hard Link Created",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Object Access",
        "subcategory": "File System",
        "default_level": "Information",
        "severity": "Medium",
        "description": "An attempt was made to create a hard link."
    },

    "4665": {
        "name": "Application Client Context",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Object Access",
        "subcategory": "Application",
        "default_level": "Information",
        "severity": "Low",
        "description": "An application client context was created."
    },

    "4667": {
        "name": "Application Client Context Generated",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Object Access",
        "subcategory": "Application",
        "default_level": "Information",
        "severity": "Low",
        "description": "An application client context was generated."
    },
    #policy change event ids 
        "4704": {
        "name": "User Right Assigned",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Policy Change",
        "subcategory": "User Rights",
        "default_level": "Information",
        "severity": "Medium",
        "description": "A user right was assigned."
    },

    "4705": {
        "name": "User Right Removed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Policy Change",
        "subcategory": "User Rights",
        "default_level": "Information",
        "severity": "Medium",
        "description": "A user right was removed."
    },

    "4715": {
        "name": "Audit Policy (SACL) Changed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Policy Change",
        "subcategory": "Audit Policy",
        "default_level": "Information",
        "severity": "High",
        "description": "The audit policy (SACL) on an object was changed."
    },

    "4719": {
        "name": "System Audit Policy Changed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Policy Change",
        "subcategory": "Audit Policy",
        "default_level": "Information",
        "severity": "Critical",
        "description": "System audit policy was changed."
    },

    "4739": {
        "name": "Domain Policy Changed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Policy Change",
        "subcategory": "Domain Policy",
        "default_level": "Information",
        "severity": "High",
        "description": "Domain policy was changed."
    },

    "4817": {
        "name": "Auditing Settings Changed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Policy Change",
        "subcategory": "Auditing",
        "default_level": "Information",
        "severity": "High",
        "description": "Auditing settings were changed."
    },

    "4902": {
        "name": "Per-User Audit Policy Table Created",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Policy Change",
        "subcategory": "Per-User Audit Policy",
        "default_level": "Information",
        "severity": "Medium",
        "description": "The Per-user audit policy table was created."
    },

    "4904": {
        "name": "Security Event Source Registered",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Policy Change",
        "subcategory": "Security Event Source",
        "default_level": "Information",
        "severity": "Medium",
        "description": "A security event source was registered."
    },

    "4905": {
        "name": "Security Event Source Unregistered",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Policy Change",
        "subcategory": "Security Event Source",
        "default_level": "Information",
        "severity": "Medium",
        "description": "A security event source was unregistered."
    },

    "4907": {
        "name": "Auditing Settings on Object Changed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Policy Change",
        "subcategory": "Object Auditing",
        "default_level": "Information",
        "severity": "High",
        "description": "Auditing settings on an object were changed."
    },

    "4908": {
        "name": "Special Groups Logon Table Modified",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Policy Change",
        "subcategory": "Special Groups",
        "default_level": "Information",
        "severity": "Medium",
        "description": "The Special Groups Logon table was modified."
    },
    #kerbos and acount log on event ids 
        "4768": {
        "name": "Kerberos Authentication Ticket (TGT) Requested",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Kerberos",
        "subcategory": "Ticket Granting Ticket",
        "default_level": "Information",
        "severity": "Information",
        "description": "A Kerberos authentication ticket (TGT) was requested."
    },

    "4769": {
        "name": "Kerberos Service Ticket Requested",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Kerberos",
        "subcategory": "Service Ticket",
        "default_level": "Information",
        "severity": "Information",
        "description": "A Kerberos service ticket was requested."
    },

    "4770": {
        "name": "Kerberos Service Ticket Renewed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Kerberos",
        "subcategory": "Service Ticket",
        "default_level": "Information",
        "severity": "Information",
        "description": "A Kerberos service ticket was renewed."
    },

    "4771": {
        "name": "Kerberos Pre-Authentication Failed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Kerberos",
        "subcategory": "Authentication Failure",
        "default_level": "Audit Failure",
        "severity": "High",
        "description": "Kerberos pre-authentication failed."
    },

    "4772": {
        "name": "Kerberos Authentication Request Failed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Kerberos",
        "subcategory": "Authentication Failure",
        "default_level": "Audit Failure",
        "severity": "High",
        "description": "A Kerberos authentication request failed."
    },

    "4773": {
        "name": "Kerberos Ticket Request Failed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Kerberos",
        "subcategory": "Ticket Failure",
        "default_level": "Audit Failure",
        "severity": "High",
        "description": "A Kerberos ticket request failed."
    },

    "4776": {
        "name": "NTLM Credential Validation",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Authentication",
        "subcategory": "NTLM",
        "default_level": "Information",
        "severity": "Information",
        "description": "The domain controller attempted to validate account credentials."
    },

    "4777": {
        "name": "Domain Controller Credential Validation Failed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Authentication",
        "subcategory": "NTLM",
        "default_level": "Audit Failure",
        "severity": "Warning",
        "description": "The domain controller failed to validate account credentials."
    },
        "4946": {
        "name": "Firewall Rule Added",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Filtering Platform",
        "subcategory": "Firewall Policy",
        "default_level": "Information",
        "severity": "High",
        "description": "A change was made to the Windows Firewall exception list. A rule was added."
    },

    "4947": {
        "name": "Firewall Rule Modified",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Filtering Platform",
        "subcategory": "Firewall Policy",
        "default_level": "Information",
        "severity": "High",
        "description": "A change was made to the Windows Firewall exception list. A rule was modified."
    },

    "4948": {
        "name": "Firewall Rule Deleted",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Filtering Platform",
        "subcategory": "Firewall Policy",
        "default_level": "Information",
        "severity": "High",
        "description": "A change was made to the Windows Firewall exception list. A rule was deleted."
    },

    "4950": {
        "name": "Firewall Settings Changed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Filtering Platform",
        "subcategory": "Firewall Configuration",
        "default_level": "Information",
        "severity": "High",
        "description": "Windows Firewall settings were changed."
    },

    "4954": {
        "name": "Firewall Group Policy Applied",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Filtering Platform",
        "subcategory": "Group Policy",
        "default_level": "Information",
        "severity": "Information",
        "description": "Windows Firewall Group Policy settings were applied."
    },

    "4956": {
        "name": "Windows Firewall Active Profile Changed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Filtering Platform",
        "subcategory": "Firewall Profile",
        "default_level": "Information",
        "severity": "Medium",
        "description": "The active Windows Firewall profile was changed."
    },

    "5024": {
        "name": "Windows Firewall Service Started",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Filtering Platform",
        "subcategory": "Firewall Service",
        "default_level": "Information",
        "severity": "Information",
        "description": "The Windows Firewall service started successfully."
    },

    "5031": {
        "name": "Application Blocked by Firewall",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Filtering Platform",
        "subcategory": "Application Filtering",
        "default_level": "Warning",
        "severity": "Medium",
        "description": "The Windows Firewall blocked an application from accepting incoming connections."
    },

    "5152": {
        "name": "Packet Blocked",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Filtering Platform",
        "subcategory": "Packet Filtering",
        "default_level": "Information",
        "severity": "Medium",
        "description": "The Windows Filtering Platform blocked a packet."
    },

    "5154": {
        "name": "Application Listening",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Filtering Platform",
        "subcategory": "Network Listener",
        "default_level": "Information",
        "severity": "Information",
        "description": "The Windows Filtering Platform permitted an application to listen on a port."
    },

    "5155": {
        "name": "Application Listening Blocked",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Filtering Platform",
        "subcategory": "Network Listener",
        "default_level": "Information",
        "severity": "Medium",
        "description": "The Windows Filtering Platform blocked an application from listening on a port."
    },

    "5156": {
        "name": "Connection Allowed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Filtering Platform",
        "subcategory": "Network Connection",
        "default_level": "Information",
        "severity": "Information",
        "description": "The Windows Filtering Platform allowed a network connection."
    },

    "5157": {
        "name": "Connection Blocked",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Filtering Platform",
        "subcategory": "Network Connection",
        "default_level": "Information",
        "severity": "High",
        "description": "The Windows Filtering Platform blocked a network connection."
    },

    "5158": {
        "name": "Bind Allowed",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Filtering Platform",
        "subcategory": "Socket Bind",
        "default_level": "Information",
        "severity": "Information",
        "description": "The Windows Filtering Platform permitted a socket to bind to a local port."
    },

    "5159": {
        "name": "Bind Blocked",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "category": "Filtering Platform",
        "subcategory": "Socket Bind",
        "default_level": "Information",
        "severity": "Medium",
        "description": "The Windows Filtering Platform blocked a socket from binding to a local port."
    }







































































}