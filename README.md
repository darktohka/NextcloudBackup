# NextcloudBackup

NextcloudBackup is an easy to use Python script that automatically backs your Nextcloud user's files up to an Unlimited Google Drive.

**All backup files are compressed and encrypted! Filenames are obfuscated!**

To use this Python script, you must own a Team Google Drive. You can get an unlimited Google Drive using Google For Education or G Suite.

The application sends a message using Discord webhooks in case of an unrecoverable error.

The backup folder ID can be found in the last part of your Google Drive link, for example: `https://drive.google.com/drive/u/1/folders/1JGkMDe7TWP15oDjXN7W4Ou8EgpqqGa2D`

# General Settings

Sample `settings.json` file (necessary to run application):

```
{
    "webhook_url": "https://discordapp.com/api/webhooks/513567234170380045/qx6jCH4MbmteWLb_kCqK66FCVXMMG_4kTK8ziL_9NTRzzHbyq622LbD32ejFBaJB8NWx",
    "backups": {
        "first": {
            "type": "nextcloud",
            "file_password": "my_custom_pw",
            "manifest_password": "my_custom_manifest_pw",
            "nextcloud_username": "darktohka",
            "nextcloud_folder": "/var/lib/nextcloud/data",
            "team_drive_id": "0BAo-tx9NqcBaKuP9AV",
            "backup_folder_id": "1JGkMDe7TWP15oDjXN7W4Ou8EgpqqGa2D",
            "mysql_host": "127.0.0.1",
            "mysql_db": "nextcloud",
            "mysql_user": "nextcloud",
            "mysql_password": "my_mysql_pw"
        },
        "second": {
            "type": "filesystem",
            "folder": "/opt/important-files",
            "file_password": "another_pw",
            "manifest_password": "another_pw",
            "team_drive_id": "0BAo-tx9NqcBaKuP9AV",
            "backup_folder_id": "1JGkMDe7TWP15oDjXN7W4Ou8EdvaeCANT"
        }
    }
}
```

# Google Drive Setup

You must create a Google application that has access to the Google Drive OAuth 2.0 scope. The OAuth 2.0 client_secrets.json file has to be copied into the root folder of the backup tool.

On your first run, you will be asked to authenticate with your Google account. This step will create a credentials.json file, which must be copied into your backup tool's root folder in production.

# Usage

To run the application, simply run:

```
python3 -m pip install -r requirements.txt
python3 -OO NextcloudBackup.py
```
