from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
import sys

FOLDER_MIME = 'application/vnd.google-apps.folder'

class GDrive(object):

    def __init__(self, team_drive_id):
        self.auth = None
        self.drive = None
        self.team_drive_id = team_drive_id

    def connect(self, filename='credentials.json'):
        self.auth = GoogleAuth()
        self.auth.LoadCredentialsFile(filename)

        if self.auth.credentials is None:
            if sys.platform == 'win32':
                self.auth.LocalWebserverAuth()
            else:
                raise Exception('Google Drive credentials have expired.')
        elif self.auth.access_token_expired:
            self.auth.Refresh()
        else:
            self.auth.Authorize()

        self.auth.SaveCredentialsFile(filename)
        self.drive = GoogleDrive(self.auth)

    def create_folder(self, name, folder_id):
        folder = self.drive.CreateFile({
            'title': name,
            'parents': [{
                'kind': 'drive#fileLink',
                'teamDriveId': self.team_drive_id,
                'id': folder_id
            }],
            'mimeType': FOLDER_MIME
        })
        folder.Upload(param={'supportsTeamDrives': True})
        return folder

    def upload_file(self, source_filename, folder_id, filename):
        file = self.drive.CreateFile({
            'title': filename,
            'parents': [{
                'kind': 'drive#fileLink',
                'teamDriveId': self.team_drive_id,
                'id': folder_id
            }]
        })
        file.SetContentFile(source_filename)
        file.Upload(param={'supportsTeamDrives': True})
        return file

    def search_files(self, query):
        try:
            return self.drive.ListFile({'q': query, 'corpora': 'teamDrive', 'teamDriveId': self.team_drive_id, 'includeTeamDriveItems': 'true', 'supportsTeamDrives': 'true', 'maxResults': 20000}).GetList()
        except:
            return []

    def list_folders_in(self, folder_id):
        return self.search_files("'{0}' in parents and trashed=false and mimeType='{1}'".format(folder_id, FOLDER_MIME))

    def list_files_in(self, folder_id):
        return self.search_files("'{0}' in parents and trashed=false".format(folder_id))

    def search_for_file(self, filename):
        return self.search_files("trashed=false and title='{0}'".format(filename))

    def find_file_in_list(self, files, filename):
        for file in files:
            if file['title'] == filename:
                return file
