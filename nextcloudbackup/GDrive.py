from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
import sys

FOLDER_MIME = 'application/vnd.google-apps.folder'

class GDrive(object):

    def __init__(self, settings, folder):
        self.settings = settings
        self.folder_id = folder
        self.auth = None
        self.drive = None

        self.team_drive = self.settings['team_drive']

    def get_name(self):
        return 'Google Drive'

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
        self.root_folders = self.drive.list_folders_in(self.folder_id)

    def create_folder(self, name, folder_id):
        folder = self.drive.CreateFile({
            'title': name,
            'parents': [{
                'kind': 'drive#fileLink',
                'teamDriveId': self.team_drive,
                'id': folder_id
            }],
            'mimeType': FOLDER_MIME
        })
        folder.Upload(param={'supportsTeamDrives': True})
        return folder

    def create_folder_in_root(self, name):
        folder = self.create_folder(name, self.folder_id)
        self.root_folders.append(folder)
        return folder

    def upload_file(self, source_filename, folder_path, filename):
        file = self.drive.CreateFile({
            'title': filename,
            'parents': [{
                'kind': 'drive#fileLink',
                'teamDriveId': self.team_drive,
                'id': folder_path
            }]
        })
        file.SetContentFile(source_filename)
        file.Upload(param={'supportsTeamDrives': True})
        return file

    def search_files(self, query):
        return self.drive.ListFile({'q': query, 'corpora': 'teamDrive', 'teamDriveId': self.team_drive, 'includeTeamDriveItems': 'true', 'supportsTeamDrives': 'true', 'maxResults': 20000}).GetList()

    def list_folders_in(self, folder_id):
        return self.search_files("'{0}' in parents and trashed=false and mimeType='{1}'".format(folder_id, FOLDER_MIME))

    def list_files_in(self, folder_id):
        return self.search_files("'{0}' in parents and trashed=false".format(folder_id))

    def search_for_file_in(self, folder_id, filename):
        return self.search_files("trashed=false and title='{0}'".format(filename))

    def find_file_in_list(self, files, filename):
        for file in files:
            if file['title'] == filename:
                return file

    def find_file_in_root(self, filename):
        return self.find_file_in_list(self.root_folders, filename)

    def get_file_size(self, file):
        return int(file[0]['fileSize'])

    def get_folder_path(self, folder):
        return folder['id']