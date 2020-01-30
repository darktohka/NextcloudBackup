import dropbox, traceback, time, os

class Dropbox(object):

    def __init__(self, settings, folder):
        self.settings = settings
        self.folder_name = '/' + folder
        self.dropbox = None

        self.access_token = self.settings['access_token']

    def get_name(self):
        return 'Dropbox'

    def connect(self):
        self.dropbox = dropbox.Dropbox(self.access_token, timeout=900)

        try:
            account = self.dropbox.users_get_current_account()
        except AuthError:
            raise Exception('Invalid Dropbox access token!')

        print('Authenticated to Dropbox as {0}.'.format(account.name.display_name))

        try:
            self.create_folder(self.folder_name)
        except:
            # Base folder already exists, everything is fine.
            pass

        self.root_folders = self.list_folders_in(self.folder_name)

    def process_folder_metadata(self, folders, entries):
        for entry in entries:
            if isinstance(entry, dropbox.files.FileMetadata) or isinstance(entry, dropbox.files.FolderMetadata):
                folders[entry.path_lower] = entry
            elif isinstance(entry, dropbox.files.DeletedMetadata):
                folders.pop(entry.path_lower, None)

        return folders

    def get_folder_children(self, path):
        result = self.dropbox.files_list_folder(path)
        files = self.process_folder_metadata({}, result.entries)

        while result.has_more:
            result = self.dropbox.files_list_folder_continue(result.cursor)
            files = self.process_folder_metadata(files, result.entries)

        return files

    def create_folder(self, path):
        result = self.dropbox.files_create_folder_v2(path)
        return result.metadata

    def create_folder_in_root(self, name):
        folder = self.create_folder(os.path.join(self.folder_name, name))
        self.root_folders.append(folder)
        return folder

    def upload_file(self, source_filename, folder_path, filename):
        while True:
            try:
                return self.upload_file_unsafe(source_filename, folder_path, filename)
            except:
                print('Exception during Dropbox file upload: {0}, resuming in 5 seconds...'.format(filename))
                traceback.print_exc()
                time.sleep(5)

    def upload_file_unsafe(self, source_filename, folder_path, filename):
        file_size = os.path.getsize(source_filename)
        chunk_size = 8 * 1024 * 1024
        target_path = os.path.join(folder_path, filename)

        with open(source_filename, 'rb') as f:
            if file_size <= chunk_size:
                return self.dropbox.files_upload(f.read(), target_path, mute=True)

            upload_session_start_result = self.dropbox.files_upload_session_start(
                f.read(chunk_size)
            )
            cursor = dropbox.files.UploadSessionCursor(
                session_id=upload_session_start_result.session_id,
                offset=f.tell()
            )
            commit = dropbox.files.CommitInfo(path=target_path)

            while f.tell() < file_size:
                if (file_size - f.tell()) <= chunk_size:
                    return self.dropbox.files_upload_session_finish(
                        f.read(chunk_size), cursor, commit
                    )
                else:
                    self.dropbox.files_upload_session_append_v2(
                        f.read(chunk_size),
                        cursor
                    )
                    cursor.offset = f.tell()

    def list_folders_in(self, path):
        return [metadata for metadata in self.get_folder_children(path).values() if isinstance(metadata, dropbox.files.FolderMetadata)]

    def list_files_in(self, path):
        return [metadata for metadata in self.get_folder_children(path).values() if isinstance(metadata, dropbox.files.FileMetadata)]

    def search_for_file_in(self, path, filename):
        result = self.dropbox.files_search(path, filename, max_results=1)
        
        if result.matches:
            return result.matches[0].metadata

    def find_file_in_list(self, files, filename):
        for file in files:
            if file.name == filename:
                return file

    def find_file_in_root(self, filename):
        return self.find_file_in_list(self.root_folders, filename)

    def get_file_size(self, file):
        return file.size

    def get_folder_path(self, folder):
        return folder.path_lower