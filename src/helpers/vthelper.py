import vt
import os
import os.path
from os import path

class VirusTotal:
    def __init__(self, apikey, limit=50):
        self.apikey = apikey
        self.limit = limit

    def getSearchResults(self, searchquery):
        with vt.Client(self.apikey) as client:
            it = client.iterator('/intelligence/search',
                params={'query': searchquery},
                limit=self.limit)

            for obj in it:
                yield obj

    def downloadSearchResults(self, searchquery, targetdir):
        if not path.exists(targetdir):
            try:
                os.mkdir(targetdir)
            except:
                return
                
        with vt.Client(self.apikey) as client:
            for result in self.getSearchResults(searchquery):
                file_path = os.path.join(targetdir, result.sha256)
                with open(file_path, 'wb') as f:
                    client.download_file(result.sha256, f)
                yield result

if __name__ == "__main__":
    vthelper = VirusTotal(os.environ["VT_API"], limit=1)
    #for result in vthelper.getSearchResults("test"):
    #    print(result)

    vthelper.downloadSearchResults("test", "/tmp/")
