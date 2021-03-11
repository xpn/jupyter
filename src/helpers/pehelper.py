import pefile

class PEHelper:
    def __init__(self):
        self.pe = None

    @staticmethod
    def usingPath(path):
        pe = PEHelper()
        pe._path = path
        return pe

    def _loadFile(self):
        if self.pe == None:
            self.pe = pefile.PE(self._path, fast_load=True)

    def getImports(self):
        self._loadFile()
        self.pe.parse_data_directories()

        results = {}

        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                results[entry.dll] = []
                for imp in entry.imports:
                    results[entry.dll].append(imp.name)

        return results

    def getExports(self):
        self._loadFile()
        self.pe.parse_data_directories()

        results = []

        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                results.append(exp.name)

        return results

if __name__ == "__main__":
    pe = PEHelper.usingPath("/tmp/test.bin")
    print(pe.getImports())
    print(pe.getExports())