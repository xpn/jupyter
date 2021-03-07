from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML

class VBAAnalysis:
    def __init__(self, filepath):
        self.filepath = filepath
        self.vbaparser = None

    def _initAnalysis(self):
        self.vbaparser = VBA_Parser(self.filepath)

    def hasMacros(self):
        if self.vbaparser==None: self._initAnalysis()
        
        return self.vbaparser.detect_vba_macros()

    def analyse(self):
        if self.vbaparser==None: self._initAnalysis()

        for (filename, stream_path, vba_filename, vba_code) in self.vbaparser.extract_macros():
            yield(vba_code)

if __name__ == "__main__":
    analysis = VBAAnalysis("/tmp/test")
    print(analysis.hasMacros())
    for code in analysis.analyse():
        print(code)