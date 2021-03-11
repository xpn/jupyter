import speakeasy

class ShellcodeEmulation:
    def __init__(self, path, arch, data=""):
        self.path = path
        self.arch = arch
        self.data = data
        self._se = speakeasy.Speakeasy()

    @staticmethod
    def usingData(data, arch):
        emu = ShellcodeEmulation('', arch, data=data)
        return emu

    def addHook(self, dll, method, callback):
        self._se.add_api_hook(callback, dll, method)

    def run(self):
        if self.data == '':
            runner = self._se.load_shellcode(self.path, self.arch)
        else:
            runner = self._se.load_shellcode(self.path, self.arch, self.data)

        self._se.run_shellcode(runner)
