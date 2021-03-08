import yara

class YaraMatch:

    @staticmethod
    def usingYaraString(yaraRule):
        m = YaraMatch()
        m.rules = yara.compile(source=yaraRule)
        return m

    @staticmethod
    def usingYaraDir(rulepath):
        m = YaraMatch()
        m.rules = yara.compile(rulepath)
        return m

    def getAllMatches(self, file):  
        matches = self.rules.match(file)
        return matches

if __name__ == "__main__":
    y = YaraMatch("/tmp/rules")
    y.getAllMatches("/tmp/test")

    y = YaraMatch.usingYaraString('rule dummy { condition: true }')
    y.getAllMatches("/tmp/test")