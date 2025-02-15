

class shellcode:
    def __init__(
        self, rawData=None, decodedBody=None, decoderStub=None, decodedFull=None
    ):
        # print ("init")
        self.rawData2 = rawData  # This is current - it is variable
        self.decodedFullBody = decodedBody  #  3   the body has been decoded
        self.decoderStub = decoderStub  # 2    just the decoder stub
        self.decodedFull = decodedFull  # 1   fully decrypted, whole thing
        self.original = rawData  # original rawdata2    #0
        # self.id = 0    # tells which one rawData2 is
        self.decryptSuccess = False
        self.hasDecoderStub = False
        self.isEncoded = False
        self.decoderStubEnd = 0xFFFFFFFFFFF

    def setRawData2(self, rawData):
        self.rawData2 = rawData

    def setDecoderStubEnd(self, end):
        self.decoderStubEnd = end

    def setDecodedBody(self, decodedBody):
        self.decodedFullBody = decodedBody

    def setDecoderStub(self, decoderStub):
        self.decoderStub = decoderStub

    def setDecoded(self, decodedFull):
        self.decodedFull = decodedFull

    def isDecrypted(self):
        return self.decryptSuccess

    def hasDecStub(self):
        return self.hasDecoderStub

    def isEncoded(self):
        return self.isEncoded
