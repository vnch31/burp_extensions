"""burp and java import"""
from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from java.util import List, ArrayList

"""python import"""
import random

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.registerIntruderPayloadGeneratorFactory(self)
        callbacks.setExtensionName("Simple Fuzzer")

        return


    def getGeneratorName(self):
        return "Simple Fuzzer"

    def createNewInstance(self, attack):
        return BHPFuzzer(self, attack)

class BHPFuzzer(IIntruderPayloadGenerator):
    def __init__(self, extender, attack):
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        self.max_payload = 10
        self.num_iteration = 0
        return

    def hasMorePayloads(self):
        if self.num_iteration == self.max_payload:
            return False
        else:
            return True

    def getNextPayload(self, current_payload):
        # convert to string
        payload = "".join(chr(x) for x in current_payload)
        # call simple mutator to fuzz the POST
        payload = self.mutate_payload(payload)

        # increase counter of attempts
        self.num_iteration += 1

        return payload

    def reset(self):
        self.num_iteration = 0
        return 

    def mutate_payload(self, original_payload):
        """pick simple mutator or call external script to use your own payload"""
        picker = random.randint(1,3)

        # select a random offset in the payload to mutate
        offset = random.randint(0, len(original_payload)-1)
        payload = original_payload[:offset]

        # SQL
        if picker == 1:
            payload += "'"

        # XSS
        if picker == 2:
            payload +="<script>alert(1)</script>"

        # repeat a chunk of the original payload a random number
        if picker == 3:
            chunk_length = random.randint(len(payload[offset:]), len(payload)-1)
            repeater = random.randint(1,10)

            for i in range(repeater):
                payload += original_payload[offset:offset+chunk_length]
            
        # add the remaining  bits of the original payload
        payload +=original_payload[offset:]

        return payload
