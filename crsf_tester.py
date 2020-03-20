from exceptions_fix import FixBurpExceptions
from burp import IBurpExtender
from burp import IHttpListener
from burp import IMessageEditorTab           
from burp import IMessageEditorTabFactory    
from datetime import datetime
import sys

PARAM_URL = 0
PARAM_BODY = 1
PARAM_COOKIE = 2

class BurpExtender(IBurpExtender, IHttpListener, IMessageEditorTabFactory):
    #create extenstion
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        #set name
        callbacks.setExtensionName("CSRF-Detecter")
        #set for debugger
        sys.stdout = callbacks.getStdout()
        #register extension as a message editor tab
        callbacks.registerMessageEditorTabFactory(self)

        return
    
    def createNewInstance(self, controller, editable):
        # create http tab
        return DisplayResults(self, controller, editable)

    
class DisplayResults(IMessageEditorTab):
    """ Create a http message tab that analyze csrf token in request"""
    def __init__(self, extender, controller, editable):
        self._txtInput = extender._callbacks.createTextEditor()
        self._extender = extender
        self._helpers = extender._callbacks.getHelpers()
        self._detectMessage = ""

    def getUiComponent(self):
        return self._txtInput.getComponent()

    def getTabCaption(self):
        return "CSRF - Detecter"

    def isEnabled(self, content, isRequest):
        self._detectMessage = ""
        if isRequest:
            found = False
            headers = list(self._helpers.analyzeRequest(content).getHeaders())
            parameters = list(self._helpers.analyzeRequest(content).getParameters())
            url_params = list()
            body_params = list()
            cookies = list()
            """ Test headers"""
            csrf_header = [header for header in headers if str(header).startswith("csrf")]
            """ Test URL parameters, Cookie, body"""
            for param in parameters:
                #test url parameters
                if param.getType() == PARAM_URL and param.getName().find("csrf") != -1: #if url parameters byte = 0
                    url_params.append("\n[+] {} : {}\n".format(param.getName(), param.getValue()))
                #test body parameters
                elif param.getType() == PARAM_BODY and param.getName().find("csrf") != -1: #if body parameters byte = 1
                    body_params.append("\n[+] {} : {}\n".format(param.getName(), param.getValue()))
                #test cookies
                elif param.getType() == PARAM_COOKIE and param.getName().find("csrf") != -1: #if cookies parameters byte = 1
                    cookies.append("\n[+] {} : {}\n".format(param.getName(), param.getValue()))
            """ Store results to display """
            if len(csrf_header) != 0:
                found = True
                self._detectMessage += "\ncsrf token in header : "
                for csrf in csrf_header:
                    self._detectMessage += "\n[+]{}\n".format(csrf)
            if len(url_params) != 0:
                found = True
                self._detectMessage += "\ncsrf token in url parameters : "
                for csrf in url_params:
                    self._detectMessage += csrf
            if len(body_params) != 0:
                found = True
                self._detectMessage += "\ncsrf token in body parameters : "
                for csrf in body_params:
                    self._detectMessage += csrf
            if len(cookies) != 0:
                found = True
                self._detectMessage += "\ncsrf token in cookies : "
                for csrf in cookies:
                    self._detectMessage += csrf
            if not found:
                self._detectMessage = "[-]No csrf token found"
            
        return isRequest and self._detectMessage          

    def setMessage(self, content, isRequest):
        if(content is None):
            self._txtInput.setText(None)
            self._txtInput.setEditable(False)
        else:
            self._txtInput.setText(self._detectMessage)
        return

FixBurpExceptions()

