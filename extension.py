from burp import IBurpExtender, IExtensionStateListener
from javax import swing
from java.awt import BorderLayout
import sys
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass


class BurpExtender(IBurpExtender, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        print "Loading timing attack extension\n"

        # Required for easier debugging:
        # https://github.com/securityMB/burp-exceptions
        sys.stdout = callbacks.getStdout()

        # Keep a reference to callbacks object
        self.callbacks = callbacks

        # Set our extension name
        self.callbacks.setExtensionName("Timing Attack")
        self.callbacks.registerExtensionStateListener(self)

        print "Extension loaded."
        return

    # Implement ITab
    def getTabCaption(self):
        """Return the text to be displayed on the tab"""
        return "Timing Attack"

    def getUiComponent(self):
        """Passes the UI to burp"""
        return self.tab

try:
    FixBurpExceptions()
except:
    pass
