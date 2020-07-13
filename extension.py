from burp import IBurpExtender, IExtensionStateListener, ITab
from javax import swing
from java.awt import BorderLayout
import sys
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass


class BurpExtender(IBurpExtender, IExtensionStateListener, ITab):
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

        self.createGUI()


        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        print "Extension loaded."
        return

    # Implement ITab
    def getTabCaption(self):
        """Return the text to be displayed on the tab"""
        return "Timing Attack"

    def getUiComponent(self):
        """Passes the UI to burp"""
        return self.tab

    def createGUI(self):
        # Create the tab
        self.tab = swing.JPanel(BorderLayout())


        # Created a tabbed pane to go in the top of the
        # main tab, below the text area
        tabbedPane = swing.JTabbedPane()
        self.tab.add("North", tabbedPane);

        # First tab
        firstTab = swing.JPanel()
        firstTab.layout = BorderLayout()
        tabbedPane.addTab("1", firstTab)

        return

try:
    FixBurpExceptions()
except:
    pass
