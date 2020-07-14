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

        # Create page layout box
        boxVertical = swing.Box.createVerticalBox()

        # Create box for top area
        boxHorizontal = swing.Box.createHorizontalBox()

        # Create box for top left, which will take in
        # valid and invalid usernames and have a submit button
        boxVert = swing.Box.createVerticalBox()
        labelArea = swing.JLabel("Enter a valid and an invalid username")
        boxVert.add(labelArea)

        # Enter valid username
        boxHor = swing.Box.createHorizontalBox()
        labelUser = swing.JLabel("Valid username: ")
        self.enterValidUser = swing.JTextField("", 30)
        boxHor.add(labelUser)
        boxHor.add(self.enterValidUser)
        boxVert.add(boxHor)

        # Enter invalid username
        boxHor = swing.Box.createHorizontalBox()
        labelUser = swing.JLabel("Invalid username: ")
        self.enterInvalidUser = swing.JTextField("", 30)
        boxHor.add(labelUser)
        boxHor.add(self.enterInvalidUser)
        boxVert.add(boxHor)

        # Submit button
        submit = swing.JButton("submit", actionPerformed=self.timeTwoUsers)
        boxVert.add(submit)

        # Put into upper-half box
        boxHorizontal.add(boxVert)

        # Create box for top right, which will output
        #  resulting time for each username
        boxVert = swing.Box.createVerticalBox()
        labelArea = swing.JLabel("Enter a valid and an invalid username")
        boxVert.add(labelArea)

        # Get results area
        self.getResults = swing.JTextField("", 50)
        boxVert.add(self.getResults)

        # View request button
        viewReq = swing.JButton("View the request")
        boxVert.add(viewReq)

        # Put into upper-half box
        boxHorizontal.add(boxVert)

        # View result
        boxVertical.add(boxHorizontal)

        self.tab.add(boxVertical, BorderLayout.NORTH)
        # Create top right
        return

    def timeTwoUsers(self, event):
        self.getResults.text = self.enterValidUser.text + " " + self.enterInvalidUser.text
        return

try:
    FixBurpExceptions()
except:
    pass
