from burp import IBurpExtender, IExtensionStateListener, ITab, IProxyListener, IExtensionHelpers
from javax import swing
import javax.swing.border.EmptyBorder
from java.awt import BorderLayout, Color, Font
import sys
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass


class BurpExtender(IBurpExtender, IExtensionStateListener, ITab, IProxyListener, IExtensionHelpers):
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
        self.callbacks.registerProxyListener(self)

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

    # Organize GUI code better
    def createGUI(self):
        # Create the tab
        self.tab = swing.JPanel(BorderLayout())

        # Create orange color variable
        orange = Color(16737843)
        # Create font for titles
        titlefont = Font("Tahoma", 1, 14)

        # Created a tabbed pane to go in the top of the
        # main tab, below the text area
        tabbedPane = swing.JTabbedPane()
        self.tab.add(tabbedPane);

        # First tab
        firstTab = swing.JPanel()
        firstTab.layout = BorderLayout()
        tabbedPane.addTab("1", firstTab)

        # Create page layout box
        boxVertical = swing.Box.createVerticalBox()

        # Create box for top-half area
        boxHorizontal = swing.Box.createHorizontalBox()

        # Create box for top left, which will take in
        # valid and invalid usernames and have a submit button
        boxVert = swing.Box.createVerticalBox()
        bord = swing.border.EmptyBorder(10, 10, 10, 10)
        boxVert.setBorder(bord)
        labelArea = swing.JLabel("Enter a valid and an invalid username")
        labelArea.setForeground(orange);
        labelArea.setFont(titlefont);
        boxVert.add(labelArea, BorderLayout.LINE_START)

        # Enter valid username
        boxHor = swing.Box.createHorizontalBox()
        labelUser = swing.JLabel("Valid username:   ")
        self.validUser = swing.JTextField("", 30)
        boxHor.add(labelUser)
        boxHor.add(self.validUser)
        boxVert.add(boxHor)

        # Enter invalid username
        boxHor = swing.Box.createHorizontalBox()
        labelUser = swing.JLabel("Invalid username: ")
        self.invalidUser = swing.JTextField("", 30)
        boxHor.add(labelUser)
        boxHor.add(self.invalidUser)
        boxVert.add(boxHor)

        # Submit button
        submit = swing.JButton("submit", actionPerformed=self.timeTwoUsers)
        boxVert.add(submit)

        # Put into upper-half box
        boxHorizontal.add(boxVert)

        # Create box for top right, which will output
        #  resulting time for each username
        boxVert = swing.Box.createVerticalBox()
        bord = swing.border.EmptyBorder(10, 10, 10, 10)
        boxVert.setBorder(bord)
        labelArea = swing.JLabel("Results")
        labelArea.setForeground(orange);
        labelArea.setFont(titlefont);
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

        # Draw a horizontal line
        sep = swing.JSeparator()
        boxVertical.add(sep)

        # Create box for bottom-half area
        boxHorizontal = swing.Box.createHorizontalBox()

        # Create bottom left box for inputting
        # a list of usernames (txt file)
        boxVert = swing.Box.createVerticalBox()
        bord = swing.border.EmptyBorder(10, 10, 10, 10)
        boxVert.setBorder(bord)
        labelArea = swing.JLabel("Input Username File")
        labelArea.setForeground(orange);
        labelArea.setFont(titlefont);
        boxVert.add(labelArea)

        # Input usernames file
        boxHor = swing.Box.createHorizontalBox()
        labelUser = swing.JLabel("Invalid username: ")
        self.usernameList = swing.JTextField("", 30)
        boxHor.add(labelUser)
        boxHor.add(self.usernameList)
        boxVert.add(boxHor)

        # Submit button
        submit = swing.JButton("submit", actionPerformed=self.timeUserList)
        boxVert.add(submit)

        # Put into lower-half box
        boxHorizontal.add(boxVert)

        # Create box for bottom right, which will output
        #  resulting time for each username
        boxVert = swing.Box.createVerticalBox()
        bord = swing.border.EmptyBorder(10, 10, 10, 10)
        boxVert.setBorder(bord)
        labelArea = swing.JLabel("Results")
        labelArea.setForeground(orange);
        labelArea.setFont(titlefont);
        boxVert.add(labelArea)

        # Get results area
        self.getListResults = swing.JTextField("", 50)
        boxVert.add(self.getListResults)

        # Create horizontal box for the two buttons
        boxHor = swing.Box.createHorizontalBox()

        # Download results button
        downRes = swing.JButton("Download results")
        boxHor.add(downRes)

        # View request button
        viewReq = swing.JButton("View the request")
        boxHor.add(viewReq)

        # Put buttons box into lower right box
        boxVert.add(boxHor)

        # Put into lower-half box
        boxHorizontal.add(boxVert)

        # Put lower-half box into page box
        boxVertical.add(boxHorizontal)

        sep = swing.JSeparator()
        boxVertical.add(sep)

        # Create box for debug output
        boxHorizontal = swing.Box.createHorizontalBox()
        bord = swing.border.EmptyBorder(10, 10, 10, 10)
        boxHorizontal.setBorder(bord)
        labelArea = swing.JLabel("Something went wrong?")
        boxHorizontal.add(labelArea)
        viewDeb = swing.JButton("View debug output")
        boxHorizontal.add(viewDeb)
        boxVertical.add(boxHorizontal)

        # Put page box in the tab
        firstTab.add(boxVertical)
        return

    def timeTwoUsers(self, event):
        self.getResults.text = self.validUser.text + " " + self.invalidUser.text
        return

    def timeUserList(self, event):
        self.getListResults.text = self.usernameList.text
        return

    def processProxyMessage(self, messageIsRequest, message):
        # Keep a reference to helpers
        helpers = self.callbacks.getHelpers()

        # Get the request
        request = message.getMessageInfo().getRequest()
        # Get request information
        requestInfo = helpers.analyzeRequest(request)

        # Check if request contains parameter "username"
        msg = helpers.bytesToString(request)
        msgsplit = msg.split("username=")

        # if request doesn't have username parameter, return error
        if (len(msgsplit) == 1):
            self.getResults.text = "Error; no username parameter" + requestMethod

        # if request has username parameter, change its value
        else:
            # loop through parameters
            for i in requestInfo.getParameters():
                # find username parameter and change its value
                if (i.getName() == "username"):
                    param = helpers.buildParameter("username", "test", i.getType())
                    request = helpers.updateParameter(request, param)
            # Build an http service to send a request to the website
            httpService = helpers.buildHttpService("127.0.0.1", 8000, False)
            # Send the changed request
            makeRequest = self.callbacks.makeHttpRequest(httpService, request)
            # Print response to the request in GUI
            self.getResults.text = helpers.bytesToString(makeRequest.getResponse())
try:
    FixBurpExceptions()
except:
    pass
