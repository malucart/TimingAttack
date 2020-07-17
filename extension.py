from burp import IBurpExtender, IExtensionStateListener, ITab, IProxyListener, IExtensionHelpers
from javax import swing
import javax.swing.border.EmptyBorder
import javax.swing.filechooser.FileNameExtensionFilter
from java.awt import BorderLayout, Color, Font
import sys
import time
import threading
import java.util.Scanner as Scanner
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

        self.curRequest = None

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
        boxVert = self.getBorderVertBox()
        self.addTitle("Enter a valid and an invalid username", boxVert)

        # Enter valid username
        boxHor = swing.Box.createHorizontalBox()
        self.addLabel("Valid username: ", boxHor)
        self.validUser = swing.JTextField("", 30)
        boxHor.add(self.validUser)
        boxVert.add(boxHor)

        # Enter invalid username
        boxHor = swing.Box.createHorizontalBox()
        self.addLabel("Invalid username: ", boxHor)
        self.invalidUser = swing.JTextField("", 30)
        boxHor.add(self.invalidUser)
        boxVert.add(boxHor)

        # Enter parameter name
        boxHor = swing.Box.createHorizontalBox()
        self.addLabel("Enter parameter: ", boxHor)
        self.parameterName = swing.JTextField("", 30)
        boxHor.add(self.parameterName)
        boxVert.add(boxHor)

        # Submit button
        submit = swing.JButton("submit", actionPerformed=self.timeTwoUsers)
        boxVert.add(submit)

        # Put into upper-half box
        boxHorizontal.add(boxVert)

        # Create box for top right, which will output
        #  resulting time for each username
        boxVert = self.getBorderVertBox()
        self.addTitle("Results", boxVert)

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
        boxVert = self.getBorderVertBox()
        self.addTitle("Input Username File", boxVert)

        # Input usernames file
        boxHor = swing.Box.createHorizontalBox()
        self.addLabel("Input file: ", boxHor)
        self.inputFile = swing.JButton("Choose file...", actionPerformed=self.chooseFile)
        boxHor.add(self.inputFile)
        boxVert.add(boxHor)

        # Input username separator
        boxHor = swing.Box.createHorizontalBox()
        self.addLabel("Enter parameter separator: ", boxHor)
        self.paramSeparator = swing.JTextField("", 30)
        boxHor.add(self.paramSeparator)
        boxVert.add(boxHor)

        # Input parameter name
        boxHor = swing.Box.createHorizontalBox()
        self.addLabel("Enter parameter: ", boxHor)
        self.fileParameterName = swing.JTextField("", 30)
        boxHor.add(self.fileParameterName)
        boxVert.add(boxHor)

        # Submit button
        submit = swing.JButton("submit", actionPerformed=self.timeUserList)
        self.fileSubmitError = swing.JLabel("")
        boxVert.add(submit)
        boxVert.add(self.fileSubmitError)

        # Put into lower-half box
        boxHorizontal.add(boxVert)

        # Create box for bottom right, which will output
        #  resulting time for each username
        boxVert = self.getBorderVertBox()
        self.addTitle("Results", boxVert)

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
        boxVert = self.getBorderVertBox()
        boxHorizontal = swing.Box.createHorizontalBox()
        self.addLabel("Something went wrong?", boxHorizontal)
        viewDeb = swing.JButton("View debug output")
        boxHorizontal.add(viewDeb)
        boxVert.add(boxHorizontal)
        boxVertical.add(boxVert)

        # Put page box in the tab
        firstTab.add(boxVertical)
        return

    def getBorderVertBox(self):
        boxVert = swing.Box.createVerticalBox()
        bord = swing.border.EmptyBorder(10, 10, 10, 10)
        boxVert.setBorder(bord)
        return boxVert

    def addLabel(self, text, box):
        labelArea = swing.JLabel(text)
        box.add(labelArea)
        return

    def addTitle(self, text, box):
        # Create orange color variable
        orange = Color(16737843)
        # Create font for titles
        titlefont = Font("Tahoma", 1, 14)
        # Create title
        labelArea = swing.JLabel(text)
        labelArea.setForeground(orange);
        labelArea.setFont(titlefont);
        box.add(labelArea)
        return

    def chooseFile(self, event):
        self.chooser = swing.JFileChooser()
        fileextensions = ["txt", "jason"]
        filter = swing.filechooser.FileNameExtensionFilter("TXT & JSON FILES", fileextensions)
        self.chooser.setFileFilter(filter)
        returnVal = self.chooser.showOpenDialog(self.chooser)
        if(returnVal == swing.JFileChooser.APPROVE_OPTION):
            self.inputFile.text = self.chooser.getSelectedFile().getName()

    def timeTwoUsers(self, event):
        if (self.curRequest == None):
            return
        threading.Thread(target=self.getTwoUserTimes).start()
        return

    def getTwoUserTimes(self):
        self.getResults.text = "Valid username: " + self.validUser.text + " "
        self.getResults.text += str(self.getTime(self.validUser.text))
        self.getResults.text += "Invalid username: " + self.invalidUser.text + " "
        self.getResults.text += str(self.getTime(self.invalidUser.text))

    def timeUserList(self, event):
        if (self.curRequest == None):
            return
        try:
            # Choose file
            file = self.chooser.getSelectedFile()
            self.getListResults.text = file.getName()
            self.fileSubmitError.text = ""

            # Read file
            scan = Scanner(file)
            readFile = ""
            while scan.hasNext():
                readFile += scan.nextLine()

            # Divide file into list of usernames
            self.userList = readFile.split(self.paramSeparator.text)

            # Get time for each username
            threading.Thread(target=self.getUserListTimes).start()
        except:
           self.fileSubmitError.text = "No File Submitted"
        return

    def getUserListTimes(self):
        for i in self.userList:
            self.getListResults.text += "Username: " + i + " Time: "
            self.getListResults.text += str(self.getTime(i)) + " "
        return

    def getTime(self, paramInput):
        # Keep a reference to helpers
        helpers = self.callbacks.getHelpers()

        # Get the request
        request = self.curRequest.getMessageInfo().getRequest()
        # Get request information
        requestInfo = helpers.analyzeRequest(request)

        paramName = self.parameterName.text
        # loop through parameters
        for i in requestInfo.getParameters():
            # find username parameter and change its value
            if (i.getName() == paramName):
                # Create request
                buildParam = helpers.buildParameter(paramName, paramInput, i.getType())
                newRequest = helpers.updateParameter(request, buildParam)

        # Build an http service to send a request to the website
        httpService = helpers.buildHttpService("127.0.0.1", 8000, False)
        # Time and send the changed request with valid parameter
        start = time.clock()
        makeRequest = self.callbacks.makeHttpRequest(httpService, newRequest)
        getTime = time.clock() - start
        # Print response to the request in GUI
        return getTime

    def processProxyMessage(self, messageIsRequest, message):
        # Keep a reference to helpers
        helpers = self.callbacks.getHelpers()

        # Get the request
        request = message.getMessageInfo().getRequest()
        # Get request information
        requestInfo = helpers.analyzeRequest(request)

        # Get name of parameter to change
        paramName = self.parameterName.text

        # Check if request has specified parameter
        for i in requestInfo.getParameters():
            if (i.getName() == paramName):
                self.curRequest = message
                return

try:
    FixBurpExceptions()
except:
    pass
