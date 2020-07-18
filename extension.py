# libraries
# necessary to connect to burp suite as a extension
from burp import IBurpExtender, IExtensionStateListener, ITab, IProxyListener, IExtensionHelpers
# necessary to create graphical user interface (gui) in java
from javax import swing
import javax.swing.border.EmptyBorder
import javax.swing.filechooser.FileNameExtensionFilter
from java.awt import BorderLayout, Color, Font
# provides access to some variables used by the interpreter and to functions that interact strongly with the interpreter
import sys
# allow to use the clock time
import time
# allow multiple activities within a single process
import threading
# allow the user types an input
import java.util.Scanner as Scanner
# allow the user download the results, so the program needs to know the path of the download folder to put the file there
import os

# if something goes wrong
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass

# main class to connect to burp suite
class BurpExtender(IBurpExtender, IExtensionStateListener, ITab, IProxyListener, IExtensionHelpers):
    # method that shows the extension is loaded
    def registerExtenderCallbacks(self, callbacks):
        print "Loading timing attack extension\n"

        # required for easier debugging:
        # https://github.com/securityMB/burp-exceptions
        sys.stdout = callbacks.getStdout()

        # keep a reference to callbacks object
        self.callbacks = callbacks

        # set our extension name
        self.callbacks.setExtensionName("Timing Attack")
        self.callbacks.registerExtensionStateListener(self)
        self.callbacks.registerProxyListener(self)

        self.curRequest = None

        self.createGUI()

        # add the custom tab to our burp suite's UI
        callbacks.addSuiteTab(self)
        print "Extension loaded."
        return

    # method that implements ITab
    def getTabCaption(self):
        # return the text to be displayed on the burp suite's new tab
        return "Timing Attack"

    def getUiComponent(self):
        # passes the UI to burp suite
        return self.tab

    # method that organizes a better GUI
    def createGUI(self):
        # create the tab
        self.tab = swing.JPanel(BorderLayout())

        # create a tabbed pane on the top left of the "timing attack" tab (in general, it's going to be numbers)
        tabbedPane = swing.JTabbedPane()
        self.tab.add(tabbedPane);
        firstTab = swing.JPanel()
        firstTab.layout = BorderLayout()
        tabbedPane.addTab("1", firstTab)

        # creation of the whole layout
        # it creates a big box (to put everything inside)
        pagebox = swing.Box.createVerticalBox()

        # create a box for top-half area
        tophalf = swing.Box.createHorizontalBox()

        # it creates a box inside of the top-half area, which is going to have a valid username, an invalid username,
        # and a parameter from the user, and the button "submit". All this is on the top-left
        topleft = self.getBorderVertBox()
        # title for the top-left area
        self.addTitle("Enter a Valid and an Invalid Username", topleft)

        # box for the valid username and it gets the data from the user
        boxHor = swing.Box.createHorizontalBox()
        self.addLabel("Valid username: ", boxHor)
        self.validUser = swing.JTextField("", 30)
        boxHor.add(self.validUser)
        topleft.add(boxHor)

        # box for the invalid username and it gets the data from the user
        boxHor = swing.Box.createHorizontalBox()
        self.addLabel("Invalid username: ", boxHor)
        self.invalidUser = swing.JTextField("", 30)
        boxHor.add(self.invalidUser)
        topleft.add(boxHor)

        # box for the parameter and it gets the data from the user
        boxHor = swing.Box.createHorizontalBox()
        self.addLabel("Enter parameter: ", boxHor)
        self.parameterName = swing.JTextField("", 30)
        boxHor.add(self.parameterName)
        topleft.add(boxHor)

        # "submit" button
        submit = swing.JButton("submit", actionPerformed=self.timeTwoUsers)
        topleft.add(submit)

        # now as we have everything we want for the top-left, let's add it inside of the top-half
        tophalf.add(topleft)

        # it creates a box for top-right
        topright = self.getBorderVertBox()
        # title for the top-right area
        self.addTitle("Results", topright)

        # gets results
        self.getResults = swing.JTextArea("", 50, 30)
        topright.add(self.getResults)

        # "view the request" button
        self.showRequestIsOn = False
        self.twoUserResultOutput = ""
        self.twoUserViewReq = swing.JButton("View the request", actionPerformed=self.showRequest)
        topright.add(self.twoUserViewReq)

        # now as we have everything we want for the top-right, let's add it inside of the top-half
        tophalf.add(topright)

        # the big box store top-half
        pagebox.add(tophalf)

        # draw a horizontal line to separate top and bottom and saves it on the big box
        sep = swing.JSeparator()
        pagebox.add(sep)

        # create box for bottom-half area
        bottomhalf = swing.Box.createHorizontalBox()

        # Create bottom left box for inputting
        # a list of usernames (txt file)
        bottomleft = self.getBorderVertBox()
        self.addTitle("Input Username File", bottomleft)

        # Input usernames file
        boxHor = swing.Box.createHorizontalBox()
        self.addLabel("Input file: ", boxHor)
        self.inputFile = swing.JButton("Choose file...", actionPerformed=self.chooseFile)
        boxHor.add(self.inputFile)
        bottomleft.add(boxHor)

        # Input username separator
        boxHor = swing.Box.createHorizontalBox()
        self.addLabel("Enter parameter separator: ", boxHor)
        self.paramSeparator = swing.JTextField("", 30)
        boxHor.add(self.paramSeparator)
        bottomleft.add(boxHor)

        # Input parameter name
        boxHor = swing.Box.createHorizontalBox()
        self.addLabel("Enter parameter: ", boxHor)
        self.fileParameterName = swing.JTextField("", 30)
        boxHor.add(self.fileParameterName)
        bottomleft.add(boxHor)

        # Submit button
        submit = swing.JButton("submit", actionPerformed=self.timeUserList)
        self.fileSubmitError = swing.JLabel("")
        bottomleft.add(submit)
        bottomleft.add(self.fileSubmitError)

        # Put into lower-half box
        bottomhalf.add(bottomleft)

        # Create box for bottom right, which will output
        #  resulting time for each username
        bottomright = self.getBorderVertBox()
        self.addTitle("Results", bottomright)

        # Get results area
        self.getListResults = swing.JTextArea("", 50, 30)
        bottomright.add(self.getListResults)

        # Create horizontal box for the two buttons
        boxHor = swing.Box.createHorizontalBox()

        # Download results button
        downRes = swing.JButton("Download results", actionPerformed=self.downloadResults)
        boxHor.add(downRes)

        # View request button
        self.showListRequestIsOn = False
        self.listResultOutput = ""
        self.listViewReq = swing.JButton("View the request", actionPerformed=self.showListRequest)
        boxHor.add(self.listViewReq)

        # Put buttons box into lower right box
        bottomright.add(boxHor)

        # Put into lower-half box
        bottomhalf.add(bottomright)

        # Put lower-half box into page box
        pagebox.add(bottomhalf)

        sep = swing.JSeparator()
        pagebox.add(sep)

        # Create box for debug output
        debugbox = self.getBorderVertBox()
        horizontaldebug = swing.Box.createHorizontalBox()
        self.addLabel("Something went wrong?", horizontaldebug)
        viewDeb = swing.JButton("View debug output")
        horizontaldebug.add(viewDeb)
        debugbox.add(horizontaldebug)
        pagebox.add(debugbox)

        # Put page box in the tab
        firstTab.add(pagebox)
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
        self.getResults.text += str(self.getTime(self.validUser.text)) + "\n"
        self.getResults.text += "Invalid username: " + self.invalidUser.text + " "
        self.getResults.text += str(self.getTime(self.invalidUser.text))

    def timeUserList(self, event):
        if (self.curRequest == None):
            return
        try:
            # Choose file
            file = self.chooser.getSelectedFile()
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
            self.getListResults.text += str(self.getTime(i)) + "\n"
        return


    def showRequest(self, event):
        if (self.showRequestIsOn):
            self.showRequestIsOn = False
            self.getResults.text = self.twoUserResultOutput
            self.twoUserViewReq.setText("View the request")
        else:
            self.showRequestIsOn = True
            helpers = self.callbacks.getHelpers()
            self.twoUserResultOutput = self.getResults.text
            self.getResults.text = helpers.bytesToString(self.curRequest.getMessageInfo().getRequest())
            self.twoUserViewReq.setText("View results")

    def showListRequest(self, event):
        if (self.showListRequestIsOn):
            self.showListRequestIsOn = False
            self.getListResults.text = self.listResultOutput
            self.listViewReq.setText("View the request")

        else:
            self.showListRequestIsOn = True
            helpers = self.callbacks.getHelpers()
            self.listResultOutput = self.getListResults.text
            self.getListResults.text = helpers.bytesToString(self.curRequest.getMessageInfo().getRequest())
            self.listViewReq.setText("View results")



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

    def downloadResults(self, event):
        if (self.getListResults.text == ""):
            return
        file = open(get_download_path() + "/downloadresults.txt", "w")
        file.write(self.getListResults.text)
        file.close()

    def get_download_path():
        """Returns the default downloads path for linux or windows"""
        if os.name == 'nt':
            import winreg
            sub_key = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
            downloads_guid = '{374DE290-123F-4565-9164-39C4925E467B}'
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub_key) as key:
                location = winreg.QueryValueEx(key, downloads_guid)[0]
            return location
        else:
            return os.path.join(os.path.expanduser('~'), 'downloads')

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
