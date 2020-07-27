from burp import IBurpExtender # for the extension
from burp import ITab # for creating an extension tab
from burp import IExtensionHelpers # for helper methods
from burp import IContextMenuFactory # for adding an option to the right click popup menu
from burp import IBurpExtenderCallbacks
from javax.swing import JPanel # for panels
from javax.swing import Box # for arranging components either in a row or in a column
from javax.swing import JTextField # for inputting text value in a single line format
from javax.swing import JTextArea # for multi-line text component to display text
from javax.swing import JButton # for buttons
from javax.swing import JSeparator # for implementing divider lines
from javax.swing import JScrollPane # for scroll panes to help with extended text areas
from javax.swing import JLabel # for labels
from javax.swing import JFileChooser # for importing and exporting dialog boxes
from javax.swing.filechooser import FileNameExtensionFilter # for importing and exporting
from javax.swing.border import EmptyBorder # for an empty/transparent border
from java.awt import BorderLayout # for panel layouts
from java.awt import Color # for setting a different background on disabled text areas
from java.awt import Font # for adding bold font to text labels in main tab
from java.awt import Component # for setting a component
from java.util import ArrayList # for arraylist
from java.util import Scanner # for reading file
import sys # provides access to some variables used by the interpreter and to functions that interact strongly with the interpreter
import time # for clock time
import threading # for multiple activities within a single process
import os # for splitting the file name and file extension when importing and exporting

#
# class for the whole UI
#
class tab():

    def __init__(self, callbacks):
        """ Method automatically called when memory is
        allocated for a new object, initiates tab object """
        print("Created a tab")
        self.callbacks = callbacks
        self.curRequest = None

        self.createTabGUI()


    def getFirstTab(self):
        """ Get the JPanel that represents the object's
        Timing Attack tab """
        return self.firstTab


    def createTabGUI(self):
        """ Create GUI for this tabbed pane """
        # create main panel to the whole layout
        self.firstTab = JPanel()
        self.firstTab.layout = BorderLayout()

        # create a big box to organize the layout inside of it
        pagebox = Box.createVerticalBox()

        # create a box for top-half area and add to the page
        tophalf = Box.createHorizontalBox()
        pagebox.add(tophalf)

        # create top-left and top-right boxes
        topleft = self.createTopLeftBox()
        topright = self.createTopRightBox()
        # add top-left and top-right boxes to top half
        tophalf.add(topleft)
        tophalf.add(topright)


        # draw a horizontal line right after top-half box
        sep = JSeparator()
        pagebox.add(sep)


        # create a box for bottom-half area and add to the page
        bottomhalf = Box.createHorizontalBox()
        pagebox.add(bottomhalf)

        # create bottom-left and bottom-right boxes
        bottomleft = self.createBottomLeftBox()
        bottomright = self.createBottomRightBox()
        # add bottom-left and bottom-right boxes to bottom-half
        bottomhalf.add(bottomleft)
        bottomhalf.add(bottomright)


        # draw a horizontal line after bottom-half box
        sep = JSeparator()
        pagebox.add(sep)


        # create a box for debugging output and add to page
        debugbox = self.createDebugBox()
        pagebox.add(debugbox)


        # timing attack tab adds the big box
        self.firstTab.add(pagebox)

        # the whole tab is returned
        return self.firstTab


    def createTopLeftBox(self):
        """ Method to create the top left box """
        topleft = self.getBorderVertBox()

        # title for the top-left area
        self.addTitle("Enter a Valid and an Invalid Username", topleft)

        # create a box for label and valid username input
        boxHor = Box.createHorizontalBox()

        # create a label for valid username into the box
        self.addLabel("Valid username: ", boxHor)

        # create input for valid username
        self.validUser = JTextField("", 30)

        # the box adds the valid username input
        boxHor.add(self.validUser)

        # top-left box adds this box
        topleft.add(boxHor)

        # create a box for an invalid username input
        boxHor = Box.createHorizontalBox()

        # create a label for an invalid username into the box
        self.addLabel("Invalid username: ", boxHor)

        # create input for invalid username
        self.invalidUser = JTextField("", 30)

        # the box adds the invalid username input
        boxHor.add(self.invalidUser)

        # top-left box adds this box
        topleft.add(boxHor)

        # create a box for the parameter input
        boxHor = Box.createHorizontalBox()

        # create a label for the parameter into the box
        self.addLabel("Enter parameter: ", boxHor)

        # create input for parameter
        self.parameterName = JTextField("", 30)

        # the box adds the parameter input
        boxHor.add(self.parameterName)

        # create a label for the number of tries into the box
        self.addLabel("How many tries would you like to average: ", boxHor)

        # create input for number of tries
        self.numTries = JTextField("", 30)

        # the box adds the number of tries input
        boxHor.add(self.numTries)

        # top-left box adds this box
        topleft.add(boxHor)

        # "submit" button is created and added into the top-left box
        submit = JButton("submit", actionPerformed=self.timeTwoUsers)
        topleft.add(submit)

        return topleft


    def createTopRightBox(self):
        """ Method to create the top right box """
        topright = self.getBorderVertBox()

        # title for the top-right area
        self.addTitle("Results", topright)

        # show results in a text area
        self.getResults = JTextArea("", 50, 30)

        # results are not editable
        self.getResults.setEditable(False)

        # top-right adds this text area
        topright.add(self.getResults)

        # "view the request" button is created and added into the top-right box
        self.showRequestTopIsOn = False
        self.twoUserResultOutput = ""
        self.twoUserViewReq = JButton("View the request", actionPerformed=self.showRequestTop)
        topright.add(self.twoUserViewReq)

        return topright


    def createBottomLeftBox(self):
        """ Method to create the bottom left box """
        bottomleft = self.getBorderVertBox()
        # title for the bottom-left area
        self.addTitle("Input Username File", bottomleft)

        # creates a box to input a list of usernames (txt or json file)
        boxHor = Box.createHorizontalBox()
        self.addLabel("Input file: ", boxHor)
        self.inputFile = JButton("Choose file...", actionPerformed=self.chooseFile)
        boxHor.add(self.inputFile)
        # bottom-left box adds this box
        bottomleft.add(boxHor)

        # creates a box to input a parameter separator
        boxHor = Box.createHorizontalBox()
        self.addLabel("Enter parameter separator: ", boxHor)
        self.paramSeparator = JTextField("", 30)
        boxHor.add(self.paramSeparator)
        # bottom-left box adds this box
        bottomleft.add(boxHor)

        # creates a box to input a parameter
        boxHor = Box.createHorizontalBox()
        self.addLabel("Enter parameter: ", boxHor)
        self.fileParameterName = JTextField("", 30)
        boxHor.add(self.fileParameterName)
        # bottom-left box adds this box
        bottomleft.add(boxHor)

        boxHor = Box.createHorizontalBox()
        # create a label for the number of tries into the box
        self.addLabel("How many tries would you like to average: ", boxHor)

        # create input for number of tries
        self.listNumTries = JTextField("", 30)

        # the box adds the number of tries input
        boxHor.add(self.listNumTries)

        # top-left box adds this box
        bottomleft.add(boxHor)

        # "submit" button is created and added into the bottom-left box
        submit = JButton("submit", actionPerformed=self.timeUserList)
        self.fileSubmitError = JLabel("")
        bottomleft.add(submit)
        bottomleft.add(self.fileSubmitError)

        return bottomleft


    def createBottomRightBox(self):
        """ Method to create the bottom right box """
        bottomright = self.getBorderVertBox()

        # title for the bottom-right area
        self.addTitle("Results", bottomright)

        # show results about of each username from txt/json file
        self.getListResults = JTextArea("", 50, 30)

        # results are not editable
        self.getListResults.setEditable(False)

        # results are scrollable
        getListResultsContainer = JScrollPane(self.getListResults)

        # these results scrollable are added into the bottom-right
        bottomright.add(getListResultsContainer)

        # create a box to store the buttons funcinalities in the bottom-right area
        boxHor = Box.createHorizontalBox()

        # "download results" button to download the results
        downRes = JButton("Download results", actionPerformed=self.downloadResults)

        # box adds this button
        boxHor.add(downRes)

        # "view the request" button
        self.showListRequestIsOn = False
        self.listResultOutput = ""

        # create a button
        self.listViewReq = JButton("View the request", actionPerformed=self.showListRequest)

        # box adds this button
        boxHor.add(self.listViewReq)

        # bottom-right box adds the box which stores the buttons funcinalities
        bottomright.add(boxHor)

        return bottomright


    def createDebugBox(self):
        """ Method to create the debug box """
        debugbox = self.getBorderVertBox()
        horizontaldebug = Box.createHorizontalBox()

        # create label for this endding section
        self.addLabel("Something went wrong?", horizontaldebug)

        # button to view debug output
        viewDeb = JButton("View debug output")

        # box adds this button
        horizontaldebug.add(viewDeb)
        debugbox.add(horizontaldebug)

        return debugbox


    def getBorderVertBox(self):
        """ Method that creates box with a border (padding)
        to put other JComponents in """
        boxVert = Box.createVerticalBox()
        bord = EmptyBorder(10, 10, 10, 10)
        boxVert.setBorder(bord)
        return boxVert


    def addLabel(self, text, box):
        """ Method that creates a label and adds it to a box """
        labelArea = JLabel(text)
        box.add(labelArea)
        labelArea.setAlignmentX(Component.LEFT_ALIGNMENT);
        return


    def addTitle(self, text, box):
        """ Method that adds titles for boxes """
        # Create orange color variable
        orange = Color(16737843)
        # Create font for titles
        titlefont = Font("Tahoma", 1, 14)
        # Create title
        labelArea = JLabel(text)
        labelArea.setForeground(orange);
        labelArea.setFont(titlefont);
        box.add(labelArea)
        return


    def chooseFile(self, event):
        """ Method that allows the user to choose a file of usernames """
        # try to load the last used directory
        try:
            # load the directory for future imports/exports
            fileChooserDirectory = self._callbacks.loadExtensionSetting("fileChooserDirectory")

        # there is not a last used directory
        except:
            # set the last used directory to blank
            fileChooserDirectory = ""

        self.chooser = JFileChooser(fileChooserDirectory)
        fileextensions = ["txt", "jason"]
        filter = FileNameExtensionFilter("TXT & JSON FILES", fileextensions)
        self.chooser.setFileFilter(filter)
        returnVal = self.chooser.showOpenDialog(self.chooser)
        if(returnVal == JFileChooser.APPROVE_OPTION):
            self.inputFile.text = self.chooser.getSelectedFile().getName()


    def timeTwoUsers(self, event):
        """ Method that sends the current request to getTwoUserTimes """
        if (self.curRequest == None):
            return
        # change button to say show request
        self.showRequestTopIsOn = False
        self.twoUserViewReq.setText("View the request")
        threading.Thread(target=self.getTwoUserTimes).start()
        return


    def getTwoUserTimes(self):
        """ Method that prints the time taken to return responses
        from one valid username and from one invalid username (called
        by timeTwoUsers) """
        self.getResults.text = "Valid username: " + self.validUser.text + " Time: "
        self.getResults.text += str(self.getTime(self.validUser.text, self.numTries.text)) + "\n"
        self.getResults.text += "Invalid username: " + self.invalidUser.text + " Time: "
        self.getResults.text += str(self.getTime(self.invalidUser.text, self.numTries.text))


    def timeUserList(self, event):
        """ Method that reads the usernames from file and sends
        them to getUserListTimes """
        # if there is no file, so the program is going to return anything
        if (self.curRequest == None):
            return
        try:
            # stores the file
            file = self.chooser.getSelectedFile()
            self.fileSubmitError.text = ""

            # reads it
            scan = Scanner(file)
            readFile = ""
            while scan.hasNext():
                readFile += scan.nextLine()

            # divides the file to a list of usernames
            self.userList = readFile.split(self.paramSeparator.text)

            # change button to say show request
            self.showListRequestIsOn = False
            self.listViewReq.setText("View the request")
            # gets the time for each username
            threading.Thread(target=self.getUserListTimes).start()
        # it will handle the error and send a message about it
        except:
           self.fileSubmitError.text = "No File Submitted"
        return


    def getUserListTimes(self):
        """ Method that prints the time taken to return responses
        for each username from file (called by timeUserList) """
        self.getListResults.text = ""
        for i in self.userList:
            self.getListResults.text += "Username: " + i + " Time: "
            self.getListResults.text += str(self.getTime(i, self.listNumTries.text)) + "\n"
        return


    def showRequestTop(self, event):
        """ Method that shows the request for top box """
        if (not self.showRequestTopIsOn):
            self.twoUserResultOutput = self.getResults.text
        self.showRequest(self.getResults, self.twoUserViewReq, self.twoUserResultOutput, self.showRequestTopIsOn)
        self.showRequestTopIsOn = not self.showRequestTopIsOn


    def showListRequest(self, event):
        """ Method that shows the request from a file of usernames """
        if (not self.showListRequestIsOn):
            self.listResultOutput = self.getListResults.text
        self.showRequest(self.getListResults, self.listViewReq, self.listResultOutput, self.showListRequestIsOn)
        self.showListRequestIsOn = not self.showListRequestIsOn


    def showRequest(self, box, button, output, bool):
        """ Switch from view request to view result and vice versa """
        if (bool):
            box.text = output
            button.setText("View the request")

        else:
            helpers = self.callbacks.getHelpers()
            output = box.text
            box.text = helpers.bytesToString(self.curRequest.getRequest())
            button.setText("View results")


    def getTime(self, paramInput, numTriesText):
        """ Method that takes in a username and returns time taken to get
        its response (called by getTwoUserTimes and getUserListTimes)"""
        numTries = int(numTriesText)
        # keeps a reference to helpers
        helpers = self.callbacks.getHelpers()
        # Get the request
        request = self.curRequest.getRequest()
        # Get request information
        requestInfo = helpers.analyzeRequest(request)
        # gets the parameter
        paramName = self.parameterName.text
        # loop through parameters
        for i in requestInfo.getParameters():
            # find username parameter and change its value
            if (i.getName() == paramName):
                # it creates the request
                buildParam = helpers.buildParameter(paramName, paramInput, i.getType())
                newRequest = helpers.updateParameter(request, buildParam)

        # it builds an http service to send a request to the website
        httpService = self.curRequest.getHttpService()
        ### requestUrl = str(requestInfo.getHost())
        httpService = helpers.buildHttpService(httpService.getHost(), httpService.getPort(), False)

        getTime = 0
        for i in range(numTries):
            # starts the time and it sends the changed request with valid parameter
            start = time.clock()
            makeRequest = self.callbacks.makeHttpRequest(httpService, newRequest)
            makeRequest.getResponse()
            getTime += time.clock() - start

        # return the response
        return getTime / numTries


    def downloadResults(self, event):
        """ Method that allows user to download file of times for responses
        for usernames from list """
        if (self.getListResults.text == ""):
            return
        file = open(get_download_path() + "/downloadresults.txt", "w")
        file.write(self.getListResults.text)
        file.close()


    def get_download_path():
        """ Method to find path of download folder (called by downloadResults) """
        # returns the default downloads path for linux or windows
        if os.name == 'nt':
            import winreg
            sub_key = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders'
            downloads_guid = '{374DE290-123F-4565-9164-39C4925E467B}'
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub_key) as key:
                location = winreg.QueryValueEx(key, downloads_guid)[0]
            return location
        else:
            return os.path.join(os.path.expanduser('~'), 'downloads')


    def getRequest(self, messageList):
        """ Method that stores the request sent from proxy """
        self.curRequest = messageList[0]
        self.showRequestTopIsOn = False
        self.twoUserResultOutput = self.getResults.text
        self.showRequest(self.getResults, self.twoUserViewReq, self.twoUserResultOutput, self.showRequestTopIsOn)
        self.showRequestTopIsOn = not self.showRequestTopIsOn
