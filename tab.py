# libraries
# necessary to connect to burp suite as a extension
from burp import IBurpExtender, IExtensionStateListener, ITab, IProxyListener, IExtensionHelpers, IContextMenuFactory

from burp import IBurpExtenderCallbacks
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

from java.util import ArrayList
from javax.swing import JMenuItem

class tab():
    def __init__(self, callbacks):
        print("Created a tab")
        self.callbacks = callbacks
        self.curRequest = None

        self.createTabGUI()

    def getFirstTab(self):
        return self.firstTab

    def createTabGUI(self):
        self.firstTab = swing.JPanel()
        self.firstTab.layout = BorderLayout()

        # creation of the whole layout
        # it creates a big box (to put everything inside)
        pagebox = swing.Box.createVerticalBox()

        # creates a box for top-half area
        tophalf = swing.Box.createHorizontalBox()

        # creates a box inside of the top-half area in the top-left
        topleft = self.getBorderVertBox()
        # title for the top-left area
        self.addTitle("Enter a Valid and an Invalid Username", topleft)

        # creates a box for a valid username and it gets data from the user
        boxHor = swing.Box.createHorizontalBox()
        self.addLabel("Valid username: ", boxHor)
        self.validUser = swing.JTextField("", 30)
        boxHor.add(self.validUser)
        # top-left box adds this box
        topleft.add(boxHor)

        # creates a box for a invalid username and it gets data from the user
        boxHor = swing.Box.createHorizontalBox()
        self.addLabel("Invalid username: ", boxHor)
        self.invalidUser = swing.JTextField("", 30)
        boxHor.add(self.invalidUser)
        # top-left box adds this box
        topleft.add(boxHor)

        # creates a box for the parameter and it gets data from the user
        boxHor = swing.Box.createHorizontalBox()
        self.addLabel("Enter parameter: ", boxHor)
        self.parameterName = swing.JTextField("", 30)
        boxHor.add(self.parameterName)
        # top-left box adds this box
        topleft.add(boxHor)

        # "submit" button is created and added into the top-left box
        submit = swing.JButton("submit", actionPerformed=self.timeTwoUsers)
        topleft.add(submit)

        # now as we have everything we want for the top-left, let's add it inside of the top-half
        tophalf.add(topleft)

        # creates a box inside of the top-half area in the top-right
        topright = self.getBorderVertBox()
        # title for the top-right area
        self.addTitle("Results", topright)

        # gets results and add them into the top-right box
        self.getResults = swing.JTextArea("", 50, 30)
        self.getResults.setEditable(False)
        topright.add(self.getResults)

        # "view the request" button is created and added into the top-right box
        self.showRequestTopIsOn = False
        self.twoUserResultOutput = ""
        self.twoUserViewReq = swing.JButton("View the request", actionPerformed=self.showRequestTop)
        topright.add(self.twoUserViewReq)

        # now as we have everything we want for the top-right, let's add it inside of the top-half
        tophalf.add(topright)

        # as we have everything we want for the top-half, let's add it inside of the big box
        pagebox.add(tophalf)

        # it draws a horizontal line right after top-half box
        sep = swing.JSeparator()
        pagebox.add(sep)

        # it creates a box for bottom-half area
        bottomhalf = swing.Box.createHorizontalBox()

        # it creates a bottom-left box
        bottomleft = self.getBorderVertBox()
        # title for the bottom-left area
        self.addTitle("Input Username File", bottomleft)

        # creates a box to input a list of usernames (txt or json file)
        boxHor = swing.Box.createHorizontalBox()
        self.addLabel("Input file: ", boxHor)
        self.inputFile = swing.JButton("Choose file...", actionPerformed=self.chooseFile)
        boxHor.add(self.inputFile)
        # bottom-left box adds this box
        bottomleft.add(boxHor)

        # creates a box to input a parameter separator
        boxHor = swing.Box.createHorizontalBox()
        self.addLabel("Enter parameter separator: ", boxHor)
        self.paramSeparator = swing.JTextField("", 30)
        boxHor.add(self.paramSeparator)
        # bottom-left box adds this box
        bottomleft.add(boxHor)

        # creates a box to input a parameter
        boxHor = swing.Box.createHorizontalBox()
        self.addLabel("Enter parameter: ", boxHor)
        self.fileParameterName = swing.JTextField("", 30)
        boxHor.add(self.fileParameterName)
        # bottom-left box adds this box
        bottomleft.add(boxHor)

        # "submit" button is created and added into the bottom-left box
        submit = swing.JButton("submit", actionPerformed=self.timeUserList)
        self.fileSubmitError = swing.JLabel("")
        bottomleft.add(submit)
        bottomleft.add(self.fileSubmitError)

        # now as we have everything we want for the bottom-left, let's add it inside of the bottom-half
        bottomhalf.add(bottomleft)

        # creates a box inside of the bottom-half area in the bottom-right
        bottomright = self.getBorderVertBox()
        # title for the bottom-right area
        self.addTitle("Results", bottomright)

        # gets results about the time for each username from txt/json file and it adds it on bottom-right
        self.getListResults = swing.JTextArea("", 50, 30)
        self.getListResults.setEditable(False)
        bottomright.add(self.getListResults)

        # it creates a box to store the buttons funcinalities in the bottom-right area
        boxHor = swing.Box.createHorizontalBox()

        # "download results" button allows the user to download the results because they are stored
        # into the box which stores the buttons funcinalities
        downRes = swing.JButton("Download results", actionPerformed=self.downloadResults)
        boxHor.add(downRes)

        # "view the request" button is stored into the box which stores the buttons funcinalities
        self.showListRequestIsOn = False
        self.listResultOutput = ""
        self.listViewReq = swing.JButton("View the request", actionPerformed=self.showListRequest)
        boxHor.add(self.listViewReq)

        # bottom-right box adds the box which stores the buttons funcinalities
        bottomright.add(boxHor)

        # now as we have everything we want for the bottom-right, let's add it inside of the bottom-half
        bottomhalf.add(bottomright)

        # as we have everything we want for the bottom-half, let's add it inside of the big box
        pagebox.add(bottomhalf)

        # it draws a horizontal line right after the bottom-half box
        sep = swing.JSeparator()
        # big box stores this horizontal line
        pagebox.add(sep)

        # it creates a box for debugging output
        debugbox = self.getBorderVertBox()
        horizontaldebug = swing.Box.createHorizontalBox()
        self.addLabel("Something went wrong?", horizontaldebug)
        viewDeb = swing.JButton("View debug output")
        horizontaldebug.add(viewDeb)
        debugbox.add(horizontaldebug)
        # big box adds this box
        pagebox.add(debugbox)

        # timing attack tab adds the big box
        self.firstTab.add(pagebox)

        return self.firstTab

    # method that creates a box without border (we can say that it can be the background box)
    def getBorderVertBox(self):
        boxVert = swing.Box.createVerticalBox()
        bord = swing.border.EmptyBorder(10, 10, 10, 10)
        boxVert.setBorder(bord)
        return boxVert

    # method that creates the label/text
    def addLabel(self, text, box):
        labelArea = swing.JLabel(text)
        box.add(labelArea)
        return

    # method that add titles for the white boxes
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

    # method that allows the user to choose a file
    def chooseFile(self, event):
        self.chooser = swing.JFileChooser()
        fileextensions = ["txt", "jason"]
        filter = swing.filechooser.FileNameExtensionFilter("TXT & JSON FILES", fileextensions)
        self.chooser.setFileFilter(filter)
        returnVal = self.chooser.showOpenDialog(self.chooser)
        if(returnVal == swing.JFileChooser.APPROVE_OPTION):
            self.inputFile.text = self.chooser.getSelectedFile().getName()

    # method that gets the time from one valid username and from one invalid username
    def timeTwoUsers(self, event):
        if (self.curRequest == None):
            return
        # change button to say show request
        self.showRequestTopIsOn = False
        self.twoUserViewReq.setText("View the request")
        threading.Thread(target=self.getTwoUserTimes).start()
        return

    # method that shows the time for the user
    def getTwoUserTimes(self):
        self.getResults.text = "Valid username: " + self.validUser.text + " ; time: "
        self.getResults.text += str(self.getTime(self.validUser.text)) + "\n"
        self.getResults.text += "Invalid username: " + self.invalidUser.text + " ; time: "
        self.getResults.text += str(self.getTime(self.invalidUser.text))

    # method that reads the usernames from a file
    def timeUserList(self, event):
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

    # method that shows the time from each username for the user
    def getUserListTimes(self):
        self.getListResults.text = ""
        for i in self.userList:
            self.getListResults.text += "Username: " + i + " Time: "
            self.getListResults.text += str(self.getTime(i)) + "\n"
        return

    # method that shows the request from one valid username and from one invalid username
    def showRequestTop(self, event):
        if (not self.showRequestTopIsOn):
            self.twoUserResultOutput = self.getResults.text
        self.showRequest(self.getResults, self.twoUserViewReq, self.twoUserResultOutput, self.showRequestTopIsOn)
        self.showRequestTopIsOn = not self.showRequestTopIsOn

    # method that shows the request from a file of usernames
    def showListRequest(self, event):
        if (not self.showListRequestIsOn):
            self.listResultOutput = self.getListResults.text
        self.showRequest(self.getListResults, self.listViewReq, self.listResultOutput, self.showListRequestIsOn)
        self.showListRequestIsOn = not self.showListRequestIsOn

    # Swicth from view request to view result and vice versa
    def showRequest(self, box, button, output, bool):
        if (bool):
            box.text = output
            button.setText("View the request")

        else:
            helpers = self.callbacks.getHelpers()
            output = box.text
            box.text = helpers.bytesToString(self.curRequest.getRequest())
            button.setText("View results")

    # method that offically gets the time from usernames
    def getTime(self, paramInput):
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

        # starts the time and it sends the changed request with valid parameter
        start = time.clock()
        makeRequest = self.callbacks.makeHttpRequest(httpService, newRequest)
        makeRequest.getResponse()
        getTime = time.clock() - start

        # prints the response to the GUI
        return getTime

    # method that allows the user to download
    def downloadResults(self, event):
        if (self.getListResults.text == ""):
            return
        file = open(get_download_path() + "/downloadresults.txt", "w")
        file.write(self.getListResults.text)
        file.close()

    # method that needs to know the path of the download folder to put the file there
    def get_download_path():
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
        self.curRequest = messageList[0]
        self.showRequestTopIsOn = False
        self.twoUserResultOutput = self.getResults.text
        self.showRequest(self.getResults, self.twoUserViewReq, self.twoUserResultOutput, self.showRequestTopIsOn)
        self.showRequestTopIsOn = not self.showRequestTopIsOn
