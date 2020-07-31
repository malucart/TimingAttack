"""
Name:           Timing Attack
Date:           7/30/2020
Author:         inbarmada & louisa
Description:    TimingAttack is open source plugin to help pentesters for guessing if a username is valid or not by how long
                the system takes to respond to an fail authentication. And then, comparing that to how long the system takes
                to respond for a valid one. It means that if attackers can guess one valid username, then they can guess
                much more using the same technique.
Copyright (c) 2020, louisa & inbarmada
All rights reserved.
Please see the attached LICENSE file for additional licensing information.
"""

from burp import IBurpExtender # for the extension
from burp import ITab # for creating an extension tab
from burp import IExtensionHelpers # for helper methods
from burp import IContextMenuFactory # for adding an option to the right click popup menu
from javax import swing # mainly library for UI
from javax.swing import JPanel # for panels
from javax.swing import JScrollPane # making the tab scrollable
from javax.swing import Box # for arranging components either in a row or in a column
from javax.swing import JTextField # for inputting text value in a single line format
from javax.swing import JTextArea # for multi-line text component to display text
from javax.swing import JButton # for buttons
from javax.swing import JSeparator # for implementing divider lines
from javax.swing import JScrollPane # for scroll panes to help with extended text areas
from javax.swing import JLabel # for labels
from javax.swing import JFileChooser # for importing and exporting file chooser
from javax.swing import GroupLayout # for adding all groups
from javax.swing.filechooser import FileNameExtensionFilter # for importing and exporting
from javax.swing.border import EmptyBorder # for an empty/transparent border
from java.awt import BorderLayout # for panel layouts
from java.awt import Color # for setting a different background on disabled text areas
from java.awt import Font # for adding bold font to text labels in main tab
from java.awt import Component # for setting a component
from java.awt import Dimension
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
        self.scrollPane = JScrollPane(self.firstTab,
                                      JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                                      JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        return self.scrollPane


    ###########################
    # SECTION 1: CREATING GUI #
    ###########################

    def createTabGUI(self):
        """ Create GUI for this tabbed pane """
        # panel for the whole tab
        self.firstTab = JPanel()

        # name of the extention
        self.titleTop = JLabel("Timing Attack")
        self.titleTop.setFont(Font("Tahoma", 1, 14))
        self.titleTop.setForeground(Color(255,102,51))

        # info about the extention
        self.infoTop = JLabel("Timing Attack is a open source extention to inform how long the system takes to respond for a valid and an invalid authentication.")
        self.infoTop.setFont(Font("Tahoma", 0, 11))

        # labels and inputs on top half
        self.addTitle = JLabel("Enter a Valid and an Invalid Username")
        self.addTitle.setFont(Font("Tahoma", 1, 13))
        self.addTitle.setForeground(Color(255,102,51))
        self.validUsername = swing.JLabel("Valid Username")
        self.validUsername.setFont(Font("Tahoma", 0, 12))
        self.invalidUsername = swing.JLabel("Invalid Username")
        self.invalidUsername.setFont(Font("Tahoma", 0, 12))
        self.parameter = swing.JLabel("Parameter")
        self.parameter.setFont(Font("Tahoma", 0, 12))
        self.average = swing.JLabel("Sample Size")
        self.average.setFont(Font("Tahoma", 0, 12))
        self.addValid = swing.JTextField("")
        self.addInvalid = swing.JTextField("")
        self.addParameter = swing.JTextField("")
        self.addAverage = swing.JTextField("")
        self.submitButton1 = swing.JButton("Submit", actionPerformed=self.timeTwoUsers)

        # result on top left
        self.resultTitle = swing.JLabel("Result")
        self.resultTitle.setFont(Font("Tahoma", 1, 13))
        self.resultTitle.setForeground(Color(255,102,51))
        self.showResults = swing.JTextArea("")
        self.showResults.setEditable(False)
        showResultsScroll = swing.JScrollPane(self.showResults)
        self.twoUserResultOutput = ""
        self.twoUserViewResult = swing.JButton("View Results", actionPerformed=self.showResultsTop)
        self.twoUserViewReq = swing.JButton("View the Request", actionPerformed=self.showRequestTop)
        self.twoUserViewValidResponse = swing.JButton("View Valid Response", actionPerformed=self.showValidResponseTop)
        self.twoUserViewInvalidResponse = swing.JButton("View Invalid Response", actionPerformed=self.showInvalidResponseTop)
        # Set top buttons to invisible until a request is submitted
        self.twoUserViewResult.setVisible(False)
        self.twoUserViewReq.setVisible(False)
        self.twoUserViewValidResponse.setVisible(False)
        self.twoUserViewInvalidResponse.setVisible(False)

        # separator
        self.bar = swing.JSeparator(swing.SwingConstants.HORIZONTAL)

        # labels, inputs and file on bottom half
        self.addTitleFile = swing.JLabel("Input Username File")
        self.addTitleFile.setFont(Font("Tahoma", 1, 13))
        self.addTitleFile.setForeground(Color(255,102,51))
        self.inputFileButton = swing.JButton("Choose File...", actionPerformed=self.chooseFile)
        self.separatorList = swing.JLabel("Separator")
        self.separatorList.setFont(Font("Tahoma", 0, 12))
        self.parameterList = swing.JLabel("Parameter")
        self.parameterList.setFont(Font("Tahoma", 0, 12))
        self.averageList = swing.JLabel("Sample Size")
        self.averageList.setFont(Font("Tahoma", 0, 12))
        self.addSeparatorList = swing.JTextField("")
        self.addParameterList = swing.JTextField("")
        self.addAverageList = swing.JTextField("")
        self.submitButton2 = swing.JButton("Submit", actionPerformed=self.timeUserList)

        # result on bottom left
        self.resultTitleList = swing.JLabel("Result")
        self.resultTitleList.setFont(Font("Tahoma", 1, 13))
        self.resultTitleList.setForeground(Color(255,102,51))
        self.showResultsList = swing.JTextArea("")
        self.showResultsList.setEditable(False)
        showResultsListScroll = swing.JScrollPane(self.showResultsList)
        self.downloadResultList = JButton("Download Results", actionPerformed=self.downloadResults)
        self.showListRequestIsOn = False
        self.listResultOutput = ""
        self.listViewReq = swing.JButton("View the Request", actionPerformed=self.showListRequest)

        # separator
        self.bar2 = swing.JSeparator(swing.SwingConstants.HORIZONTAL)

        # something wrong?
        self.somethingWrong = swing.JLabel("Something Wrong?")
        self.debugOn = False
        self.viewDebug = JButton("View debug output", actionPerformed=self.showDebug)
        self.debugText = swing.JTextArea("")
        self.debugTextScroll = swing.JScrollPane(self.debugText)
        self.debugTextScroll.setVisible(False)

        # layout
        layout = swing.GroupLayout(self.firstTab)
        self.firstTab.setLayout(layout)


        layout.setHorizontalGroup(
            layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
            # whole layout
            .addGroup(layout.createSequentialGroup()
                .addGap(15)
                # title + description
                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                    .addComponent(self.titleTop)
                    .addComponent(self.infoTop)
                    # titles
                    .addGroup(layout.createSequentialGroup()
                        # title left
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                            .addComponent(self.addTitle))
                            .addGap(168)
                        # title right
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                            .addComponent(self.resultTitle)))

                    .addGroup(layout.createSequentialGroup()
                        # left
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                            .addComponent(self.validUsername)
                            .addComponent(self.invalidUsername)
                            .addComponent(self.parameter)
                            .addComponent(self.average)
                            .addComponent(self.addTitleFile)
                            .addComponent(self.inputFileButton)
                            .addComponent(self.separatorList)
                            .addComponent(self.parameterList)
                            .addComponent(self.averageList)
                            .addComponent(self.somethingWrong))
                            .addGap(12)
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                            .addComponent(self.addValid, swing.GroupLayout.PREFERRED_SIZE, 200, swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(self.addInvalid, swing.GroupLayout.PREFERRED_SIZE, 200, swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(self.addParameter, swing.GroupLayout.PREFERRED_SIZE, 200, swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(self.addAverage, swing.GroupLayout.PREFERRED_SIZE, 80, swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(self.submitButton1)
                            .addComponent(self.addSeparatorList, swing.GroupLayout.PREFERRED_SIZE, 200, swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(self.addParameterList, swing.GroupLayout.PREFERRED_SIZE, 200, swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(self.addAverageList, swing.GroupLayout.PREFERRED_SIZE, 80, swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(self.submitButton2)
                            .addComponent(self.viewDebug))
                        .addGap(50)
                        # right
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                            .addComponent(showResultsScroll, swing.GroupLayout.PREFERRED_SIZE, 600, swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(self.twoUserViewResult))
                                .addGap(15)
                                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(self.twoUserViewReq))
                                .addGap(15)
                                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(self.twoUserViewValidResponse))
                                    .addGap(15)
                                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(self.twoUserViewInvalidResponse)))
                            .addComponent(self.resultTitleList)
                            .addComponent(showResultsListScroll, swing.GroupLayout.PREFERRED_SIZE, 600, swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(self.downloadResultList))
                                .addGap(15)
                                .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(self.listViewReq)))
                            .addGap(10)
                            .addComponent(self.debugTextScroll, swing.GroupLayout.PREFERRED_SIZE, 300, swing.GroupLayout.PREFERRED_SIZE))))))


        layout.setVerticalGroup(
            layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
            # whole layout
            .addGroup(layout.createSequentialGroup()
                .addGap(15)
                .addComponent(self.titleTop)
                .addGap(10)
                .addComponent(self.infoTop)
                .addGap(10)
                # titles
                .addGroup(layout.createSequentialGroup()
                    # left
                    .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                        .addComponent(self.addTitle)
                        .addGap(25)
                    # right
                    .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.LEADING)
                        .addComponent(self.resultTitle))))
                # top half
                .addGroup(layout.createSequentialGroup()
                    # left top half
                    .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                        .addGroup(layout.createSequentialGroup()
                            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(self.validUsername)
                                .addGap(5)
                                .addComponent(self.addValid, swing.GroupLayout.PREFERRED_SIZE, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(5)
                            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(self.invalidUsername)
                                .addGap(5)
                                .addComponent(self.addInvalid, swing.GroupLayout.PREFERRED_SIZE, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(5)
                            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(self.parameter)
                                .addGap(5)
                                .addComponent(self.addParameter, swing.GroupLayout.PREFERRED_SIZE, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(5)
                            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(self.average)
                                .addGap(5)
                                .addComponent(self.addAverage, swing.GroupLayout.PREFERRED_SIZE, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.PREFERRED_SIZE))
                            .addGap(5)
                            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(self.submitButton1)))
                            .addGap(5)
                    # right top half
                    .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(showResultsScroll, swing.GroupLayout.PREFERRED_SIZE, 200, swing.GroupLayout.PREFERRED_SIZE))))
                .addGap(5)
                # buttons + titles
                .addGroup(layout.createSequentialGroup()
                    .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(self.twoUserViewResult)
                        .addGap(20)
                        .addComponent(self.twoUserViewReq)
                        .addGap(20)
                        .addComponent(self.twoUserViewValidResponse)
                        .addGap(20)
                        .addComponent(self.twoUserViewInvalidResponse))
                    .addGap(10)
                    .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(self.addTitleFile)
                        .addGap(25)
                        .addComponent(self.resultTitleList)))
                        .addGap(3)
                # bottom half
                .addGroup(layout.createSequentialGroup()
                    # left bottom half
                    .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                        .addGroup(layout.createSequentialGroup()
                            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(self.inputFileButton))
                                .addGap(10)
                            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(self.separatorList)
                                .addGap(5)
                                .addComponent(self.addSeparatorList, swing.GroupLayout.PREFERRED_SIZE, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(5)
                            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(self.parameterList)
                                .addGap(5)
                                .addComponent(self.addParameterList, swing.GroupLayout.PREFERRED_SIZE, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(5)
                            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(self.averageList)
                                .addGap(5)
                                .addComponent(self.addAverageList, swing.GroupLayout.PREFERRED_SIZE, swing.GroupLayout.DEFAULT_SIZE, swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(5)
                            .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(self.submitButton2)))
                                .addGap(5)
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                                .addComponent(showResultsListScroll, swing.GroupLayout.PREFERRED_SIZE, 200, swing.GroupLayout.PREFERRED_SIZE))))
                    .addGap(5)
                    # right bottom half
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(self.downloadResultList)
                            .addGap(10)
                            .addComponent(self.listViewReq)))
                    .addGap(30)
                # something wrong section
                .addGroup(layout.createSequentialGroup()
                    .addGroup(layout.createParallelGroup(swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(self.somethingWrong)
                        .addGap(10)
                        .addComponent(self.viewDebug)
                        .addGap(10)
                        .addComponent(self.debugTextScroll, swing.GroupLayout.PREFERRED_SIZE, 150, swing.GroupLayout.PREFERRED_SIZE)))))
        return


    def chooseFile(self, event):
        # Method that allows the user to choose a file of usernames
        # try to load the last used directory
        try:
            # load the directory for future imports/exports
            fileChooserDirectory = self._callbacks.loadExtensionSetting("fileChooserDirectory")

        # there is not a last used directory
        except:
            # set the last used directory to blank
            fileChooserDirectory = ""

        self.chooser = swing.JFileChooser(fileChooserDirectory)
        fileextensions = ["txt"]
        filter = FileNameExtensionFilter("TXT FILES", fileextensions)
        self.chooser.setFileFilter(filter)
        returnVal = self.chooser.showOpenDialog(self.chooser)
        if(returnVal == swing.JFileChooser.APPROVE_OPTION):
            self.inputFile.text = self.chooser.getSelectedFile().getName()


    ##################################
    # SECTION 2: SEND TIMING REQUEST #
    ##################################


    def timeTwoUsers(self, event):
        # Method that sends the current request to getTwoUserTimes
        if (self.curRequest == None):
            self.debugOutput("Timing Attack does not have a request")
            return
        # change button to say show request
        self.twoUserViewResult.setVisible(True)
        self.twoUserViewReq.setVisible(True)
        self.twoUserViewValidResponse.setVisible(True)
        self.twoUserViewInvalidResponse.setVisible(True)
        threading.Thread(target=self.getTwoUserTimes).start()
        return


    def getTwoUserTimes(self):
        # Method that prints the time taken to return responses
        # from one valid username and from one invalid username (called
        # by timeTwoUsers)
        self.twoUserViewReq.setVisible(True)
        validTime, self.validResponse = self.getTime(self.addParameter.text, self.addValid.text, self.addAverage.text)
        invalidTime, self.invalidResponse = self.getTime(self.addParameter.text, self.addInvalid.text, self.addAverage.text)
        self.showResults.text = "Valid username: " + self.addValid.text + "\t Time: "
        self.showResults.text += str(validTime) + "\n"
        self.showResults.text += "Invalid username: " + self.addInvalid.text + "\t Time: "
        self.showResults.text += str(invalidTime)
        self.twoUserResult = self.showResults.text


    def timeUserList(self, event):
        # Method that reads the usernames from file and sends
        # them to getUserListTimes
        # if there is no file, so the program is going to return anything
        if (self.curRequest == None):
            self.debugOutput("Timing Attack does not have a request")
            return
        try:
            # stores the file
            file = self.chooser.getSelectedFile()

            # reads it
            scan = Scanner(file)
            readFile = ""
            while scan.hasNext():
                readFile += scan.nextLine()

            # divides the file to a list of usernames
            self.userList = readFile.split(self.addSeparatorList.text)

            # change button to say show request
            self.showListRequestIsOn = False
            self.listViewReq.setText("View the Request")
            # gets the time for each username
            threading.Thread(target=self.getUserListTimes).start()
        # it will handle the error and send a message about it
        except:
           self.debugOutput("No File Submitted")
        return


    def getUserListTimes(self):
        # Method that prints the time taken to return responses
        # for each username from file (called by timeUserList)
        self.listViewReq.setVisible(True)
        self.showResultsList.text = ""
        for i in self.userList:
            self.showResultsList.text += "Username: " + i + " Time: "
            self.showResultsList.text += str(self.getTime(self.addParameterList.text, i, self.addAverageList.text)) + "\n"
        return


    def getTime(self, paramName, paramInput, numTriesText):
        # Method that takes in a username and returns time taken to get
        # its response (called by getTwoUserTimes and getUserListTimes)
        try:
            numTries = int(numTriesText)
        except:
            self.debugOutput("Sample size must be an integer")
        # keeps a reference to helpers
        helpers = self.callbacks.getHelpers()
        # Get the request
        request = self.curRequest.getRequest()
        # Get request information
        requestInfo = helpers.analyzeRequest(request)

        # loop through parameters
        for i in requestInfo.getParameters():
            # find username parameter and change its value
            if (i.getName() == paramName):
                # it creates the request
                buildParam = helpers.buildParameter(paramName, paramInput, i.getType())
                newRequest = helpers.updateParameter(request, buildParam)

        if 'newRequest' not in locals():
            self.debugOutput("Parameter " + paramName + " cannot be found in request")
        # it builds an http service to send a request to the website
        httpService = self.curRequest.getHttpService()
        httpService = helpers.buildHttpService(httpService.getHost(), httpService.getPort(), False)

        getTime = 0
        for i in range(numTries):
            # starts the time and it sends the changed request with valid parameter
            start = time.clock()
            makeRequest = self.callbacks.makeHttpRequest(httpService, newRequest)
            makeRequest.getResponse()
            getTime += time.clock() - start

        response = self.callbacks.makeHttpRequest(httpService, newRequest).getResponse()
        # return the response
        return getTime / numTries, response


    ###################################
    # SECTION 3: VIEW REQUEST BUTTONS #
    ###################################


    def showRequestTop(self, event):
        # Method that shows the request for top box
        helpers = self.callbacks.getHelpers()
        self.showResults.text = helpers.bytesToString(self.curRequest.getRequest())


    def showListRequest(self, event):
        # Method that shows the request from a file of usernames
        if (not self.showListRequestIsOn):
            self.listResultOutput = self.showResultsList.text
        self.showRequest(self.showResultsList, self.listViewReq, self.listResultOutput, self.showListRequestIsOn)
        if self.listResultOutput:
            self.showListRequestIsOn = not self.showListRequestIsOn


    def showRequest(self, box, button, output, bool):
        # Switch from view request to view result and vice versa
        if (bool):
            if not output:
                return
            else:
                box.text = output
                button.setText("View the Request")

        else:
            helpers = self.callbacks.getHelpers()
            output = box.text
            box.text = helpers.bytesToString(self.curRequest.getRequest())
            button.setText("View Results")

    def showResultsTop(self, event):
        self.showResults.text = self.twoUserResult

    def showValidResponseTop(self, event):
        helpers = self.callbacks.getHelpers()
        self.showResults.text = helpers.bytesToString(self.validResponse)

    def showInvalidResponseTop(self, event):
        helpers = self.callbacks.getHelpers()
        self.showResults.text = helpers.bytesToString(self.invalidResponse)


    ###############################
    # SECTION 4: DOWNLOAD BUTTONS #
    ###############################


    def downloadResults(self, event):
        # Method that allows user to download file of times for responses
        # for usernames from list
        if (self.showResultsList.text == ""):
            return
        file = open(get_download_path() + "/downloadresults.txt", "w")
        file.write(self.showResultsList.text)
        file.close()


    def get_download_path():
        # Method to find path of download folder (called by downloadResults)
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


    ###########################
    # SECTION 5: DEBUG BUTTON #
    ###########################


    def debugOutput(self, message):
        # Write a debug message in the debug box
        self.debugText.text = message
        # self.debugText.setVisible(True)
        self.debugTextScroll.setVisible(True)
        self.viewDebug.setText("Close Debug Output")
        self.debugOn = True


    def showDebug(self, event):
        # Open or close debug box
        if self.debugOn:
            # self.debugText.setVisible(False)
            self.debugTextScroll.setVisible(False)
            self.viewDebug.setText("View Debug Output")
            self.debugOn = False
            self.debugText.text = ""
        else:
            # self.debugText.setVisible(True)
            self.debugTextScroll.setVisible(True)
            self.viewDebug.setText("Close Debug Output")
            self.debugOn = True


    ###################################
    # SECTION 6: TAB RECIEVES REQUEST #
    ###################################


    def getRequest(self, messageList):
        # Method that stores the request sent from proxy
        self.curRequest = messageList[0]
        # Make sure show request tabs start out empty
        self.showListRequestIsOn = False
        self.listResultOutput = self.showResultsList.text
        # Show request in both top and bottom windows
        self.showRequest(self.showResultsList, self.listViewReq, self.listResultOutput, self.showListRequestIsOn)
        self.showListRequestIsOn = True
        self.listViewReq.setVisible(False)
        # Show request in top box
        helpers = self.callbacks.getHelpers()
        self.showResults.text = helpers.bytesToString(self.curRequest.getRequest())
